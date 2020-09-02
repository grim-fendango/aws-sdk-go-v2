package v4

import (
	"container/heap"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
)

func lookupKey(accessKey, service, region, date string) string {
	var s strings.Builder
	s.Grow(len(accessKey) + len(date) + len(region) + len(service) + 3)
	s.WriteString(accessKey)
	s.WriteRune('/')
	s.WriteString(date)
	s.WriteRune('/')
	s.WriteString(region)
	s.WriteRune('/')
	s.WriteString(service)
	return s.String()
}

type keyValue struct {
	Key        string
	Accessed   atomic.Value
	Credential []byte
}

func (v *keyValue) Expired(t time.Time) bool {
	return v.Accessed.Load().(time.Time).Before(t)
}

type lastAccessHeap []*keyValue

func (h lastAccessHeap) Len() int {
	return len(h)
}

func (h lastAccessHeap) Less(i, j int) bool {
	return h[i].Accessed.Load().(time.Time).Before(h[j].Accessed.Load().(time.Time))
}

func (h lastAccessHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *lastAccessHeap) Push(x interface{}) {
	*h = append(*h, x.(*keyValue))
}

func (h *lastAccessHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type KeyDerivator struct {
	lastAccess lastAccessHeap
	values     map[string]*keyValue
	rw         sync.RWMutex
}

func NewKeyDerivator() *KeyDerivator {
	return &KeyDerivator{
		values: make(map[string]*keyValue),
	}
}

func (k *KeyDerivator) DeriveKey(credential aws.Credentials, service, region string, t time.Time) ([]byte, error) {
	signingTime := NewSigningTime(t)

	lookupKey := lookupKey(credential.AccessKeyID, service, region, signingTime.ShortTimeFormat())

	k.rw.RLock()
	key, ok := k.getKey(lookupKey)
	if ok {
		k.rw.RUnlock()
		return key, nil
	}
	k.rw.RUnlock()

	k.rw.Lock()
	key, err := k.deriveKey(lookupKey, credential, service, region, signingTime)
	k.rw.Unlock()

	return key, err
}

func (k *KeyDerivator) getKey(lookup string) ([]byte, bool) {
	currentTime := sdk.NowTime().UTC()
	value, ok := k.values[lookup]
	if !ok {
		return nil, false
	}
	value.Accessed.Store(currentTime)
	return value.Credential, true
}

func (k *KeyDerivator) deriveKey(lookup string, credential aws.Credentials, service string, region string, signingTime SigningTime) ([]byte, error) {
	if v, ok := k.getKey(lookup); ok {
		return v, nil
	}

	cred := deriveKey(credential.SecretAccessKey, service, region, signingTime)

	entry := &keyValue{
		Key:        lookup,
		Credential: cred,
	}
	entry.Accessed.Store(sdk.NowTime().UTC())

	k.values[lookup] = entry
	heap.Push(&k.lastAccess, entry)

	return cred, nil
}

func deriveKey(secret, service, region string, t SigningTime) []byte {
	hmacDate := HMACSHA256([]byte("AWS4"+secret), []byte(t.ShortTimeFormat()))
	hmacRegion := HMACSHA256(hmacDate, []byte(region))
	hmacService := HMACSHA256(hmacRegion, []byte(service))
	return HMACSHA256(hmacService, []byte("aws4_request"))
}

func (k *KeyDerivator) manageLastAccess(now time.Time) {
	heap.Init(&k.lastAccess)
	exp := now.Add(time.Minute * -5)
	pop := heap.Pop(&k.lastAccess).(*keyValue)
	for pop.Expired(exp) && len(k.lastAccess) > 0 {
		delete(k.values, pop.Key)
		if len(k.lastAccess) > 0 {
			pop = heap.Pop(&k.lastAccess).(*keyValue)
		}
	}
	if !pop.Expired(exp) {
		heap.Push(&k.lastAccess, pop)
	}
}
