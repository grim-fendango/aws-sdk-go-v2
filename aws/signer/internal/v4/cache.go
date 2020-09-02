package v4

import (
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func lookupKey(service, region string) string {
	var s strings.Builder
	s.Grow(len(region) + len(service) + 3)
	s.WriteString(region)
	s.WriteRune('/')
	s.WriteString(service)
	return s.String()
}

type credentialCacheEntry struct {
	AccessKey  string
	Date       time.Time
	Credential []byte
}

type signingCache struct {
	values map[string]credentialCacheEntry
	mutex  sync.RWMutex
}

func isSameDay(x, y time.Time) bool {
	xYear, xMonth, xDay := x.Date()
	yYear, yMonth, yDay := y.Date()

	if xYear != yYear {
		return false
	}

	if xMonth != yMonth {
		return false
	}

	return xDay == yDay
}

func (s *signingCache) Get(credentials aws.Credentials, service, region string, signingTime SigningTime) []byte {
	key := lookupKey(service, region)
	s.mutex.RLock()
	if cred, ok := s.get(key, credentials, signingTime.Time); ok {
		s.mutex.RUnlock()
		return cred
	}
	s.mutex.RUnlock()

	s.mutex.Lock()
	if cred, ok := s.get(key, credentials, signingTime.Time); ok {
		s.mutex.Unlock()
		return cred
	}
	cred := deriveKey(credentials.SecretAccessKey, service, region, signingTime)
	entry := credentialCacheEntry{
		AccessKey:  credentials.AccessKeyID,
		Date:       signingTime.Time,
		Credential: cred,
	}
	s.values[key] = entry
	s.mutex.Unlock()

	return cred
}

func (s *signingCache) get(key string, credentials aws.Credentials, signingTime time.Time) ([]byte, bool) {
	cacheEntry, ok := s.retrieveFromCache(key)
	if ok && cacheEntry.AccessKey == credentials.AccessKeyID && isSameDay(signingTime, cacheEntry.Date) {
		return cacheEntry.Credential, true
	}
	return nil, false
}

func (s *signingCache) retrieveFromCache(key string) (credentialCacheEntry, bool) {
	if v, ok := s.values[key]; ok {
		return v, true
	}
	return credentialCacheEntry{}, false
}

type KeyDerivator struct {
	cache signingCache
}

func NewKeyDerivator() *KeyDerivator {
	return &KeyDerivator{
		cache: signingCache{values: make(map[string]credentialCacheEntry)},
	}
}

func (k *KeyDerivator) DeriveKey(credential aws.Credentials, service, region string, t time.Time) []byte {
	signingTime := NewSigningTime(t)
	return k.cache.Get(credential, service, region, signingTime)
}

func deriveKey(secret, service, region string, t SigningTime) []byte {
	hmacDate := HMACSHA256([]byte("AWS4"+secret), []byte(t.ShortTimeFormat()))
	hmacRegion := HMACSHA256(hmacDate, []byte(region))
	hmacService := HMACSHA256(hmacRegion, []byte(service))
	return HMACSHA256(hmacService, []byte("aws4_request"))
}
