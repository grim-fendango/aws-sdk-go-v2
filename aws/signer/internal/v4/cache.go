package v4

import (
	"strings"
	"sync"
	"sync/atomic"
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
	values map[string]atomic.Value
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
	cacheEntry, cacheResult := s.get(key, credentials, signingTime.Time)
	if cacheResult == Match {
		s.mutex.RUnlock()
		return cacheEntry.Credential
	}
	s.mutex.RUnlock()

	cred := deriveKey(credentials.SecretAccessKey, service, region, signingTime)
	entry := credentialCacheEntry{
		AccessKey:  credentials.AccessKeyID,
		Date:       signingTime.Time,
		Credential: cred,
	}

	if cacheResult == NotMatching {
		v := s.values[key]
		v.Store(entry)
		return cred
	}

	s.mutex.Lock()
	v := s.values[key]
	v.Store(entry)
	s.mutex.Unlock()

	return cred
}

type CacheResult int

const (
	Missing CacheResult = iota
	NotMatching
	Match
)

func (s *signingCache) get(key string, credentials aws.Credentials, signingTime time.Time) (credentialCacheEntry, CacheResult) {
	cacheEntry, ok := s.retrieveFromCache(key)
	if ok {
		if cacheEntry.AccessKey == credentials.AccessKeyID && isSameDay(signingTime, cacheEntry.Date) {
			return cacheEntry, Match
		}
		return credentialCacheEntry{}, NotMatching
	}

	return credentialCacheEntry{}, Missing
}

func (s *signingCache) retrieveFromCache(key string) (credentialCacheEntry, bool) {
	if v, ok := s.values[key]; ok {
		return v.Load().(credentialCacheEntry), true
	}
	return credentialCacheEntry{}, false
}

type KeyDerivator struct {
	cache signingCache
}

func NewKeyDerivator() *KeyDerivator {
	return &KeyDerivator{
		cache: signingCache{values: make(map[string]atomic.Value)},
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
