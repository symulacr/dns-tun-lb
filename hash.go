package main

import (
	"encoding/binary"
	"hash/maphash"
	"sort"
)

// jumpHash implements Google's consistent hash (arXiv:1406.2294).
// Returns a bucket index in [0, numBuckets). O(1) time, O(1) memory.
func jumpHash(key uint64, numBuckets int) int {
	var b int64 = -1
	var j int64
	for j < int64(numBuckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(1<<31) / float64((key>>33)+1)))
	}
	return int(b)
}

// hashRing is a consistent hash ring backed by jump hash.
type hashRing struct {
	backends []BackendConfig // sorted by ID
	seed     maphash.Seed
}

// newHashRing builds a hashRing sorted by backend ID for deterministic selection.
func newHashRing(backends []BackendConfig, replicas int) *hashRing {
	if len(backends) == 0 {
		return &hashRing{}
	}
	_ = replicas // jump hash needs no replicas; kept for API compatibility
	sorted := make([]BackendConfig, len(backends))
	copy(sorted, backends)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	return &hashRing{
		backends: sorted,
		seed:     maphash.MakeSeed(),
	}
}

// choose returns the backend for the given protocol, domain suffix, and session ID.
// ok=false when the ring is empty.
func (r *hashRing) choose(protocol, domainSuffix string, sessionID []byte) (BackendConfig, bool) {
	if len(r.backends) == 0 {
		return BackendConfig{}, false
	}

	if len(sessionID) == 0 {
		// Use deterministic jitter from protocol+domain instead of random.
		var fallbackBuf [256]byte
		n := copy(fallbackBuf[:], protocol)
		fallbackBuf[n] = 0; n++
		n += copy(fallbackBuf[n:], domainSuffix)
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], maphash.Bytes(r.seed, fallbackBuf[:n]))
		sessionID = buf[:]
	}

	var keyBuf [256]byte
	n := copy(keyBuf[:], protocol)
	keyBuf[n] = 0; n++
	n += copy(keyBuf[n:], domainSuffix)
	keyBuf[n] = 0; n++
	n += copy(keyBuf[n:], sessionID)

	keyHash := maphash.Bytes(r.seed, keyBuf[:n])
	idx := jumpHash(keyHash, len(r.backends))
	return r.backends[idx], true
}
