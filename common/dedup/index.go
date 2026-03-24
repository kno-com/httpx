package dedup

import (
	"math/bits"
	"sync"
)

// bandIndex is a band-partitioned index for near-duplicate detection using
// 64-bit simhash fingerprints. It splits each hash into 4 x 16-bit bands and
// maintains a lookup table per band. By the pigeonhole principle, if two
// hashes differ in <= 3 bits, at least one 16-bit band must be identical,
// guaranteeing O(1) amortized candidate lookup instead of O(n) linear scan.
type bandIndex struct {
	// mu guards all mutable fields below.
	mu    sync.RWMutex
	full  map[uint64]struct{}
	bands [4]map[uint16][]uint64
}

// newBandIndex creates a ready-to-use bandIndex.
func newBandIndex() *bandIndex {
	idx := &bandIndex{
		full: make(map[uint64]struct{}),
	}
	for i := range idx.bands {
		idx.bands[i] = make(map[uint16][]uint64)
	}
	return idx
}

// add inserts hash into the full set and all four band tables.
// The caller must NOT hold any lock; add acquires a write lock internally.
func (idx *bandIndex) add(hash uint64) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.full[hash] = struct{}{}
	for i := range idx.bands {
		band := extractBand(hash, i)
		idx.bands[i][band] = append(idx.bands[i][band], hash)
	}
}

// hasNearDuplicate reports whether hash is within threshold Hamming distance
// of any previously added hash. It checks the exact-match set first (O(1)),
// then queries each band table for candidate hashes sharing a 16-bit band and
// computes Hamming distance only on those candidates.
//
// The caller must NOT hold any lock; hasNearDuplicate acquires a read lock.
func (idx *bandIndex) hasNearDuplicate(hash uint64, threshold uint8) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Fast path: exact match.
	if _, ok := idx.full[hash]; ok {
		return true
	}

	// Collect candidates from all four band tables. Use a set to avoid
	// computing Hamming distance on the same candidate twice.
	seen := make(map[uint64]struct{})
	for i := range idx.bands {
		band := extractBand(hash, i)
		for _, candidate := range idx.bands[i][band] {
			if _, already := seen[candidate]; already {
				continue
			}
			seen[candidate] = struct{}{}
			if hammingDistance(candidate, hash) <= threshold {
				return true
			}
		}
	}
	return false
}

// addIfAbsent atomically checks for a near duplicate and, if none is found,
// inserts hash. It returns true when a near duplicate already exists (i.e. hash
// is a duplicate). This combines the read-check and write-insert under a single
// write lock to avoid TOCTOU races.
func (idx *bandIndex) addIfAbsent(hash uint64, threshold uint8) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Exact match fast path.
	if _, ok := idx.full[hash]; ok {
		return true
	}

	// Check candidates from band tables.
	seen := make(map[uint64]struct{})
	for i := range idx.bands {
		band := extractBand(hash, i)
		for _, candidate := range idx.bands[i][band] {
			if _, already := seen[candidate]; already {
				continue
			}
			seen[candidate] = struct{}{}
			if hammingDistance(candidate, hash) <= threshold {
				return true
			}
		}
	}

	// No near duplicate found — insert.
	idx.full[hash] = struct{}{}
	for i := range idx.bands {
		band := extractBand(hash, i)
		idx.bands[i][band] = append(idx.bands[i][band], hash)
	}
	return false
}

// size returns the number of distinct hashes stored.
func (idx *bandIndex) size() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.full)
}

// extractBand returns the i-th 16-bit band from a 64-bit hash.
// Band 0 is bits [0..15], band 1 is bits [16..31], etc.
func extractBand(hash uint64, band int) uint16 {
	return uint16(hash >> (band * 16))
}

// hammingDistance returns the number of bit positions where a and b differ.
func hammingDistance(a, b uint64) uint8 {
	return uint8(bits.OnesCount64(a ^ b))
}
