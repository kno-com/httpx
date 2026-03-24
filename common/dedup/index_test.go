package dedup

import (
	"math/bits"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBandIndex_ExactMatch(t *testing.T) {
	tests := []struct {
		name string
		hash uint64
	}{
		{name: "zero hash", hash: 0},
		{name: "max hash", hash: ^uint64(0)},
		{name: "typical hash", hash: 0xDEADBEEFCAFEBABE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := newBandIndex()

			// Not present yet.
			assert.False(t, idx.hasNearDuplicate(tt.hash, 0),
				"should not find hash before insertion")

			idx.add(tt.hash)

			// Exact match with threshold 0.
			assert.True(t, idx.hasNearDuplicate(tt.hash, 0),
				"should find exact match at threshold 0")

			// Exact match with higher threshold.
			assert.True(t, idx.hasNearDuplicate(tt.hash, 3),
				"should find exact match at threshold 3")
		})
	}
}

func TestBandIndex_NearDuplicate_WithinThreshold(t *testing.T) {
	// Pigeonhole guarantee: if two 64-bit hashes differ in <= 3 bits,
	// at least one of the four 16-bit bands must be identical.
	tests := []struct {
		name      string
		base      uint64
		distance  uint8
		threshold uint8
		wantMatch bool
	}{
		{
			name:      "1-bit distance, threshold 3",
			base:      0xAAAABBBBCCCCDDDD,
			distance:  1,
			threshold: 3,
			wantMatch: true,
		},
		{
			name:      "2-bit distance, threshold 3",
			base:      0xAAAABBBBCCCCDDDD,
			distance:  2,
			threshold: 3,
			wantMatch: true,
		},
		{
			name:      "3-bit distance, threshold 3",
			base:      0xAAAABBBBCCCCDDDD,
			distance:  3,
			threshold: 3,
			wantMatch: true,
		},
		{
			name:      "1-bit distance, threshold 1",
			base:      0x1234567890ABCDEF,
			distance:  1,
			threshold: 1,
			wantMatch: true,
		},
		{
			name:      "exact match, threshold 0",
			base:      0x1234567890ABCDEF,
			distance:  0,
			threshold: 0,
			wantMatch: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := newBandIndex()
			idx.add(tt.base)

			candidate := flipBitsAt(tt.base, tt.distance)
			require.Equal(t, tt.distance, uint8(bits.OnesCount64(tt.base^candidate)),
				"flipBitsAt sanity check")

			got := idx.hasNearDuplicate(candidate, tt.threshold)
			assert.Equal(t, tt.wantMatch, got)
		})
	}
}

func TestBandIndex_BeyondThreshold_NotMatched(t *testing.T) {
	tests := []struct {
		name      string
		base      uint64
		distance  uint8
		threshold uint8
	}{
		{
			name:      "4-bit distance, threshold 3",
			base:      0xAAAABBBBCCCCDDDD,
			distance:  4,
			threshold: 3,
		},
		{
			name:      "1-bit distance, threshold 0",
			base:      0x1234567890ABCDEF,
			distance:  1,
			threshold: 0,
		},
		{
			name:      "10-bit distance, threshold 5",
			base:      0xFFFFFFFFFFFFFFFF,
			distance:  10,
			threshold: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := newBandIndex()
			idx.add(tt.base)

			candidate := flipBitsAt(tt.base, tt.distance)
			require.Equal(t, tt.distance, uint8(bits.OnesCount64(tt.base^candidate)),
				"flipBitsAt sanity check")

			got := idx.hasNearDuplicate(candidate, tt.threshold)
			assert.False(t, got,
				"should NOT match when distance %d exceeds threshold %d",
				tt.distance, tt.threshold)
		})
	}
}

func TestBandIndex_DifferentThresholds(t *testing.T) {
	base := uint64(0xDEADBEEFCAFEBABE)
	// Create a candidate exactly 3 bits away.
	candidate := flipBitsAt(base, 3)

	tests := []struct {
		name      string
		threshold uint8
		wantMatch bool
	}{
		{name: "threshold 0", threshold: 0, wantMatch: false},
		{name: "threshold 1", threshold: 1, wantMatch: false},
		{name: "threshold 2", threshold: 2, wantMatch: false},
		{name: "threshold 3 (equal)", threshold: 3, wantMatch: true},
		{name: "threshold 4", threshold: 4, wantMatch: true},
		{name: "threshold 10", threshold: 10, wantMatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := newBandIndex()
			idx.add(base)

			got := idx.hasNearDuplicate(candidate, tt.threshold)
			assert.Equal(t, tt.wantMatch, got)
		})
	}
}

func TestBandIndex_AddIfAbsent(t *testing.T) {
	idx := newBandIndex()
	h := uint64(0xCAFEBABE12345678)

	// First insert: not a duplicate.
	dup := idx.addIfAbsent(h, 3)
	assert.False(t, dup, "first insert should not be duplicate")
	assert.Equal(t, 1, idx.size())

	// Second insert of same hash: duplicate.
	dup = idx.addIfAbsent(h, 3)
	assert.True(t, dup, "second insert of same hash should be duplicate")
	assert.Equal(t, 1, idx.size(), "duplicate should not increase size")

	// Near-duplicate within threshold: duplicate.
	near := flipBitsAt(h, 2)
	dup = idx.addIfAbsent(near, 3)
	assert.True(t, dup, "near-duplicate within threshold should be duplicate")
	assert.Equal(t, 1, idx.size(), "near-duplicate should not increase size")

	// Beyond threshold: not duplicate.
	far := flipBitsAt(h, 10)
	dup = idx.addIfAbsent(far, 3)
	assert.False(t, dup, "beyond-threshold should not be duplicate")
	assert.Equal(t, 2, idx.size(), "novel hash should increase size")
}

func TestBandIndex_ConcurrentSafety(t *testing.T) {
	idx := newBandIndex()
	const goroutines = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			h := uint64(n) * 0x9E3779B97F4A7C15 // spread via golden ratio
			idx.add(h)
			idx.hasNearDuplicate(h, 3)
			idx.addIfAbsent(h+1, 3)
		}(i)
	}
	wg.Wait()

	assert.Greater(t, idx.size(), 0, "index should have entries after concurrent ops")
}

func TestExtractBand(t *testing.T) {
	// 0x1111222233334444
	// Band 0 (bits 0-15):  0x4444
	// Band 1 (bits 16-31): 0x3333
	// Band 2 (bits 32-47): 0x2222
	// Band 3 (bits 48-63): 0x1111
	hash := uint64(0x1111222233334444)
	assert.Equal(t, uint16(0x4444), extractBand(hash, 0))
	assert.Equal(t, uint16(0x3333), extractBand(hash, 1))
	assert.Equal(t, uint16(0x2222), extractBand(hash, 2))
	assert.Equal(t, uint16(0x1111), extractBand(hash, 3))
}

// ---------- Benchmarks ----------

// BenchmarkLinearScan benchmarks the old O(n) approach: iterating over all
// stored hashes and computing Hamming distance for each one.
func BenchmarkLinearScan(b *testing.B) {
	const numEntries = 10_000
	hashes := make([]uint64, numEntries)
	for i := range hashes {
		hashes[i] = uint64(i) * 0x9E3779B97F4A7C15
	}

	// Target: a hash that is NOT a near-duplicate of any stored hash (worst case).
	target := uint64(0xFFFFFFFFFFFFFFFF)

	b.ResetTimer()
	for range b.N {
		for _, stored := range hashes {
			if hammingDistance(stored, target) <= 3 {
				break
			}
		}
	}
}

// BenchmarkBandIndex benchmarks the band-partitioned O(1) amortized approach
// with the same 10k entries.
func BenchmarkBandIndex(b *testing.B) {
	const numEntries = 10_000
	idx := newBandIndex()
	for i := range numEntries {
		h := uint64(i) * 0x9E3779B97F4A7C15
		idx.add(h)
	}

	// Target: a hash that is NOT a near-duplicate of any stored hash (worst case).
	target := uint64(0xFFFFFFFFFFFFFFFF)

	b.ResetTimer()
	for range b.N {
		idx.hasNearDuplicate(target, 3)
	}
}
