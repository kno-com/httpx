package dedup

import (
	"fmt"
	"math/bits"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Defaults(t *testing.T) {
	d := New()
	require.NotNil(t, d)
	assert.Equal(t, uint8(3), d.threshold, "default threshold should be 3")
	assert.True(t, d.stripDynamic, "default stripDynamic should be true")
	assert.NotNil(t, d.idx)
	assert.NotNil(t, d.preprocessor)
	assert.NotNil(t, d.featureHasher)
}

func TestNew_WithOptions(t *testing.T) {
	d := New(WithThreshold(2), WithStripDynamic(false))
	assert.Equal(t, uint8(2), d.threshold)
	assert.False(t, d.stripDynamic)
}

func TestNew_ThresholdCapped(t *testing.T) {
	d := New(WithThreshold(10))
	assert.Equal(t, maxGuaranteedThreshold, d.threshold,
		"threshold should be capped at maxGuaranteedThreshold")
}

func TestHammingDistance(t *testing.T) {
	tests := []struct {
		name string
		a, b uint64
		want uint8
	}{
		{name: "identical", a: 0xFF, b: 0xFF, want: 0},
		{name: "one bit", a: 0, b: 1, want: 1},
		{name: "all bits", a: 0, b: ^uint64(0), want: 64},
		{name: "three bits", a: 0b1010, b: 0b0101, want: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hammingDistance(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsDuplicate_ExactDuplicate(t *testing.T) {
	d := New()
	body := []byte("the quick brown fox jumps over the lazy dog")

	first := d.IsDuplicate(body)
	require.False(t, first, "first occurrence should not be a duplicate")

	second := d.IsDuplicate(body)
	assert.True(t, second, "identical content should be detected as duplicate")
}

func TestIsDuplicate_NonDuplicate(t *testing.T) {
	d := New()

	body1 := []byte("the quick brown fox jumps over the lazy dog")
	body2 := []byte("completely different content about quantum physics and relativity")

	first := d.IsDuplicate(body1)
	require.False(t, first)

	second := d.IsDuplicate(body2)
	assert.False(t, second, "completely different content should not be a duplicate")
}

func TestIsDuplicate_CustomThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold uint8
		distance  uint8
		wantDup   bool
	}{
		{name: "within threshold", threshold: 3, distance: 2, wantDup: true},
		{name: "at threshold", threshold: 3, distance: 3, wantDup: true},
		{name: "beyond threshold", threshold: 3, distance: 4, wantDup: false},
		{name: "zero threshold exact", threshold: 0, distance: 0, wantDup: true},
		{name: "zero threshold one bit", threshold: 0, distance: 1, wantDup: false},
		{name: "threshold 1 at 1", threshold: 1, distance: 1, wantDup: true},
		{name: "threshold 1 at 2", threshold: 1, distance: 2, wantDup: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := New(WithThreshold(tt.threshold))

			// Seed the index with a known fingerprint.
			baseFP := uint64(0xDEADBEEFCAFEBABE)
			d.idx.add(baseFP)

			// Build a fingerprint at exactly tt.distance bits away.
			candidateFP := flipBitsAt(baseFP, tt.distance)
			require.Equal(t, tt.distance, uint8(bits.OnesCount64(baseFP^candidateFP)),
				"flipBitsAt should produce exactly the requested distance")

			// Override extractor to return our controlled fingerprint.
			d.featureHasher = func([]byte) uint64 { return candidateFP }

			got := d.IsDuplicate([]byte("anything"))
			assert.Equal(t, tt.wantDup, got)
		})
	}
}

func TestIsDuplicate_CrossBandNearDuplicate(t *testing.T) {
	// Flip bits across different bands to exercise the pigeonhole guarantee:
	// 3 bits spread across 3 bands must still be caught at threshold 3.
	d := New(WithThreshold(3))

	baseFP := uint64(0xDEADBEEFCAFEBABE)
	d.idx.add(baseFP)

	// Flip bit 0 (band 0), bit 20 (band 1), bit 40 (band 2) — 3 bands touched.
	crossBandFP := baseFP ^ (1 << 0) ^ (1 << 20) ^ (1 << 40)
	require.Equal(t, uint8(3), uint8(bits.OnesCount64(baseFP^crossBandFP)))

	d.featureHasher = func([]byte) uint64 { return crossBandFP }
	assert.True(t, d.IsDuplicate([]byte("anything")),
		"3 bits across 3 bands should still be detected at threshold 3")
}

func TestIsDuplicate_ConcurrentSafety(t *testing.T) {
	d := New()
	const goroutines = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			body := fmt.Appendf(nil, "unique document number %d with enough words to form a feature set", i)
			d.IsDuplicate(body)
		}()
	}
	wg.Wait()

	// Verify the index was populated — at least some entries should exist.
	count := d.idx.size()
	assert.Greater(t, count, 0, "index should have entries after concurrent inserts")
}

func TestIsDuplicate_TOCTOU(t *testing.T) {
	// Verify that two goroutines racing to insert the same content don't
	// both succeed — only one insert should win; the other sees a duplicate.
	d := New()
	body := []byte("identical body submitted concurrently from two goroutines")

	results := make(chan bool, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			results <- d.IsDuplicate(body)
		}()
	}
	wg.Wait()
	close(results)

	var trueCount, falseCount int
	for r := range results {
		if r {
			trueCount++
		} else {
			falseCount++
		}
	}
	assert.Equal(t, 1, falseCount, "exactly one goroutine should see novel content")
	assert.Equal(t, 1, trueCount, "exactly one goroutine should see a duplicate")
}

// flipBitsAt returns v with exactly n bits flipped, spread across bands.
// Bit positions: 0, 16, 32, 48, 1, 17, ... to ensure cross-band coverage.
func flipBitsAt(v uint64, n uint8) uint64 {
	positions := [...]int{0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50}
	for i := range n {
		v ^= 1 << positions[i]
	}
	return v
}
