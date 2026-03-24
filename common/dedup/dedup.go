// Package dedup provides near-duplicate detection for HTTP response bodies
// using locality-sensitive hashing (simhash). It encapsulates feature
// extraction, fingerprint storage, and Hamming-distance comparison behind
// a single IsDuplicate call.
package dedup

import (
	"math/bits"
	"sync"
)

// defaultThreshold is the maximum Hamming distance at which two fingerprints
// are considered near-duplicates.
const defaultThreshold uint8 = 3

// Option configures a Deduplicator.
type Option func(*Deduplicator)

// WithThreshold sets the maximum Hamming distance for near-duplicate detection.
// Two fingerprints whose Hamming distance is less than or equal to n are
// considered duplicates. The default is 3.
func WithThreshold(n uint8) Option {
	return func(d *Deduplicator) {
		d.threshold = n
	}
}

// WithStripDynamic controls whether dynamic content (e.g. timestamps, CSRF
// tokens) is stripped before hashing. The default is true. This is a no-op
// placeholder that will be replaced in a future task.
func WithStripDynamic(enabled bool) Option {
	return func(d *Deduplicator) {
		d.stripDynamic = enabled
	}
}

// WithContentType sets a content-type hint used by selectExtractor to choose
// the best feature extraction strategy for the data being deduplicated.
func WithContentType(ct string) Option {
	return func(d *Deduplicator) {
		d.contentType = ct
	}
}

// Deduplicator detects exact and near-duplicate documents using simhash
// fingerprints. It is safe for concurrent use.
type Deduplicator struct {
	// Immutable after construction.
	threshold      uint8
	stripDynamic   bool
	contentType    string
	preprocessor   func([]byte) []byte
	featureHasher  func([]byte) uint64

	// mu guards index.
	mu    sync.RWMutex
	index map[uint64]struct{}
}

// New creates a Deduplicator with the given options. Zero-value defaults are:
// threshold=3, stripDynamic=true.
func New(opts ...Option) *Deduplicator {
	d := &Deduplicator{
		index:        make(map[uint64]struct{}),
		threshold:    defaultThreshold,
		stripDynamic: true,
		// Placeholder preprocessor — no-op until Task #5 replaces it.
		preprocessor: func(b []byte) []byte { return b },
	}
	for _, o := range opts {
		o(d)
	}
	// Wire featureHasher to use the content-type-aware extractor system.
	// Capture contentType once so the closure does not hold a pointer to d.
	ct := d.contentType
	d.featureHasher = func(b []byte) uint64 {
		return selectExtractor(ct, b).extract(b)
	}
	return d
}

// IsDuplicate reports whether raw is a duplicate of any previously seen
// document. If raw is novel it is recorded and future near-duplicates will
// match against it.
func (d *Deduplicator) IsDuplicate(raw []byte) bool {
	data := d.preprocessor(raw)
	fp := d.featureHasher(data)

	d.mu.RLock()
	dup := d.isDup(fp)
	d.mu.RUnlock()

	if dup {
		return true
	}

	// Promote to write lock and re-check to avoid TOCTOU races.
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isDup(fp) {
		return true
	}

	d.index[fp] = struct{}{}
	return false
}

// isDup performs a linear Hamming scan over the index. The caller must hold
// at least a read lock on d.mu. This will be replaced by a band-partitioned
// index in Task #4.
func (d *Deduplicator) isDup(fp uint64) bool {
	for stored := range d.index {
		if hammingDistance(stored, fp) <= d.threshold {
			return true
		}
	}
	return false
}

// hammingDistance returns the number of bit positions where a and b differ.
func hammingDistance(a, b uint64) uint8 {
	return uint8(bits.OnesCount64(a ^ b))
}
