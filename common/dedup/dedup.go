// Package dedup provides near-duplicate detection for HTTP response bodies
// using locality-sensitive hashing (simhash). It encapsulates feature
// extraction, fingerprint storage, and Hamming-distance comparison behind
// a single IsDuplicate call.
package dedup

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

	idx *bandIndex
}

// New creates a Deduplicator with the given options. Zero-value defaults are:
// threshold=3, stripDynamic=true. Threshold is capped at maxGuaranteedThreshold
// (3) because the band-partitioned index cannot guarantee correctness beyond
// that value.
func New(opts ...Option) *Deduplicator {
	d := &Deduplicator{
		idx:          newBandIndex(),
		threshold:    defaultThreshold,
		stripDynamic: true,
		// Placeholder preprocessor — no-op until Task #5 replaces it.
		preprocessor: func(b []byte) []byte { return b },
	}
	for _, o := range opts {
		o(d)
	}
	if d.threshold > maxGuaranteedThreshold {
		d.threshold = maxGuaranteedThreshold
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

	// Fast read-only check.
	if d.idx.hasNearDuplicate(fp, d.threshold) {
		return true
	}

	// Atomic check-and-insert under write lock to avoid TOCTOU races.
	return d.idx.addIfAbsent(fp, d.threshold)
}
