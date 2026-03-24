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
// tokens) is stripped before hashing. The default is true.
func WithStripDynamic(enabled bool) Option {
	return func(d *Deduplicator) {
		d.stripDynamic = enabled
	}
}

// WithContentType sets a content-type hint used to choose the best feature
// extraction strategy for the data being deduplicated.
func WithContentType(ct string) Option {
	return func(d *Deduplicator) {
		d.contentType = ct
	}
}

// Deduplicator detects exact and near-duplicate documents using simhash
// fingerprints. It is safe for concurrent use.
type Deduplicator struct {
	// Immutable after construction.
	threshold    uint8
	stripDynamic bool
	contentType  string

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
	}
	for _, o := range opts {
		o(d)
	}
	if d.threshold > maxGuaranteedThreshold {
		d.threshold = maxGuaranteedThreshold
	}
	return d
}

// IsDuplicate reports whether raw is a duplicate of any previously seen
// document. If raw is novel it is recorded and future near-duplicates will
// match against it.
func (d *Deduplicator) IsDuplicate(raw []byte) bool {
	data := raw
	if d.stripDynamic {
		data = stripDynamicTokens(data)
	}
	fp := fingerprint(d.contentType, data)

	// Fast read-only check.
	if d.idx.hasNearDuplicate(fp, d.threshold) {
		return true
	}

	// Atomic check-and-insert under write lock to avoid TOCTOU races.
	return d.idx.addIfAbsent(fp, d.threshold)
}
