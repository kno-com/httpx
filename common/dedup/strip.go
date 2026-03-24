package dedup

import "regexp"

// Compiled package-level regexps for stripping dynamic content that would
// otherwise cause near-identical pages to produce different simhash
// fingerprints.
var (
	// hexTokenRe matches hex strings of 32+ characters (tokens, hashes, UUIDs
	// without dashes, session IDs, etc.).
	hexTokenRe = regexp.MustCompile(`[a-fA-F0-9]{32,}`)

	// iso8601Re matches ISO 8601 timestamps (e.g. 2024-01-15T09:30:00).
	iso8601Re = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)

	// csrfAttrRe matches HTML attributes whose name or id contains csrf,
	// nonce, or token together with the associated value attribute. This
	// strips the entire attribute pair so the token value does not pollute
	// the fingerprint.
	csrfAttrRe = regexp.MustCompile(`(name|id)="(csrf|nonce|token)[^"]*"\s*value="[^"]*"`)
)

// stripDynamicTokens removes dynamic content (hex tokens, timestamps, CSRF
// attribute values) from data so that near-identical pages hash the same way.
func stripDynamicTokens(data []byte) []byte {
	data = hexTokenRe.ReplaceAll(data, nil)
	data = iso8601Re.ReplaceAll(data, nil)
	data = csrfAttrRe.ReplaceAll(data, nil)
	return data
}
