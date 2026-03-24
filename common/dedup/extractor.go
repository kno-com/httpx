package dedup

import (
	"bytes"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/mfonda/simhash"
)

// WordBoundary splits on word boundaries (same pattern as mfonda/simhash).
// Exported so that common/hashes can share the same tokenizer.
var WordBoundary = regexp.MustCompile(`[\w']+(?:\://[\w\./]+){0,1}`)

// jsonKeyRe matches JSON object keys (double-quoted strings followed by colon).
var jsonKeyRe = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"[ \t\n\r]*:`)

// fingerprint computes a simhash fingerprint for data, choosing the best
// extraction strategy based on contentType and the data itself.
func fingerprint(contentType string, data []byte) uint64 {
	ct := strings.ToLower(contentType)

	switch {
	case strings.Contains(ct, "json"):
		return extractJSONKeys(data)

	case strings.Contains(ct, "javascript"),
		strings.Contains(ct, "css"):
		return extractByteWindows(data)

	default:
		// For text/html or unknown types, compute words once. This avoids
		// running the word-boundary regex twice (once in isMinified, once
		// in extractShingles).
		lower := bytes.ToLower(data)
		words := WordBoundary.FindAll(lower, -1)

		if isMinifiedFromWords(data, words) {
			return extractByteWindows(data)
		}
		return extractShinglesFromWords(words)
	}
}

// extractShinglesFromWords computes a simhash from pre-tokenized words using
// w=3 shingling.
func extractShinglesFromWords(words [][]byte) uint64 {
	if len(words) == 0 {
		return 0
	}
	shingles := simhash.Shingle(3, words)
	return simhash.SimhashBytes(shingles)
}

// extractShingles splits data on word boundaries, applies w=3 shingling,
// and returns a simhash fingerprint.
func extractShingles(data []byte) uint64 {
	words := WordBoundary.FindAll(bytes.ToLower(data), -1)
	return extractShinglesFromWords(words)
}

// extractByteWindows uses an 8-byte sliding window over raw bytes. Suited
// for minified JS/CSS where word boundaries are scarce.
func extractByteWindows(data []byte) uint64 {
	lower := bytes.ToLower(data)
	if len(lower) < byteWindowSize {
		h := fnv.New64()
		h.Write(lower)
		return h.Sum64()
	}
	count := len(lower) - byteWindowSize + 1
	windows := make([][]byte, count)
	for i := range count {
		windows[i] = lower[i : i+byteWindowSize]
	}
	return simhash.SimhashBytes(windows)
}

const byteWindowSize = 8

// extractJSONKeys extracts JSON key paths only (ignoring values), shingles
// the key sequence, and returns a simhash fingerprint.
func extractJSONKeys(data []byte) uint64 {
	matches := jsonKeyRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return extractShingles(data)
	}
	keys := make([][]byte, len(matches))
	for i, m := range matches {
		keys[i] = bytes.ToLower(m[1])
	}
	shingles := simhash.Shingle(3, keys)
	return simhash.SimhashBytes(shingles)
}

// isMinified reports whether data appears to be minified content:
// fewer than 0.05 words per byte and content > 512 bytes.
func isMinified(data []byte) bool {
	words := WordBoundary.FindAll(data, -1)
	return isMinifiedFromWords(data, words)
}

// isMinifiedFromWords is the inner check, accepting pre-computed words to
// avoid running the word-boundary regex twice on the hot path.
func isMinifiedFromWords(data []byte, words [][]byte) bool {
	if len(data) <= 512 {
		return false
	}
	if len(words) == 0 {
		return true
	}
	ratio := float64(len(words)) / float64(len(data))
	return ratio < 0.05
}
