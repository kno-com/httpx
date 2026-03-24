package dedup

import (
	"bytes"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/mfonda/simhash"
)

// featureExtractor computes a simhash fingerprint from raw bytes.
// Each implementation uses a different strategy suited to the content type.
type featureExtractor interface {
	extract(data []byte) uint64
}

// wordBoundary splits on word boundaries (same pattern as mfonda/simhash).
var wordBoundary = regexp.MustCompile(`[\w']+(?:\://[\w\./]+){0,1}`)

// jsonKeyRe matches JSON object keys (double-quoted strings followed by colon).
var jsonKeyRe = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"[ \t\n\r]*:`)

// ---------- shingleExtractor ----------

// shingleExtractor splits on word boundaries, applies w=3 shingling,
// hashes each shingle, and returns a simhash fingerprint.
type shingleExtractor struct{}

func (shingleExtractor) extract(data []byte) uint64 {
	words := wordBoundary.FindAll(bytes.ToLower(data), -1)
	if len(words) == 0 {
		return 0
	}
	shingles := shingle(3, words)
	return simhash.SimhashBytes(shingles)
}

// ---------- byteWindowExtractor ----------

// byteWindowExtractor uses an 8-byte sliding window over raw bytes.
// It is intended for minified JS/CSS where word boundaries are scarce.
type byteWindowExtractor struct{}

const byteWindowSize = 8

func (byteWindowExtractor) extract(data []byte) uint64 {
	lower := bytes.ToLower(data)
	if len(lower) < byteWindowSize {
		// Too short for a window; hash the whole thing as one feature.
		h := fnv.New64()
		h.Write(lower)
		return h.Sum64()
	}
	count := len(lower) - byteWindowSize + 1
	windows := make([][]byte, count)
	for i := 0; i < count; i++ {
		windows[i] = lower[i : i+byteWindowSize]
	}
	return simhash.SimhashBytes(windows)
}

// ---------- jsonKeyExtractor ----------

// jsonKeyExtractor extracts JSON key paths only (ignoring values),
// shingles the key sequence, and returns a simhash fingerprint.
type jsonKeyExtractor struct{}

func (jsonKeyExtractor) extract(data []byte) uint64 {
	matches := jsonKeyRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		// Fallback: treat as plain text.
		return shingleExtractor{}.extract(data)
	}
	keys := make([][]byte, len(matches))
	for i, m := range matches {
		keys[i] = bytes.ToLower(m[1])
	}
	shingles := shingle(3, keys)
	return simhash.SimhashBytes(shingles)
}

// ---------- selectExtractor ----------

// selectExtractor returns the most appropriate featureExtractor for the given
// content-type and data. When content-type is empty or unknown it falls back
// to shingleExtractor.
func selectExtractor(contentType string, data []byte) featureExtractor {
	ct := strings.ToLower(contentType)

	switch {
	case strings.Contains(ct, "json"):
		return jsonKeyExtractor{}

	case strings.Contains(ct, "javascript"),
		strings.Contains(ct, "css"):
		// Always use byte-window for JS/CSS content types.
		return byteWindowExtractor{}

	default:
		// For text/html or unknown types, check whether the content looks
		// minified: word count abnormally low relative to byte length.
		if isMinified(data) {
			return byteWindowExtractor{}
		}
		return shingleExtractor{}
	}
}

// isMinified reports whether data appears to be minified content:
// fewer than 0.05 words per byte and content > 512 bytes.
func isMinified(data []byte) bool {
	if len(data) <= 512 {
		return false
	}
	wordCount := len(wordBoundary.FindAll(data, -1))
	ratio := float64(wordCount) / float64(len(data))
	return ratio < 0.05
}

// shingle returns the w-shingling of the given set of byte slices.
// Each shingle is the concatenation of w consecutive elements joined by a space.
func shingle(w int, tokens [][]byte) [][]byte {
	if w < 1 {
		w = 1
	}
	if w == 1 {
		return tokens
	}
	if w > len(tokens) {
		w = len(tokens)
	}
	count := len(tokens) - w + 1
	shingles := make([][]byte, count)
	for i := 0; i < count; i++ {
		shingles[i] = bytes.Join(tokens[i:i+w], []byte(" "))
	}
	return shingles
}
