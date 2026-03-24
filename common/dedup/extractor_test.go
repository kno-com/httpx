package dedup

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractShingles_DifferentFingerprintsForReorderedContent(t *testing.T) {
	original := []byte("the quick brown fox jumps over the lazy dog near the river bank")
	reordered := []byte("lazy dog near the river bank the quick brown fox jumps over the")

	fpOrig := extractShingles(original)
	fpReorder := extractShingles(reordered)

	assert.NotEqual(t, fpOrig, fpReorder,
		"shingled fingerprints must differ for reordered content")
}

func TestExtractShingles_SameContentSameFingerprint(t *testing.T) {
	data := []byte("hello world this is a test document with enough words")
	fp1 := extractShingles(data)
	fp2 := extractShingles(data)
	assert.Equal(t, fp1, fp2, "same content must produce the same fingerprint")
}

func TestExtractShingles_EmptyInput(t *testing.T) {
	assert.Equal(t, uint64(0), extractShingles(nil))
	assert.Equal(t, uint64(0), extractShingles([]byte{}))
}

func TestFingerprint_MinifiedActivatesByteWindows(t *testing.T) {
	minified := []byte("var a=" + strings.Repeat("x", 600) + ";")
	require.True(t, isMinified(minified), "test data should be detected as minified")

	// Verify that fingerprint on text/html with minified data produces a
	// non-zero result (the byte-window path).
	fp := fingerprint("text/html", minified)
	assert.NotEqual(t, uint64(0), fp)
}

func TestFingerprint_ShortContentUsesShingles(t *testing.T) {
	short := []byte("the quick brown fox jumps")
	// Short content should use shingle path, not byte-window.
	fp := fingerprint("text/html", short)
	assert.Equal(t, extractShingles(short), fp)
}

func TestExtractByteWindows_ProducesFingerprint(t *testing.T) {
	data := []byte("function(){var a=1;var b=2;return a+b;}")
	fp := extractByteWindows(data)
	assert.NotEqual(t, uint64(0), fp)
}

func TestExtractByteWindows_ShortInput(t *testing.T) {
	fp := extractByteWindows([]byte("abc"))
	assert.NotEqual(t, uint64(0), fp, "short input should still produce a fingerprint")
}

func TestExtractJSONKeys_IgnoresValues(t *testing.T) {
	doc1 := []byte(`{"name":"Alice","age":30,"city":"NYC"}`)
	doc2 := []byte(`{"name":"Bob","age":99,"city":"LA"}`)

	fp1 := extractJSONKeys(doc1)
	fp2 := extractJSONKeys(doc2)

	assert.Equal(t, fp1, fp2,
		"must ignore values — same keys must yield same fingerprint")
}

func TestExtractJSONKeys_DifferentKeysProduceDifferentFingerprints(t *testing.T) {
	doc1 := []byte(`{"name":"Alice","age":30,"city":"NYC"}`)
	doc2 := []byte(`{"username":"Alice","height":170,"country":"US"}`)

	fp1 := extractJSONKeys(doc1)
	fp2 := extractJSONKeys(doc2)

	assert.NotEqual(t, fp1, fp2,
		"different JSON key sets must produce different fingerprints")
}

func TestExtractJSONKeys_FallsBackForNonJSON(t *testing.T) {
	data := []byte("just some plain text without json keys")
	fp := extractJSONKeys(data)
	assert.NotEqual(t, uint64(0), fp,
		"should fall back to shingle for non-JSON data")
}

func TestFingerprint_DispatchByContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		data        []byte
	}{
		{"application/json", "application/json", []byte(`{"key":"val"}`)},
		{"application/json charset", "application/json; charset=utf-8", []byte(`{"key":"val"}`)},
		{"application/javascript", "application/javascript", []byte("var x=1;")},
		{"text/css", "text/css", []byte("body{margin:0}")},
		{"text/html normal", "text/html", []byte("the quick brown fox jumps over the lazy dog")},
		{"empty content type", "", []byte("hello world test")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := fingerprint(tt.contentType, tt.data)
			// Just verify it doesn't panic and produces a result.
			_ = fp
		})
	}
}

func TestFingerprint_FallbackForUnknownTypes(t *testing.T) {
	data := []byte("normal text with plenty of words for the test")
	for _, ct := range []string{"", "application/octet-stream", "image/png", "text/plain"} {
		fp := fingerprint(ct, data)
		// Unknown types should use shingle extraction — same as extractShingles.
		assert.Equal(t, extractShingles(data), fp,
			"content-type %q should use shingle extraction", ct)
	}
}

func TestWithContentType_IntegratesWithDeduplicator(t *testing.T) {
	d := New(WithContentType("application/json"))
	assert.Equal(t, "application/json", d.contentType)

	doc1 := []byte(`{"name":"Alice","age":30}`)
	doc2 := []byte(`{"name":"Bob","age":99}`)

	first := d.IsDuplicate(doc1)
	assert.False(t, first, "first document should not be a duplicate")

	second := d.IsDuplicate(doc2)
	assert.True(t, second,
		"JSON docs with same keys but different values should be duplicates")
}

func TestIsMinified(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"short content", []byte(strings.Repeat("x", 100)), false},
		{"normal text", []byte(strings.Repeat("hello world this is text ", 40)), false},
		{"minified content", []byte(strings.Repeat("x", 600)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMinified(tt.data))
		})
	}
}
