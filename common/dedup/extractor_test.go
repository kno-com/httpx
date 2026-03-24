package dedup

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShingleExtractor_DifferentFingerprintsForReorderedContent(t *testing.T) {
	ext := shingleExtractor{}

	original := []byte("the quick brown fox jumps over the lazy dog near the river bank")
	reordered := []byte("lazy dog near the river bank the quick brown fox jumps over the")

	fpOrig := ext.extract(original)
	fpReorder := ext.extract(reordered)

	// Shingle-based extraction should produce different fingerprints for
	// reordered content because the 3-grams differ.
	assert.NotEqual(t, fpOrig, fpReorder,
		"shingled fingerprints must differ for reordered content")
}

func TestShingleExtractor_SameContentSameFingerprint(t *testing.T) {
	ext := shingleExtractor{}
	data := []byte("hello world this is a test document with enough words")

	fp1 := ext.extract(data)
	fp2 := ext.extract(data)
	assert.Equal(t, fp1, fp2, "same content must produce the same fingerprint")
}

func TestShingleExtractor_EmptyInput(t *testing.T) {
	ext := shingleExtractor{}
	assert.Equal(t, uint64(0), ext.extract(nil))
	assert.Equal(t, uint64(0), ext.extract([]byte{}))
}

func TestByteWindowExtractor_ActivatesForMinifiedContent(t *testing.T) {
	// Build minified-looking content: long string with very few word boundaries.
	minified := []byte("var a=" + strings.Repeat("x", 600) + ";")

	require.True(t, isMinified(minified),
		"test data should be detected as minified")

	ext := selectExtractor("text/html", minified)
	_, ok := ext.(byteWindowExtractor)
	assert.True(t, ok,
		"selectExtractor should return byteWindowExtractor for minified content")
}

func TestByteWindowExtractor_ShortContentFallsBackToShingle(t *testing.T) {
	// Content <= 512 bytes should not trigger minified detection.
	short := []byte(strings.Repeat("x", 100))
	ext := selectExtractor("text/html", short)
	_, ok := ext.(shingleExtractor)
	assert.True(t, ok,
		"short content should fall back to shingleExtractor")
}

func TestByteWindowExtractor_ProducesFingerprint(t *testing.T) {
	ext := byteWindowExtractor{}
	data := []byte("function(){var a=1;var b=2;return a+b;}")
	fp := ext.extract(data)
	assert.NotEqual(t, uint64(0), fp, "byteWindowExtractor must produce a non-zero fingerprint")
}

func TestByteWindowExtractor_ShortInput(t *testing.T) {
	ext := byteWindowExtractor{}
	// Shorter than the 8-byte window.
	fp := ext.extract([]byte("abc"))
	assert.NotEqual(t, uint64(0), fp, "short input should still produce a fingerprint")
}

func TestJsonKeyExtractor_IgnoresValues(t *testing.T) {
	ext := jsonKeyExtractor{}

	doc1 := []byte(`{"name":"Alice","age":30,"city":"NYC"}`)
	doc2 := []byte(`{"name":"Bob","age":99,"city":"LA"}`)

	fp1 := ext.extract(doc1)
	fp2 := ext.extract(doc2)

	assert.Equal(t, fp1, fp2,
		"jsonKeyExtractor must ignore values — same keys must yield same fingerprint")
}

func TestJsonKeyExtractor_DifferentKeysProduceDifferentFingerprints(t *testing.T) {
	ext := jsonKeyExtractor{}

	doc1 := []byte(`{"name":"Alice","age":30,"city":"NYC"}`)
	doc2 := []byte(`{"username":"Alice","height":170,"country":"US"}`)

	fp1 := ext.extract(doc1)
	fp2 := ext.extract(doc2)

	assert.NotEqual(t, fp1, fp2,
		"different JSON key sets must produce different fingerprints")
}

func TestJsonKeyExtractor_FallsBackForNonJSON(t *testing.T) {
	ext := jsonKeyExtractor{}
	data := []byte("just some plain text without json keys")
	fp := ext.extract(data)
	// Should fall back to shingleExtractor — verify it doesn't panic and
	// produces a non-zero result.
	assert.NotEqual(t, uint64(0), fp,
		"jsonKeyExtractor should fall back to shingle for non-JSON data")
}

func TestSelectExtractor_DispatchByContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		data        []byte
		wantType    string
	}{
		{
			name:        "application/json",
			contentType: "application/json",
			data:        []byte(`{"key":"val"}`),
			wantType:    "jsonKeyExtractor",
		},
		{
			name:        "application/json charset",
			contentType: "application/json; charset=utf-8",
			data:        []byte(`{"key":"val"}`),
			wantType:    "jsonKeyExtractor",
		},
		{
			name:        "application/javascript",
			contentType: "application/javascript",
			data:        []byte("var x=1;"),
			wantType:    "byteWindowExtractor",
		},
		{
			name:        "text/javascript",
			contentType: "text/javascript",
			data:        []byte("var x=1;"),
			wantType:    "byteWindowExtractor",
		},
		{
			name:        "text/css",
			contentType: "text/css",
			data:        []byte("body{margin:0}"),
			wantType:    "byteWindowExtractor",
		},
		{
			name:        "text/html normal",
			contentType: "text/html",
			data:        []byte("the quick brown fox jumps over the lazy dog"),
			wantType:    "shingleExtractor",
		},
		{
			name:        "unknown content type",
			contentType: "application/octet-stream",
			data:        []byte("some data"),
			wantType:    "shingleExtractor",
		},
		{
			name:        "empty content type",
			contentType: "",
			data:        []byte("hello world test"),
			wantType:    "shingleExtractor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := selectExtractor(tt.contentType, tt.data)
			require.NotNil(t, ext)
			switch tt.wantType {
			case "shingleExtractor":
				_, ok := ext.(shingleExtractor)
				assert.True(t, ok, "expected shingleExtractor, got %T", ext)
			case "byteWindowExtractor":
				_, ok := ext.(byteWindowExtractor)
				assert.True(t, ok, "expected byteWindowExtractor, got %T", ext)
			case "jsonKeyExtractor":
				_, ok := ext.(jsonKeyExtractor)
				assert.True(t, ok, "expected jsonKeyExtractor, got %T", ext)
			}
		})
	}
}

func TestSelectExtractor_FallbackForUnknownTypes(t *testing.T) {
	unknownTypes := []string{
		"",
		"application/octet-stream",
		"image/png",
		"multipart/form-data",
		"text/plain",
	}
	data := []byte("normal text with plenty of words for the test")

	for _, ct := range unknownTypes {
		ext := selectExtractor(ct, data)
		_, ok := ext.(shingleExtractor)
		assert.True(t, ok,
			"content-type %q should fall back to shingleExtractor, got %T", ct, ext)
	}
}

func TestSelectExtractor_MinifiedHTMLActivatesByteWindow(t *testing.T) {
	// Construct content that looks minified: large byte count, very few words.
	minified := []byte("a{" + strings.Repeat("x", 600) + "}")
	ext := selectExtractor("text/html", minified)
	_, ok := ext.(byteWindowExtractor)
	assert.True(t, ok,
		"minified HTML should activate byteWindowExtractor, got %T", ext)
}

func TestWithContentType_IntegratesWithDeduplicator(t *testing.T) {
	d := New(WithContentType("application/json"))
	assert.Equal(t, "application/json", d.contentType)

	// Verify it can process JSON and detect duplicates.
	doc1 := []byte(`{"name":"Alice","age":30}`)
	doc2 := []byte(`{"name":"Bob","age":99}`)

	first := d.IsDuplicate(doc1)
	assert.False(t, first, "first document should not be a duplicate")

	// Same keys, different values — jsonKeyExtractor should see these as duplicates.
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
		{
			name: "short content",
			data: []byte(strings.Repeat("x", 100)),
			want: false,
		},
		{
			name: "normal text",
			data: []byte(strings.Repeat("hello world this is text ", 40)),
			want: false,
		},
		{
			name: "minified content",
			data: []byte(strings.Repeat("x", 600)),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMinified(tt.data))
		})
	}
}

