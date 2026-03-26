package runner

import (
	"bytes"
	"regexp"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/projectdiscovery/httpx/common/httpx"
)

func BenchmarkComputeHashes(b *testing.B) {
	// Generate a realistic ~50KB response body
	body := bytes.Repeat([]byte("<html><body>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</body></html>"), 600)
	headers := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeHashes(body, headers, "md5,sha256,simhash")
	}
}

func BenchmarkExtractTech(b *testing.B) {
	// Initialize wappalyzer
	wap, err := wappalyzer.New()
	if err != nil {
		b.Fatal(err)
	}
	r := &Runner{wappalyzer: wap}

	// Create a realistic response with known tech signatures
	resp := &httpx.Response{
		Headers: map[string][]string{
			"Server":       {"nginx/1.21.0"},
			"X-Powered-By": {"PHP/8.1"},
		},
		Data: []byte(`<html><head><meta name="generator" content="WordPress 6.0"></head><body>Hello</body></html>`),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.extractTech(resp)
	}
}

func BenchmarkExtractRegex(b *testing.B) {
	body := []byte(`{"api_key": "sk-1234567890", "email": "test@example.com", "ip": "192.168.1.1"}`)
	body = bytes.Repeat(body, 100)
	regexps := map[string]*regexp.Regexp{
		"email": regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		"ipv4":  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractRegex(body, regexps)
	}
}

func BenchmarkFormatOutput(b *testing.B) {
	result := &Result{
		URL:           "https://example.com",
		StatusCode:    200,
		ContentLength: 1234,
		ContentType:   "text/html",
		Title:         "Example Domain",
		WebServer:     "nginx",
		ResponseTime:  "150ms",
		Technologies:  []string{"nginx", "PHP"},
		HTTP2:         true,
		HostIP:        "93.184.216.34",
		CDN:           true,
		CDNName:       "Cloudflare",
		Lines:         50,
		Words:         200,
		ChainStatusCodes: []int{301, 200},
	}
	scanopts := &ScanOptions{
		OutputStatusCode:    true,
		OutputContentLength: true,
		OutputContentType:   true,
		OutputTitle:         true,
		OutputServerHeader:  true,
		OutputResponseTime:  true,
		OutputIP:            true,
		OutputCDN:           "true",
		HTTP2Probe:          true,
		TechDetect:          true,
		OutputLinesCount:    true,
		OutputWordsCount:    true,
		OutputWithNoColor:   true,
	}
	opts := &Options{TechDetect: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatOutput(result, scanopts, opts)
	}
}

func BenchmarkComputeHashes_Individual(b *testing.B) {
	body := bytes.Repeat([]byte("benchmark test data for hashing"), 2000)
	headers := "HTTP/1.1 200 OK\r\n"
	for _, hashType := range []string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"} {
		b.Run(hashType, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				computeHashes(body, headers, hashType)
			}
		})
	}
}
