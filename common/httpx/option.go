package httpx

import (
	"net/http"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/networkpolicy"
)

// DefaultMaxResponseBodySize is the default maximum response body size
var DefaultMaxResponseBodySize int64

func init() {
	maxResponseBodySize, _ := humanize.ParseBytes("512Mb")
	DefaultMaxResponseBodySize = int64(maxResponseBodySize)
}

// Options contains configuration options for the client
type Options struct {
	RandomAgent      bool
	AutoReferer      bool
	DefaultUserAgent string
	Proxy            string
	// Deprecated: use Proxy
	HTTPProxy string
	// Deprecated: use Proxy
	SocksProxy  string
	Threads     int
	CdnCheck    string
	ExcludeCdn  bool
	// Timeout is the maximum time to wait for the request
	Timeout time.Duration
	// RetryMax is the maximum number of retries
	RetryMax      int
	CustomHeaders map[string]string
	FollowRedirects      bool
	FollowHostRedirects  bool
	RespectHSTS          bool
	MaxRedirects         int
	Unsafe               bool
	MaxResponseBodySizeToSave int64
	MaxResponseBodySizeToRead int64
	UnsafeURI                 string
	Resolvers                 []string
	customCookies             []*http.Cookie
	NetworkPolicy             *networkpolicy.NetworkPolicy
	CDNCheckClient            *cdncheck.Client
	Protocol                  Proto
	Trace                     bool
}

// DefaultOptions contains the default options
var DefaultOptions = Options{
	RandomAgent:               true,
	Threads:                   25,
	Timeout:                   30 * time.Second,
	RetryMax:                  5,
	MaxRedirects:              10,
	Unsafe:                    false,
	CdnCheck:                  "true",
	ExcludeCdn:                false,
	MaxResponseBodySizeToRead: DefaultMaxResponseBodySize,
	DefaultUserAgent:         "httpx - Open-source project (github.com/projectdiscovery/httpx)",
}

func (options *Options) parseCustomCookies() {
	// parse and fill the custom field
	for k, v := range options.CustomHeaders {
		if strings.EqualFold(k, "cookie") {
			req := http.Request{Header: http.Header{"Cookie": []string{v}}}
			options.customCookies = req.Cookies()
		}
	}
}

func (options *Options) hasCustomCookies() bool {
	return len(options.customCookies) > 0
}
