package runner

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/customextract"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	httpxcommon "github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/inputformats"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/networkpolicy"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	two                    = 2
	defaultThreads         = 50
	DefaultResumeFile      = "resume.cfg"
	DefaultOutputDirectory = "output"
)

// OnResultCallback (hostResult)
type OnResultCallback func(Result)

type ScanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	OutputTitle               bool
	OutputStatusCode          bool
	OutputLocation            bool
	OutputContentLength       bool
	StoreResponse             bool
	OmitBody                  bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	OutputWithNoColor         bool
	OutputMethod              bool
	ResponseHeadersInStdout   bool
	ResponseInStdout          bool
	Base64ResponseInStdout    bool
	ChainInStdout             bool
	OutputContentType         bool
	Unsafe                    bool
	HTTP2Probe                bool
	OutputIP                  bool
	OutputCName               bool
	OutputCDN                 string
	OutputResponseTime        bool
	PreferHTTPS               bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	StoreChain                bool
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	extractRegexps            map[string]*regexp.Regexp
	ExcludeCDN                bool
	HostMaxErrors             int
	ProbeAllIPS               bool
	Favicon                   bool
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputWordsCount          bool
	Hashes                    string
	DisableStdin              bool
}

func (s *ScanOptions) Clone() *ScanOptions {
	return &ScanOptions{
		Methods:                   s.Methods,
		StoreResponseDirectory:    s.StoreResponseDirectory,
		RequestURI:                s.RequestURI,
		RequestBody:               s.RequestBody,
		OutputTitle:               s.OutputTitle,
		OutputStatusCode:          s.OutputStatusCode,
		OutputLocation:            s.OutputLocation,
		OutputContentLength:       s.OutputContentLength,
		StoreResponse:             s.StoreResponse,
		OmitBody:                  s.OmitBody,
		OutputServerHeader:        s.OutputServerHeader,
		OutputWebSocket:           s.OutputWebSocket,
		OutputWithNoColor:         s.OutputWithNoColor,
		OutputMethod:              s.OutputMethod,
		ResponseHeadersInStdout:   s.ResponseHeadersInStdout,
		ResponseInStdout:          s.ResponseInStdout,
		Base64ResponseInStdout:    s.Base64ResponseInStdout,
		ChainInStdout:             s.ChainInStdout,
		OutputContentType:         s.OutputContentType,
		Unsafe:                    s.Unsafe,
		HTTP2Probe:                s.HTTP2Probe,
		OutputIP:                  s.OutputIP,
		OutputCName:               s.OutputCName,
		OutputCDN:                 s.OutputCDN,
		OutputResponseTime:        s.OutputResponseTime,
		PreferHTTPS:               s.PreferHTTPS,
		NoFallback:                s.NoFallback,
		NoFallbackScheme:          s.NoFallbackScheme,
		TechDetect:                s.TechDetect,
		StoreChain:                s.StoreChain,
		OutputExtractRegex:        s.OutputExtractRegex,
		MaxResponseBodySizeToSave: s.MaxResponseBodySizeToSave,
		MaxResponseBodySizeToRead: s.MaxResponseBodySizeToRead,
		HostMaxErrors:             s.HostMaxErrors,
		Favicon:                   s.Favicon,
		extractRegexps:            s.extractRegexps,
		LeaveDefaultPorts:         s.LeaveDefaultPorts,
		OutputLinesCount:          s.OutputLinesCount,
		OutputWordsCount:          s.OutputWordsCount,
		Hashes:                    s.Hashes,
	}
}

// Options contains configuration options for httpx.
type Options struct {
	CustomHeaders       customheader.CustomHeaders
	CustomPorts         customport.CustomPorts
	matchStatusCode     []int
	matchContentLength  []int
	filterStatusCode    []int
	filterContentLength []int
	Output              string
	OutputAll           bool
	StoreResponseDir    string
	OmitBody            bool
	// Deprecated: use Proxy
	HTTPProxy string
	// Deprecated: use Proxy
	SocksProxy                string
	Proxy                     string
	InputFile                 string
	InputMode                 string
	InputTargetHost           goflags.StringSlice
	Methods                   string
	RequestURI                string
	RequestURIs               string
	requestURIs               []string
	OutputMatchStatusCode     string
	OutputMatchContentLength  string
	OutputFilterStatusCode    string
	OutputFilterPageType      goflags.StringSlice
	FilterOutDuplicates       bool
	OutputFilterContentLength string
	InputRawRequest           string
	rawRequest                string
	RequestBody               string
	OutputFilterString        goflags.StringSlice
	OutputMatchString         goflags.StringSlice
	OutputFilterRegex         goflags.StringSlice
	OutputMatchRegex          goflags.StringSlice
	Retries                   int
	Threads                   int
	Timeout                   int
	Delay                     time.Duration
	filterRegexes             []*regexp.Regexp
	matchRegexes              []*regexp.Regexp
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	FollowRedirects           bool
	RespectHSTS               bool
	StoreResponse             bool
	JSONOutput                bool
	CSVOutput                 bool
	CSVOutputEncoding         string
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	ResponseHeadersInStdout   bool
	ResponseInStdout          bool
	Base64ResponseInStdout    bool
	ChainInStdout             bool
	FollowHostRedirects       bool
	MaxRedirects              int
	OutputMethod              bool
	OutputContentType         bool
	OutputIP                  bool
	OutputCName               bool
	Unsafe                    bool
	Debug                     bool
	HTTP2Probe                bool
	OutputCDN                 string
	OutputResponseTime        bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	protocol                  string
	RandomAgent               bool
	AutoReferer               bool
	StoreChain                bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	ResponseBodyPreviewSize   int
	OutputExtractRegexs       goflags.StringSlice
	OutputExtractPresets      goflags.StringSlice
	RateLimit                 int
	RateLimitMinute           int
	Resume                    bool
	resumeCfg                 *ResumeCfg
	Exclude                   goflags.StringSlice
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
	ProbeAllIPS               bool
	Resolvers                 goflags.StringSlice
	Favicon                   bool
	OutputFilterFavicon       goflags.StringSlice
	OutputMatchFavicon        goflags.StringSlice
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputMatchLinesCount     string
	matchLinesCount           []int
	OutputFilterLinesCount    string
	Memprofile                string
	filterLinesCount          []int
	OutputWordsCount          bool
	OutputMatchWordsCount     string
	matchWordsCount           []int
	OutputFilterWordsCount    string
	filterWordsCount          []int
	Hashes                    string
	SimhashThreshold          int
	OutputMatchCdn            goflags.StringSlice
	OutputFilterCdn           goflags.StringSlice
	OutputMatchResponseTime   string
	OutputFilterResponseTime  string
	OutputFilterCondition     string
	OutputMatchCondition      string
	StripFilter               string
	ExcludeOutputFields       goflags.StringSlice
	//The OnResult callback function is invoked for each result. It is important to check for errors in the result before using Result.Err.
	OnResult             OnResultCallback
	NoDecode             bool
	DisableStdin         bool
	DisableStdout             bool

	// OnClose adds a callback function that is invoked when httpx is closed
	// to be exact at end of existing closures
	OnClose func()

	// Optional pre-created objects to reduce allocations
	Wappalyzer     *wappalyzer.Wappalyze
	Networkpolicy  *networkpolicy.NetworkPolicy
	CDNCheckClient *cdncheck.Client
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "input file containing list of hosts to process"),
		flagSet.StringVarP(&options.InputRawRequest, "request", "rr", "", "file containing raw request"),
		flagSet.StringSliceVarP(&options.InputTargetHost, "target", "u", nil, "input target host(s) to probe", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.InputMode, "input-mode", "im", "", fmt.Sprintf("mode of input file (%s)", inputformats.SupportedFormats())),
	)

	flagSet.CreateGroup("Probes", "Probes",
		flagSet.BoolVarP(&options.StatusCode, "status-code", "sc", false, "display response status-code"),
		flagSet.BoolVarP(&options.ContentLength, "content-length", "cl", false, "display response content-length"),
		flagSet.BoolVarP(&options.OutputContentType, "content-type", "ct", false, "display response content-type"),
		flagSet.BoolVar(&options.Location, "location", false, "display response redirect location"),
		flagSet.BoolVar(&options.Favicon, "favicon", false, "display mmh3 hash for '/favicon.ico' file"),
		flagSet.StringVar(&options.Hashes, "hash", "", "display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)"),
		flagSet.IntVar(&options.SimhashThreshold, "simhash-threshold", 3, "simhash near-duplicate threshold (0-3)"),
		flagSet.BoolVarP(&options.OutputResponseTime, "response-time", "rt", false, "display response time"),
		flagSet.BoolVarP(&options.OutputLinesCount, "line-count", "lc", false, "display response body line count"),
		flagSet.BoolVarP(&options.OutputWordsCount, "word-count", "wc", false, "display response body word count"),
		flagSet.BoolVar(&options.ExtractTitle, "title", false, "display page title"),
		flagSet.DynamicVarP(&options.ResponseBodyPreviewSize, "body-preview", "bp", 100, "display first N characters of response body"),
		flagSet.BoolVarP(&options.OutputServerHeader, "web-server", "server", false, "display server name"),
		flagSet.BoolVarP(&options.TechDetect, "tech-detect", "td", false, "display technology in use based on wappalyzer dataset"),
		flagSet.BoolVar(&options.OutputMethod, "method", false, "display http request method"),
		flagSet.BoolVarP(&options.OutputWebSocket, "websocket", "ws", false, "display server using websocket"),
		flagSet.BoolVar(&options.OutputIP, "ip", false, "display host ip"),
		flagSet.BoolVar(&options.OutputCName, "cname", false, "display host cname"),
		flagSet.DynamicVar(&options.OutputCDN, "cdn", "true", "display cdn/waf in use"),
	)

	flagSet.CreateGroup("matchers", "Matchers",
		flagSet.StringVarP(&options.OutputMatchStatusCode, "match-code", "mc", "", "match response with specified status code (-mc 200,302)"),
		flagSet.StringVarP(&options.OutputMatchContentLength, "match-length", "ml", "", "match response with specified content length (-ml 100,102)"),
		flagSet.StringVarP(&options.OutputMatchLinesCount, "match-line-count", "mlc", "", "match response body with specified line count (-mlc 423,532)"),
		flagSet.StringVarP(&options.OutputMatchWordsCount, "match-word-count", "mwc", "", "match response body with specified word count (-mwc 43,55)"),
		flagSet.StringSliceVarP(&options.OutputMatchFavicon, "match-favicon", "mfc", nil, "match response with specified favicon hash (-mfc 1494302000)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputMatchString, "match-string", "ms", nil, "match response with specified string (-ms admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputMatchRegex, "match-regex", "mr", nil, "match response with specified regex (-mr admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputMatchCdn, "match-cdn", "mcdn", nil, fmt.Sprintf("match host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputMatchResponseTime, "match-response-time", "mrt", "", "match response with specified response time in seconds (-mrt '< 1')"),
		flagSet.StringVarP(&options.OutputMatchCondition, "match-condition", "mdc", "", "match response with dsl expression condition"),
	)

	flagSet.CreateGroup("extractor", "Extractor",
		flagSet.StringSliceVarP(&options.OutputExtractRegexs, "extract-regex", "er", nil, "display response content with matched regex", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputExtractPresets, "extract-preset", "ep", nil, fmt.Sprintf("display response content matched by a pre-defined regex (%s)", strings.Join(maps.Keys(customextract.ExtractPresets), ",")), goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("filters", "Filters",
		flagSet.StringVarP(&options.OutputFilterStatusCode, "filter-code", "fc", "", "filter response with specified status code (-fc 403,401)"),
		flagSet.StringSliceVarP(&options.OutputFilterPageType, "filter-page-type", "fpt", nil, "filter response with specified page type (e.g. -fpt login,captcha,parked)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.FilterOutDuplicates, "filter-duplicates", "fd", false, "filter out near-duplicate responses (only first response is retained)"),
		flagSet.StringVarP(&options.OutputFilterContentLength, "filter-length", "fl", "", "filter response with specified content length (-fl 23,33)"),
		flagSet.StringVarP(&options.OutputFilterLinesCount, "filter-line-count", "flc", "", "filter response body with specified line count (-flc 423,532)"),
		flagSet.StringVarP(&options.OutputFilterWordsCount, "filter-word-count", "fwc", "", "filter response body with specified word count (-fwc 423,532)"),
		flagSet.StringSliceVarP(&options.OutputFilterFavicon, "filter-favicon", "ffc", nil, "filter response with specified favicon hash (-ffc 1494302000)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputFilterString, "filter-string", "fs", nil, "filter response with specified string (-fs admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputFilterRegex, "filter-regex", "fe", nil, "filter response with specified regex (-fe admin)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputFilterCdn, "filter-cdn", "fcdn", nil, fmt.Sprintf("filter host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputFilterResponseTime, "filter-response-time", "frt", "", "filter response with specified response time in seconds (-frt '> 1')"),
		flagSet.StringVarP(&options.OutputFilterCondition, "filter-condition", "fdc", "", "filter response with dsl expression condition"),
		flagSet.DynamicVar(&options.StripFilter, "strip", "html", "strips all tags in response. supported formats: html,xml"),
		flagSet.StringSliceVarP(&options.ExcludeOutputFields, "exclude-output-fields", "eof", nil, "exclude output fields output based on a condition", goflags.NormalizedOriginalStringSliceOptions),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.Threads, "threads", "t", defaultThreads, "number of threads to use"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum requests to send per second"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum number of requests to send per minute"),
	)

	flagSet.CreateGroup("Misc", "Miscellaneous",
		flagSet.BoolVarP(&options.ProbeAllIPS, "probe-all-ips", "pa", false, "probe all the ips associated with same host"),
		flagSet.VarP(&options.CustomPorts, "ports", "p", "ports to probe (nmap syntax: eg http:1,2-10,11,https:80)"),
		flagSet.StringVar(&options.RequestURIs, "path", "", "path or list of paths to probe (comma-separated, file)"),
		flagSet.BoolVar(&options.HTTP2Probe, "http2", false, "probe and display server supporting HTTP2"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output results"),
		flagSet.BoolVarP(&options.OutputAll, "output-all", "oa", false, "filename to write output results in all formats"),
		flagSet.BoolVarP(&options.StoreResponse, "store-response", "sr", false, "store http response to output directory"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-response-dir", "srd", "", "store http response to custom directory"),
		flagSet.BoolVarP(&options.OmitBody, "omit-body", "ob", false, "omit response body in output"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "store output in csv format"),
		flagSet.StringVarP(&options.CSVOutputEncoding, "csv-output-encoding", "csvo", "", "define output encoding"),
		flagSet.BoolVarP(&options.JSONOutput, "json", "j", false, "store output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.ResponseHeadersInStdout, "include-response-header", "irh", false, "include http response (headers) in JSON output (-json only)"),
		flagSet.BoolVarP(&options.ResponseInStdout, "include-response", "irr", false, "include http request/response (headers + body) in JSON output (-json only)"),
		flagSet.BoolVarP(&options.Base64ResponseInStdout, "include-response-base64", "irrb", false, "include base64 encoded http request/response in JSON output (-json only)"),
		flagSet.BoolVar(&options.ChainInStdout, "include-chain", false, "include redirect http chain in JSON output (-json only)"),
		flagSet.BoolVar(&options.StoreChain, "store-chain", false, "include http redirect chain in responses (-sr only)"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the httpx configuration file (default $HOME/.config/httpx/config.yaml)"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "list of custom resolver (file or comma separated)", goflags.NormalizedStringSliceOptions),
		flagSet.Var(&options.Allow, "allow", "allowed list of IP/CIDR's to process (file or comma separated)"),
		flagSet.Var(&options.Deny, "deny", "denied list of IP/CIDR's to process (file or comma separated)"),
		flagSet.BoolVar(&options.RandomAgent, "random-agent", true, "enable Random User-Agent to use"),
		flagSet.BoolVar(&options.AutoReferer, "auto-referer", false, "set the Referer header to the current URL"),
		flagSet.VarP(&options.CustomHeaders, "header", "H", "custom http headers to send with request"),
		flagSet.StringVarP(&options.Proxy, "proxy", "http-proxy", "", "proxy (http|socks) to use (eg http://127.0.0.1:8080)"),
		flagSet.BoolVar(&options.Unsafe, "unsafe", false, "send raw requests skipping golang normalization"),
		flagSet.BoolVar(&options.Resume, "resume", false, "resume scan using resume.cfg"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "follow http redirects"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "maxr", 10, "max number of redirects to follow per host"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "follow redirects on the same host"),
		flagSet.BoolVarP(&options.RespectHSTS, "respect-hsts", "rhsts", false, "respect HSTS response headers for redirect requests"),
		flagSet.StringVar(&options.Methods, "x", "", "request methods to probe, use 'all' to probe all HTTP methods"),
		flagSet.StringVar(&options.RequestBody, "body", "", "post body to include in http request"),
		flagSet.BoolVarP(&options.Stream, "stream", "s", false, "stream mode - start elaborating input targets without sorting"),
		flagSet.BoolVarP(&options.SkipDedupe, "skip-dedupe", "sd", false, "disable dedupe input items (only used with stream mode)"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "leave default http/https ports in host header (eg. http://host:80 - https://host:443"),
		flagSet.BoolVar(&options.NoDecode, "no-decode", false, "avoid decoding body"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "Disable Stdin processing"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "display request/response content in cli"),
		flagSet.BoolVar(&options.Version, "version", false, "display httpx version"),
		flagSet.StringVar(&options.Memprofile, "profile-mem", "", "optional httpx memory profile dump file"),
		flagSet.BoolVar(&options.Silent, "silent", false, "silent mode"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "verbose mode"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in cli output"),
	)

	flagSet.CreateGroup("Optimizations", "Optimizations",
		flagSet.BoolVarP(&options.NoFallback, "no-fallback", "nf", false, "display both probed protocol (HTTPS and HTTP)"),
		flagSet.BoolVarP(&options.NoFallbackScheme, "no-fallback-scheme", "nfs", false, "probe with protocol scheme specified in input "),
		flagSet.IntVarP(&options.HostMaxErrors, "max-host-error", "maxhr", 30, "max error count per host before skipping remaining path/s"),
		flagSet.StringSliceVarP(&options.Exclude, "exclude", "e", nil, "exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVar(&options.Retries, "retries", 0, "number of retries"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "timeout in seconds"),
		flagSet.DurationVar(&options.Delay, "delay", -1, "duration between each http request (eg: 200ms, 1s)"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToSave, "response-size-to-save", "rsts", int(httpxcommon.DefaultMaxResponseBodySize), "max response size to save in bytes"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToRead, "response-size-to-read", "rstr", int(httpxcommon.DefaultMaxResponseBodySize), "max response size to read in bytes"),
	)

	_ = flagSet.Parse()

	if options.OutputAll && options.Output == "" {
		gologger.Fatal().Msg("Please specify an output file using -o/-output when using -oa/-output-all")
	}

	if options.OutputAll {
		options.JSONOutput = true
		options.CSVOutput = true
	}

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	if options.ResponseBodyPreviewSize > 0 && options.StripFilter == "" {
		options.StripFilter = "html"
	}

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	return options
}

func (options *Options) ValidateOptions() error {
	if options.InputFile != "" && !fileutilz.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		return fmt.Errorf("file '%s' does not exist", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		return fmt.Errorf("file '%s' does not exist", options.InputRawRequest)
	}

	if options.InputMode != "" && inputformats.GetFormat(options.InputMode) == nil {
		return fmt.Errorf("invalid input mode '%s', supported formats: %s", options.InputMode, inputformats.SupportedFormats())
	}

	if options.InputMode != "" && options.InputFile == "" {
		return errors.New("-im/-input-mode requires -l/-list to specify an input file")
	}

	if options.Silent {
		incompatibleFlagsList := flagsIncompatibleWithSilent(options)
		if len(incompatibleFlagsList) > 0 {
			last := incompatibleFlagsList[len(incompatibleFlagsList)-1]
			first := incompatibleFlagsList[:len(incompatibleFlagsList)-1]
			msg := ""
			if len(incompatibleFlagsList) > 1 {
				msg += fmt.Sprintf("%s and %s flags are", strings.Join(first, ", "), last)
			} else {
				msg += fmt.Sprintf("%s flag is", last)
			}
			msg += " incompatible with silent flag"
			return errors.New(msg)
		}
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		return errors.Wrap(err, "Invalid value for match status code option")
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		return errors.Wrap(err, "Invalid value for match content length option")
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		return errors.Wrap(err, "Invalid value for filter status code option")
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		return errors.Wrap(err, "Invalid value for filter content length option")
	}
	for _, filterRegexStr := range options.OutputFilterRegex {
		filterRegex, err := regexp.Compile(filterRegexStr)
		if err != nil {
			return errors.Wrap(err, "Invalid value for regex filter option")
		}
		options.filterRegexes = append(options.filterRegexes, filterRegex)
	}

	for _, matchRegexStr := range options.OutputMatchRegex {
		matchRegex, err := regexp.Compile(matchRegexStr)
		if err != nil {
			return errors.Wrap(err, "Invalid value for match regex option")
		}
		options.matchRegexes = append(options.matchRegexes, matchRegex)
	}

	if options.matchLinesCount, err = stringz.StringToSliceInt(options.OutputMatchLinesCount); err != nil {
		return errors.Wrap(err, "Invalid value for match lines count option")
	}
	if options.matchWordsCount, err = stringz.StringToSliceInt(options.OutputMatchWordsCount); err != nil {
		return errors.Wrap(err, "Invalid value for match words count option")
	}
	if options.filterLinesCount, err = stringz.StringToSliceInt(options.OutputFilterLinesCount); err != nil {
		return errors.Wrap(err, "Invalid value for filter lines count option")
	}
	if options.filterWordsCount, err = stringz.StringToSliceInt(options.OutputFilterWordsCount); err != nil {
		return errors.Wrap(err, "Invalid value for filter words count option")
	}

	var resolvers []string
	for _, resolver := range options.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				return errors.Wrapf(err, "Couldn't process resolver file \"%s\"", resolver)
			}
			for line := range chFile {
				line = strings.TrimSpace(line)
				if line != "" && strings.Contains(line, ",") {
					for item := range strings.SplitSeq(line, ",") {
						item = strings.TrimSpace(item)
						if item != "" {
							resolvers = append(resolvers, item)
						}
					}
				} else if line != "" {
					resolvers = append(resolvers, line)
				}
			}
		} else {
			if strings.ContainsAny(resolver, `/\`) {
				gologger.Warning().Msgf("Resolver argument \"%s\" looks like a file path but the file does not exist", resolver)
			}
			resolvers = append(resolvers, resolver)
		}
	}

	options.Resolvers = resolvers
	if len(options.Resolvers) > 0 {
		gologger.Debug().Msgf("Using resolvers: %s\n", strings.Join(options.Resolvers, ","))
	}

	if options.StoreResponse && options.StoreResponseDir == "" {
		gologger.Debug().Msgf("Store response directory not specified, using \"%s\"\n", DefaultOutputDirectory)
		options.StoreResponseDir = DefaultOutputDirectory
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}

	if options.Hashes != "" {
		for _, hashType := range strings.Split(options.Hashes, ",") {
			if !sliceutil.Contains([]string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"}, strings.ToLower(hashType)) {
				gologger.Error().Msgf("Unsupported hash type: %s\n", hashType)
			}
		}
	}
	if options.SimhashThreshold < 0 || options.SimhashThreshold > 3 {
		return fmt.Errorf("invalid simhash threshold %d: must be between 0 and 3", options.SimhashThreshold)
	}
	if len(options.OutputMatchCdn) > 0 || len(options.OutputFilterCdn) > 0 {
		options.OutputCDN = "true"
	}

	if options.Threads == 0 {
		gologger.Info().Msgf("Threads automatically set to %d", defaultThreads)
		options.Threads = defaultThreads
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if len(options.OutputMatchResponseTime) > 0 || len(options.OutputFilterResponseTime) > 0 {
		options.OutputResponseTime = true
	}
	if options.CSVOutputEncoding != "" {
		options.CSVOutput = true
	}
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

func flagsIncompatibleWithSilent(options *Options) []string {
	var incompatibleFlagsList []string
	for k, v := range map[string]bool{
		"debug":   options.Debug,
		"verbose": options.Verbose,
	} {
		if v {
			incompatibleFlagsList = append(incompatibleFlagsList, k)
		}
	}
	return incompatibleFlagsList
}
