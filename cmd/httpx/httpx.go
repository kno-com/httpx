package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/internal/db"
	"github.com/projectdiscovery/httpx/runner"
	_ "github.com/projectdiscovery/utils/pprof"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	// Profiling related code
	if options.Memprofile != "" {
		f, err := os.Create(options.Memprofile)
		if err != nil {
			gologger.Fatal().Msgf("profile: could not create memory profile %q: %v", options.Memprofile, err)
		}
		old := runtime.MemProfileRate
		runtime.MemProfileRate = 4096
		gologger.Print().Msgf("profile: memory profiling enabled (rate %d), %s", runtime.MemProfileRate, options.Memprofile)

		defer func() {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			_ = f.Close()
			runtime.MemProfileRate = old
			gologger.Print().Msgf("profile: memory profiling disabled, %s", options.Memprofile)
		}()
	}

	// setup optional database output
	_ = setupDatabaseOutput(options)

	httpxRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		// First Ctrl+C: stop dispatching, let in-flight requests finish
		<-c
		gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
		httpxRunner.Interrupt()
		// Second Ctrl+C: force exit
		<-c
		gologger.Info().Msgf("Forcing exit\n")
		os.Exit(1)
	}()

	httpxRunner.RunEnumeration()

	if httpxRunner.IsInterrupted() && options.ShouldSaveResume() {
		gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFile)
		err := httpxRunner.SaveResumeConfig()
		if err != nil {
			gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
		}
	}

	httpxRunner.Close()
}

// setupDatabaseOutput sets up database output for storing results
// This is optional and only initialized when explicitly enabled via -rdb flag
func setupDatabaseOutput(opts *runner.Options) *db.Writer {
	if !opts.ResultDatabase {
		return nil
	}

	var cfg *db.Config
	var err error

	if opts.ResultDatabaseConfig != "" {
		// Load configuration from file
		cfg, err = db.LoadConfigFromFile(opts.ResultDatabaseConfig)
		if err != nil {
			gologger.Fatal().Msgf("Could not load database config: %s\n", err)
		}
	} else {
		// Build configuration from CLI options
		dbOpts := &db.Options{
			Enabled:          opts.ResultDatabase,
			Type:             opts.ResultDatabaseType,
			ConnectionString: opts.ResultDatabaseConnStr,
			DatabaseName:     opts.ResultDatabaseName,
			TableName:        opts.ResultDatabaseTable,
			BatchSize:        opts.ResultDatabaseBatchSize,
			OmitRaw:          opts.ResultDatabaseOmitRaw,
		}
		cfg, err = dbOpts.ToConfig()
		if err != nil {
			gologger.Fatal().Msgf("Invalid database configuration: %s\n", err)
		}
	}

	writer, err := db.NewWriter(context.Background(), cfg)
	if err != nil {
		gologger.Fatal().Msgf("Could not setup database output: %s\n", err)
	}

	// Chain with existing OnResult callback if present
	existingCallback := opts.OnResult
	opts.OnResult = func(r runner.Result) {
		if existingCallback != nil {
			existingCallback(r)
		}
		writer.GetWriterCallback()(r)
	}

	// Chain with existing OnClose callback if present
	existingClose := opts.OnClose
	opts.OnClose = func() {
		writer.Close()
		if existingClose != nil {
			existingClose()
		}
	}

	return writer
}
