// Xray Exporter - A Prometheus exporter for Xray/V2Ray metrics.
// Collects both runtime metrics via gRPC and user activity metrics via log parsing.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"xray-exporter/internal/geoip"
)

// Command line configuration
var opts struct {
	Listen                 string `short:"l" long:"listen" description:"Listen address" value-name:"[ADDR]:PORT" default:":9550"`
	MetricsPath            string `short:"m" long:"metrics-path" description:"Metrics path" value-name:"PATH" default:"/scrape"`
	XRayEndpoint           string `short:"e" long:"xray-endpoint" description:"Xray API endpoint" value-name:"HOST:PORT" default:"127.0.0.1:8080"`
	ScrapeTimeoutInSeconds int64  `short:"t" long:"scrape-timeout" description:"The timeout in seconds for every individual scrape" value-name:"N" default:"5"`
	UserTrafficMetrics     bool   `short:"u" long:"user-traffic-metrics" description:"Export per-user traffic byte counters (high cardinality: one series per user)"`
	LogPath                string `short:"p" long:"log-path" description:"Path to Xray access log file (empty to disable user metrics)" value-name:"PATH" default:"/var/log/xray/access.log"`
	LogTimeWindowMinutes   int    `short:"w" long:"log-time-window" description:"Time window in minutes for user metrics" value-name:"N"`
	GeoIPDir               string `short:"g" long:"geoip-dir" description:"Directory for GeoLite2 databases" value-name:"PATH" default:"."`
	Version                bool   `long:"version" description:"Display the version and exit"`
	LogLevel               string `long:"log-level" description:"Log level: error, warn, info, debug (env: LOG_LEVEL) (default: warn)" value-name:"LEVEL"`
}

// Build information injected during compilation
var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// Creates an HTTP handler for the Prometheus scrape endpoint
func scrapeHandler(exporter *Exporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		promhttp.HandlerFor(
			exporter.registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError},
		).ServeHTTP(w, r)
	}
}

// Simple health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// configureLogging sets the global logrus level. Precedence: the --log-level
// flag, then the LOG_LEVEL env var, then "warn". Only error, warn, info, and
// debug are accepted; anything else is non-fatal and falls back to warn, so a
// typo never stops startup.
func configureLogging(flagLevel string) {
	levelStr := flagLevel
	if levelStr == "" {
		levelStr = os.Getenv("LOG_LEVEL")
	}
	if levelStr == "" {
		levelStr = "warn"
	}

	var level logrus.Level
	switch strings.ToLower(levelStr) {
	case "error":
		level = logrus.ErrorLevel
	case "warn":
		level = logrus.WarnLevel
	case "info":
		level = logrus.InfoLevel
	case "debug":
		level = logrus.DebugLevel
	default:
		logrus.Warnf("invalid log level %q, defaulting to warn", levelStr)
		level = logrus.WarnLevel
	}
	logrus.SetLevel(level)
}

func main() {
	// Parse command line arguments
	if _, err := flags.Parse(&opts); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			return
		}
		logrus.WithError(err).Fatal("Failed to parse flags")
	}

	configureLogging(opts.LogLevel)

	// Print the identity banner directly so it is never hidden by the log level
	// (the default is warn, which would otherwise suppress this and --version).
	fmt.Printf("Xray Exporter %v-%v (built %v)\n", buildVersion, buildCommit, buildDate)

	if opts.Version {
		return
	}

	// Download GeoLite2 databases on startup. GeoIP is optional enrichment, so a
	// download failure is non-fatal: the exporter still serves core gRPC metrics.
	geoip.Dir = opts.GeoIPDir
	if err := geoip.DownloadDB(); err != nil {
		logrus.WithError(err).Warn("Failed to initialize GeoIP database, GeoIP metrics will be unavailable")
	}

	// Initialize exporter with configuration
	scrapeTimeout := time.Duration(opts.ScrapeTimeoutInSeconds) * time.Second

	// Use default time window if not specified
	timeWindowMinutes := opts.LogTimeWindowMinutes
	if timeWindowMinutes == 0 {
		timeWindowMinutes = DefaultLogTimeWindowMinutes
	}
	logTimeWindow := time.Duration(timeWindowMinutes) * time.Minute
	exporter, err := NewExporterWithLogConfig(opts.XRayEndpoint, scrapeTimeout, opts.UserTrafficMetrics, opts.LogPath, logTimeWindow)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create exporter")
	}
	defer exporter.Close()

	// Set up HTTP routes
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc(opts.MetricsPath, scrapeHandler(exporter))
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html>
<head><title>Xray Exporter</title></head>
<body>
<h1>Xray Exporter %s</h1>
<p><a href='/metrics'>Exporter Metrics</a></p>
<p><a href='%s'>Scrape Xray Metrics</a></p>
<p><a href='/health'>Health Check</a></p>
</body>
</html>
`, buildVersion, opts.MetricsPath)
	})

	// Configure HTTP server with reasonable timeouts
	server := &http.Server{
		Addr:         opts.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in background; a startup failure is routed back to main so the
	// deferred cleanup (exporter.Close) still runs instead of os.Exit-ing here.
	serverErr := make(chan error, 1)
	go func() {
		logrus.Infof("Server starting on %s", opts.Listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for a shutdown signal or a server startup error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		logrus.WithError(err).Error("Server failed to start")
		return
	case <-quit:
	}

	logrus.Info("Shutting down server...")

	// Graceful shutdown with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logrus.WithError(err).Error("Server forced to shutdown")
	}

	logrus.Info("Server exited")
}
