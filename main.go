// Xray Exporter - A Prometheus exporter for Xray/V2Ray metrics.
// Collects both runtime metrics via gRPC and user activity metrics via log parsing.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Command line configuration
var opts struct {
	Listen                 string `short:"l" long:"listen" description:"Listen address" value-name:"[ADDR]:PORT" default:":9550"`
	MetricsPath            string `short:"m" long:"metrics-path" description:"Metrics path" value-name:"PATH" default:"/scrape"`
	XRayEndpoint           string `short:"e" long:"xray-endpoint" description:"Xray API endpoint" value-name:"HOST:PORT" default:"127.0.0.1:8080"`
	ScrapeTimeoutInSeconds int64  `short:"t" long:"scrape-timeout" description:"The timeout in seconds for every individual scrape" value-name:"N" default:"5"`
	LogPath                string `short:"p" long:"log-path" description:"Path to Xray access log file (empty to disable user metrics)" value-name:"PATH" default:"/var/log/xray/access.log"`
	LogTimeWindowMinutes   int    `short:"w" long:"log-time-window" description:"Time window in minutes for user metrics" value-name:"N"`
	Version                bool   `long:"version" description:"Display the version and exit"`
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

func main() {
	// Parse command line arguments
	if _, err := flags.Parse(&opts); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			return
		}
		logrus.WithError(err).Fatal("Failed to parse flags")
	}

	logrus.Infof("Xray Exporter %v-%v (built %v)", buildVersion, buildCommit, buildDate)

	if opts.Version {
		return
	}

	// Initialize exporter with configuration
	scrapeTimeout := time.Duration(opts.ScrapeTimeoutInSeconds) * time.Second

	// Use default time window if not specified
	timeWindowMinutes := opts.LogTimeWindowMinutes
	if timeWindowMinutes == 0 {
		timeWindowMinutes = DefaultLogTimeWindowMinutes
	}
	logTimeWindow := time.Duration(timeWindowMinutes) * time.Minute
	exporter, err := NewExporterWithLogConfig(opts.XRayEndpoint, scrapeTimeout, opts.LogPath, logTimeWindow)
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

	// Start server in background
	go func() {
		logrus.Infof("Server starting on %s", opts.Listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Fatal("Server failed to start")
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	// Graceful shutdown with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logrus.WithError(err).Error("Server forced to shutdown")
	}

	logrus.Info("Server exited")
}
