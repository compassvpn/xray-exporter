// Core exporter functionality for collecting Xray metrics.
package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/xtls/xray-core/app/stats/command"

	"xray-exporter/internal/geoip"
	"xray-exporter/internal/logparser"
)

// Default time window for user activity metrics (in minutes)
const DefaultLogTimeWindowMinutes = 5

// Collects Xray metrics and exposes them in Prometheus format.
// Connects to Xray's gRPC API for runtime stats and optionally parses
// access logs for user activity metrics.
type Exporter struct {
	endpoint           string
	scrapeTimeout      time.Duration
	userTrafficMetrics bool
	registry           *prometheus.Registry
	totalScrapes       prometheus.Counter
	metricDescriptions map[string]*prometheus.Desc
	conn               *grpc.ClientConn

	// Log parsing for user metrics
	logParser     *logparser.Parser
	logPath       string
	logTimeWindow time.Duration

	// GeoIP for ASN lookups
	geoipASNReader     *geoip2.Reader
	geoipCityReader    *geoip2.Reader
	geoipCountryReader *geoip2.Reader
}

// Creates a new Xray exporter with custom log parsing configuration.
// Pass empty logPath to disable user metrics from log parsing.
func NewExporterWithLogConfig(endpoint string, scrapeTimeout time.Duration, userTrafficMetrics bool, logPath string, logTimeWindow time.Duration) (*Exporter, error) {
	e := Exporter{
		endpoint:           endpoint,
		scrapeTimeout:      scrapeTimeout,
		userTrafficMetrics: userTrafficMetrics,
		registry:           prometheus.NewRegistry(),
		logPath:            logPath,
		logTimeWindow:      logTimeWindow,

		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "xray",
			Name:      "scrapes_total",
			Help:      "Total number of scrapes performed",
		}),
	}

	// Initialize all metric descriptions
	e.metricDescriptions = map[string]*prometheus.Desc{}

	for k, desc := range map[string]struct {
		txt  string
		lbls []string
	}{
		// Core Xray metrics
		"up":                           {txt: "Indicate scrape succeeded or not"},
		"scrape_duration_seconds":      {txt: "Scrape duration in seconds"},
		"uptime_seconds":               {txt: "Xray uptime in seconds"},
		"traffic_uplink_bytes_total":   {txt: "Number of transmitted bytes", lbls: []string{"dimension", "target"}},
		"traffic_downlink_bytes_total": {txt: "Number of received bytes", lbls: []string{"dimension", "target"}},

		// User activity metrics from log parsing
		"unique_users":      {txt: "Number of unique users in time window"},
		"total_connections": {txt: "Total number of connections in time window"},
		"asns_total": {
			txt:  "Total number of requests per ASN",
			lbls: []string{"asn", "org"},
		},
		"countries_total": {
			txt:  "Total number of requests per country",
			lbls: []string{"country"},
		},
		"cities_total": {
			txt:  "Total number of requests per city",
			lbls: []string{"city", "country"},
		},
	} {
		e.metricDescriptions[k] = e.newMetricDescr(k, desc.txt, desc.lbls)
	}

	e.registry.MustRegister(&e)

	// Create simple gRPC connection
	// No keepalive needed for short, infrequent calls every 15-30s
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	e.conn = conn

	// Initialize GeoIP readers. GeoIP is optional enrichment, so a missing or
	// unreadable database is logged and skipped rather than being fatal.
	if asnDB, err := geoip2.Open(geoip.ASNPath()); err != nil {
		logrus.WithError(err).Warn("Failed to open GeoIP ASN database, ASN metrics will be unavailable")
	} else {
		e.geoipASNReader = asnDB
	}

	if cityDB, err := geoip2.Open(geoip.CityPath()); err != nil {
		// If city database is missing, we still continue but city/country metrics will be unknown
		logrus.WithError(err).Warn("Failed to open GeoIP City database, city/country metrics will be unavailable")
	} else {
		e.geoipCityReader = cityDB
	}

	if countryDB, err := geoip2.Open(geoip.CountryPath()); err != nil {
		logrus.WithError(err).Warn("Failed to open GeoIP Country database, country metrics will be limited")
	} else {
		e.geoipCountryReader = countryDB
	}

	// Initialize log parser if path provided
	if logPath != "" && logPath != "disabled" {
		if _, err := os.Stat(logPath); err != nil {
			logrus.WithError(err).Warn("Log file not found, user metrics will not be available")
		} else {
			parser, err := logparser.NewParser(logparser.Config{
				LogPath:       logPath,
				TimeWindow:    logTimeWindow,
				ASNReader:     e.geoipASNReader,
				CountryReader: e.geoipCountryReader,
				CityReader:    e.geoipCityReader,
			})
			if err != nil {
				logrus.WithError(err).Warn("Failed to create log parser")
			} else {
				e.logParser = parser
				if err := e.logParser.Start(); err != nil {
					logrus.WithError(err).Warn("Failed to start log parser")
				} else {
					logrus.Info("Log parser started successfully")
				}
			}
		}
	}

	return &e, nil
}

// Implements prometheus.Collector interface - gathers all metrics from Xray and log sources.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	// A panic anywhere in collection runs in a registry-spawned goroutine that
	// Prometheus does not recover, so it would crash the whole process. Contain
	// it here and surface the failure as up=0 instead.
	defer func() {
		if r := recover(); r != nil {
			logrus.WithField("panic", r).Error("recovered panic during metrics collection")
			e.registerConstMetricGauge(ch, "up", 0)
		}
	}()

	e.totalScrapes.Inc()
	start := time.Now()

	// Attempt to scrape Xray metrics via gRPC
	var up float64 = 1
	if err := e.scrapeXray(ch); err != nil {
		up = 0
		logrus.WithError(err).Warn("Scrape failed")
	}

	// Collect log-based metrics
	e.collectLogMetrics(ch)
	e.collectDomainMetrics(ch)
	e.collectOutboundMetrics(ch)
	e.collectASNMetrics(ch)
	e.collectCountryMetrics(ch)
	e.collectCityMetrics(ch)

	// Core metrics
	e.registerConstMetricGauge(ch, "up", up)
	e.registerConstMetricGauge(ch, "scrape_duration_seconds", time.Since(start).Seconds())

	ch <- e.totalScrapes
}

// Implements prometheus.Collector interface - describes all metrics this collector can produce.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range e.metricDescriptions {
		ch <- desc
	}

	ch <- e.totalScrapes.Desc()

	ch <- prometheus.NewDesc(
		prometheus.BuildFQName("xray", "", "requested_domain_ip_total"),
		"Total number of requests per domain or IP",
		[]string{"target"},
		nil,
	)
}

// Connects to Xray's gRPC API and collects all available metrics.
func (e *Exporter) scrapeXray(ch chan<- prometheus.Metric) error {
	ctx, cancel := context.WithTimeout(context.Background(), e.scrapeTimeout)
	defer cancel()

	client := command.NewStatsServiceClient(e.conn)

	if err := e.scrapeXraySysMetrics(ctx, ch, client); err != nil {
		return err
	}

	if err := e.scrapeXrayMetrics(ctx, ch, client); err != nil {
		return err
	}

	return nil
}

// Collects traffic statistics from Xray's stats API.
func (e *Exporter) scrapeXrayMetrics(ctx context.Context, ch chan<- prometheus.Metric, client command.StatsServiceClient) error {
	resp, err := e.callWithRetry(ctx, func() (any, error) {
		return client.QueryStats(ctx, &command.QueryStatsRequest{Reset_: false})
	})
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	statsResp := resp.(*command.QueryStatsResponse)
	for _, s := range statsResp.GetStat() {
		// Parse format: inbound>>>socks-proxy>>>traffic>>>uplink
		p := strings.Split(s.GetName(), ">>>")

		// Skip names that don't match the expected 4-part format to avoid
		// index-out-of-range panics on custom/unexpected stat names.
		if len(p) < 4 {
			logrus.Debugf("skipping unexpected stat name %q", s.GetName())
			continue
		}

		// Skip per-user traffic metrics unless explicitly enabled. Per-user
		// series are unbounded (one per user, with no top-N cap), so they stay
		// off by default to control cardinality.
		if p[0] == "user" && !e.userTrafficMetrics {
			continue
		}

		metric := p[2] + "_" + p[3] + "_bytes_total"
		dimension := p[0]
		target := p[1]

		e.registerConstMetricCounter(ch, metric, float64(s.GetValue()), dimension, target)
	}

	return nil
}

// Collects system runtime metrics from Xray.
func (e *Exporter) scrapeXraySysMetrics(ctx context.Context, ch chan<- prometheus.Metric, client command.StatsServiceClient) error {
	resp, err := e.callWithRetry(ctx, func() (any, error) {
		return client.GetSysStats(ctx, &command.SysStatsRequest{})
	})
	if err != nil {
		return fmt.Errorf("failed to get sys stats: %w", err)
	}

	sysResp := resp.(*command.SysStatsResponse)
	e.registerConstMetricGauge(ch, "uptime_seconds", float64(sysResp.GetUptime()))

	// Memory and runtime metrics following Go collector naming conventions
	e.registerConstMetricGauge(ch, "goroutines", float64(sysResp.GetNumGoroutine()))
	e.registerConstMetricGauge(ch, "memstats_alloc_bytes", float64(sysResp.GetAlloc()))
	e.registerConstMetricGauge(ch, "memstats_alloc_bytes_total", float64(sysResp.GetTotalAlloc()))
	e.registerConstMetricGauge(ch, "memstats_sys_bytes", float64(sysResp.GetSys()))
	e.registerConstMetricGauge(ch, "memstats_mallocs_total", float64(sysResp.GetMallocs()))
	e.registerConstMetricGauge(ch, "memstats_frees_total", float64(sysResp.GetFrees()))

	// Additional memory metrics not in standard Go collector
	e.registerConstMetricGauge(ch, "memstats_num_gc", float64(sysResp.GetNumGC()))
	e.registerConstMetricGauge(ch, "memstats_pause_total_ns", float64(sysResp.GetPauseTotalNs()))

	return nil
}

// Implements exponential backoff retry for gRPC calls.
// Helps handle temporary network issues or Xray restarts.
func (e *Exporter) callWithRetry(ctx context.Context, fn func() (any, error)) (any, error) {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond

	for attempt := range maxRetries {
		resp, err := fn()
		if err == nil {
			return resp, nil
		}

		if attempt == maxRetries-1 {
			return nil, err
		}

		delay := baseDelay * time.Duration(1<<attempt)
		logrus.WithError(err).WithField("attempt", attempt+1).WithField("delay", delay).Debug("gRPC call failed, retrying")
		// Honour the scrape deadline instead of blocking on a fixed sleep.
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("max retries exceeded")
}

func (e *Exporter) registerConstMetricGauge(ch chan<- prometheus.Metric, metric string, val float64, labels ...string) {
	e.registerConstMetric(ch, metric, val, prometheus.GaugeValue, labels...)
}

func (e *Exporter) registerConstMetricCounter(ch chan<- prometheus.Metric, metric string, val float64, labels ...string) {
	e.registerConstMetric(ch, metric, val, prometheus.CounterValue, labels...)
}

func (e *Exporter) registerConstMetric(ch chan<- prometheus.Metric, metric string, val float64, valType prometheus.ValueType, labelValues ...string) {
	descr := e.metricDescriptions[metric]
	if descr == nil {
		descr = e.newMetricDescr(metric, metric+" metric", nil)
	}

	if m, err := prometheus.NewConstMetric(descr, valType, val, labelValues...); err == nil {
		ch <- m
	} else {
		logrus.Debugf("NewConstMetric() err: %s", err)
	}
}

func (e *Exporter) newMetricDescr(metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName("xray", "", metricName), docString, labels, nil)
}

// Pairs a metric key with its count for top-N sorting.
type countEntry struct {
	key   string
	count int64
}

// Returns the n entries with the highest counts, sorted descending.
// If the map has fewer than n entries, all of them are returned.
// This bounds metric cardinality (e.g. only the top domains are exported).
func topN(counts map[string]int64, n int) []countEntry {
	entries := make([]countEntry, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, countEntry{key: key, count: count})
	}
	slices.SortFunc(entries, func(a, b countEntry) int {
		return cmp.Compare(b.count, a.count)
	})
	return entries[:min(n, len(entries))]
}

// Collects user activity metrics from log parser.
func (e *Exporter) collectLogMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	uniqueUsers, totalConns := e.logParser.GetMetrics()

	e.registerConstMetricGauge(ch, "unique_users", float64(uniqueUsers))
	e.registerConstMetricGauge(ch, "total_connections", float64(totalConns))
}

// Collects domain and IP request statistics from log parser.
func (e *Exporter) collectDomainMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	metricDesc := prometheus.NewDesc(
		prometheus.BuildFQName("xray", "", "requested_domain_ip_total"),
		"Total number of requests per domain or IP",
		[]string{"target"},
		nil,
	)

	// Only export the top domains and IPs to prevent cardinality leak.
	// These are gauges: the backing counts are periodically trimmed to the
	// top-N, so the value is not monotonic and must not be treated as a counter.
	for _, entry := range topN(e.logParser.GetDomainCounts(), logparser.MaxTrackedDomains) {
		ch <- prometheus.MustNewConstMetric(metricDesc, prometheus.GaugeValue, float64(entry.count), entry.key)
	}
	for _, entry := range topN(e.logParser.GetIPCounts(), logparser.MaxTrackedIPs) {
		ch <- prometheus.MustNewConstMetric(metricDesc, prometheus.GaugeValue, float64(entry.count), entry.key)
	}
}

// Collects outbound routing statistics from log parser.
func (e *Exporter) collectOutboundMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	metricDesc := prometheus.NewDesc(
		prometheus.BuildFQName("xray", "", "outbound_requests_total"),
		"Total number of requests per outbound",
		[]string{"outbound"},
		nil,
	)

	// Only export the top outbounds to prevent cardinality leak (gauge, see note above).
	for _, entry := range topN(e.logParser.GetOutboundCounts(), logparser.MaxTrackedOutbounds) {
		ch <- prometheus.MustNewConstMetric(metricDesc, prometheus.GaugeValue, float64(entry.count), entry.key)
	}
}

// Collects ASN statistics from log parser.
func (e *Exporter) collectASNMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	for _, entry := range topN(e.logParser.GetASNCounts(), logparser.MaxTrackedASNs) {
		// Key format: asn|org
		parts := strings.Split(entry.key, "|")
		asn := parts[0]
		org := ""
		if len(parts) > 1 {
			org = parts[1]
		}
		e.registerConstMetricGauge(ch, "asns_total", float64(entry.count), asn, org)
	}
}

// Collects country statistics from log parser.
func (e *Exporter) collectCountryMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	for _, entry := range topN(e.logParser.GetCountryCounts(), logparser.MaxTrackedCountries) {
		e.registerConstMetricGauge(ch, "countries_total", float64(entry.count), entry.key)
	}
}

// Collects city statistics from log parser.
func (e *Exporter) collectCityMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	for _, entry := range topN(e.logParser.GetCityCounts(), logparser.MaxTrackedCities) {
		// Key format: city|country
		parts := strings.Split(entry.key, "|")
		city := parts[0]
		country := ""
		if len(parts) > 1 {
			country = parts[1]
		}
		e.registerConstMetricGauge(ch, "cities_total", float64(entry.count), city, country)
	}
}

// Properly closes gRPC connection and stops log parser.
func (e *Exporter) Close() error {
	if e.logParser != nil {
		e.logParser.Stop()
	}
	if e.geoipASNReader != nil {
		e.geoipASNReader.Close()
	}
	if e.geoipCityReader != nil {
		e.geoipCityReader.Close()
	}
	if e.geoipCountryReader != nil {
		e.geoipCountryReader.Close()
	}
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}
