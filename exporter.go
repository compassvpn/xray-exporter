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

	// Log parsing for user metrics.
	logParser     *logparser.Parser
	logPath       string
	logTimeWindow time.Duration

	// GeoIP readers for log enrichment.
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

	e.metricDescriptions = map[string]*prometheus.Desc{}

	for k, desc := range map[string]struct {
		txt  string
		lbls []string
	}{
		// Core Xray metrics.
		"up":                           {txt: "Indicate scrape succeeded or not"},
		"scrape_duration_seconds":      {txt: "Scrape duration in seconds"},
		"uptime_seconds":               {txt: "Xray uptime in seconds"},
		"traffic_uplink_bytes_total":   {txt: "Number of transmitted bytes", lbls: []string{"dimension", "target"}},
		"traffic_downlink_bytes_total": {txt: "Number of received bytes", lbls: []string{"dimension", "target"}},

		// Xray runtime metrics from GetSysStats.
		"goroutines":                 {txt: "Number of goroutines running in the Xray process"},
		"memstats_alloc_bytes":       {txt: "Bytes of allocated heap objects"},
		"memstats_alloc_bytes_total": {txt: "Cumulative bytes allocated for heap objects"},
		"memstats_sys_bytes":         {txt: "Total bytes of memory obtained from the OS"},
		"memstats_mallocs_total":     {txt: "Cumulative count of heap objects allocated"},
		"memstats_frees_total":       {txt: "Cumulative count of heap objects freed"},
		"memstats_num_gc":            {txt: "Number of completed GC cycles"},
		"memstats_pause_total_ns":    {txt: "Cumulative nanoseconds in GC stop-the-world pauses"},

		// User activity metrics from log parsing.
		"unique_users":      {txt: "Number of unique users in time window"},
		"total_connections": {txt: "Total number of connections in time window"},
		"outbound_requests": {
			txt:  "Number of requests per outbound (top-N in time window)",
			lbls: []string{"outbound"},
		},

		// Cumulative per-target counters. They only ever rise, apart from a
		// restart, which is a normal counter reset.
		"requested_domain_ip_total": {
			txt:  "Requests per domain or IP since startup (top-N by activity in the time window)",
			lbls: []string{"target"},
		},
		"asns_total": {
			txt:  "Requests per ASN since startup (top-N by activity in the time window)",
			lbls: []string{"asn", "org"},
		},
		"countries_total": {
			txt:  "Requests per country since startup (top-N by activity in the time window)",
			lbls: []string{"country"},
		},
		"cities_total": {
			txt:  "Requests per city since startup (top-N by activity in the time window)",
			lbls: []string{"city", "country"},
		},

		// Replaced by the _total counters above, kept for one release so
		// dashboards can catch up. These drop back to zero when a key ages out of
		// the time window, so rate() and increase() over them are meaningless.
		"requested_domain_ip": {
			txt:  "DEPRECATED, use xray_requested_domain_ip_total. Number of requests per domain or IP (top-N in time window)",
			lbls: []string{"target"},
		},
		"asns": {
			txt:  "DEPRECATED, use xray_asns_total. Number of requests per ASN (top-N in time window)",
			lbls: []string{"asn", "org"},
		},
		"countries": {
			txt:  "DEPRECATED, use xray_countries_total. Number of requests per country (top-N in time window)",
			lbls: []string{"country"},
		},
		"cities": {
			txt:  "DEPRECATED, use xray_cities_total. Number of requests per city (top-N in time window)",
			lbls: []string{"city", "country"},
		},
	} {
		e.metricDescriptions[k] = e.newMetricDescr(k, desc.txt, desc.lbls)
	}

	e.registry.MustRegister(&e)

	// No keepalive: calls are short and infrequent (one per 15-30s scrape).
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
		logrus.WithError(err).Warn("Failed to open GeoIP City database, city/country metrics will be unavailable")
	} else {
		e.geoipCityReader = cityDB
	}

	if countryDB, err := geoip2.Open(geoip.CountryPath()); err != nil {
		logrus.WithError(err).Warn("Failed to open GeoIP Country database, country metrics will be limited")
	} else {
		e.geoipCountryReader = countryDB
	}

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

	var up float64 = 1
	if err := e.scrapeXray(ch); err != nil {
		up = 0
		logrus.WithError(err).Warn("Scrape failed")
	}

	e.collectLogMetrics(ch)
	e.collectDomainMetrics(ch)
	e.collectOutboundMetrics(ch)
	e.collectASNMetrics(ch)
	e.collectCountryMetrics(ch)
	e.collectCityMetrics(ch)

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
		// Stat name format: inbound>>>socks-proxy>>>traffic>>>uplink.
		p := strings.Split(s.GetName(), ">>>")

		// Custom or unexpected stat names may not have all 4 parts.
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

	// Memory and runtime metrics following Go collector naming conventions.
	// Current-value readings are gauges; cumulative counts carry _total and are counters.
	e.registerConstMetricGauge(ch, "goroutines", float64(sysResp.GetNumGoroutine()))
	e.registerConstMetricGauge(ch, "memstats_alloc_bytes", float64(sysResp.GetAlloc()))
	e.registerConstMetricCounter(ch, "memstats_alloc_bytes_total", float64(sysResp.GetTotalAlloc()))
	e.registerConstMetricGauge(ch, "memstats_sys_bytes", float64(sysResp.GetSys()))
	e.registerConstMetricCounter(ch, "memstats_mallocs_total", float64(sysResp.GetMallocs()))
	e.registerConstMetricCounter(ch, "memstats_frees_total", float64(sysResp.GetFrees()))

	// Additional memory metrics not in the standard Go collector.
	e.registerConstMetricCounter(ch, "memstats_num_gc", float64(sysResp.GetNumGC()))
	e.registerConstMetricCounter(ch, "memstats_pause_total_ns", float64(sysResp.GetPauseTotalNs()))

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

	// Still top-N by activity in the time window, so panels keep showing what is
	// busy now. Only the value changed. A key that falls out of the top-N leaves
	// a gap and comes back higher, never lower.
	e.collectCumulative(ch, "requested_domain_ip_total", "requested_domain_ip",
		e.logParser.GetDomainCounts(), e.logParser.GetDomainTotals(), logparser.MaxTrackedDomains, singleLabel)
	e.collectCumulative(ch, "requested_domain_ip_total", "requested_domain_ip",
		e.logParser.GetIPCounts(), e.logParser.GetIPTotals(), logparser.MaxTrackedIPs, singleLabel)
}

// Exports the top-N busiest keys of one log metric twice: the cumulative total
// as a counter, and the in-window count under the deprecated gauge name.
// labelsFor turns a map key into label values.
func (e *Exporter) collectCumulative(ch chan<- prometheus.Metric, counterName, gaugeName string, counts, totals map[string]int64, n int, labelsFor func(string) []string) {
	for _, entry := range topN(counts, n) {
		labels := labelsFor(entry.key)

		// No total means the key cap evicted it. Skip it instead of reporting
		// zero, which would look like a reset.
		if total, ok := totals[entry.key]; ok {
			e.registerConstMetricCounter(ch, counterName, float64(total), labels...)
		}
		e.registerConstMetricGauge(ch, gaugeName, float64(entry.count), labels...)
	}
}

func singleLabel(key string) []string {
	return []string{key}
}

// Splits a "first|second" key (asn|org, city|country) into two label values.
// A key without a separator gets an empty second value.
func splitPairLabel(key string) []string {
	first, second, _ := strings.Cut(key, "|")
	return []string{first, second}
}

// Collects outbound routing statistics from log parser.
func (e *Exporter) collectOutboundMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	metricDesc := e.metricDescriptions["outbound_requests"]

	// Top-N only, to bound cardinality. Still a gauge: its keys age out of the
	// time window, so the value goes down as well as up.
	for _, entry := range topN(e.logParser.GetOutboundCounts(), logparser.MaxTrackedOutbounds) {
		ch <- prometheus.MustNewConstMetric(metricDesc, prometheus.GaugeValue, float64(entry.count), entry.key)
	}
}

// Collects ASN statistics from log parser.
func (e *Exporter) collectASNMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	// Key format: asn|org.
	e.collectCumulative(ch, "asns_total", "asns",
		e.logParser.GetASNCounts(), e.logParser.GetASNTotals(), logparser.MaxTrackedASNs, splitPairLabel)
}

// Collects country statistics from log parser.
func (e *Exporter) collectCountryMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	e.collectCumulative(ch, "countries_total", "countries",
		e.logParser.GetCountryCounts(), e.logParser.GetCountryTotals(), logparser.MaxTrackedCountries, singleLabel)
}

// Collects city statistics from log parser.
func (e *Exporter) collectCityMetrics(ch chan<- prometheus.Metric) {
	if e.logParser == nil {
		return
	}

	// Key format: city|country.
	e.collectCumulative(ch, "cities_total", "cities",
		e.logParser.GetCityCounts(), e.logParser.GetCityTotals(), logparser.MaxTrackedCities, splitPairLabel)
}

// Closes the gRPC connection, GeoIP readers, and log parser.
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
