// Parses Xray access logs and extracts user metrics.
// Monitors log files for changes and maintains real-time statistics about user activity,
// domain requests, and connection patterns.
package logparser

import (
	"bufio"
	"cmp"
	"context"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

// Cardinality limits to prevent excessive metric series
const (
	MaxTrackedDomains   = 20 // Keep only top 20 domains for pie chart
	MaxTrackedIPs       = 20 // Keep only top 20 IPs for pie chart
	MaxTrackedOutbounds = 10 // Keep only top 10 outbounds
	MaxTrackedASNs      = 20 // Keep only top 20 ASNs
	MaxTrackedCountries = 20 // Keep only top 20 countries
	MaxTrackedCities    = 20 // Keep only top 20 cities

	// SafetyMaxKeys caps distinct keys held per metric as a memory backstop
	// against high-cardinality bursts (e.g. random-subdomain floods). It sits far
	// above the exported top-N, so it never disturbs the series actually scraped.
	SafetyMaxKeys = 10000
)

// Represents a parsed line from the Xray access log.
type LogEntry struct {
	Timestamp time.Time
	IP        string
	ParsedIP  net.IP
}

// windowedCount tracks a per-key request count together with the last time the
// key was seen. Keeping last-seen lets idle keys be expired out of the time
// window instead of being dropped by rank, which discarded live keys' history
// and let stale winners stick around forever.
type windowedCount struct {
	count    int64
	lastSeen time.Time
}

// Holds collected metrics for a specified time window.
// Uses a circular buffer for connection timestamps to prevent memory growth.
type MetricsData struct {
	UniqueIPs      map[string]time.Time      // IP -> last seen time
	DomainCounts   map[string]*windowedCount // domain -> count + last seen
	IPCounts       map[string]*windowedCount // direct IP requests -> count + last seen
	OutboundCounts map[string]*windowedCount // outbound -> count + last seen
	ASNCounts      map[string]*windowedCount // ASN -> count + last seen (key: asn|org)
	CountryCounts  map[string]*windowedCount // country -> count + last seen (labels: country)
	CityCounts     map[string]*windowedCount // city -> count + last seen (labels: city, country)

	// Circular buffer for connection timestamps to limit memory usage.
	// The backing slice grows lazily up to ConnectionsBufCap so low-traffic
	// servers don't pay the full allocation upfront.
	ConnectionTimestamps []time.Time // circular buffer of connection timestamps
	ConnectionsBufHead   int         // current write position in buffer
	ConnectionsBufSize   int         // number of in-window entries currently held
	ConnectionsBufCap    int         // maximum buffer capacity

	LastPos   int64  // last position read in log file
	LastInode uint64 // last inode of log file (for rotation detection)
	mu        sync.RWMutex
}

// Handles log file monitoring and metrics collection.
// Runs continuously, parsing new log entries and maintaining statistics.
type Parser struct {
	logPath    string
	timeWindow time.Duration
	ipFilter   *IPFilter
	metrics    *MetricsData
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex

	// GeoIP readers for real-time tracking
	asnReader     *geoip2.Reader
	countryReader *geoip2.Reader
	cityReader    *geoip2.Reader
}

// Configuration options for the log parser.
type Config struct {
	LogPath       string
	TimeWindow    time.Duration
	ASNReader     *geoip2.Reader
	CountryReader *geoip2.Reader
	CityReader    *geoip2.Reader
}

// Regular expressions for parsing different log line formats
var (
	timestampRegex   = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)
	newFormatIPRegex = regexp.MustCompile(`from (?:tcp:)?(\d+\.\d+\.\d+\.\d+|\S+):`)
	oldFormatIPRegex = regexp.MustCompile(`from (?:\[([0-9a-fA-F:]+)\]|(\d+\.\d+\.\d+\.\d+)):`)
	outboundRegex    = regexp.MustCompile(`\[[^\]]*?(?:->|>>)\s*([^\]]+?)\]`)
)

// metricsDelta accumulates a batch of parsed results so the expensive parsing
// and GeoIP lookups can run WITHOUT holding the metrics lock. The deltas are
// merged into the shared MetricsData under a brief lock at the end of a batch.
type metricsDelta struct {
	domainCounts   map[string]*windowedCount
	ipCounts       map[string]*windowedCount
	outboundCounts map[string]*windowedCount
	asnCounts      map[string]*windowedCount
	countryCounts  map[string]*windowedCount
	cityCounts     map[string]*windowedCount
	uniqueIPs      map[string]time.Time
	timestamps     []time.Time
}

func newMetricsDelta() *metricsDelta {
	return &metricsDelta{
		domainCounts:   make(map[string]*windowedCount),
		ipCounts:       make(map[string]*windowedCount),
		outboundCounts: make(map[string]*windowedCount),
		asnCounts:      make(map[string]*windowedCount),
		countryCounts:  make(map[string]*windowedCount),
		cityCounts:     make(map[string]*windowedCount),
		uniqueIPs:      make(map[string]time.Time),
	}
}

// recordCount increments the per-key count in m and advances its last-seen time.
func recordCount(m map[string]*windowedCount, key string, ts time.Time) {
	wc := m[key]
	if wc == nil {
		wc = &windowedCount{}
		m[key] = wc
	}
	wc.count++
	if ts.After(wc.lastSeen) {
		wc.lastSeen = ts
	}
}

// Performs quick checks to skip obviously invalid lines before expensive parsing.
// Improves performance by filtering out non-log lines early.
func shouldSkipLine(line string) bool {
	// Skip empty or very short lines
	if len(line) < 19 { // "2024/01/01 00:00:00" is 19 chars minimum
		return true
	}

	// Quick check for timestamp pattern at start
	if len(line) < 4 || line[0] < '1' || line[0] > '9' || line[4] != '/' {
		return true
	}

	// Skip comment lines
	if strings.HasPrefix(line, "#") {
		return true
	}

	// Must contain "from" for IP extraction
	if !strings.Contains(line, "from ") {
		return true
	}

	return false
}

// Extracts the registrable (eTLD+1) domain from a full domain name, using the
// public suffix list so multi-part suffixes are handled correctly.
// Example: a.sub.example.co.uk -> example.co.uk
func getRootDomain(domain string) string {
	if domain == "" {
		return ""
	}

	if etld1, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil && etld1 != "" {
		return etld1
	}

	// Fallback: last two labels.
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

// Extracts the outbound name from [inbound -> outbound] format.
func extractOutbound(line string) string {
	match := outboundRegex.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}

	return strings.TrimSpace(match[1])
}

// Adds a timestamp to the circular buffer.
// The backing slice grows lazily up to the cap, then overwrites the oldest entry.
func (p *Parser) addConnectionTimestamp(ts time.Time) {
	m := p.metrics
	if m.ConnectionsBufHead == len(m.ConnectionTimestamps) && len(m.ConnectionTimestamps) < m.ConnectionsBufCap {
		// Still growing the backing array.
		m.ConnectionTimestamps = append(m.ConnectionTimestamps, ts)
	} else {
		m.ConnectionTimestamps[m.ConnectionsBufHead] = ts
	}
	m.ConnectionsBufHead = (m.ConnectionsBufHead + 1) % m.ConnectionsBufCap
	if m.ConnectionsBufSize < m.ConnectionsBufCap {
		m.ConnectionsBufSize++
	}
}

// Helper struct for sorting map entries by count
type countEntry struct {
	key   string
	count int64
}

// Expires per-key counts that have aged out of the time window and enforces a
// memory backstop. Keys not seen since cutoff are dropped so stale winners fade
// and idle keys stop consuming memory. If a map still exceeds SafetyMaxKeys
// afterwards (a high-cardinality burst), only the highest-count keys are kept.
func (p *Parser) expireStaleCounts(cutoff time.Time) {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	expireCounts(p.metrics.DomainCounts, cutoff)
	expireCounts(p.metrics.IPCounts, cutoff)
	expireCounts(p.metrics.OutboundCounts, cutoff)
	expireCounts(p.metrics.ASNCounts, cutoff)
	expireCounts(p.metrics.CountryCounts, cutoff)
	expireCounts(p.metrics.CityCounts, cutoff)
}

// Drops keys last seen at or before cutoff, then applies the SafetyMaxKeys
// backstop by keeping only the highest-count keys if still over the limit.
func expireCounts(m map[string]*windowedCount, cutoff time.Time) {
	for k, v := range m {
		if !v.lastSeen.After(cutoff) {
			delete(m, k)
		}
	}

	if len(m) <= SafetyMaxKeys {
		return
	}

	entries := make([]countEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, countEntry{key: k, count: v.count})
	}
	slices.SortFunc(entries, func(a, b countEntry) int {
		return cmp.Compare(b.count, a.count)
	})
	dropped := entries[SafetyMaxKeys:]
	logrus.Debugf("key cap hit: dropped %d low-count keys over SafetyMaxKeys", len(dropped))
	for _, e := range dropped {
		delete(m, e.key)
	}
}

// Drops user activity that has aged out of the time window: expired unique IPs
// and connection timestamps at the tail of the circular buffer. Runs on the
// parse loop so memory is reclaimed regardless of scrape traffic.
func (p *Parser) expireWindowed(cutoff time.Time) {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	for ip, lastSeen := range p.metrics.UniqueIPs {
		if !lastSeen.After(cutoff) {
			delete(p.metrics.UniqueIPs, ip)
		}
	}

	bufCap := p.metrics.ConnectionsBufCap
	for p.metrics.ConnectionsBufSize > 0 {
		tail := ((p.metrics.ConnectionsBufHead-p.metrics.ConnectionsBufSize)%bufCap + bufCap) % bufCap
		if p.metrics.ConnectionTimestamps[tail].After(cutoff) {
			break
		}
		p.metrics.ConnectionsBufSize--
	}
}

// Keeps only the top N entries by count from a map
func keepTopN(counts map[string]int64, n int) map[string]int64 {
	if len(counts) <= n {
		return counts
	}

	// Convert to slice for sorting
	entries := make([]countEntry, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, countEntry{key: key, count: count})
	}

	// Sort by count (descending)
	slices.SortFunc(entries, func(a, b countEntry) int {
		return cmp.Compare(b.count, a.count)
	})

	// Keep only top N
	result := make(map[string]int64, n)
	for _, entry := range entries[:n] {
		result[entry.key] = entry.count
	}

	return result
}

// Creates a new log parser with automatic buffer sizing based on time window.
func NewParser(config Config) (*Parser, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Calculate buffer capacity automatically based on time window.
	// The buffer is a cap, not an upfront allocation: it grows lazily with
	// actual traffic (see addConnectionTimestamp).
	minutes := int(config.TimeWindow.Minutes())

	var bufferCap int
	switch {
	case minutes <= 5:
		bufferCap = 500000 // Short windows: up to 500K entries (~12MB)
	case minutes <= 10:
		bufferCap = 1000000 // Medium windows: up to 1M entries (~24MB)
	case minutes <= 30:
		bufferCap = 2000000 // Long windows: up to 2M entries (~48MB)
	default:
		bufferCap = 5000000 // Very long windows: up to 5M entries (~120MB)
	}

	// Start small and let the buffer grow with traffic.
	initialCap := min(bufferCap, 1024)

	parser := &Parser{
		logPath:       config.LogPath,
		timeWindow:    config.TimeWindow,
		ipFilter:      NewIPFilter(),
		asnReader:     config.ASNReader,
		countryReader: config.CountryReader,
		cityReader:    config.CityReader,
		metrics: &MetricsData{
			UniqueIPs:            make(map[string]time.Time),
			DomainCounts:         make(map[string]*windowedCount),
			IPCounts:             make(map[string]*windowedCount),
			OutboundCounts:       make(map[string]*windowedCount),
			ASNCounts:            make(map[string]*windowedCount),
			CountryCounts:        make(map[string]*windowedCount),
			CityCounts:           make(map[string]*windowedCount),
			ConnectionTimestamps: make([]time.Time, 0, initialCap),
			ConnectionsBufHead:   0,
			ConnectionsBufSize:   0,
			ConnectionsBufCap:    bufferCap,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	return parser, nil
}

// Begins log file monitoring in a background goroutine.
func (p *Parser) Start() error {
	go p.parseLoop()
	return nil
}

// Gracefully stops the log parser.
func (p *Parser) Stop() {
	p.cancel()
}

// Returns current user activity metrics within the time window: unique users
// and total connections. It is read-only. Reclaiming aged-out entries happens on
// the parse loop (see expireWindowed), so the counts stay correct even when
// scrapes pause and a scrape never mutates parser state.
func (p *Parser) GetMetrics() (int, int64) {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	cutoff := time.Now().Add(-p.timeWindow)

	activeIPs := 0
	for _, lastSeen := range p.metrics.UniqueIPs {
		if lastSeen.After(cutoff) {
			activeIPs++
		}
	}

	// Connections are stored chronologically, so aged-out entries sit at the
	// oldest (tail) end. Count how many trailing entries have expired and
	// subtract; the remainder is the in-window connection count.
	bufCap := p.metrics.ConnectionsBufCap
	expired := 0
	for expired < p.metrics.ConnectionsBufSize {
		tail := ((p.metrics.ConnectionsBufHead-p.metrics.ConnectionsBufSize+expired)%bufCap + bufCap) % bufCap
		if p.metrics.ConnectionTimestamps[tail].After(cutoff) {
			break
		}
		expired++
	}

	return activeIPs, int64(p.metrics.ConnectionsBufSize - expired)
}

// Returns a copy of current domain request counts.
func (p *Parser) GetDomainCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return snapshotCounts(p.metrics.DomainCounts)
}

// Returns a copy of current direct IP request counts.
func (p *Parser) GetIPCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return snapshotCounts(p.metrics.IPCounts)
}

// Returns a copy of current outbound request counts.
func (p *Parser) GetOutboundCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return snapshotCounts(p.metrics.OutboundCounts)
}

// Returns a copy of current ASN request counts.
func (p *Parser) GetASNCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return snapshotCounts(p.metrics.ASNCounts)
}

// Returns a copy of current country request counts.
func (p *Parser) GetCountryCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return snapshotCounts(p.metrics.CountryCounts)
}

// Returns a copy of current city request counts.
func (p *Parser) GetCityCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return snapshotCounts(p.metrics.CityCounts)
}

// snapshotCounts returns a plain key->count copy, dropping the last-seen
// bookkeeping so callers (the exporter) keep working with map[string]int64.
func snapshotCounts(m map[string]*windowedCount) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v.count
	}
	return out
}

// Continuously monitors the log file for changes and processes new entries.
// Runs every 5 seconds to balance responsiveness with system overhead, expiring
// aged-out data right after each parse so a single pass bounds map growth.
func (p *Parser) parseLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Track the last parse error so a persistent failure (missing file, bad
	// permissions) is logged once on change rather than every 5s tick.
	var lastErrMsg string

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.parseLogFile(); err != nil {
				if msg := err.Error(); msg != lastErrMsg {
					logrus.WithError(err).Warn("Failed to parse log file")
					lastErrMsg = msg
				}
			} else if lastErrMsg != "" {
				logrus.Info("Log file parsing recovered")
				lastErrMsg = ""
			}
			cutoff := time.Now().Add(-p.timeWindow)
			p.expireWindowed(cutoff)
			p.expireStaleCounts(cutoff)
		}
	}
}

// Reads and processes new entries from the log file since the last position.
// Handles log rotation by detecting inode changes and supports file truncation.
func (p *Parser) parseLogFile() error {
	file, err := os.Open(p.logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	p.mu.Lock()
	currentInode := getInode(file, stat)

	switch {
	case p.metrics.LastInode == 0:
		// First run: adopt the current file identity, keep position (0).
		p.metrics.LastInode = currentInode
	case currentInode != p.metrics.LastInode:
		logrus.Debug("Log file rotated, resetting position")
		p.metrics.LastPos = 0
		p.metrics.LastInode = currentInode
	case p.metrics.LastPos > stat.Size():
		logrus.Debug("Log file truncated, resetting position")
		p.metrics.LastPos = 0
	}

	startPos := p.metrics.LastPos
	p.mu.Unlock()

	// Seek to last known position
	if _, err := file.Seek(startPos, 0); err != nil {
		return err
	}

	cutoff := time.Now().Add(-p.timeWindow)
	newPos := startPos
	delta := newMetricsDelta()

	// bufio.Reader (not Scanner) avoids the 64KB line cap and lets us track the
	// exact number of bytes consumed (including \r and \n), so the position never
	// drifts on CRLF logs.
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// io.EOF (or any read error): a trailing line without a newline is a
			// partial write; stop without consuming it so it is re-read once
			// complete on the next pass.
			break
		}
		newPos += int64(len(line))
		p.processLine(strings.TrimRight(line, "\r\n"), cutoff, delta)
	}

	// Merge the batch under the metrics lock. No parsing or I/O happens here,
	// so scrapes are only blocked for the duration of a few map merges.
	p.metrics.mu.Lock()
	p.mergeDelta(delta)
	p.metrics.mu.Unlock()

	// Update file position for next read.
	p.mu.Lock()
	p.metrics.LastPos = newPos
	p.mu.Unlock()

	return nil
}

// processLine parses a single log line and records its data into delta.
// It performs no shared-state mutation (the IP filter and GeoIP readers are
// safe for concurrent use), so it can run without holding the metrics lock.
func (p *Parser) processLine(line string, cutoff time.Time, delta *metricsDelta) {
	// Quick pre-filtering to skip obviously invalid lines
	if shouldSkipLine(line) {
		return
	}

	entry, err := p.parseLine(line)
	if err != nil || entry == nil {
		return
	}

	// Always track domain and IP requests.
	if domain := extractDomainOptimized(line); domain != "" {
		if isIPAddressFast(domain) {
			// Normalize and exclude system/DNS/private IPs.
			if normalized := normalizeIP(domain); normalized != "" && !p.ipFilter.ShouldFilter(normalized) {
				recordCount(delta.ipCounts, normalized, entry.Timestamp)
			}
		} else if rootDomain := getRootDomain(domain); rootDomain != "" {
			recordCount(delta.domainCounts, rootDomain, entry.Timestamp)
		}
	}

	// Always track outbound requests.
	if outbound := extractOutbound(line); outbound != "" {
		recordCount(delta.outboundCounts, outbound, entry.Timestamp)
	}

	// Skip entries outside time window (for user metrics only).
	if entry.Timestamp.Before(cutoff) {
		return
	}

	// Filter out internal/system IPs.
	if p.ipFilter.ShouldFilter(entry.IP) {
		return
	}

	// Update user metrics (time-windowed).
	delta.timestamps = append(delta.timestamps, entry.Timestamp)
	delta.uniqueIPs[entry.IP] = entry.Timestamp

	// Extract context for detailed tracking.
	countryCode := "unknown"
	cityName := "unknown"
	asn := "unknown"
	org := "unknown"

	if p.cityReader != nil {
		if record, err := p.cityReader.City(entry.ParsedIP); err == nil {
			if record.Country.IsoCode != "" {
				countryCode = record.Country.IsoCode
			}
			if name, ok := record.City.Names["en"]; ok && name != "" {
				cityName = name
			}
		}
	} else if p.countryReader != nil {
		if record, err := p.countryReader.Country(entry.ParsedIP); err == nil {
			if record.Country.IsoCode != "" {
				countryCode = record.Country.IsoCode
			}
		}
	}

	if p.asnReader != nil {
		if record, err := p.asnReader.ASN(entry.ParsedIP); err == nil {
			asn = strconv.FormatUint(uint64(record.AutonomousSystemNumber), 10)
			org = record.AutonomousSystemOrganization
		}
	}

	// Update aggregated metrics.
	if countryCode != "unknown" {
		recordCount(delta.countryCounts, countryCode, entry.Timestamp)
	}
	if cityName != "unknown" {
		recordCount(delta.cityCounts, cityName+"|"+countryCode, entry.Timestamp)
	}
	// Key format: asn|org
	recordCount(delta.asnCounts, asn+"|"+org, entry.Timestamp)
}

// mergeDelta folds a parsed batch into the shared metrics. Caller must hold metrics.mu.
func (p *Parser) mergeDelta(d *metricsDelta) {
	mergeCounts(p.metrics.DomainCounts, d.domainCounts)
	mergeCounts(p.metrics.IPCounts, d.ipCounts)
	mergeCounts(p.metrics.OutboundCounts, d.outboundCounts)
	mergeCounts(p.metrics.ASNCounts, d.asnCounts)
	mergeCounts(p.metrics.CountryCounts, d.countryCounts)
	mergeCounts(p.metrics.CityCounts, d.cityCounts)
	for ip, ts := range d.uniqueIPs {
		p.metrics.UniqueIPs[ip] = ts
	}
	for _, ts := range d.timestamps {
		p.addConnectionTimestamp(ts)
	}
}

// mergeCounts folds src into dst, summing counts and keeping the latest last-seen.
func mergeCounts(dst, src map[string]*windowedCount) {
	for k, v := range src {
		wc := dst[k]
		if wc == nil {
			wc = &windowedCount{}
			dst[k] = wc
		}
		wc.count += v.count
		if v.lastSeen.After(wc.lastSeen) {
			wc.lastSeen = v.lastSeen
		}
	}
}

// Parses a single log line, extracting timestamp and client IP.
func (p *Parser) parseLine(line string) (*LogEntry, error) {
	// Parse timestamp
	timestampMatch := timestampRegex.FindStringSubmatch(line)
	if len(timestampMatch) < 2 {
		return nil, nil // Skip lines without timestamp
	}

	// Xray writes local time, so parse in the local zone. Parsing as UTC would
	// shift every timestamp by the UTC offset and break the time-window filter.
	timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", timestampMatch[1], time.Local)
	if err != nil {
		return nil, err
	}

	// Extract IP with single pass through formats
	var ip string
	if match := newFormatIPRegex.FindStringSubmatch(line); len(match) > 1 {
		ip = match[1]
	} else if match := oldFormatIPRegex.FindStringSubmatch(line); len(match) > 1 {
		if match[1] != "" {
			ip = match[1] // IPv6
		} else {
			ip = match[2] // IPv4
		}
	}

	if ip == "" {
		return nil, nil // Skip lines without IP
	}

	// Normalize and parse the IP once, reusing the parsed value.
	normalizedIP, parsedIP := normalizeIPParsed(ip)
	if parsedIP == nil {
		return nil, nil // Skip invalid IPs
	}

	return &LogEntry{
		Timestamp: timestamp,
		IP:        normalizedIP,
		ParsedIP:  parsedIP,
	}, nil
}

// Performs a quick heuristic check for IP addresses without full parsing.
// Avoids expensive net.ParseIP calls for obvious non-IP strings.
func isIPAddressFast(s string) bool {
	// Quick heuristic: if it contains only digits, dots, and colons, it might be an IP
	for _, c := range s {
		if !((c >= '0' && c <= '9') || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return strings.Contains(s, ".") || strings.Contains(s, ":")
}

// Extracts domain with fewer string operations than the standard method.
func extractDomainOptimized(line string) string {
	// Look for "accepted" keyword first to avoid extracting from client part
	acceptedIdx := strings.Index(line, "accepted ")
	if acceptedIdx == -1 {
		return ""
	}

	// Search for tcp: or udp: patterns AFTER "accepted"
	searchArea := line[acceptedIdx:]
	tcpIdx := strings.Index(searchArea, "tcp:")
	udpIdx := strings.Index(searchArea, "udp:")

	var startIdx int
	if tcpIdx != -1 && (udpIdx == -1 || tcpIdx < udpIdx) {
		startIdx = acceptedIdx + tcpIdx + 4
	} else if udpIdx != -1 {
		startIdx = acceptedIdx + udpIdx + 4
	} else {
		return ""
	}

	// Find space to end the domain:port section
	spaceIdx := strings.Index(line[startIdx:], " ")
	if spaceIdx == -1 {
		return ""
	}

	domainPort := line[startIdx : startIdx+spaceIdx]

	// Find last colon to separate domain from port
	colonIdx := strings.LastIndex(domainPort, ":")
	if colonIdx == -1 {
		return ""
	}

	return domainPort[:colonIdx]
}

// normalizeIPParsed canonicalizes an IP address string and returns both the
// canonical string form and the parsed net.IP, so callers don't parse twice.
func normalizeIPParsed(ip string) (string, net.IP) {
	ip = strings.Trim(ip, "[]")

	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String(), parsed
	}

	return "", nil
}

// Normalizes an IP address string, returning "" if it is not a valid IP.
func normalizeIP(ip string) string {
	s, _ := normalizeIPParsed(ip)
	return s
}
