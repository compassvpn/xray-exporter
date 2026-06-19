// Parses Xray access logs and extracts user metrics.
// Monitors log files for changes and maintains real-time statistics about user activity,
// domain requests, and connection patterns.
package logparser

import (
	"bufio"
	"cmp"
	"context"
	"maps"
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

	// Emergency cleanup thresholds to prevent unlimited growth
	MaxDomainsBeforeCleanup   = 100 // Force cleanup if domains exceed this (small buffer)
	MaxIPsBeforeCleanup       = 40  // Force cleanup if IPs exceed this (small buffer)
	MaxOutboundsBeforeCleanup = 20  // Force cleanup if outbounds exceed this
	MaxASNsBeforeCleanup      = 100
	MaxCountriesBeforeCleanup = 100
	MaxCitiesBeforeCleanup    = 100
)

// Represents a parsed line from the Xray access log.
type LogEntry struct {
	Timestamp time.Time
	IP        string
	ParsedIP  net.IP
}

// Holds collected metrics for a specified time window.
// Uses a circular buffer for connection timestamps to prevent memory growth.
type MetricsData struct {
	UniqueIPs      map[string]time.Time // IP -> last seen time
	DomainCounts   map[string]int64     // domain -> total request count
	IPCounts       map[string]int64     // direct IP requests -> total count
	OutboundCounts map[string]int64     // outbound -> total request count
	ASNCounts      map[string]int64     // ASN -> total request count (key: asn|org)
	CountryCounts  map[string]int64     // country -> total request count (labels: country)
	CityCounts     map[string]int64     // city -> total request count (labels: city, country)

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
	domainCounts   map[string]int64
	ipCounts       map[string]int64
	outboundCounts map[string]int64
	asnCounts      map[string]int64
	countryCounts  map[string]int64
	cityCounts     map[string]int64
	uniqueIPs      map[string]time.Time
	timestamps     []time.Time
}

func newMetricsDelta() *metricsDelta {
	return &metricsDelta{
		domainCounts:   make(map[string]int64),
		ipCounts:       make(map[string]int64),
		outboundCounts: make(map[string]int64),
		asnCounts:      make(map[string]int64),
		countryCounts:  make(map[string]int64),
		cityCounts:     make(map[string]int64),
		uniqueIPs:      make(map[string]time.Time),
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

// Trims maps to keep only top N entries by count to control cardinality
func (p *Parser) trimToTopN() {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.DomainCounts = keepTopN(p.metrics.DomainCounts, MaxTrackedDomains)
	p.metrics.IPCounts = keepTopN(p.metrics.IPCounts, MaxTrackedIPs)
	p.metrics.OutboundCounts = keepTopN(p.metrics.OutboundCounts, MaxTrackedOutbounds)
	p.metrics.ASNCounts = keepTopN(p.metrics.ASNCounts, MaxTrackedASNs)
	p.metrics.CountryCounts = keepTopN(p.metrics.CountryCounts, MaxTrackedCountries)
	p.metrics.CityCounts = keepTopN(p.metrics.CityCounts, MaxTrackedCities)
}

// Emergency cleanup if maps grow too large between regular cleanups
func (p *Parser) checkEmergencyCleanup() {
	p.metrics.mu.RLock()
	needCleanup := len(p.metrics.DomainCounts) > MaxDomainsBeforeCleanup ||
		len(p.metrics.IPCounts) > MaxIPsBeforeCleanup ||
		len(p.metrics.OutboundCounts) > MaxOutboundsBeforeCleanup ||
		len(p.metrics.ASNCounts) > MaxASNsBeforeCleanup ||
		len(p.metrics.CountryCounts) > MaxCountriesBeforeCleanup ||
		len(p.metrics.CityCounts) > MaxCitiesBeforeCleanup
	p.metrics.mu.RUnlock()

	if needCleanup {
		logrus.Debug("Emergency cleanup triggered - too many domains/IPs")
		p.trimToTopN()
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
			DomainCounts:         make(map[string]int64),
			IPCounts:             make(map[string]int64),
			OutboundCounts:       make(map[string]int64),
			ASNCounts:            make(map[string]int64),
			CountryCounts:        make(map[string]int64),
			CityCounts:           make(map[string]int64),
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

// Returns current user activity metrics within the time window.
// Also performs cleanup of expired data to prevent memory leaks.
func (p *Parser) GetMetrics() (int, int64) {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	cutoff := time.Now().Add(-p.timeWindow)

	// Clean up expired IPs efficiently
	activeIPs := 0
	expiredIPs := make([]string, 0, len(p.metrics.UniqueIPs)/10) // Pre-allocate for ~10% expired
	for ip, lastSeen := range p.metrics.UniqueIPs {
		if lastSeen.After(cutoff) {
			activeIPs++
		} else {
			expiredIPs = append(expiredIPs, ip)
		}
	}

	// Remove expired IPs in separate loop to avoid iterator invalidation
	for _, ip := range expiredIPs {
		delete(p.metrics.UniqueIPs, ip)
	}

	// Expire connection timestamps from the oldest end. Because entries are
	// stored chronologically, we only walk the newly-expired tail, and the
	// remaining size IS the in-window connection count (amortized O(1)).
	bufCap := p.metrics.ConnectionsBufCap
	for p.metrics.ConnectionsBufSize > 0 {
		tail := ((p.metrics.ConnectionsBufHead-p.metrics.ConnectionsBufSize)%bufCap + bufCap) % bufCap
		if p.metrics.ConnectionTimestamps[tail].After(cutoff) {
			break
		}
		p.metrics.ConnectionsBufSize--
	}

	return activeIPs, int64(p.metrics.ConnectionsBufSize)
}

// Returns a copy of current domain request counts.
func (p *Parser) GetDomainCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return maps.Clone(p.metrics.DomainCounts)
}

// Returns a copy of current direct IP request counts.
func (p *Parser) GetIPCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return maps.Clone(p.metrics.IPCounts)
}

// Returns a copy of current outbound request counts.
func (p *Parser) GetOutboundCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return maps.Clone(p.metrics.OutboundCounts)
}

// Returns a copy of current ASN request counts.
func (p *Parser) GetASNCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return maps.Clone(p.metrics.ASNCounts)
}

// Returns a copy of current country request counts.
func (p *Parser) GetCountryCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return maps.Clone(p.metrics.CountryCounts)
}

// Returns a copy of current city request counts.
func (p *Parser) GetCityCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return maps.Clone(p.metrics.CityCounts)
}

// Continuously monitors the log file for changes and processes new entries.
// Runs every 5 seconds to balance responsiveness with system overhead.
// Also performs periodic cardinality cleanup every 30 seconds for aggressive control.
func (p *Parser) parseLoop() {
	ticker := time.NewTicker(5 * time.Second)
	cleanupTicker := time.NewTicker(30 * time.Second) // More frequent cleanup
	defer ticker.Stop()
	defer cleanupTicker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-cleanupTicker.C:
			p.trimToTopN()
		case <-ticker.C:
			if err := p.parseLogFile(); err != nil {
				logrus.WithError(err).Warn("Failed to parse log file")
			}
			// Check for emergency cleanup after processing logs
			p.checkEmergencyCleanup()
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
				delta.ipCounts[normalized]++
			}
		} else if rootDomain := getRootDomain(domain); rootDomain != "" {
			delta.domainCounts[rootDomain]++
		}
	}

	// Always track outbound requests.
	if outbound := extractOutbound(line); outbound != "" {
		delta.outboundCounts[outbound]++
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
		delta.countryCounts[countryCode]++
	}
	if cityName != "unknown" {
		delta.cityCounts[cityName+"|"+countryCode]++
	}
	// Key format: asn|org
	delta.asnCounts[asn+"|"+org]++
}

// mergeDelta folds a parsed batch into the shared metrics. Caller must hold metrics.mu.
func (p *Parser) mergeDelta(d *metricsDelta) {
	for k, v := range d.domainCounts {
		p.metrics.DomainCounts[k] += v
	}
	for k, v := range d.ipCounts {
		p.metrics.IPCounts[k] += v
	}
	for k, v := range d.outboundCounts {
		p.metrics.OutboundCounts[k] += v
	}
	for k, v := range d.asnCounts {
		p.metrics.ASNCounts[k] += v
	}
	for k, v := range d.countryCounts {
		p.metrics.CountryCounts[k] += v
	}
	for k, v := range d.cityCounts {
		p.metrics.CityCounts[k] += v
	}
	for ip, ts := range d.uniqueIPs {
		p.metrics.UniqueIPs[ip] = ts
	}
	for _, ts := range d.timestamps {
		p.addConnectionTimestamp(ts)
	}
}

// Parses a single log line, extracting timestamp and client IP.
func (p *Parser) parseLine(line string) (*LogEntry, error) {
	// Parse timestamp
	timestampMatch := timestampRegex.FindStringSubmatch(line)
	if len(timestampMatch) < 2 {
		return nil, nil // Skip lines without timestamp
	}

	timestamp, err := time.Parse("2006/01/02 15:04:05", timestampMatch[1])
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
