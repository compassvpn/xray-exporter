// Parses Xray access logs and extracts user metrics.
// Monitors log files for changes and maintains real-time statistics about user activity,
// domain requests, and connection patterns.
package logparser

import (
	"bufio"
	"context"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Cardinality limits to prevent excessive metric series
const (
	MaxTrackedDomains   = 50 // Keep only top 50 domains for pie chart
	MaxTrackedIPs       = 20 // Keep only top 20 IPs for pie chart
	MaxTrackedOutbounds = 10 // Keep only top 10 outbounds

	// Emergency cleanup thresholds to prevent unlimited growth
	MaxDomainsBeforeCleanup   = 100 // Force cleanup if domains exceed this (small buffer)
	MaxIPsBeforeCleanup       = 40  // Force cleanup if IPs exceed this (small buffer)
	MaxOutboundsBeforeCleanup = 20  // Force cleanup if outbounds exceed this
)

// Represents a parsed line from the Xray access log.
type LogEntry struct {
	Timestamp time.Time
	IP        string
	Domain    string
}

// Holds collected metrics for a specified time window.
// Uses a circular buffer for connection timestamps to prevent memory growth.
type MetricsData struct {
	UniqueIPs      map[string]time.Time // IP -> last seen time
	DomainCounts   map[string]int64     // domain -> total request count
	IPCounts       map[string]int64     // direct IP requests -> total count
	OutboundCounts map[string]int64     // outbound -> total request count

	// Circular buffer for connection timestamps to limit memory usage
	ConnectionTimestamps []time.Time // circular buffer of connection timestamps
	ConnectionsBufHead   int         // current write position in buffer
	ConnectionsBufSize   int         // actual size of valid data in buffer
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
}

// Configuration options for the log parser.
type Config struct {
	LogPath    string
	TimeWindow time.Duration
}

// Regular expressions for parsing different log line formats
var (
	timestampRegex   = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)
	newFormatIPRegex = regexp.MustCompile(`from (?:tcp:)?(\d+\.\d+\.\d+\.\d+|\S+):`)
	oldFormatIPRegex = regexp.MustCompile(`from (?:\[([0-9a-fA-F:]+)\]|(\d+\.\d+\.\d+\.\d+)):`)
	outboundRegex    = regexp.MustCompile(`\[.* -> ([^]]+)\]`)
)

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

// Extracts the root domain from a full domain name.
// Example: sub.google.com -> google.com
func getRootDomain(domain string) string {
	if domain == "" {
		return ""
	}

	// Handle domain names - extract root domain
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

	return match[1]
}

// Adds a timestamp to the circular buffer.
// Prevents memory growth by overwriting old entries when the buffer is full.
func (p *Parser) addConnectionTimestamp(ts time.Time) {
	p.metrics.ConnectionTimestamps[p.metrics.ConnectionsBufHead] = ts
	p.metrics.ConnectionsBufHead = (p.metrics.ConnectionsBufHead + 1) % p.metrics.ConnectionsBufCap
	if p.metrics.ConnectionsBufSize < p.metrics.ConnectionsBufCap {
		p.metrics.ConnectionsBufSize++
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
}

// Emergency cleanup if maps grow too large between regular cleanups
func (p *Parser) checkEmergencyCleanup() {
	p.metrics.mu.RLock()
	needCleanup := len(p.metrics.DomainCounts) > MaxDomainsBeforeCleanup ||
		len(p.metrics.IPCounts) > MaxIPsBeforeCleanup ||
		len(p.metrics.OutboundCounts) > MaxOutboundsBeforeCleanup
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
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	// Keep only top N
	result := make(map[string]int64, n)
	for i := 0; i < n && i < len(entries); i++ {
		result[entries[i].key] = entries[i].count
	}

	return result
}

// Creates a new log parser with automatic buffer sizing based on time window.
func NewParser(config Config) (*Parser, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Calculate buffer capacity automatically based on time window
	// Use adaptive sizing: more time = bigger buffer, with sensible bounds
	minutes := int(config.TimeWindow.Minutes())

	var bufferCap int
	switch {
	case minutes <= 5:
		bufferCap = 500000 // Short windows: 500K entries (~12MB)
	case minutes <= 10:
		bufferCap = 1000000 // Medium windows: 1M entries (~24MB)
	case minutes <= 30:
		bufferCap = 2000000 // Long windows: 2M entries (~48MB)
	default:
		bufferCap = 5000000 // Very long windows: 5M entries (~120MB)
	}

	parser := &Parser{
		logPath:    config.LogPath,
		timeWindow: config.TimeWindow,
		ipFilter:   NewIPFilter(),
		metrics: &MetricsData{
			UniqueIPs:            make(map[string]time.Time),
			DomainCounts:         make(map[string]int64),
			IPCounts:             make(map[string]int64),
			OutboundCounts:       make(map[string]int64),
			ConnectionTimestamps: make([]time.Time, bufferCap),
			ConnectionsBufHead:   0,
			ConnectionsBufSize:   0,
			ConnectionsBufCap:    bufferCap,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Immediate cleanup on startup to ensure clean state
	parser.trimToTopN()

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

	// Count valid connections in circular buffer
	var validConnections int64
	for i := 0; i < p.metrics.ConnectionsBufSize; i++ {
		idx := (p.metrics.ConnectionsBufHead - i - 1 + p.metrics.ConnectionsBufCap) % p.metrics.ConnectionsBufCap
		if p.metrics.ConnectionTimestamps[idx].After(cutoff) {
			validConnections++
		} else {
			// Since we store in chronological order, older entries won't be valid either
			break
		}
	}

	return activeIPs, validConnections
}

// Returns a copy of current domain request counts.
// These are cumulative counters since parser startup.
func (p *Parser) GetDomainCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	result := make(map[string]int64, len(p.metrics.DomainCounts))
	for domain, count := range p.metrics.DomainCounts {
		result[domain] = count
	}
	return result
}

// Returns a copy of current IP request counts.
// These are cumulative counters since parser startup.
func (p *Parser) GetIPCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	result := make(map[string]int64, len(p.metrics.IPCounts))
	for ip, count := range p.metrics.IPCounts {
		result[ip] = count
	}
	return result
}

// Returns a copy of current outbound request counts.
// These are cumulative counters since parser startup.
func (p *Parser) GetOutboundCounts() map[string]int64 {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	result := make(map[string]int64, len(p.metrics.OutboundCounts))
	for outbound, count := range p.metrics.OutboundCounts {
		result[outbound] = count
	}
	return result
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
	currentInode := getInode(stat)

	// Check for log rotation by comparing inodes
	if currentInode != p.metrics.LastInode {
		logrus.Debug("Log file rotated, resetting position")
		p.metrics.LastPos = 0
		p.metrics.LastInode = currentInode
	}

	// Handle file truncation (file got smaller)
	if p.metrics.LastPos > stat.Size() {
		logrus.Debug("Log file truncated, resetting position")
		p.metrics.LastPos = 0
	}

	// Initialize tracking on first run
	if p.metrics.LastInode == 0 {
		p.metrics.LastPos = 0
		p.metrics.LastInode = currentInode
	}

	// Seek to last known position
	if _, err := file.Seek(p.metrics.LastPos, 0); err != nil {
		p.mu.Unlock()
		return err
	}
	p.mu.Unlock()

	scanner := bufio.NewScanner(file)
	cutoff := time.Now().Add(-p.timeWindow)
	newPos := p.metrics.LastPos

	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	for scanner.Scan() {
		line := scanner.Text()
		newPos += int64(len(line)) + 1 // +1 for newline

		// Quick pre-filtering to skip obviously invalid lines
		if shouldSkipLine(line) {
			continue
		}

		entry, err := p.parseLine(line)
		if err != nil || entry == nil {
			continue
		}

		// Always track domain and IP requests (cumulative counters)
		originalDomain := extractDomainOptimized(line)
		if originalDomain != "" {
			if isIPAddressFast(originalDomain) {
				// Track IP requests separately
				p.metrics.IPCounts[originalDomain]++
			} else {
				// Track domain requests (root domain)
				rootDomain := getRootDomain(originalDomain)
				if rootDomain != "" {
					p.metrics.DomainCounts[rootDomain]++
				}
			}
		}

		// Always track outbound requests (cumulative counters)
		outbound := extractOutbound(line)
		if outbound != "" {
			p.metrics.OutboundCounts[outbound]++
		}

		// Skip entries outside time window (for user metrics only)
		if entry.Timestamp.Before(cutoff) {
			continue
		}

		// Filter out internal/system IPs
		if p.ipFilter.ShouldFilter(entry.IP) {
			continue
		}

		// Update user metrics (time-windowed)
		p.addConnectionTimestamp(entry.Timestamp)
		// Track unique IPs with last seen time
		p.metrics.UniqueIPs[entry.IP] = entry.Timestamp
	}

	// Update file position for next read
	p.mu.Lock()
	p.metrics.LastPos = newPos
	p.mu.Unlock()

	return scanner.Err()
}

// Parses a single log line with optimized string operations.
// Extracts timestamp, IP address, domain, and blocked status.
func (p *Parser) parseLine(line string) (*LogEntry, error) {
	entry := &LogEntry{}

	// Parse timestamp
	timestampMatch := timestampRegex.FindStringSubmatch(line)
	if len(timestampMatch) < 2 {
		return nil, nil // Skip lines without timestamp
	}

	timestamp, err := time.Parse("2006/01/02 15:04:05", timestampMatch[1])
	if err != nil {
		return nil, err
	}
	entry.Timestamp = timestamp

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

	// Normalize IP once and reuse result
	normalizedIP := normalizeIP(ip)
	if normalizedIP == "" {
		return nil, nil // Skip invalid IPs
	}
	entry.IP = normalizedIP

	// Extract domain for entry (just for reference, actual tracking done later)
	// Use optimized domain extraction that reuses already parsed line components
	domain := extractDomainOptimized(line)
	if domain != "" {
		// Check if it's an IP by testing if it's the same as our normalized IP
		// This avoids calling net.ParseIP again
		if domain == normalizedIP || isIPAddressFast(domain) {
			entry.Domain = domain // Keep IP as-is
		} else {
			entry.Domain = getRootDomain(domain) // Store root domain
		}
	}

	return entry, nil
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

// Normalizes an IP address string.
func normalizeIP(ip string) string {
	ip = strings.Trim(ip, "[]")

	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}

	return ""
}
