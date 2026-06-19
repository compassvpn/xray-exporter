// IP filtering functionality to exclude system and internal traffic
// from user metrics. Helps focus on real user activity rather than infrastructure noise.
package logparser

import (
	"container/list"
	"net"
	"sync"
)

// Efficiently filters out unwanted IP addresses from metrics collection.
// Uses multiple strategies: exact matches for system IPs, network ranges for private IPs,
// and an LRU cache (O(1) eviction) to avoid repeated expensive lookups.
type IPFilter struct {
	systemIPs   map[string]bool // Known system/localhost addresses
	dnsServers  map[string]bool // Common public DNS servers
	privateNets []*net.IPNet    // Private network ranges (RFC 1918, etc.)

	mu           sync.Mutex               // Protects the LRU cache
	cache        map[string]*list.Element // ip -> element in lru
	lru          *list.List               // most-recently-used at the front
	maxCacheSize int                      // Maximum cache entries before eviction
}

// Stores a cached filter result for one IP.
type cacheItem struct {
	ip     string
	result bool
}

// Creates a new IP filter with predefined lists of addresses to exclude.
// Includes localhost, private networks, and common public DNS servers.
func NewIPFilter() *IPFilter {
	filter := &IPFilter{
		systemIPs:    make(map[string]bool),
		dnsServers:   make(map[string]bool),
		cache:        make(map[string]*list.Element),
		lru:          list.New(),
		maxCacheSize: 100000,
	}

	// System and localhost addresses
	systemIPs := []string{
		"127.0.0.1",
		"localhost",
		"::1",
	}
	for _, ip := range systemIPs {
		filter.systemIPs[ip] = true
	}

	// Common public DNS servers - these generate noise in proxy logs
	dnsServers := []string{
		// Cloudflare DNS
		"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
		"2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112",
		"2606:4700:4700::1002", "2606:4700:4700::1113", "2606:4700:4700::1003",

		// Google DNS
		"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",

		// Quad9 DNS
		"9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
		"2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",

		// OpenDNS
		"208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
		"2620:119:35::35", "2620:119:53::53", "2620:0:ccc::2", "2620:0:ccd::2",

		// AdGuard DNS
		"94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141", "94.140.14.15", "94.140.15.16",
		"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::1:ff", "2a10:50c0::2:ff",
		"2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff",
	}
	for _, ip := range dnsServers {
		filter.dnsServers[ip] = true
	}

	// Private network ranges (RFC 1918 and IPv6 equivalents)
	privateNetworks := []string{
		"10.0.0.0/8",     // Class A private networks
		"172.16.0.0/12",  // Class B private networks
		"192.168.0.0/16", // Class C private networks
		"fc00::/7",       // IPv6 unique local addresses
		"fe80::/10",      // IPv6 link-local addresses
	}

	for _, cidr := range privateNetworks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			filter.privateNets = append(filter.privateNets, ipNet)
		}
	}

	return filter
}

// Returns true if the IP address should be excluded from user metrics.
// Uses an LRU cache (O(1) lookup and eviction) to avoid repeated network checks.
func (f *IPFilter) ShouldFilter(ip string) bool {
	f.mu.Lock()
	if el, ok := f.cache[ip]; ok {
		f.lru.MoveToFront(el)
		result := el.Value.(*cacheItem).result
		f.mu.Unlock()
		return result
	}
	f.mu.Unlock()

	// Perform actual filtering logic (no lock needed; reads immutable data).
	result := f.shouldFilterInternal(ip)

	f.mu.Lock()
	if el, ok := f.cache[ip]; ok {
		// Inserted by a concurrent caller in the meantime; just refresh it.
		f.lru.MoveToFront(el)
		el.Value.(*cacheItem).result = result
	} else {
		f.cache[ip] = f.lru.PushFront(&cacheItem{ip: ip, result: result})
		// Evict the least-recently-used entry in O(1) when over capacity.
		if f.lru.Len() > f.maxCacheSize {
			if oldest := f.lru.Back(); oldest != nil {
				f.lru.Remove(oldest)
				delete(f.cache, oldest.Value.(*cacheItem).ip)
			}
		}
	}
	f.mu.Unlock()

	return result
}

// Performs the actual filtering logic without caching.
// Checks system IPs, DNS servers, and private network ranges in order of efficiency.
func (f *IPFilter) shouldFilterInternal(ip string) bool {
	// Check exact matches first (fastest)
	if f.systemIPs[ip] {
		return true
	}

	if f.dnsServers[ip] {
		return true
	}

	// Parse IP for network range checks
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return true // Filter invalid IPs
	}

	// Check if IP falls within private network ranges
	for _, ipNet := range f.privateNets {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	// IP is not filtered - it's a real user
	return false
}
