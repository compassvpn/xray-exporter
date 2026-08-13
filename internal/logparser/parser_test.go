package logparser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testDomain    = "example.com"
	testDestIP    = "203.0.113.9"  // TEST-NET-3, never filtered.
	testClientIP  = "198.51.100.7" // TEST-NET-2, never filtered.
	unknownASNKey = "unknown|unknown"
)

// Drives a Parser against a real file on disk, so rotation goes through the
// filesystem instead of injected state.
type parserHarness struct {
	t       *testing.T
	parser  *Parser
	logPath string
	seq     int
}

func newParserHarness(t *testing.T, window time.Duration) *parserHarness {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("create log: %v", err)
	}

	parser, err := NewParser(Config{LogPath: logPath, TimeWindow: window})
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}

	return &parserHarness{t: t, parser: parser, logPath: logPath}
}

// One Xray access log line. Every line gets a unique source port so no two log
// files share their leading bytes, which is what the fingerprint hashes.
func (h *parserHarness) line(dest string) string {
	h.seq++

	return fmt.Sprintf("%s from tcp:%s:%d accepted tcp:%s:443 [inbound-1 -> proxy]\n",
		time.Now().Format("2006/01/02 15:04:05"), testClientIP, 10000+h.seq, dest)
}

// Appends n requests to a domain and n requests to a bare IP.
func (h *parserHarness) appendBatch(n int) {
	h.t.Helper()

	var buf strings.Builder
	for range n {
		buf.WriteString(h.line(testDomain))
		buf.WriteString(h.line(testDestIP))
	}

	file, err := os.OpenFile(h.logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		h.t.Fatalf("open log for append: %v", err)
	}

	if _, err := file.WriteString(buf.String()); err != nil {
		h.t.Fatalf("append to log: %v", err)
	}
	if err := file.Close(); err != nil {
		h.t.Fatalf("close log: %v", err)
	}
}

// Moves the log aside and makes a fresh empty one, like hourly logrotate does.
func (h *parserHarness) rotate(suffix string) {
	h.t.Helper()

	if err := os.Rename(h.logPath, h.logPath+suffix); err != nil {
		h.t.Fatalf("rotate log: %v", err)
	}
	if err := os.WriteFile(h.logPath, nil, 0o644); err != nil {
		h.t.Fatalf("create new log: %v", err)
	}
}

// Empties the log in place, like copytruncate does.
func (h *parserHarness) truncate() {
	h.t.Helper()

	if err := os.Truncate(h.logPath, 0); err != nil {
		h.t.Fatalf("truncate log: %v", err)
	}
}

func (h *parserHarness) parse() {
	h.t.Helper()

	if err := h.parser.parseLogFile(); err != nil {
		h.t.Fatalf("parseLogFile: %v", err)
	}
}

// Same expiry the parse loop runs, but with a cutoff past every line written so
// far, so the whole window ages out at once and the test never has to wait.
func (h *parserHarness) expireEverything() {
	cutoff := time.Now().Add(time.Hour)
	h.parser.expireWindowed(cutoff)
	h.parser.expireStaleCounts(cutoff)
	h.parser.capTotals()
}

// Walks one log file through appends, both kinds of rotation, truncation and a
// full window expiry. After every step the totals must match the exact number of
// lines written and must not have gone down.
func TestParserTotalsOnlyRiseAcrossRotation(t *testing.T) {
	t.Parallel()

	h := newParserHarness(t, 5*time.Minute)

	// One ordered run through the life of a single log file: each step builds on
	// the last, so no t.Parallel() in here.
	steps := []struct {
		name       string
		act        func()
		wantDomain int64
		wantIP     int64
		wantASN    int64
	}{
		{
			name:       "first append",
			act:        func() { h.appendBatch(50); h.parse() },
			wantDomain: 50, wantIP: 50, wantASN: 100,
		},
		{
			name:       "second append",
			act:        func() { h.appendBatch(20); h.parse() },
			wantDomain: 70, wantIP: 70, wantASN: 140,
		},
		{
			name:       "rotate away and keep appending",
			act:        func() { h.rotate(".1"); h.appendBatch(30); h.parse() },
			wantDomain: 100, wantIP: 100, wantASN: 200,
		},
		{
			name:       "whole time window ages out",
			act:        h.expireEverything,
			wantDomain: 100, wantIP: 100, wantASN: 200,
		},
		{
			name:       "append after expiry",
			act:        func() { h.appendBatch(15); h.parse() },
			wantDomain: 115, wantIP: 115, wantASN: 230,
		},
		{
			name:       "parse again with nothing new",
			act:        h.parse,
			wantDomain: 115, wantIP: 115, wantASN: 230,
		},
		{
			name:       "truncated in place and refilled",
			act:        func() { h.truncate(); h.appendBatch(10); h.parse() },
			wantDomain: 125, wantIP: 125, wantASN: 250,
		},
		{
			name:       "rotate again while idle",
			act:        func() { h.rotate(".2"); h.parse() },
			wantDomain: 125, wantIP: 125, wantASN: 250,
		},
		{
			name:       "append to the fresh file",
			act:        func() { h.appendBatch(10); h.parse() },
			wantDomain: 135, wantIP: 135, wantASN: 270,
		},
	}

	var prevDomain, prevIP, prevASN int64
	for _, tt := range steps {
		t.Run(tt.name, func(t *testing.T) {
			tt.act()

			domain := h.parser.GetDomainTotals()[testDomain]
			ip := h.parser.GetIPTotals()[testDestIP]
			asn := h.parser.GetASNTotals()[unknownASNKey]

			if domain < prevDomain || ip < prevIP || asn < prevASN {
				t.Errorf("total decreased: domain %d->%d, ip %d->%d, asn %d->%d",
					prevDomain, domain, prevIP, ip, prevASN, asn)
			}
			if domain != tt.wantDomain {
				t.Errorf("domain total = %d, want %d", domain, tt.wantDomain)
			}
			if ip != tt.wantIP {
				t.Errorf("ip total = %d, want %d", ip, tt.wantIP)
			}
			if asn != tt.wantASN {
				t.Errorf("asn total = %d, want %d", asn, tt.wantASN)
			}

			prevDomain, prevIP, prevASN = domain, ip, asn
		})
	}
}

// Which of the two values an expiry is allowed to reset. The windowed count
// dropping to zero is what made increase() unusable when it was all we exported.
func TestParserWindowExpiryKeepsTotals(t *testing.T) {
	t.Parallel()

	h := newParserHarness(t, 5*time.Minute)
	h.appendBatch(25)
	h.parse()

	if got := h.parser.GetDomainCounts()[testDomain]; got != 25 {
		t.Fatalf("windowed count before expiry = %d, want 25", got)
	}
	if got := h.parser.GetDomainTotals()[testDomain]; got != 25 {
		t.Fatalf("total before expiry = %d, want 25", got)
	}

	h.expireEverything()

	if _, ok := h.parser.GetDomainCounts()[testDomain]; ok {
		t.Error("windowed count survived expiry, expected the key to be dropped")
	}
	if got := h.parser.GetDomainTotals()[testDomain]; got != 25 {
		t.Errorf("total after expiry = %d, want 25", got)
	}

	h.appendBatch(5)
	h.parse()

	if got := h.parser.GetDomainCounts()[testDomain]; got != 5 {
		t.Errorf("windowed count after expiry = %d, want 5 (window restarted)", got)
	}
	if got := h.parser.GetDomainTotals()[testDomain]; got != 30 {
		t.Errorf("total after expiry = %d, want 30 (carried across the expiry)", got)
	}
}

func TestFileIdentitySameFileAs(t *testing.T) {
	t.Parallel()

	prev := fileIdentity{dev: 1, ino: 2, fingerprint: 100, hasPrint: true, known: true}

	tests := []struct {
		name    string
		current fileIdentity
		want    bool
	}{
		{
			name:    "unchanged file",
			current: prev,
			want:    true,
		},
		{
			name:    "rotated to a new inode",
			current: fileIdentity{dev: 1, ino: 3, fingerprint: 100, hasPrint: true, known: true},
			want:    false,
		},
		{
			name:    "same inode number on another device",
			current: fileIdentity{dev: 2, ino: 2, fingerprint: 100, hasPrint: true, known: true},
			want:    false,
		},
		{
			name:    "inode reused by a replacement file",
			current: fileIdentity{dev: 1, ino: 2, fingerprint: 999, hasPrint: true, known: true},
			want:    false,
		},
		{
			name:    "still too short to fingerprint",
			current: fileIdentity{dev: 1, ino: 2, known: true},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.current.sameFileAs(prev); got != tt.want {
				t.Errorf("sameFileAs = %v, want %v", got, tt.want)
			}
		})
	}
}

// The hash must not change while the log is being appended to, or every pass
// would think a growing file was a new one.
func TestFingerprintFileStableWhileGrowing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", fingerprintSize-1)), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	fingerprint := func() (uint64, bool) {
		t.Helper()

		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open log: %v", err)
		}
		defer func() { _ = file.Close() }()

		stat, err := file.Stat()
		if err != nil {
			t.Fatalf("stat log: %v", err)
		}

		return fingerprintFile(file, stat.Size())
	}

	grow := func(n int) {
		t.Helper()

		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("open log for append: %v", err)
		}

		if _, err := file.WriteString(strings.Repeat("b", n)); err != nil {
			t.Fatalf("append to log: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close log: %v", err)
		}
	}

	if _, ok := fingerprint(); ok {
		t.Errorf("file shorter than %d bytes reported a fingerprint", fingerprintSize)
	}

	grow(1)
	first, ok := fingerprint()
	if !ok {
		t.Fatalf("file of exactly %d bytes reported no fingerprint", fingerprintSize)
	}

	grow(4096)
	second, ok := fingerprint()
	if !ok {
		t.Fatal("grown file reported no fingerprint")
	}
	if first != second {
		t.Errorf("fingerprint changed while growing: %d then %d", first, second)
	}
}

func TestCapCumulativeUnderLimitKeepsEverything(t *testing.T) {
	t.Parallel()

	totals := map[string]int64{"a": 1, "b": 2}
	capCumulative(totals, map[string]*windowedCount{})

	if len(totals) != 2 {
		t.Errorf("totals size = %d, want 2", len(totals))
	}
}

// Eviction drops the lowest totals, which is exactly where a newly busy target
// sits. Dropping one would restart its counter from zero and read as a reset.
func TestCapCumulativeKeepsActiveKeys(t *testing.T) {
	t.Parallel()

	const activeKeys = 5

	totals := make(map[string]int64, SafetyMaxKeys+activeKeys+5)
	active := make(map[string]*windowedCount, activeKeys)

	for i := range SafetyMaxKeys + 5 {
		totals[fmt.Sprintf("idle-%d", i)] = int64(1000 + i)
	}
	for i := range activeKeys {
		key := fmt.Sprintf("active-%d", i)
		totals[key] = 1
		active[key] = &windowedCount{count: 1}
	}

	capCumulative(totals, active)

	if len(totals) > SafetyMaxKeys {
		t.Errorf("totals size = %d, want at most %d", len(totals), SafetyMaxKeys)
	}
	for key := range active {
		if _, ok := totals[key]; !ok {
			t.Errorf("active key %q was evicted, its total would restart from zero", key)
		}
	}
}
