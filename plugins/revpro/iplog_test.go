package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAccessLine(t *testing.T) {
	line := `203.0.113.9 - - [30/Aug/2026:12:04:08 +0000] "GET / HTTP/2.0" 200 1234 "-" "curl/8.0"`
	ip, ts, ok := parseAccessLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ip != "203.0.113.9" {
		t.Errorf("ip = %q", ip)
	}
	want := time.Date(2026, time.August, 30, 12, 4, 8, 0, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("ts = %v, want %v", ts, want)
	}
}

func TestParseAccessLineGarbageIsSkipped(t *testing.T) {
	if _, _, ok := parseAccessLine("not a log line at all"); ok {
		t.Error("expected ok=false for a line with no parseable IP")
	}
	if _, _, ok := parseAccessLine(""); ok {
		t.Error("expected ok=false for an empty line")
	}
}

func TestIPAccessStatsAggregatesAcrossSites(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.example.tld_access.log",
		`203.0.113.9 - - [30/Aug/2026:12:00:00 +0000] "GET / HTTP/2.0" 200 1 "-" "-"`+"\n"+
			`203.0.113.9 - - [30/Aug/2026:12:00:05 +0000] "GET /x HTTP/2.0" 200 1 "-" "-"`+"\n")
	write("b.example.tld_access.log",
		`203.0.113.9 - - [30/Aug/2026:12:01:00 +0000] "GET / HTTP/2.0" 200 1 "-" "-"`+"\n"+
			`198.51.100.4 - - [30/Aug/2026:11:00:00 +0000] "GET / HTTP/2.0" 404 1 "-" "-"`+"\n")

	c := &proxyConfig{logDir: dir}
	stats, err := c.ipAccessStats(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("expected 2 distinct IPs, got %d: %+v", len(stats), stats)
	}
	// Most-recently-seen first.
	if stats[0].IP != "203.0.113.9" {
		t.Errorf("first row = %s, want 203.0.113.9", stats[0].IP)
	}
	if stats[0].Requests != 3 {
		t.Errorf("203.0.113.9 requests = %d, want 3", stats[0].Requests)
	}
	if len(stats[0].Sites) != 2 {
		t.Errorf("203.0.113.9 sites = %v, want 2 distinct sites", stats[0].Sites)
	}
}

func TestIPAccessStatsMissingLogDirIsNotAnError(t *testing.T) {
	c := &proxyConfig{logDir: filepath.Join(t.TempDir(), "does-not-exist")}
	stats, err := c.ipAccessStats(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 0 {
		t.Errorf("expected no stats, got %v", stats)
	}
}

func TestIPAccessStatsRespectsLimit(t *testing.T) {
	dir := t.TempDir()
	body := ""
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	for i, ip := range ips {
		body += ip + " - - [30/Aug/2026:12:0" + string(rune('0'+i)) + ":00 +0000] \"GET / HTTP/2.0\" 200 1 \"-\" \"-\"\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "s.example.tld_access.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &proxyConfig{logDir: dir}
	stats, err := c.ipAccessStats(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("expected limit=2 to cap the result, got %d", len(stats))
	}
}

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":   true,
		"::1":         true,
		"192.168.1.5": true,
		"10.0.0.1":    true,
		"172.16.0.1":  true,
		"203.0.113.9": false,
		"8.8.8.8":     false,
		"not-an-ip":   true, // unparseable → treated as "don't spend quota on this"
	}
	for ip, want := range cases {
		if got := isPrivateOrLoopback(ip); got != want {
			t.Errorf("isPrivateOrLoopback(%q) = %v, want %v", ip, got, want)
		}
	}
}
