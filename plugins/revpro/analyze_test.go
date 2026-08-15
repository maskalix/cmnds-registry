package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeGeneratedDetectsMissingAndStale(t *testing.T) {
	c := writeSites(t, `==example.tld
@   10.0.0.1:8080
`)
	s := c.mustSites()[0]

	if n := c.analyzeGenerated(s); n != 1 {
		t.Errorf("expected 1 problem for a never-generated config, got %d", n)
	}

	c.generateOne(s)
	if n := c.analyzeGenerated(s); n != 0 {
		t.Errorf("expected 0 problems right after generate, got %d", n)
	}

	// Simulate drift: sites.conf changed but conf/ wasn't regenerated.
	confFile := filepath.Join(c.confDir, s.fqdn+".conf")
	if err := os.WriteFile(confFile, []byte("stale content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := c.analyzeGenerated(s); n != 1 {
		t.Errorf("expected 1 problem for stale config, got %d", n)
	}
}

func TestAnalyzeUpstreamUnreachable(t *testing.T) {
	// Port 0 on loopback with no listener; expect a fast, clean failure count.
	if n := analyzeUpstream("127.0.0.1:1"); n != 1 {
		t.Errorf("expected unreachable upstream to count as 1 problem, got %d", n)
	}
}

func TestTrimNetErr(t *testing.T) {
	err := errors.New(`dial tcp 127.0.0.1:1: connect: connection refused`)
	if got := trimNetErr(err); got != "connection refused" {
		t.Errorf("trimNetErr = %q, want %q", got, "connection refused")
	}
	plain := errors.New("boom")
	if got := trimNetErr(plain); got != "boom" {
		t.Errorf("trimNetErr passthrough = %q, want %q", got, "boom")
	}
}
