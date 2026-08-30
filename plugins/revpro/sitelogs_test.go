package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTailLinesMissingFileIsNotAnError(t *testing.T) {
	lines, err := tailLines(filepath.Join(t.TempDir(), "does-not-exist.log"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if lines != nil {
		t.Errorf("expected no lines for a missing file, got %v", lines)
	}
}

func TestTailLinesReturnsLastN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	var b strings.Builder
	for i := 1; i <= 20; i++ {
		b.WriteString("line " + strconv.Itoa(i) + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, err := tailLines(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"line 16", "line 17", "line 18", "line 19", "line 20"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(lines), len(want), lines)
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d = %q, want %q", i, lines[i], w)
		}
	}
}

func TestTailLinesFewerThanNReturnsAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("only\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := tailLines(path, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "only" || lines[1] != "two" {
		t.Errorf("got %v", lines)
	}
}

func TestTailLinesCapsBytesReadFromLargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Write more than maxLogTailBytes so tailLines must seek instead of
	// reading (and discarding) the whole thing.
	line := strings.Repeat("x", 100) + "\n"
	total := 0
	for total < maxLogTailBytes*2 {
		f.WriteString(line)
		total += len(line)
	}
	f.WriteString("THE-LAST-LINE\n")
	f.Close()

	lines, err := tailLines(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 || lines[len(lines)-1] != "THE-LAST-LINE" {
		t.Errorf("expected the last line to be THE-LAST-LINE, got %v", lines)
	}
}

func TestSiteLogPath(t *testing.T) {
	c := &proxyConfig{logDir: "/revpro/logs"}
	access, err := c.siteLogPath("app.example.tld", "access")
	if err != nil || access != "/revpro/logs/app.example.tld_access.log" {
		t.Errorf("access path = %q, err = %v", access, err)
	}
	errLog, err := c.siteLogPath("app.example.tld", "error")
	if err != nil || errLog != "/revpro/logs/app.example.tld_error.log" {
		t.Errorf("error path = %q, err = %v", errLog, err)
	}
	if _, err := c.siteLogPath("app.example.tld", "bogus"); err == nil {
		t.Error("expected an error for an unknown 'which'")
	}
}
