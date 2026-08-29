package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSiteMetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := &proxyConfig{mainFolder: dir}

	m, err := c.loadSiteMeta()
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected empty map for missing file, got %+v", m)
	}

	if err := c.setSiteMeta("ai.lnln.eu", siteMeta{
		Name: "AI Dashboard",
		Tags: []string{"internal", "AI", "internal"}, // dupe + case variant
		Note: "  runs the local model server  ",
	}); err != nil {
		t.Fatalf("setSiteMeta: %v", err)
	}

	m, err = c.loadSiteMeta()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := m["ai.lnln.eu"]
	if got.Name != "AI Dashboard" {
		t.Errorf("name = %q", got.Name)
	}
	if got.Note != "runs the local model server" {
		t.Errorf("note not trimmed: %q", got.Note)
	}
	want := []string{"AI", "internal"} // deduped case-insensitively, sorted
	if !reflect.DeepEqual(got.Tags, want) {
		t.Errorf("tags = %v, want %v", got.Tags, want)
	}
}

func TestSiteMetaClearingRemovesEntry(t *testing.T) {
	dir := t.TempDir()
	c := &proxyConfig{mainFolder: dir}

	if err := c.setSiteMeta("x.tld", siteMeta{Name: "X"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.siteMetaFile()); err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}

	// Clearing the only field back out should drop the entry entirely.
	if err := c.setSiteMeta("x.tld", siteMeta{}); err != nil {
		t.Fatal(err)
	}
	m, err := c.loadSiteMeta()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["x.tld"]; ok {
		t.Errorf("expected entry to be removed once emptied, got %+v", m)
	}
}

func TestNormalizeTags(t *testing.T) {
	got := normalizeTags([]string{" docs ", "Docs", "", "internal", "  "})
	want := []string{"docs", "internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSiteMetaFilePath(t *testing.T) {
	c := &proxyConfig{mainFolder: "/tmp/revpro-test"}
	want := filepath.Join("/tmp/revpro-test", "site-meta.json")
	if got := c.siteMetaFile(); got != want {
		t.Errorf("siteMetaFile() = %q, want %q", got, want)
	}
}
