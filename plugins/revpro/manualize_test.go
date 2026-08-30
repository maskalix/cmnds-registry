package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveSiteLineRemovesOnlyThatLine(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := c.removeSiteLine("sct.lnln.eu"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(c.configFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "sct") {
		t.Errorf("expected sct's line to be gone, got:\n%s", text)
	}
	if !strings.Contains(text, "neaty") {
		t.Errorf("expected neaty's line (same block) to survive, got:\n%s", text)
	}
	if !strings.Contains(text, "ad.r") || !strings.Contains(text, "==nunissum.eu") {
		t.Errorf("expected the other blocks untouched, got:\n%s", text)
	}

	_, blocks, err := c.readConfBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if blocks[0].siteCount != 1 {
		t.Errorf("expected block 0 siteCount 1 after removal, got %d", blocks[0].siteCount)
	}
}

func TestRemoveSiteLineApex(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := c.removeSiteLine("nunissum.eu"); err != nil {
		t.Fatal(err)
	}
	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		if s.fqdn == "nunissum.eu" {
			t.Errorf("expected nunissum.eu (apex) to be removed, still present: %+v", s)
		}
	}
}

func TestRemoveSiteLineNoSuchSite(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := c.removeSiteLine("does-not-exist.lnln.eu"); err == nil {
		t.Error("expected an error for an unknown fqdn")
	}
}

func TestConvertSiteToManualMovesLineAndWritesFile(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	c.confDir = filepath.Join(c.mainFolder, "conf")
	if err := os.MkdirAll(c.confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(c.confDir, "sct.lnln.eu.conf")
	if err := os.WriteFile(stale, []byte("server { listen 443; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	edited := "server {\n    listen 443 ssl;\n    server_name sct.lnln.eu;\n}\n"
	path, err := c.convertSiteToManual("sct.lnln.eu", edited)
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != edited {
		t.Errorf("manual config content = %q, want %q", got, edited)
	}
	if path != filepath.Join(c.manconfDir(), "sct.lnln.eu.conf") {
		t.Errorf("unexpected manual config path: %s", path)
	}

	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		if s.fqdn == "sct.lnln.eu" {
			t.Errorf("expected sct.lnln.eu to be removed from sites.conf, still present: %+v", s)
		}
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("expected the stale generated conf file to be removed, stat err = %v", err)
	}
}

func TestConvertSiteToManualAddsTrailingNewline(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	path, err := c.convertSiteToManual("sct.lnln.eu", "server {}")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "server {}\n" {
		t.Errorf("expected a trailing newline to be added, got %q", got)
	}
}

func TestConvertSiteToManualRefusesExistingManualFile(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := os.MkdirAll(c.manconfDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(c.manconfDir(), "sct.lnln.eu.conf")
	if err := os.WriteFile(existing, []byte("# hand-written already\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := c.convertSiteToManual("sct.lnln.eu", "server {}\n"); err == nil {
		t.Fatal("expected an error when a manual config already exists")
	}

	// sites.conf must be untouched — the line stays put since the move
	// never actually happened.
	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range sites {
		if s.fqdn == "sct.lnln.eu" {
			found = true
		}
	}
	if !found {
		t.Error("expected sct.lnln.eu to remain in sites.conf after a refused conversion")
	}

	// And the pre-existing manual file must be left exactly as it was.
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# hand-written already\n" {
		t.Errorf("existing manual config was modified: %q", got)
	}
}
