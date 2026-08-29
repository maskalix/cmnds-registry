package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWildcardCertsRoundTrip(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}

	if got := c.loadWildcardCerts(); got != nil {
		t.Fatalf("expected nil before any registration, got %v", got)
	}

	if err := c.registerWildcardCert("lnln.eu", "lnln.eu-wildcard"); err != nil {
		t.Fatal(err)
	}
	if err := c.registerWildcardCert("nunissum.eu", "nunissum.eu-wildcard"); err != nil {
		t.Fatal(err)
	}
	// Registering the same cert name again must not duplicate the entry.
	if err := c.registerWildcardCert("lnln.eu", "lnln.eu-wildcard"); err != nil {
		t.Fatal(err)
	}

	got := c.loadWildcardCerts()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	byDomain := map[string]string{}
	for _, w := range got {
		byDomain[w.Domain] = w.Cert
	}
	if byDomain["lnln.eu"] != "lnln.eu-wildcard" || byDomain["nunissum.eu"] != "nunissum.eu-wildcard" {
		t.Errorf("unexpected contents: %+v", got)
	}
}

func TestCertSitesIncludesWildcards(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "sites.conf")
	if err := os.WriteFile(cfgFile, []byte("==lnln.eu <-w>\napi 10.0.0.1:8080\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &proxyConfig{mainFolder: dir, configFile: cfgFile}
	if err := c.registerWildcardCert("lnln.eu", "lnln.eu-wildcard"); err != nil {
		t.Fatal(err)
	}

	sites := c.certSites()
	var found *certSite
	for i := range sites {
		if sites[i].certName == "lnln.eu-wildcard" {
			found = &sites[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a wildcard cert job among certSites(), got %+v", sites)
	}
	want := []string{"lnln.eu", "*.lnln.eu"}
	if len(found.sans) != 2 || found.sans[0] != want[0] || found.sans[1] != want[1] {
		t.Errorf("sans = %v, want %v", found.sans, want)
	}
}
