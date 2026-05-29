package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCertSitesDedup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "site-configs.conf")
	os.WriteFile(cfg, []byte(`# comment
app.example.com      192.168.0.10:8080    app.example.com
[L]intra.example.com 192.168.0.11:3000    intra.example.com
api.example.com      s:192.168.0.12:8443  app.example.com
nocert.example.com   192.168.0.13:80
`), 0o644)
	c := &proxyConfig{configFile: cfg}
	sites := c.certSites()
	// app.example.com (dedup with api line), intra.example.com (L stripped). nocert skipped.
	if len(sites) != 2 {
		t.Fatalf("expected 2 deduped certs, got %d: %+v", len(sites), sites)
	}
	if sites[0].certName != "app.example.com" || sites[0].domain != "app.example.com" {
		t.Errorf("site0 wrong: %+v", sites[0])
	}
	if sites[1].certName != "intra.example.com" || sites[1].domain != "intra.example.com" {
		t.Errorf("site1 should have [L] stripped: %+v", sites[1])
	}
}

func TestDaysUntilExpiry(t *testing.T) {
	dir := t.TempDir()
	certsSub := filepath.Join(dir, "certs")
	name := "test.example.com"
	cdir := filepath.Join(certsSub, name)
	os.MkdirAll(cdir, 0o755)
	// Generate a self-signed cert valid 10 days via openssl.
	crt := filepath.Join(cdir, name+".crt")
	key := filepath.Join(cdir, name+".key")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", crt, "-days", "10", "-subj", "/CN="+name)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl unavailable: %v %s", err, out)
	}
	iss := &issuer{certsSub: certsSub}
	days, ok := iss.daysUntilExpiry(name)
	if !ok {
		t.Fatal("expected to parse cert")
	}
	if days < 8 || days > 10 {
		t.Errorf("expected ~10 days, got %d", days)
	}
	// Missing cert → (0,false)
	if _, ok := iss.daysUntilExpiry("does-not-exist"); ok {
		t.Error("expected missing cert to report ok=false")
	}
}
