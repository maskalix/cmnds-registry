package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// writeSites drops a sites.conf into a temp dir and returns a proxyConfig.
func writeSites(t *testing.T, body string) *proxyConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sites.conf")
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return &proxyConfig{
		configFile: cfg,
		confDir:    filepath.Join(dir, "conf"),
		logDir:     filepath.Join(dir, "logs"),
		certsSub:   filepath.Join(dir, "certs"),
	}
}

func TestParseSitesFlagResolution(t *testing.T) {
	c := writeSites(t, `==example.tld <+a +s>
@        10.0.0.1:8443
api      10.0.0.2:8443    -a            # auth off
status   10.0.0.3:8080    -s -a -w      # http, no auth, no www
admin    10.0.0.4:8443    --cert="admin-cert"

==internal.tld <+l>
@        192.168.1.10:3000    -w
dash     192.168.1.11:3000
`)
	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 6 {
		t.Fatalf("expected 6 sites, got %d", len(sites))
	}

	by := map[string]site{}
	for _, s := range sites {
		by[s.fqdn] = s
	}

	// apex inherits group +a +s, www on by default
	apex := by["example.tld"]
	if !apex.flags.auth || !apex.flags.https || !apex.flags.www {
		t.Errorf("apex flags wrong: %+v", apex.flags)
	}
	if apex.certName != "example.tld" {
		t.Errorf("apex cert should default to domain, got %q", apex.certName)
	}
	// api: auth off (line -a), https on (group), www on (default)
	if api := by["api.example.tld"]; api.flags.auth || !api.flags.https || !api.flags.www {
		t.Errorf("api flags wrong: %+v", api.flags)
	}
	// status: https off, auth off, www off
	if st := by["status.example.tld"]; st.flags.https || st.flags.auth || st.flags.www {
		t.Errorf("status flags wrong: %+v", st.flags)
	}
	// admin: explicit cert name
	if ad := by["admin.example.tld"]; ad.certName != "admin-cert" {
		t.Errorf("admin cert should be admin-cert, got %q", ad.certName)
	}
	// internal group: local on, apex has www off
	if in := by["internal.tld"]; !in.flags.local || in.flags.www {
		t.Errorf("internal apex flags wrong: %+v", in.flags)
	}
	// dash inherits +l, www default on
	if d := by["dash.internal.tld"]; !d.flags.local || !d.flags.www {
		t.Errorf("dash flags wrong: %+v", d.flags)
	}
}

func TestCertSitesSANs(t *testing.T) {
	c := writeSites(t, `==example.tld <+s>
@      10.0.0.1:8443
api    10.0.0.2:8443    -w        # no www SAN
shared 10.0.0.3:8443    --cert="example.tld"   # rolls into apex cert
`)
	certs := c.certSites()
	by := map[string]certSite{}
	for _, cs := range certs {
		by[cs.certName] = cs
	}
	// apex + shared both use cert "example.tld" → SANs aggregate
	apex := by["example.tld"]
	want := map[string]bool{
		"example.tld":            true,
		"www.example.tld":        true,
		"shared.example.tld":     true,
		"www.shared.example.tld": true,
	}
	for _, s := range apex.sans {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Errorf("example.tld SANs missing %v (got %v)", want, apex.sans)
	}
	// api has its own cert, www off → only api.example.tld
	api := by["api.example.tld"]
	if len(api.sans) != 1 || api.sans[0] != "api.example.tld" {
		t.Errorf("api SANs wrong: %v", api.sans)
	}
}

func TestStripComment(t *testing.T) {
	cases := map[string]string{
		`api 1.2.3.4 -a # comment`:       `api 1.2.3.4 -a `,
		`admin 1.2.3.4 --cert="a#b" # x`: `admin 1.2.3.4 --cert="a#b" `,
		`# whole line`:                   ``,
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDaysUntilExpiry(t *testing.T) {
	dir := t.TempDir()
	certsSub := filepath.Join(dir, "certs")
	name := "test.example.com"
	cdir := filepath.Join(certsSub, name)
	os.MkdirAll(cdir, 0o755)
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
	if _, ok := iss.daysUntilExpiry("does-not-exist"); ok {
		t.Error("expected missing cert to report ok=false")
	}
}

func TestConvertLegacy(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "site-configs.conf")
	os.WriteFile(legacy, []byte(`# legacy
example.tld          192.168.0.10:8080    example.tld
[L]intra.example.tld 192.168.0.11:3000    intra.example.tld
auth.example.tld     a:s:192.168.0.12:9000 auth.example.tld
`), 0o644)
	c := &proxyConfig{
		configFile:       filepath.Join(dir, "sites.conf"),
		legacyConfigFile: legacy,
	}
	c.convertCmd()

	out, err := os.ReadFile(c.configFile)
	if err != nil {
		t.Fatal(err)
	}
	sites, err := c.parseSites()
	if err != nil {
		t.Fatalf("converted file does not parse: %v\n%s", err, out)
	}
	by := map[string]site{}
	for _, s := range sites {
		by[s.fqdn] = s
	}
	if in := by["intra.example.tld"]; !in.flags.local {
		t.Errorf("intra should be local-only after convert: %+v", in.flags)
	}
	if a := by["auth.example.tld"]; !a.flags.auth || !a.flags.https {
		t.Errorf("auth should have auth+https after convert: %+v", a.flags)
	}
	if _, err := os.Stat(legacy + ".bak"); err != nil {
		t.Errorf("expected backup file: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("expected legacy file to be renamed away")
	}
}
