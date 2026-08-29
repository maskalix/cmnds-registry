package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestPurgeContentsKeepsDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "conf")
	sub := filepath.Join(target, "sub")
	os.MkdirAll(sub, 0o755)
	os.WriteFile(filepath.Join(target, "a.conf"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(sub, "b.conf"), []byte("y"), 0o644)

	// Record identity so we can prove neither dir was deleted and recreated —
	// a recreated dir would orphan a docker bind mount pinned to the old inode
	// until the container restarts.
	beforeTarget, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	beforeSub, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}

	if err := purgeContents(target); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatalf("dir should still exist: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "sub" {
		t.Fatalf("expected only the (now-empty) 'sub' subdir to remain, got %v", entries)
	}
	subEntries, err := os.ReadDir(sub)
	if err != nil {
		t.Fatalf("sub dir should still exist: %v", err)
	}
	if len(subEntries) != 0 {
		t.Errorf("expected sub dir emptied of files, got %d entries", len(subEntries))
	}

	afterTarget, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(beforeTarget, afterTarget) {
		t.Error("target directory was recreated, expected same inode preserved")
	}
	afterSub, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(beforeSub, afterSub) {
		t.Error("nested 'sub' directory was recreated, expected same inode preserved (this is the bind-mount bug)")
	}
}

// TestPurgeContentsPreservesBindMountedSubdirs reproduces 'revpro init setup'
// re-running purgeContents over an existing $REVPRO whose conf/, manconf/,
// misc/ and logs/ children are each bind-mounted separately into the
// reverseproxy container (see templates/docker-compose.yml). Those
// subdirectory inodes must survive the purge, or the container's mounts go
// stale until it's restarted.
func TestPurgeContentsPreservesBindMountedSubdirs(t *testing.T) {
	main := t.TempDir()
	subdirs := []string{"conf", "manconf", "misc", "logs"}
	before := map[string]os.FileInfo{}
	for _, d := range subdirs {
		path := filepath.Join(main, d)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "x.conf"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[d] = fi
	}
	os.WriteFile(filepath.Join(main, "sites.conf"), []byte("stuff"), 0o644)

	if err := purgeContents(main); err != nil {
		t.Fatal(err)
	}

	for _, d := range subdirs {
		path := filepath.Join(main, d)
		after, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s should still exist after purge: %v", d, err)
		}
		if !os.SameFile(before[d], after) {
			t.Errorf("%s was deleted and recreated — a bind mount on it would now be stale until container restart", d)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Errorf("%s should be emptied of files, got entries=%v err=%v", d, entries, err)
		}
	}
	if _, err := os.Stat(filepath.Join(main, "sites.conf")); !os.IsNotExist(err) {
		t.Error("sites.conf should have been removed by the purge")
	}
}

func TestPurgeContentsCreatesMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "logs")
	if err := purgeContents(target); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Errorf("expected dir to be created: %v", err)
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

func TestConvertLegacyHoistsGroupCert(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "site-configs.conf")
	// Four sites under lnln.eu: three share the domain-wide "lnln.eu" cert,
	// one (custom.lnln.eu) has its own dedicated cert.
	os.WriteFile(legacy, []byte(`ai.lnln.eu        192.168.2.20:3210    lnln.eu
picshr.lnln.eu    192.168.2.20:8431    lnln.eu
share.lnln.eu     192.168.2.20:9221    lnln.eu
custom.lnln.eu    192.168.2.20:9999    custom-cert
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
	text := string(out)

	if !strings.Contains(text, `==lnln.eu <-w> --cert="lnln.eu"`) {
		t.Errorf("expected group header to hoist the shared cert, got:\n%s", text)
	}
	if strings.Contains(text, `ai           `+"192.168.2.20:3210"+`          --cert`) {
		t.Errorf("line matching the hoisted group cert should not repeat --cert=:\n%s", text)
	}
	if !strings.Contains(text, `--cert="custom-cert"`) {
		t.Errorf("expected the outlier line to keep its own --cert=, got:\n%s", text)
	}

	// And it should round-trip: parsing the converted file resolves every
	// site's cert correctly, whether inherited from the group or its own.
	sites, err := c.parseSites()
	if err != nil {
		t.Fatalf("converted file does not parse: %v\n%s", err, text)
	}
	by := map[string]site{}
	for _, s := range sites {
		by[s.fqdn] = s
	}
	for _, fqdn := range []string{"ai.lnln.eu", "picshr.lnln.eu", "share.lnln.eu"} {
		if got := by[fqdn].certName; got != "lnln.eu" {
			t.Errorf("%s: expected inherited cert \"lnln.eu\", got %q", fqdn, got)
		}
	}
	if got := by["custom.lnln.eu"].certName; got != "custom-cert" {
		t.Errorf("custom.lnln.eu: expected own cert \"custom-cert\", got %q", got)
	}
}

// Regression: a saved account.json must be loaded onto the user BEFORE the lego
// client is built, so the KID (reg.Location) is present. This checks the load
// step restores Location; the ordering itself is enforced in connect().
func TestLoadSavedAccount(t *testing.T) {
	dir := t.TempDir()
	iss := &issuer{acmeDir: dir, email: "x@y.z"}
	iss.user = &acmeUser{email: "x@y.z"}

	// No file yet → false.
	if iss.loadSavedAccount() {
		t.Fatal("expected false with no account.json")
	}
	// Write an account with a Location (the KID source).
	os.WriteFile(iss.accountRegPath(),
		[]byte(`{"accountURL":"https://acme.example/acct/123","status":"valid"}`), 0o600)
	if !iss.loadSavedAccount() {
		t.Fatal("expected true after writing account.json")
	}
	if iss.user.GetRegistration() == nil || iss.user.GetRegistration().Location != "https://acme.example/acct/123" {
		t.Fatalf("KID/location not restored: %+v", iss.user.reg)
	}
	// A registration without Location must be treated as unusable.
	os.WriteFile(iss.accountRegPath(), []byte(`{"status":"valid"}`), 0o600)
	iss.user.reg = nil
	if iss.loadSavedAccount() {
		t.Fatal("expected false when Location empty")
	}
}
