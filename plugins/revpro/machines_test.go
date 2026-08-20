package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMachinesText(t *testing.T) {
	ms, err := parseMachinesText(`
# comment
A        192.168.2.20
AVA      192.168.2.30    # trailing comment
AVA01    192.168.2.31
N        node100.lan
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 4 {
		t.Fatalf("expected 4 machines, got %d: %+v", len(ms), ms)
	}
	if ms[0].slug != "A" || ms[0].host != "192.168.2.20" {
		t.Errorf("first machine parsed as %+v", ms[0])
	}
	if ms[3].host != "node100.lan" {
		t.Errorf("hostname hosts should be allowed, got %+v", ms[3])
	}
}

func TestParseMachinesTextErrors(t *testing.T) {
	for _, bad := range []string{
		"A\n",                    // missing host
		"A 1.2.3.4 extra\n",      // too many fields
		"TOOLONG123 1.2.3.4\n",   // slug over 8 chars
		"1A 1.2.3.4\n",           // starts with a digit
		"A-B 1.2.3.4\n",          // non-alphanumeric slug
		"A 1.2.3.4:80\n",         // host must not carry a port
		"A -evil\n",              // flag-like host
		"A 1.2.3.4\na 5.6.7.8\n", // duplicate (case-insensitive)
	} {
		if _, err := parseMachinesText(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestResolveMachineAndTarget(t *testing.T) {
	slugs := map[string]string{"A": "192.168.2.20", "AVA01": "192.168.2.31"}

	if got := resolveMachine(slugs, "a"); got != "192.168.2.20" {
		t.Errorf("slug lookup should be case-insensitive, got %q", got)
	}
	if got := resolveMachine(slugs, "10.0.0.9"); got != "10.0.0.9" {
		t.Errorf("non-slug must pass through, got %q", got)
	}
	if got := resolveTarget(slugs, "AVA01:8080"); got != "192.168.2.31:8080" {
		t.Errorf("resolveTarget = %q", got)
	}
	if got := resolveTarget(slugs, "myhost:8080"); got != "myhost:8080" {
		t.Errorf("unknown host must pass through, got %q", got)
	}
}

func TestParseSitesResolvesSlugs(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "machines.conf"),
		[]byte("A     192.168.2.20\nN     192.168.2.100\n"), 0o644)
	conf := filepath.Join(dir, "sites.conf")
	os.WriteFile(conf, []byte(`
==example.tld
@        A:8443
app      n:8080
plain    10.0.0.5:9000
`), 0o644)

	c := &proxyConfig{mainFolder: dir, configFile: conf}
	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	if sites[0].target != "192.168.2.20:8443" || sites[0].rawTarget != "A:8443" {
		t.Errorf("apex resolved as %q (raw %q)", sites[0].target, sites[0].rawTarget)
	}
	if sites[1].target != "192.168.2.100:8080" {
		t.Errorf("lowercase slug should resolve, got %q", sites[1].target)
	}
	if sites[2].target != "10.0.0.5:9000" || sites[2].rawTarget != "10.0.0.5:9000" {
		t.Errorf("plain target must pass through, got %q (raw %q)", sites[2].target, sites[2].rawTarget)
	}

	// usedPortsByMachine must key by the RESOLVED host.
	used, err := c.usedPortsByMachine()
	if err != nil {
		t.Fatal(err)
	}
	if len(used["192.168.2.20"]) != 1 || used["A"] != nil {
		t.Errorf("usage should be keyed by resolved host: %+v", used)
	}

	// The rendered nginx config must carry the resolved host, never the slug.
	rendered := c.renderSite(sites[0])
	if !strings.Contains(rendered, "set $server 192.168.2.20;") || strings.Contains(rendered, "set $server A;") {
		t.Errorf("renderSite must use the resolved host:\n%s", rendered)
	}
}

func TestParseSitesBrokenMachinesConfFails(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "machines.conf"), []byte("not a valid line at all here\n"), 0o644)
	conf := filepath.Join(dir, "sites.conf")
	os.WriteFile(conf, []byte("==example.tld\n@ 1.2.3.4:80\n"), 0o644)

	c := &proxyConfig{mainFolder: dir, configFile: conf}
	if _, err := c.parseSites(); err == nil {
		t.Error("a broken machines.conf must fail loudly, not silently skip resolution")
	}
}

func TestParseGroupHeaderMachine(t *testing.T) {
	cases := []struct {
		in      string
		domain  string
		machine string
		https   bool
	}{
		{"==example.tld", "example.tld", "", false},
		{"==example.tld [A]", "example.tld", "A", false},
		{"==example.tld [A] <+s>", "example.tld", "A", true},
		{"==example.tld <+s> [AVA01]", "example.tld", "AVA01", true},
		{"==example.tld [192.168.2.30]", "example.tld", "192.168.2.30", false},
	}
	for _, tc := range cases {
		domain, gi := parseGroupHeader(tc.in)
		if domain != tc.domain || gi.machine != tc.machine || gi.flags.https != tc.https {
			t.Errorf("parseGroupHeader(%q) = %q, %+v; want %q machine=%q https=%v",
				tc.in, domain, gi, tc.domain, tc.machine, tc.https)
		}
	}
}

func TestPortOnlyTarget(t *testing.T) {
	for in, want := range map[string]string{
		"8080": "8080", ":8080": "8080", "443": "443",
	} {
		if p, okp := portOnlyTarget(in); !okp || p != want {
			t.Errorf("portOnlyTarget(%q) = %q,%v; want %q,true", in, p, okp, want)
		}
	}
	for _, in := range []string{"1.2.3.4:80", "A:80", "host", "70000", ":0", ":"} {
		if _, okp := portOnlyTarget(in); okp {
			t.Errorf("portOnlyTarget(%q) should be false", in)
		}
	}
}

func TestParseSitesGroupMachine(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "machines.conf"), []byte("A     192.168.2.20\n"), 0o644)
	conf := filepath.Join(dir, "sites.conf")
	os.WriteFile(conf, []byte(`
==apps.tld [A] <+s>
@        8443
grafana  :3000
backup   10.0.0.9:9000
`), 0o644)

	c := &proxyConfig{mainFolder: dir, configFile: conf}
	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	if sites[0].target != "192.168.2.20:8443" || sites[0].rawTarget != "8443" {
		t.Errorf("bare port: got %q (raw %q)", sites[0].target, sites[0].rawTarget)
	}
	if !sites[0].flags.https {
		t.Error("group flags must still apply alongside [machine]")
	}
	if sites[1].target != "192.168.2.20:3000" {
		t.Errorf(":port form: got %q", sites[1].target)
	}
	if sites[2].target != "10.0.0.9:9000" {
		t.Errorf("full target must override the group machine, got %q", sites[2].target)
	}

	// A port-only line without a group [machine] must fail loudly.
	os.WriteFile(conf, []byte("==plain.tld\n@ 8443\n"), 0o644)
	if _, err := c.parseSites(); err == nil {
		t.Error("port-only target without a group machine must be an error")
	}

	// A group machine carrying a port is malformed.
	os.WriteFile(conf, []byte("==bad.tld [A:80]\n@ 8443\n"), 0o644)
	if _, err := c.parseSites(); err == nil {
		t.Error("group machine with a port must be an error")
	}
}

func TestMachinesSetAndRm(t *testing.T) {
	dir := t.TempDir()
	c := &proxyConfig{mainFolder: dir, configFile: filepath.Join(dir, "sites.conf")}

	c.machinesSet("A", "192.168.2.20")
	c.machinesSet("N", "192.168.2.100")
	c.machinesSet("a", "192.168.2.99") // update via different case

	slugs, err := c.machineSlugs()
	if err != nil {
		t.Fatal(err)
	}
	if slugs["A"] != "192.168.2.99" {
		t.Errorf("set should update in place, got %q", slugs["A"])
	}
	if slugs["N"] != "192.168.2.100" {
		t.Errorf("N = %q", slugs["N"])
	}

	c.machinesRm("n")
	slugs, _ = c.machineSlugs()
	if _, still := slugs["N"]; still {
		t.Error("rm should remove the slug (case-insensitive)")
	}
	if slugs["A"] != "192.168.2.99" {
		t.Error("rm must not touch other slugs")
	}
}
