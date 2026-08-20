package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePortCategoriesText(t *testing.T) {
	cats, err := parsePortCategoriesText(`
# comment
web        3000-3999
apps       8000-8099, 8200-8299   # two ranges
single     9090
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 3 {
		t.Fatalf("expected 3 categories, got %d: %+v", len(cats), cats)
	}
	if cats[0].name != "web" || cats[0].rangesString() != "3000-3999" {
		t.Errorf("web parsed as %+v", cats[0])
	}
	if cats[1].rangesString() != "8000-8099 8200-8299" {
		t.Errorf("apps ranges = %q", cats[1].rangesString())
	}
	if cats[2].rangesString() != "9090" || !cats[2].contains(9090) || cats[2].contains(9091) {
		t.Errorf("single-port category parsed as %+v", cats[2])
	}
}

func TestParsePortCategoriesTextErrors(t *testing.T) {
	for _, bad := range []string{
		"",                     // no categories
		"web\n",                // missing range
		"web 3999-3000\n",      // inverted
		"web 0-10\n",           // port 0
		"web 1-70000\n",        // out of range
		"web 1-2\nweb 3-4\n",   // duplicate category
		"web three-thousand\n", // not a number
	} {
		if _, err := parsePortCategoriesText(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestSuggestPortSequentialThenGaps(t *testing.T) {
	cat := portCategory{name: "web", ranges: []portRange{{3000, 3005}}}
	used := func(ports ...int) map[int][]string {
		m := map[int][]string{}
		for _, p := range ports {
			m[p] = []string{"x"}
		}
		return m
	}

	// Sequential: next after the highest used port, skipping the gap at 3001.
	port, reason, err := suggestPort(cat, used(3000, 3002), nil, 25)
	if err != nil || port != 3003 {
		t.Fatalf("got %d (%s), err %v; want 3003", port, reason, err)
	}
	if !strings.Contains(reason, "3002") {
		t.Errorf("reason %q should mention the highest used port", reason)
	}

	// Nothing used yet: start of the range.
	if port, _, _ = suggestPort(cat, used(), nil, 25); port != 3000 {
		t.Errorf("empty machine: got %d, want 3000", port)
	}

	// Tail exhausted: wrap around to the first gap.
	port, reason, err = suggestPort(cat, used(3000, 3002, 3003, 3004, 3005), nil, 25)
	if err != nil || port != 3001 {
		t.Fatalf("wrap: got %d, err %v; want 3001", port, err)
	}
	if !strings.Contains(reason, "gap") {
		t.Errorf("wrap reason %q should mention the gap fallback", reason)
	}

	// Fully allocated range.
	if _, _, err = suggestPort(cat, used(3000, 3001, 3002, 3003, 3004, 3005), nil, 25); err == nil {
		t.Error("expected an error when every port is used")
	}
}

func TestSuggestPortSkipsLiveListeners(t *testing.T) {
	cat := portCategory{name: "web", ranges: []portRange{{3000, 3010}}}
	used := map[int][]string{3000: {"a"}}
	listening := map[int]bool{3001: true, 3002: true}

	port, _, err := suggestPort(cat, used, func(p int) bool { return listening[p] }, 25)
	if err != nil || port != 3003 {
		t.Fatalf("got %d, err %v; want 3003 (3001/3002 have listeners)", port, err)
	}

	// Probe budget exhausted → explicit error, not a bad suggestion.
	if _, _, err = suggestPort(cat, used, func(int) bool { return true }, 3); err == nil {
		t.Error("expected an error when the probe budget runs out")
	}
}

func TestSuggestPortMultipleRanges(t *testing.T) {
	cat := portCategory{name: "apps", ranges: []portRange{{8000, 8001}, {8200, 8202}}}
	used := map[int][]string{8000: {"a"}, 8001: {"b"}}
	// Highest used is 8001 — the next candidate lives in the second range.
	port, _, err := suggestPort(cat, used, nil, 25)
	if err != nil || port != 8200 {
		t.Fatalf("got %d, err %v; want 8200", port, err)
	}
}

func TestUsedPortsByMachine(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sites.conf")
	os.WriteFile(conf, []byte(`
==example.tld
@        10.0.0.1:8443
api      10.0.0.2:8443
status   10.0.0.2:8080

==other.tld
app      10.0.0.2:8443
`), 0o644)

	c := &proxyConfig{mainFolder: dir, configFile: conf}
	used, err := c.usedPortsByMachine()
	if err != nil {
		t.Fatal(err)
	}
	if len(used["10.0.0.1"]) != 1 || len(used["10.0.0.2"]) != 2 {
		t.Fatalf("unexpected machine map: %+v", used)
	}
	if got := used["10.0.0.2"][8443]; len(got) != 2 {
		t.Errorf("8443 on 10.0.0.2 should be used by 2 sites, got %v", got)
	}
}

func TestGroupFlags(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sites.conf")
	os.WriteFile(conf, []byte("==plain.tld\n@ 1.2.3.4:80\n==secure.tld <+a +s -w>\n@ 1.2.3.4:443\n"), 0o644)

	c := &proxyConfig{configFile: conf}
	gf, err := c.groupFlags()
	if err != nil {
		t.Fatal(err)
	}
	if f := gf["plain.tld"]; f != defaultFlags() {
		t.Errorf("plain.tld flags = %+v, want defaults", f)
	}
	if f := gf["secure.tld"]; !f.auth || !f.https || f.www {
		t.Errorf("secure.tld flags = %+v, want +a +s -w", f)
	}
}

func TestDiffTokens(t *testing.T) {
	base := defaultFlags() // w on, rest off
	if got := diffTokens(base, base); len(got) != 0 {
		t.Errorf("identical flags should emit no tokens, got %v", got)
	}
	want := siteFlags{auth: true, https: true, www: false}
	got := strings.Join(diffTokens(base, want), " ")
	if got != "+a +s -w" {
		t.Errorf("diffTokens = %q, want \"+a +s -w\"", got)
	}
	// Group already has +a: enabling auth again emits nothing, disabling does.
	base.auth = true
	if got := strings.Join(diffTokens(base, siteFlags{www: true}), " "); got != "-a" {
		t.Errorf("diffTokens vs +a group = %q, want \"-a\"", got)
	}
}
