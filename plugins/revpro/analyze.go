// analyze.go — 'revpro analyze [name...]': verifies configured sites (and
// recognized manconf files) actually work, instead of just being present in
// sites.conf. Read-only: it never writes or reloads anything.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// analyzeCmd checks every site in sites.conf plus every recognized manconf
// file, or only the ones named in args (matched against a site's fqdn/cert
// name, or a manconf file's base name).
func (c *proxyConfig) analyzeCmd(args []string) {
	sites := c.mustSites()
	manual := c.manconfFiles()

	if len(args) > 0 {
		want := map[string]bool{}
		for _, a := range args {
			want[a] = true
		}
		var fs []site
		for _, s := range sites {
			if want[s.fqdn] || want[s.certName] {
				fs = append(fs, s)
			}
		}
		var fm []manconfFile
		for _, m := range manual {
			if want[m.name] || want[filepath.Base(m.path)] {
				fm = append(fm, m)
			}
		}
		if len(fs)+len(fm) == 0 {
			fail("no site or manual config matches %v", args)
		}
		sites, manual = fs, fm
	}

	renewDays := defaultRenewDays
	if v := configRead("REVPRO_RENEW_DAYS"); v != "" {
		if n := atoiSafe(v); n > 0 {
			renewDays = n
		}
	}
	probe := &issuer{certsSub: c.certsSub}

	info("Analyzing %d site(s), %d manual config(s)...", len(sites), len(manual))
	fmt.Println("-----------------------")

	problems := 0
	for _, s := range sites {
		fmt.Printf("🔎 %s\n", s.fqdn)
		problems += c.analyzeCert(probe, s.certName, renewDays)
		problems += c.analyzeGenerated(s)
		problems += analyzeUpstream(s.target)
	}

	for _, m := range manual {
		fmt.Printf("🔎 %s (manual)\n", m.name)
		fmt.Printf("   ✓ recognized at %s\n", m.path)
	}

	fmt.Println("-----------------------")
	if err := run("docker", "exec", "-t", "reverseproxy", "nginx", "-t"); err != nil {
		warn("nginx -t failed — see errors above")
		problems++
	} else {
		ok("nginx config test passed")
	}

	if problems > 0 {
		fail("%d problem(s) found", problems)
	}
	ok("All checks passed")
}

// analyzeCert reports (and counts as a problem) a missing cert; an expiring
// one is a warning, not a failure.
func (c *proxyConfig) analyzeCert(probe *issuer, certName string, renewDays int) int {
	days, have := probe.daysUntilExpiry(certName)
	switch {
	case !have:
		fmt.Printf("   ✗ cert %q missing — run 'revpro issue %s'\n", certName, certName)
		return 1
	case days < renewDays:
		fmt.Printf("   ⚠ cert %q expires in %dd — run 'revpro renew'\n", certName, days)
		return 0
	default:
		fmt.Printf("   ✓ cert %q valid (%dd left)\n", certName, days)
		return 0
	}
}

// analyzeGenerated reports a missing or stale (out of sync with sites.conf)
// generated config.
func (c *proxyConfig) analyzeGenerated(s site) int {
	confFile := filepath.Join(c.confDir, s.fqdn+".conf")
	got, err := os.ReadFile(confFile)
	if err != nil {
		fmt.Printf("   ✗ config not generated — run 'revpro generate'\n")
		return 1
	}
	if string(got) != c.renderSite(s) {
		fmt.Printf("   ⚠ config out of date — run 'revpro regenerate'\n")
		return 1
	}
	fmt.Printf("   ✓ config up to date\n")
	return 0
}

// analyzeUpstream reports whether the proxied target accepts TCP connections.
func analyzeUpstream(target string) int {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		fmt.Printf("   ✗ upstream %s unreachable: %v\n", target, trimNetErr(err))
		return 1
	}
	conn.Close()
	fmt.Printf("   ✓ upstream %s reachable\n", target)
	return 0
}

// trimNetErr strips the redundant "dial tcp <target>: " prefix net.DialTimeout
// errors carry, since the target is already printed alongside it.
func trimNetErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}
