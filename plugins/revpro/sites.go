// sites.conf — the v2 site configuration format.
//
// Grouped by domain. A group header declares the base domain and optional
// group-level default flags; each indented line is one site (subdomain) under
// it. Flags resolve in three layers: global defaults → group <...> → line.
//
//	==example.tld <+a +s>
//	@        10.0.0.1:8443                    # apex: auth + https (from group)
//	api      10.0.0.2:8443    -a              # api.example.tld, auth off
//	status   10.0.0.3:8080    -s -a -w        # plain http, no auth, no www
//	admin    10.0.0.4:8443    --cert="admin-cert"
//
// Flags (each +x enables, -x disables):
//
//	a  authentik auth proxy
//	s  upstream over https (else http)
//	w  also serve/redirect www.<domain> (SAN + server_name)  [ON by default]
//	l  local-only (include local.conf)
//
// Global defaults: w ON, a/s/l OFF. `@` means the apex domain itself.
// Cert name defaults to the site's full domain unless --cert="name" is given.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// siteFlags is the resolved on/off state for one site.
type siteFlags struct {
	auth  bool
	https bool
	www   bool
	local bool
}

func defaultFlags() siteFlags { return siteFlags{www: true} } // w on, rest off

// apply toggles flags from tokens like "+a", "-s", "+w".
func (f *siteFlags) apply(tokens []string) {
	for _, t := range tokens {
		if len(t) < 2 || (t[0] != '+' && t[0] != '-') {
			continue
		}
		on := t[0] == '+'
		switch t[1:] {
		case "a":
			f.auth = on
		case "s":
			f.https = on
		case "w":
			f.www = on
		case "l":
			f.local = on
		}
	}
}

// site is a fully-resolved entry from sites.conf.
type site struct {
	fqdn     string // e.g. api.example.tld (apex → example.tld)
	target   string // server:port
	certName string // cert folder/name
	flags    siteFlags
}

// parseSites reads sites.conf into resolved site records.
func (c *proxyConfig) parseSites() ([]site, error) {
	f, err := os.Open(c.configFile)
	if err != nil {
		return nil, fmt.Errorf("Configuration file not found at %s (run 'revpro convert' or 'revpro init setup')", c.configFile)
	}
	defer f.Close()

	var sites []site
	var groupDomain string
	var groupFlags siteFlags

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		// Strip trailing comments (a '#' not inside a quoted --cert).
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Group header: ==domain.tld <+a +s>
		if strings.HasPrefix(trimmed, "==") {
			rest := strings.TrimSpace(trimmed[2:])
			groupFlags = defaultFlags()
			if i := strings.Index(rest, "<"); i >= 0 {
				j := strings.Index(rest, ">")
				if j > i {
					groupFlags.apply(strings.Fields(rest[i+1 : j]))
				}
				groupDomain = strings.TrimSpace(rest[:i])
			} else {
				groupDomain = rest
			}
			if groupDomain == "" {
				return nil, fmt.Errorf("line %d: group header missing domain", lineNo)
			}
			continue
		}

		if groupDomain == "" {
			return nil, fmt.Errorf("line %d: site %q before any '==domain' header", lineNo, trimmed)
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: need at least <name> <target>", lineNo)
		}
		sub, target := fields[0], fields[1]

		// Per-line flags start as the group's resolved flags, then toggle.
		fl := groupFlags
		certName := ""
		for _, tok := range fields[2:] {
			if strings.HasPrefix(tok, "--cert=") {
				certName = strings.Trim(strings.TrimPrefix(tok, "--cert="), `"'`)
				continue
			}
			fl.apply([]string{tok})
		}

		fqdn := groupDomain
		if sub != "@" {
			fqdn = sub + "." + groupDomain
		}
		if certName == "" {
			certName = fqdn
		}

		sites = append(sites, site{fqdn: fqdn, target: target, certName: certName, flags: fl})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

// stripComment removes a trailing "# ..." comment, but not a '#' inside a
// double/single-quoted token (so --cert="a#b" survives).
func stripComment(line string) string {
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote != 0:
			if ch == inQuote {
				inQuote = 0
			}
		case ch == '"' || ch == '\'':
			inQuote = ch
		case ch == '#':
			return line[:i]
		}
	}
	return line
}

// ---------- conversion from the legacy site-configs.conf ----------

// convertCmd reads the old site-configs.conf, writes sites.conf grouped by
// base domain, and backs up the old file to site-configs.conf.bak.
func (c *proxyConfig) convertCmd() {
	oldPath := c.legacyConfigFile
	old, err := os.Open(oldPath)
	if err != nil {
		fail("legacy config not found at %s", oldPath)
	}
	defer old.Close()

	// Group legacy lines by their base domain (last two labels).
	type legacy struct {
		sub      string
		target   string
		certName string
		flags    siteFlags
	}
	groups := map[string][]legacy{}
	var order []string

	sc := bufio.NewScanner(old)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		domain, container, certificate := fields[0], fields[1], fields[2]

		fl := defaultFlags()
		if strings.HasPrefix(domain, "[L]") {
			fl.local = true
			domain = domain[3:]
		}
		if strings.Contains(container, "s:") {
			fl.https = true
		}
		if strings.HasPrefix(container, "a:") ||
			strings.HasPrefix(container, "a:s:") ||
			strings.HasPrefix(container, "s:a:") {
			fl.auth = true
		}
		// Recover server:port by stripping a:/s:/w: prefixes.
		cleaned := container
		for len(cleaned) >= 2 && strings.ContainsRune("asw", rune(cleaned[0])) && cleaned[1] == ':' {
			cleaned = cleaned[2:]
		}

		base := baseDomain(domain)
		sub := "@"
		if domain != base {
			sub = strings.TrimSuffix(domain, "."+base)
		}
		if _, ok := groups[base]; !ok {
			order = append(order, base)
		}
		groups[base] = append(groups[base], legacy{sub: sub, target: cleaned, certName: certificate, flags: fl})
	}
	if err := sc.Err(); err != nil {
		fail("read legacy config: %v", err)
	}

	sort.Strings(order)
	var b strings.Builder
	b.WriteString(sitesTutorial)
	for _, base := range order {
		b.WriteString(fmt.Sprintf("\n==%s\n", base))
		for _, l := range groups[base] {
			toks := flagTokens(l.flags)
			line := fmt.Sprintf("%-12s %-24s", l.sub, l.target)
			if toks != "" {
				line += " " + toks
			}
			// Preserve an explicit cert name only when it differs from the fqdn default.
			fqdn := base
			if l.sub != "@" {
				fqdn = l.sub + "." + base
			}
			if l.certName != "" && l.certName != fqdn {
				line += fmt.Sprintf(` --cert="%s"`, l.certName)
			}
			b.WriteString(strings.TrimRight(line, " ") + "\n")
		}
	}

	if err := os.WriteFile(c.configFile, []byte(b.String()), 0o644); err != nil {
		fail("write %s: %v", c.configFile, err)
	}
	// Back up the legacy file.
	bak := oldPath + ".bak"
	if err := os.Rename(oldPath, bak); err != nil {
		warn("wrote %s but could not back up old file: %v", c.configFile, err)
	} else {
		ok("Converted → %s (old file backed up to %s)", c.configFile, bak)
	}
}

// flagTokens renders the non-default flags as "+a -w" style tokens. The www
// default is ON, so it is only emitted when turned OFF.
func flagTokens(f siteFlags) string {
	var t []string
	if f.auth {
		t = append(t, "+a")
	}
	if f.https {
		t = append(t, "+s")
	}
	if !f.www {
		t = append(t, "-w")
	}
	if f.local {
		t = append(t, "+l")
	}
	return strings.Join(t, " ")
}

// baseDomain returns the registrable-ish base (last two labels). Good enough for
// the common example.tld / sub.example.tld case; multi-label TLDs would need a
// public-suffix list, out of scope here.
func baseDomain(d string) string {
	parts := strings.Split(d, ".")
	if len(parts) <= 2 {
		return d
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// sitesTutorial is prepended to every generated sites.conf.
const sitesTutorial = `##############################################################################
# revpro sites.conf — reverse-proxy site definitions
##############################################################################
#
# Sites are grouped by domain. A group header sets the base domain and optional
# group-wide default flags; each line below it is one site under that domain.
#
#   ==example.tld <+a +s>          # group: example.tld, auth + https by default
#   @        10.0.0.1:8443         # apex (example.tld) — inherits +a +s
#   api      10.0.0.2:8443  -a     # api.example.tld — auth OFF (overrides group)
#   status   10.0.0.3:8080  -s -a -w   # plain http, no auth, no www
#   admin    10.0.0.4:8443  --cert="admin-cert"   # custom cert name
#
#   ==internal.tld <+l>            # group: internal.tld, local-only by default
#   @        192.168.1.10:3000  -w # internal.tld, no www
#   dash     192.168.1.11:3000
#
# Columns:  <name>  <target host:port>  [flags]  [--cert="name"]  [# comment]
#   name      subdomain label, or '@' for the apex domain
#   target    upstream server:port
#
# Flags (each +x enables, -x disables; resolved global → group → line):
#   a   authentik auth proxy        (default OFF)
#   s   upstream over HTTPS          (default OFF — plain http)
#   w   also serve www.<domain>      (default ON  — use -w to disable)
#   l   local-only (include local.conf, deny external)  (default OFF)
#
# Cert name defaults to the site's full domain (e.g. api.example.tld) unless
# overridden with --cert="name". Certs are issued for <domain> (+ www if w on)
# via 'revpro issue' and written to $CERTS_SUB/<cert>/.
#
# Lines starting with '#' are comments. Edit, then run 'revpro regenerate'.
##############################################################################
`
