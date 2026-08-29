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
// Cert name defaults to the site's full domain unless --cert="name" is given
// on the line, or on the group header as a group-wide default.
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
	fqdn       string // e.g. api.example.tld (apex → example.tld)
	target     string // server:port, machine slug resolved
	rawTarget  string // target as written in sites.conf (may use a slug)
	certName   string // cert folder/name
	flags      siteFlags
	group      string // the base domain from this site's ==domain header
	groupIndex int    // 0-based ordinal of the ==domain header block this came from
	groupLabel string // the '# ...' comment line immediately above that header, if any
}

// parseSites reads sites.conf into resolved site records. Targets written
// with a machine slug (see machines.conf) come back with the slug resolved
// in target and the original spelling in rawTarget.
func (c *proxyConfig) parseSites() ([]site, error) {
	f, err := os.Open(c.configFile)
	if err != nil {
		return nil, fmt.Errorf("Configuration file not found at %s (run 'revpro convert' or 'revpro init setup')", c.configFile)
	}
	defer f.Close()

	slugs, err := c.machineSlugs()
	if err != nil {
		return nil, err
	}

	var sites []site
	var groupDomain string
	var group groupInfo
	groupIndex := -1
	groupLabel := ""
	pendingComment := "" // most recent full-line comment, cleared by any non-comment line

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		rawTrimmed := strings.TrimSpace(raw)

		// A full-line comment is remembered as the label for the next group
		// header (e.g. "# lnln.eu — public sites" above "==lnln.eu <-w>").
		if strings.HasPrefix(rawTrimmed, "#") {
			pendingComment = strings.TrimSpace(strings.TrimPrefix(rawTrimmed, "#"))
			continue
		}
		if rawTrimmed == "" {
			continue
		}

		// Strip trailing comments (a '#' not inside a quoted --cert).
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			pendingComment = ""
			continue
		}

		// Group header: ==domain.tld [machine] <+a +s>
		if strings.HasPrefix(trimmed, "==") {
			groupDomain, group = parseGroupHeader(trimmed)
			if groupDomain == "" {
				return nil, fmt.Errorf("line %d: group header missing domain", lineNo)
			}
			if strings.ContainsAny(group.machine, ": ") {
				return nil, fmt.Errorf("line %d: bad group machine %q (a host or a machines.conf slug, no port)", lineNo, group.machine)
			}
			groupIndex++
			groupLabel = pendingComment
			pendingComment = ""
			continue
		}
		pendingComment = ""

		if groupDomain == "" {
			return nil, fmt.Errorf("line %d: site %q before any '==domain' header", lineNo, trimmed)
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: need at least <name> <target>", lineNo)
		}
		sub, target := fields[0], fields[1]

		// A port-only target ("8080" or ":8080") borrows the group's [machine].
		expanded := target
		if port, portOnly := portOnlyTarget(target); portOnly {
			if group.machine == "" {
				return nil, fmt.Errorf("line %d: target %q has no host and group ==%s declares no [machine]", lineNo, target, groupDomain)
			}
			expanded = group.machine + ":" + port
		}

		// Per-line flags start as the group's resolved flags, then toggle.
		fl := group.flags
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
			certName = group.cert
		}
		if certName == "" {
			certName = fqdn
		}

		sites = append(sites, site{
			fqdn:       fqdn,
			target:     resolveTarget(slugs, expanded),
			rawTarget:  target,
			group:      groupDomain,
			groupIndex: groupIndex,
			groupLabel: groupLabel,
			certName:   certName,
			flags:      fl,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

// groupInfo is what a group header declares for the lines below it.
type groupInfo struct {
	flags   siteFlags
	machine string // default machine for port-only targets ("" = none)
	cert    string // default cert name for lines with no --cert= of their own ("" = none)
}

// parseGroupHeader parses a trimmed "==domain.tld [machine] <+a +s> --cert=name"
// header line into the domain and its group defaults. [machine] and <flags>
// may appear in either order; the machine is a host or a machines.conf slug.
// A trailing --cert="name" sets the default cert for every line in the group
// that doesn't specify its own.
func parseGroupHeader(trimmed string) (string, groupInfo) {
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "=="))
	gi := groupInfo{flags: defaultFlags()}
	if i := strings.Index(rest, "["); i >= 0 {
		if j := strings.Index(rest, "]"); j > i {
			gi.machine = strings.TrimSpace(rest[i+1 : j])
			rest = strings.TrimSpace(rest[:i] + " " + rest[j+1:])
		}
	}
	if i := strings.Index(rest, "<"); i >= 0 {
		if j := strings.Index(rest, ">"); j > i {
			gi.flags.apply(strings.Fields(rest[i+1 : j]))
			for _, tok := range strings.Fields(rest[j+1:]) {
				if strings.HasPrefix(tok, "--cert=") {
					gi.cert = strings.Trim(strings.TrimPrefix(tok, "--cert="), `"'`)
				}
			}
		}
		rest = strings.TrimSpace(rest[:i])
	}
	return rest, gi
}

// portOnlyTarget reports whether target names just a port ("8080" or
// ":8080"), returning the bare port when it does.
func portOnlyTarget(target string) (string, bool) {
	p := strings.TrimPrefix(target, ":")
	if p == "" {
		return "", false
	}
	if n := atoiSafe(p); n >= 1 && n <= 65535 {
		return p, true
	}
	return "", false
}

// groupMeta maps each group domain in sites.conf to its header defaults
// (flags + machine). A missing config file yields an empty map, not an error.
func (c *proxyConfig) groupMeta() (map[string]groupInfo, error) {
	f, err := os.Open(c.configFile)
	if err != nil {
		return map[string]groupInfo{}, nil
	}
	defer f.Close()
	out := map[string]groupInfo{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		trimmed := strings.TrimSpace(stripComment(sc.Text()))
		if strings.HasPrefix(trimmed, "==") {
			if domain, gi := parseGroupHeader(trimmed); domain != "" {
				out[domain] = gi
			}
		}
	}
	return out, sc.Err()
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
		entries := groups[base]

		// The legacy format has no www concept at all — sites were never
		// auto-served on www.<domain>. Converted groups default -w so
		// behavior matches what was actually live, instead of silently
		// picking up sites.conf's own www-on default.
		header := fmt.Sprintf("==%s <-w>", base)

		// Hoist the group's most common cert name into the header so
		// per-line --cert= is only needed where a site's cert actually
		// differs from the rest of the group (e.g. one shared domain cert
		// covering most subdomains, per-fqdn certs for the rest).
		counts := map[string]int{}
		for _, l := range entries {
			counts[l.certName]++
		}
		groupCert, best := "", 1 // only hoist a cert shared by more than one site
		for _, cert := range sortedKeys(counts) {
			if n := counts[cert]; n > best {
				groupCert, best = cert, n
			}
		}
		if groupCert != "" {
			header += fmt.Sprintf(` --cert="%s"`, groupCert)
		}
		b.WriteString("\n" + header + "\n")

		for _, l := range entries {
			toks := flagTokensNoWWW(l.flags)
			line := fmt.Sprintf("%-12s %-24s", l.sub, l.target)
			if toks != "" {
				line += " " + toks
			}
			// Preserve an explicit cert name only when it differs from
			// whatever the line would otherwise default to (the hoisted
			// group cert, or the site's own fqdn).
			fqdn := base
			if l.sub != "@" {
				fqdn = l.sub + "." + base
			}
			defaultCert := fqdn
			if groupCert != "" {
				defaultCert = groupCert
			}
			if l.certName != "" && l.certName != defaultCert {
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

// flagTokensNoWWW is flagTokens without the www token, for convertCmd: the
// legacy format has no www concept, so the group header's own <-w> already
// says everything there is to say about it — per-line output would just be
// noise (and every legacy site would otherwise render a redundant -w).
func flagTokensNoWWW(f siteFlags) string {
	var t []string
	if f.auth {
		t = append(t, "+a")
	}
	if f.https {
		t = append(t, "+s")
	}
	if f.local {
		t = append(t, "+l")
	}
	return strings.Join(t, " ")
}

// sortedKeys returns a map's keys sorted, for deterministic iteration when
// picking among tied counts.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
#   ==apps.tld [A] <+s>            # group machine A (a machines.conf slug or host)
#   @        8443                  # port only → A:8443
#   grafana  :3000                 # ":port" works too → A:3000
#   backup   B:9000                # full target still overrides the group machine
#
#   ==shared.tld <-w> --cert="shared.tld"   # group-wide default cert
#   api      10.0.0.1:8080         # inherits cert "shared.tld"
#   admin    10.0.0.2:8080  --cert="admin-only"   # overrides the group default
#
# Columns:  <name>  <target>  [flags]  [--cert="name"]  [# comment]
#   name      subdomain label, or '@' for the apex domain
#   target    upstream server:port; the server may be a machine slug from
#             machines.conf (e.g. A:8080 for 192.168.2.20:8080). When the
#             group header declares [machine], a bare port ("8080" or
#             ":8080") is enough — the group's machine fills in the host.
#
# Flags (each +x enables, -x disables; resolved global → group → line):
#   a   authentik auth proxy        (default OFF)
#   s   upstream over HTTPS          (default OFF — plain http)
#   w   also serve www.<domain>      (default ON  — use -w to disable)
#   l   local-only (include local.conf, deny external)  (default OFF)
#
# Cert name defaults to the site's full domain (e.g. api.example.tld), unless
# the group header sets a default with --cert="name" (handy when one cert
# covers most of a domain's subdomains), and a line's own --cert="name"
# overrides either default. Certs are issued for <domain> (+ www if w on) via
# 'revpro issue' and written to $CERTS_SUB/<cert>/.
#
# Lines starting with '#' are comments. Edit, then run 'revpro regenerate'.
##############################################################################
`
