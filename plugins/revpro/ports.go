// ports.go — 'revpro port': per-category port ranges and next-free-port
// suggestion for a machine.
//
// The user declares port ranges for app categories in $REVPRO/ports.conf:
//
//	# category   ranges (space or comma separated; single ports allowed)
//	web          3000-3999
//	apps         8000-8099 8200-8299
//	db           5400-5499
//
// 'revpro port suggest <machine> [category]' then proposes the next port on
// that machine: sequential allocation — the first port after the highest one
// already used in the category's ranges — falling back to the first gap when
// the tail of the range is exhausted. "Used" combines what sites.conf targets
// reference with (optionally) a live TCP probe of the machine, so a port that
// something already listens on is never suggested.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type portRange struct{ lo, hi int }

type portCategory struct {
	name   string
	ranges []portRange
}

func (pc portCategory) contains(p int) bool {
	for _, r := range pc.ranges {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

// rangesString renders "3000-3999 8200-8299" (single ports as "8080").
func (pc portCategory) rangesString() string {
	var parts []string
	for _, r := range pc.ranges {
		if r.lo == r.hi {
			parts = append(parts, itoa(r.lo))
		} else {
			parts = append(parts, itoa(r.lo)+"-"+itoa(r.hi))
		}
	}
	return strings.Join(parts, " ")
}

func (c *proxyConfig) portsFile() string { return filepath.Join(c.mainFolder, "ports.conf") }

// parsePortCategories reads ports.conf. A missing file is an error carrying
// the 'revpro port init' hint.
func (c *proxyConfig) parsePortCategories() ([]portCategory, error) {
	data, err := os.ReadFile(c.portsFile())
	if err != nil {
		return nil, fmt.Errorf("no port ranges defined at %s — run 'revpro port init' and edit it", c.portsFile())
	}
	return parsePortCategoriesText(string(data))
}

func parsePortCategoriesText(text string) ([]portCategory, error) {
	var cats []portCategory
	seen := map[string]bool{}
	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		if len(fields) < 2 {
			return nil, fmt.Errorf("ports.conf line %d: need <category> <range...>", lineNo+1)
		}
		name := fields[0]
		if seen[name] {
			return nil, fmt.Errorf("ports.conf line %d: duplicate category %q", lineNo+1, name)
		}
		seen[name] = true
		cat := portCategory{name: name}
		for _, tok := range fields[1:] {
			r, err := parseRangeToken(tok)
			if err != nil {
				return nil, fmt.Errorf("ports.conf line %d: %v", lineNo+1, err)
			}
			cat.ranges = append(cat.ranges, r)
		}
		sort.Slice(cat.ranges, func(i, j int) bool { return cat.ranges[i].lo < cat.ranges[j].lo })
		cats = append(cats, cat)
	}
	if len(cats) == 0 {
		return nil, fmt.Errorf("ports.conf defines no categories")
	}
	return cats, nil
}

// parseRangeToken parses "3000-3999" or a single "8080".
func parseRangeToken(tok string) (portRange, error) {
	lo, hi := tok, tok
	if i := strings.Index(tok, "-"); i >= 0 {
		lo, hi = tok[:i], tok[i+1:]
	}
	l, h := atoiSafe(lo), atoiSafe(hi)
	if l < 1 || l > 65535 || h < 1 || h > 65535 || h < l {
		return portRange{}, fmt.Errorf("bad port range %q", tok)
	}
	return portRange{lo: l, hi: h}, nil
}

// usedPortsByMachine maps host → port → fqdns using it, from sites.conf
// targets.
func (c *proxyConfig) usedPortsByMachine() (map[string]map[int][]string, error) {
	sites, err := c.parseSites()
	if err != nil {
		return nil, err
	}
	used := map[string]map[int][]string{}
	for _, s := range sites {
		host, port := splitTarget(s.target)
		p := atoiSafe(port)
		if host == "" || p == 0 {
			continue
		}
		if used[host] == nil {
			used[host] = map[int][]string{}
		}
		used[host][p] = append(used[host][p], s.fqdn)
	}
	return used, nil
}

// splitTarget splits "host:port" on the last colon (host may be a v6 literal).
func splitTarget(target string) (host, port string) {
	i := strings.LastIndex(target, ":")
	if i < 0 {
		return target, ""
	}
	return target[:i], target[i+1:]
}

// suggestPort proposes the next port for a category. Sequential-first: start
// right after the highest port already used inside the category's ranges,
// then wrap to fill gaps from the beginning. probe (optional) reports whether
// something is LISTENING on a candidate — such ports are skipped, at most
// maxProbes of them checked.
func suggestPort(cat portCategory, used map[int][]string, probe func(port int) bool, maxProbes int) (int, string, error) {
	// All candidate ports of the category, ascending.
	var all []int
	for _, r := range cat.ranges {
		for p := r.lo; p <= r.hi; p++ {
			all = append(all, p)
		}
	}
	sort.Ints(all)

	// Index to start from: after the highest used port within the ranges.
	start := 0
	highest := 0
	for i, p := range all {
		if _, ok := used[p]; ok && p > highest {
			highest = p
			start = i + 1
		}
	}

	reason := "first free port in range"
	if highest > 0 {
		reason = fmt.Sprintf("next after highest used port %d", highest)
	}

	probes := 0
	try := func(p int) (bool, error) {
		if _, ok := used[p]; ok {
			return false, nil
		}
		if probe != nil {
			if probes >= maxProbes {
				return false, fmt.Errorf("gave up after probing %d candidate ports — retry with --no-probe", maxProbes)
			}
			probes++
			if probe(p) {
				return false, nil // something already listening
			}
		}
		return true, nil
	}

	for _, i := range scanOrder(len(all), start) {
		free, err := try(all[i])
		if err != nil {
			return 0, "", err
		}
		if free {
			if i < start {
				reason = "range tail exhausted — first free gap"
			}
			return all[i], reason, nil
		}
	}
	return 0, "", fmt.Errorf("no free port left in category %q (%s)", cat.name, cat.rangesString())
}

// scanOrder yields indices start..n-1 then 0..start-1.
func scanOrder(n, start int) []int {
	out := make([]int, 0, n)
	for i := start; i < n; i++ {
		out = append(out, i)
	}
	for i := 0; i < start && i < n; i++ {
		out = append(out, i)
	}
	return out
}

// probeListening reports whether a TCP connect to host:port succeeds — i.e.
// something is already listening there. A refused/timed-out connection means
// the port looks free (a firewall that drops packets is indistinguishable
// from free; hence probing is best-effort and can be disabled).
func probeListening(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), 400*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// categoryFor returns the category whose ranges contain p, if any.
func categoryFor(cats []portCategory, p int) (portCategory, bool) {
	for _, c := range cats {
		if c.contains(p) {
			return c, true
		}
	}
	return portCategory{}, false
}

// ---------- CLI ----------

func (c *proxyConfig) portCmd(args []string) {
	if len(args) == 0 {
		portUsage()
		os.Exit(1)
	}

	// Strip the global --no-probe flag wherever it appears.
	probe := true
	rest := args[:0:0]
	for _, a := range args {
		if a == "--no-probe" {
			probe = false
			continue
		}
		rest = append(rest, a)
	}

	switch rest[0] {
	case "init":
		c.portInit()
	case "list":
		machine := ""
		if len(rest) > 1 {
			machine = rest[1]
		}
		c.portList(machine)
	case "suggest":
		if len(rest) < 2 {
			fail("Usage: revpro port suggest <machine> [category] [--no-probe]")
		}
		category := ""
		if len(rest) > 2 {
			category = rest[2]
		}
		c.portSuggest(rest[1], category, probe)
	case "check":
		if len(rest) < 3 {
			fail("Usage: revpro port check <machine> <port> [--no-probe]")
		}
		c.portCheck(rest[1], atoiSafe(rest[2]), probe)
	case "help":
		portUsage()
	default:
		fail("unknown port command %q — see 'revpro port help'", rest[0])
	}
}

func (c *proxyConfig) portInit() {
	if _, err := os.Stat(c.portsFile()); err == nil {
		fail("%s already exists — edit it directly", c.portsFile())
	}
	if err := os.MkdirAll(c.mainFolder, 0o755); err != nil {
		fail("mkdir %s: %v", c.mainFolder, err)
	}
	if err := os.WriteFile(c.portsFile(), []byte(portsTutorial), 0o644); err != nil {
		fail("write %s: %v", c.portsFile(), err)
	}
	ok("Wrote starter %s — edit the categories/ranges to taste.", c.portsFile())
}

func (c *proxyConfig) portList(machine string) {
	cats, err := c.parsePortCategories()
	if err != nil {
		warn("%v", err)
	}
	used, err := c.usedPortsByMachine()
	if err != nil {
		fail("%v", err)
	}

	if len(cats) > 0 {
		info("Categories (%s):", c.portsFile())
		for _, cat := range cats {
			fmt.Printf("  %-12s %s\n", cat.name, cat.rangesString())
		}
		fmt.Println()
	}

	slugs, _ := c.machineSlugs()
	names := c.machineNames()
	machine = resolveMachine(slugs, machine)

	var hosts []string
	for _, h := range sortedMachineHosts(used, names) {
		if machine == "" || h == machine {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		warn("no sites found%s in %s", forMachine(machine), c.configFile)
		return
	}

	info("Ports in use per machine (from sites.conf):")
	for _, h := range hosts {
		label := h
		if slug, okn := names[h]; okn {
			label = slug + " — " + h
		}
		fmt.Printf("  %s\n", label)
		ports := make([]int, 0, len(used[h]))
		for p := range used[h] {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		for _, p := range ports {
			catNote := ""
			if cat, okc := categoryFor(cats, p); okc {
				catNote = " [" + cat.name + "]"
			}
			fmt.Printf("    %-6d %s%s\n", p, strings.Join(used[h][p], ", "), catNote)
		}
	}
}

func forMachine(machine string) string {
	if machine == "" {
		return ""
	}
	return " for machine " + machine
}

func (c *proxyConfig) portSuggest(machine, category string, probe bool) {
	cats, err := c.parsePortCategories()
	if err != nil {
		fail("%v", err)
	}
	allUsed, err := c.usedPortsByMachine()
	if err != nil {
		fail("%v", err)
	}
	slugs, _ := c.machineSlugs()
	if resolved := resolveMachine(slugs, machine); resolved != machine {
		info("machine %s = %s", machine, resolved)
		machine = resolved
	}
	used := allUsed[machine]
	if used == nil {
		used = map[int][]string{}
		warn("machine %s has no sites in sites.conf yet — suggesting from the start of the range", machine)
	}

	var probeFn func(int) bool
	if probe {
		probeFn = func(p int) bool { return probeListening(machine, p) }
	}

	matched := false
	for _, cat := range cats {
		if category != "" && cat.name != category {
			continue
		}
		matched = true
		port, reason, err := suggestPort(cat, used, probeFn, 25)
		if err != nil {
			warn("%-12s %v", cat.name, err)
			continue
		}
		note := "not probed"
		if probe {
			note = "probed free"
		}
		fmt.Printf("%s✓%s %-12s → %s%d%s   (%s; %s; ranges %s)\n",
			cGreen, cReset, cat.name, cCyan, port, cReset, reason, note, cat.rangesString())
	}
	if !matched {
		fail("category %q not found in %s", category, c.portsFile())
	}
}

func (c *proxyConfig) portCheck(machine string, port int, probe bool) {
	if port < 1 || port > 65535 {
		fail("bad port")
	}
	cats, _ := c.parsePortCategories()
	allUsed, err := c.usedPortsByMachine()
	if err != nil {
		fail("%v", err)
	}
	slugs, _ := c.machineSlugs()
	if resolved := resolveMachine(slugs, machine); resolved != machine {
		info("machine %s = %s", machine, resolved)
		machine = resolved
	}

	info("%s:%d", machine, port)
	if cat, okc := categoryFor(cats, port); okc {
		fmt.Printf("   category: %s (%s)\n", cat.name, cat.rangesString())
	} else if len(cats) > 0 {
		fmt.Printf("   category: none — port is outside every defined range\n")
	}

	problems := 0
	if fqdns := allUsed[machine][port]; len(fqdns) > 0 {
		fmt.Printf("   ✗ referenced in sites.conf by: %s\n", strings.Join(fqdns, ", "))
		problems++
	} else {
		fmt.Printf("   ✓ not referenced in sites.conf\n")
	}
	if probe {
		if probeListening(machine, port) {
			fmt.Printf("   ✗ something is LISTENING on %s:%d\n", machine, port)
			problems++
		} else {
			fmt.Printf("   ✓ nothing listening (or host filtered)\n")
		}
	}
	if problems > 0 {
		fail("port %d looks TAKEN on %s", port, machine)
	}
	ok("port %d looks free on %s", port, machine)
}

func portUsage() {
	fmt.Print(`revpro port — category port ranges & next-free-port suggestion

Usage:
  revpro port init                                 Write a starter $REVPRO/ports.conf
  revpro port list [machine]                       Show categories + ports used per machine
  revpro port suggest <machine> [category] [--no-probe]
                                                   Suggest the next port for the machine
                                                   (all categories when none given)
  revpro port check <machine> <port> [--no-probe]  Is the port referenced/listening?

Ranges live in $REVPRO/ports.conf, one category per line:
  web    3000-3999
  apps   8000-8099 8200-8299
  db     5400-5499

Suggestion = next port after the highest one the machine already uses inside
the category's ranges (sequential allocation), wrapping to the first gap when
the tail is exhausted. Candidates are TCP-probed so a port with a live
listener is never suggested (--no-probe skips that).
`)
}

// portsTutorial is the starter ports.conf written by 'revpro port init'.
const portsTutorial = `##############################################################################
# revpro ports.conf — port ranges per app category
##############################################################################
#
# One category per line:  <category>  <range> [range ...]
# Ranges are inclusive; single ports and multiple ranges are allowed.
#
# 'revpro port suggest <machine> [category]' uses these to propose the next
# port on a machine: it looks at what sites.conf already routes to that
# machine, takes the next port after the highest used one in the category's
# ranges, and TCP-probes the candidate so live listeners are skipped.
#
# Edit the examples below to your own scheme:
##############################################################################

web        3000-3999
apps       8000-8499
media      8500-8999
db         5400-5499
`
