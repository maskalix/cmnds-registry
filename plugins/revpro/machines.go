// machines.go — machine slugs: short codes standing in for whole IP
// addresses / hostnames, defined in $REVPRO/machines.conf:
//
//	# slug   host
//	A        192.168.2.20
//	AVA      192.168.2.30
//	AVA01    192.168.2.31
//	N        192.168.2.100
//
// A slug is 1–8 letters/digits starting with a letter, matched
// case-insensitively. Slugs resolve wherever a machine is named: sites.conf
// targets (`app  A:8080`), 'revpro port suggest A web', and the web UI. The
// nginx configs always receive the resolved host.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var slugRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,7}$`)

type machine struct {
	slug string
	host string
}

func (c *proxyConfig) machinesFile() string { return filepath.Join(c.mainFolder, "machines.conf") }

// parseMachines reads machines.conf. A missing file yields no machines, not
// an error (slugs are optional).
func (c *proxyConfig) parseMachines() ([]machine, error) {
	data, err := os.ReadFile(c.machinesFile())
	if err != nil {
		return nil, nil
	}
	ms, err := parseMachinesText(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", c.machinesFile(), err)
	}
	return ms, nil
}

func parseMachinesText(text string) ([]machine, error) {
	var out []machine
	seen := map[string]bool{}
	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("machines.conf line %d: need <slug> <host>", lineNo+1)
		}
		slug, host := fields[0], fields[1]
		if !slugRe.MatchString(slug) {
			return nil, fmt.Errorf("machines.conf line %d: bad slug %q (1-8 letters/digits, starts with a letter)", lineNo+1, slug)
		}
		if strings.ContainsAny(host, ":/ ") || strings.HasPrefix(host, "-") || host == "" {
			return nil, fmt.Errorf("machines.conf line %d: bad host %q", lineNo+1, host)
		}
		key := strings.ToUpper(slug)
		if seen[key] {
			return nil, fmt.Errorf("machines.conf line %d: duplicate slug %q", lineNo+1, slug)
		}
		seen[key] = true
		out = append(out, machine{slug: slug, host: host})
	}
	return out, nil
}

// machineSlugs returns the UPPER(slug) → host lookup map.
func (c *proxyConfig) machineSlugs() (map[string]string, error) {
	ms, err := c.parseMachines()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range ms {
		out[strings.ToUpper(m.slug)] = m.host
	}
	return out, nil
}

// machineNames returns the host → slug reverse map (first definition wins),
// for display purposes.
func (c *proxyConfig) machineNames() map[string]string {
	ms, err := c.parseMachines()
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, m := range ms {
		if _, dup := out[m.host]; !dup {
			out[m.host] = m.slug
		}
	}
	return out
}

// resolveMachine turns a slug into its host; anything that isn't a defined
// slug passes through unchanged.
func resolveMachine(slugs map[string]string, s string) string {
	if h, okm := slugs[strings.ToUpper(s)]; okm {
		return h
	}
	return s
}

// resolveTarget resolves the host part of a "host:port" target through the
// slug map, keeping the port untouched.
func resolveTarget(slugs map[string]string, target string) string {
	host, port := splitTarget(target)
	resolved := resolveMachine(slugs, host)
	if resolved == host {
		return target
	}
	if port == "" {
		return resolved
	}
	return resolved + ":" + port
}

// ---------- CLI ----------

func (c *proxyConfig) machinesCmd(args []string) {
	if len(args) == 0 {
		c.machinesList()
		return
	}
	switch args[0] {
	case "list":
		c.machinesList()
	case "init":
		c.machinesInit()
	case "set":
		if len(args) != 3 {
			fail("Usage: revpro machines set <slug> <host>")
		}
		c.machinesSet(args[1], args[2])
	case "rm":
		if len(args) != 2 {
			fail("Usage: revpro machines rm <slug>")
		}
		c.machinesRm(args[1])
	case "help":
		machinesUsage()
	default:
		fail("unknown machines command %q — see 'revpro machines help'", args[0])
	}
}

func (c *proxyConfig) machinesList() {
	ms, err := c.parseMachines()
	if err != nil {
		fail("%v", err)
	}
	if len(ms) == 0 {
		warn("no machine slugs defined — run 'revpro machines init' or 'revpro machines set A 192.168.2.20'")
		return
	}
	// Count how many sites target each machine (after resolution).
	usage := map[string]int{}
	if used, err := c.usedPortsByMachine(); err == nil {
		for host, ports := range used {
			for _, fqdns := range ports {
				usage[host] += len(fqdns)
			}
		}
	}
	info("Machine slugs (%s):", c.machinesFile())
	for _, m := range ms {
		note := ""
		if n := usage[m.host]; n > 0 {
			note = fmt.Sprintf("   %d site(s)", n)
		}
		fmt.Printf("  %-8s → %-20s%s\n", m.slug, m.host, note)
	}
}

func (c *proxyConfig) machinesInit() {
	if _, err := os.Stat(c.machinesFile()); err == nil {
		fail("%s already exists — edit it directly or use 'revpro machines set'", c.machinesFile())
	}
	if err := os.MkdirAll(c.mainFolder, 0o755); err != nil {
		fail("mkdir %s: %v", c.mainFolder, err)
	}
	if err := os.WriteFile(c.machinesFile(), []byte(machinesTutorial), 0o644); err != nil {
		fail("write %s: %v", c.machinesFile(), err)
	}
	ok("Wrote starter %s — define your slugs there.", c.machinesFile())
}

// machinesSet adds or replaces a slug definition in place, preserving the
// rest of the file (comments included).
func (c *proxyConfig) machinesSet(slug, host string) {
	if !slugRe.MatchString(slug) {
		fail("bad slug %q (1-8 letters/digits, starts with a letter)", slug)
	}
	if strings.ContainsAny(host, ":/ ") || strings.HasPrefix(host, "-") || host == "" {
		fail("bad host %q", host)
	}
	data, _ := os.ReadFile(c.machinesFile())
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, raw := range lines {
		fields := strings.Fields(strings.TrimSpace(stripComment(raw)))
		if len(fields) >= 1 && strings.EqualFold(fields[0], slug) {
			lines[i] = fmt.Sprintf("%-8s %s", slug, host)
			replaced = true
			break
		}
	}
	text := strings.Join(lines, "\n")
	if !replaced {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += fmt.Sprintf("%-8s %s\n", slug, host)
	}
	if _, err := parseMachinesText(text); err != nil {
		fail("%v", err)
	}
	if err := os.MkdirAll(c.mainFolder, 0o755); err != nil {
		fail("mkdir %s: %v", c.mainFolder, err)
	}
	if err := os.WriteFile(c.machinesFile(), []byte(text), 0o644); err != nil {
		fail("write %s: %v", c.machinesFile(), err)
	}
	ok("%s → %s", slug, host)
}

func (c *proxyConfig) machinesRm(slug string) {
	data, err := os.ReadFile(c.machinesFile())
	if err != nil {
		fail("no %s", c.machinesFile())
	}
	var out []string
	removed := false
	for _, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(stripComment(raw)))
		if len(fields) >= 1 && strings.EqualFold(fields[0], slug) {
			removed = true
			continue
		}
		out = append(out, raw)
	}
	if !removed {
		fail("slug %q not found", slug)
	}
	if err := os.WriteFile(c.machinesFile(), []byte(strings.Join(out, "\n")), 0o644); err != nil {
		fail("write %s: %v", c.machinesFile(), err)
	}
	ok("removed %s", slug)
}

func machinesUsage() {
	fmt.Print(`revpro machines — short slugs for machine addresses

Usage:
  revpro machines [list]           Show defined slugs (+ how many sites use each)
  revpro machines init             Write a starter $REVPRO/machines.conf
  revpro machines set <slug> <host>   Add or update a slug (A → 192.168.2.20)
  revpro machines rm <slug>        Remove a slug

Slugs are 1-8 letters/digits starting with a letter, matched
case-insensitively. Once defined they work anywhere a machine is named:
  sites.conf targets:   app   A:8080
  group headers:        ==apps.tld [A]   (lines below need only a port)
  port suggestion:      revpro port suggest A web
  the web UI's machine fields
Generated nginx configs always contain the resolved host.
`)
}

// sortedMachineHosts returns the hosts of used, slug-named hosts first (in
// slug definition order), then the rest alphabetically — a friendlier order
// for listings.
func sortedMachineHosts(used map[string]map[int][]string, names map[string]string) []string {
	var withSlug, plain []string
	for h := range used {
		if _, okn := names[h]; okn {
			withSlug = append(withSlug, h)
		} else {
			plain = append(plain, h)
		}
	}
	sort.Strings(withSlug)
	sort.Strings(plain)
	return append(withSlug, plain...)
}

// machinesTutorial is the starter machines.conf.
const machinesTutorial = `##############################################################################
# revpro machines.conf — machine slugs
##############################################################################
#
# One machine per line:  <slug>  <host>
# A slug is 1-8 letters/digits starting with a letter (case-insensitive).
#
# Slugs stand in for the full address anywhere a machine is named:
#   sites.conf:   app   A:8080        # instead of 192.168.2.20:8080
#   CLI:          revpro port suggest A web
# Generated nginx configs always get the resolved host.
#
# Edit the examples below:
##############################################################################

# A        192.168.2.20
# AVA      192.168.2.30
# AVA01    192.168.2.31
# N        192.168.2.100
`
