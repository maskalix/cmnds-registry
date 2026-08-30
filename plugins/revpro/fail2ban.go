// fail2ban.go — a thin wrapper around fail2ban-client (status, ban/unban)
// plus a one-shot 'setup' that installs and configures fail2ban with sane
// defaults for a revpro box: protects sshd, watches the generated nginx
// access/error logs with the bundled botsearch/http-auth filters, adds a
// long-bantime recidive jail for repeat offenders, and a ban-only
// 'revpro-manual' jail the web UI uses for one-off and AbuseIPDB-driven
// bans. Every rule carries an ignoreip covering loopback and this box's own
// private-network address(es), auto-detected — so revpro can never ban its
// own admin/management traffic. Bantime is finite (not permanent), so even
// a wrong ignoreip self-heals instead of locking the box out for good.
package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func fail2banClient(args ...string) (string, error) {
	cmd := exec.Command("fail2ban-client", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return "", fmt.Errorf("fail2ban-client %s: %v: %s", strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

// f2bAvailable reports whether fail2ban-client is on PATH — 'setup' hasn't
// necessarily run yet, or the package failed to install.
func f2bAvailable() bool {
	_, err := exec.LookPath("fail2ban-client")
	return err == nil
}

// manualJail is a dedicated, filter-less jail: nothing ever bans into it
// automatically via a log filter — it exists purely so the web UI (and the
// AbuseIPDB auto-block scan) has somewhere to put a one-off ban that blocks
// every port, not just one service's. Its bantime is permanent (-1, see
// f2bJailLocal), unlike every other jail here: these are deliberate,
// already-considered blocks (a human clicking Ban, or an AbuseIPDB
// confidence-score match), not an automatic filter match that could be a
// false positive — so there's no reason for one to quietly expire on its
// own the way an sshd or botsearch ban should.
const manualJail = "revpro-manual"

// f2bJail is one jail's live status, as reported by 'fail2ban-client status <name>'.
type f2bJail struct {
	Name          string   `json:"name"`
	CurrentFailed int      `json:"currentFailed"`
	TotalFailed   int      `json:"totalFailed"`
	CurrentBanned int      `json:"currentBanned"`
	TotalBanned   int      `json:"totalBanned"`
	BannedIPs     []string `json:"bannedIPs"`
}

// f2bListJails parses 'fail2ban-client status' for the "Jail list:" line.
func f2bListJails() ([]string, error) {
	out, err := fail2banClient("status")
	if err != nil {
		return nil, err
	}
	return parseJailList(out), nil
}

func parseJailList(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "Jail list:")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("Jail list:"):])
		if rest == "" {
			return nil
		}
		var jails []string
		for _, j := range strings.Split(rest, ",") {
			if j = strings.TrimSpace(j); j != "" {
				jails = append(jails, j)
			}
		}
		return jails
	}
	return nil
}

// f2bJailStatus parses 'fail2ban-client status <jail>'.
func f2bJailStatus(name string) (f2bJail, error) {
	out, err := fail2banClient("status", name)
	if err != nil {
		return f2bJail{}, err
	}
	j := parseJailStatus(out)
	j.Name = name
	return j, nil
}

func parseJailStatus(out string) f2bJail {
	var j f2bJail
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "Currently failed:"):
			j.CurrentFailed = intAfterColon(line)
		case strings.Contains(line, "Total failed:"):
			j.TotalFailed = intAfterColon(line)
		case strings.Contains(line, "Currently banned:"):
			j.CurrentBanned = intAfterColon(line)
		case strings.Contains(line, "Total banned:"):
			j.TotalBanned = intAfterColon(line)
		case strings.Contains(line, "Banned IP list:"):
			idx := strings.Index(line, "Banned IP list:")
			if rest := strings.TrimSpace(line[idx+len("Banned IP list:"):]); rest != "" {
				j.BannedIPs = strings.Fields(rest)
			}
		}
	}
	return j
}

func intAfterColon(line string) int {
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line[idx+1:]))
	return n
}

func f2bBan(jail, ip string) error {
	_, err := fail2banClient("set", jail, "banip", ip)
	return err
}

func f2bUnban(jail, ip string) error {
	_, err := fail2banClient("set", jail, "unbanip", ip)
	return err
}

// detectLocalCIDRs returns this host's own private-range IPv4 network(s),
// in CIDR form, straight from its interfaces — used as the fail2ban
// ignoreip default so a box is never provisioned with an empty or wrong
// allowlist for its own management traffic. Deliberately generic (no
// hardcoded subnet) so the same code is correct on any revpro install.
func detectLocalCIDRs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipnet, isNet := a.(*net.IPNet)
		if !isNet || ipnet.IP.IsLoopback() {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil || !ip4.IsPrivate() {
			continue
		}
		out = append(out, ipnet.String())
	}
	return out
}

// errorRedirectFilterConf matches every line of the error-redirect trap
// host's access log — being logged there at all *is* the signal (see
// templates/error.conf: every generated site 302s its 4xx/5xx upstream
// errors to one shared $error_redirect_base host), so the filter doesn't
// need to parse a status code, just the client IP.
const errorRedirectFilterConf = `[Definition]
failregex = ^<HOST> -
ignoreregex =
`

// httpErrorsFilterConf matches any 4xx/5xx response in a standard combined-
// format access log — the generic "frequently gets HTTP error codes" signal,
// applied across every site's own log rather than one shared trap host.
const httpErrorsFilterConf = `[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/\d(\.\d)?" (4\d\d|5\d\d)
ignoreregex =
`

// f2bJailLocal renders /etc/fail2ban/jail.local. ignoreLAN is a
// space-separated list of extra CIDRs/IPs to never ban (in addition to
// loopback) — normally this box's own detected private-network address(es).
// errorHost, if set, is the shared error-redirect trap host (e.g.
// "error.example.tld" — see REVPRO_F2B_ERROR_HOST in fail2banUsage) whose
// access log gets its own low-threshold jail, since nothing legitimate
// should hit it often. The generic http-errors jail (any 4xx/5xx, across
// every site) is always included — findtime/maxretry chosen generously
// (30 in 10m) so ordinary browsing 404s don't trip it.
func f2bJailLocal(logDir, ignoreLAN, errorHost string) string {
	ignore := "127.0.0.1/8 ::1"
	if ignoreLAN != "" {
		ignore += " " + ignoreLAN
	}
	action := "%(action_)s"
	if f2bAbuseIPDBConfigured() {
		// Chain the default ban action with the AbuseIPDB report hook
		// (see abuseipdb.go) so every jail's bans get reported outward too,
		// not just ones the web UI's guard scan triggers.
		action = "%(action_)s\n         revpro-abuseipdb[name=%(__name__)s]"
	}

	var errorJail string
	if errorHost != "" {
		// findtime=3m, maxretry=8: tolerates a once-a-minute external
		// monitor (a steady ~3 hits per 3m window) while still catching a
		// scanner bursting many requests in seconds.
		errorJail = fmt.Sprintf(`
[nginx-error-redirect]
enabled = true
filter = nginx-error-redirect
logpath = %s/%s_access.log
findtime = 3m
maxretry = 8
`, logDir, errorHost)
	}

	return fmt.Sprintf(`# Written by 'revpro fail2ban setup' — re-running setup overwrites this
# file, so hand edits belong in a jail.d/*.local drop-in instead.
[DEFAULT]
ignoreip = %s
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
action = %s

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
logpath = %s/*_error.log

[nginx-botsearch]
enabled = true
logpath = %s/*_access.log

[nginx-http-errors]
enabled = true
filter = nginx-http-errors
logpath = %s/*_access.log
findtime = 10m
maxretry = 30
%s
[recidive]
enabled = true
bantime = 1w
findtime = 1d
maxretry = 5
logpath = /var/log/fail2ban.log

[%s]
enabled = true
filter =
banaction = iptables-allports
logpath =
bantime = -1
`, ignore, action, logDir, logDir, logDir, errorJail, manualJail)
}

// f2bActionConf renders the AbuseIPDB report-hook fail2ban action: on ban,
// it shells back into this same revpro binary rather than curl-ing
// AbuseIPDB directly from the action file, so the API key and category
// mapping stay in one place (abuseipdb.go) instead of being duplicated into
// generated shell.
func f2bActionConf(revproPath string) string {
	return fmt.Sprintf(`[Definition]
actionban = %s fail2ban report-hook <ip> <name>
actionunban =
`, revproPath)
}

// warnAboutDockerFail2ban checks for a docker container literally named
// "fail2ban" — a common pattern (e.g. linuxserver/fail2ban) for watching
// the same nginx logs revpro just configured host-level jails for. It's
// only a warning: a containerized fail2ban usually lacks NET_ADMIN/host
// networking, so its bans typically never reach the host's real iptables
// rules at all — but two things tailing the same logs is worth flagging
// either way. Best-effort; docker not being present or reachable is fine.
func warnAboutDockerFail2ban() {
	out, err := exec.Command("docker", "ps", "--filter", "name=^fail2ban$", "--format", "{{.Names}}: {{.Image}}").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return
	}
	warn("also found a docker container watching the same logs: %s", strings.TrimSpace(string(out)))
	warn("a containerized fail2ban usually can't actually block traffic (no NET_ADMIN/host networking) —")
	warn("consider stopping it to avoid two things tailing the same logs: docker stop fail2ban")
}

// f2bSetup installs fail2ban (if needed), writes jail.local + the
// AbuseIPDB action drop-in, and enables+starts the service. Safe to re-run.
func (c *proxyConfig) f2bSetup() error {
	warnAboutDockerFail2ban()
	if !f2bAvailable() {
		info("Installing fail2ban...")
		if err := run("apt-get", "update", "-qq"); err != nil {
			return fmt.Errorf("apt-get update: %w", err)
		}
		if err := run("apt-get", "install", "-y", "fail2ban"); err != nil {
			return fmt.Errorf("apt-get install fail2ban: %w", err)
		}
	}

	if err := os.MkdirAll("/etc/fail2ban/action.d", 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/fail2ban/filter.d", 0o755); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own path for the report-hook action: %w", err)
	}
	if err := os.WriteFile("/etc/fail2ban/action.d/revpro-abuseipdb.conf", []byte(f2bActionConf(exe)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/fail2ban/filter.d/nginx-error-redirect.conf", []byte(errorRedirectFilterConf), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/fail2ban/filter.d/nginx-http-errors.conf", []byte(httpErrorsFilterConf), 0o644); err != nil {
		return err
	}

	ignoreLAN := configRead("REVPRO_F2B_IGNORE_LAN")
	if ignoreLAN == "" {
		ignoreLAN = strings.Join(detectLocalCIDRs(), " ")
	}
	errorHost := configRead("REVPRO_F2B_ERROR_HOST")
	content := f2bJailLocal(c.logDir, ignoreLAN, errorHost)
	if err := os.WriteFile("/etc/fail2ban/jail.local", []byte(content), 0o644); err != nil {
		return err
	}
	ok("Wrote /etc/fail2ban/jail.local (ignoreip: %s)", ignore(content))
	if errorHost != "" {
		ok("Error-redirect trap jail watching %s/%s_access.log", c.logDir, errorHost)
	} else {
		info("No REVPRO_F2B_ERROR_HOST set — skipping the error-redirect trap jail. Set it to your " +
			"$error_redirect_base host (see templates/nginx.conf) to ban IPs that repeatedly land there.")
	}

	if err := run("systemctl", "enable", "--now", "fail2ban"); err != nil {
		return err
	}
	if err := run("systemctl", "restart", "fail2ban"); err != nil {
		return err
	}
	jails := "sshd, nginx-http-auth, nginx-botsearch, nginx-http-errors, recidive, " + manualJail
	if errorHost != "" {
		jails += ", nginx-error-redirect"
	}
	ok("fail2ban installed and running — jails: %s", jails)
	fireWebhook(c, "fail2ban-setup", map[string]any{"logDir": c.logDir, "errorHost": errorHost})
	return nil
}

// ignore extracts the rendered ignoreip line back out of jail.local content,
// purely so f2bSetup's confirmation message can echo what it wrote.
func ignore(jailLocal string) string {
	for _, line := range strings.Split(jailLocal, "\n") {
		if strings.HasPrefix(line, "ignoreip = ") {
			return strings.TrimPrefix(line, "ignoreip = ")
		}
	}
	return "?"
}

// fail2banCmd is 'revpro fail2ban <setup|status|ban|unban|report-hook|guard>'.
func (c *proxyConfig) fail2banCmd(args []string) {
	if len(args) == 0 {
		fail2banUsage()
		return
	}
	switch args[0] {
	case "setup":
		if err := c.f2bSetup(); err != nil {
			fail("fail2ban setup: %v", err)
		}
	case "status":
		jails, err := f2bListJails()
		if err != nil {
			fail("%v", err)
		}
		for _, name := range jails {
			js, err := f2bJailStatus(name)
			if err != nil {
				warn("%s: %v", name, err)
				continue
			}
			info("%-16s banned %d/%d  failed %d/%d  %v", name,
				js.CurrentBanned, js.TotalBanned, js.CurrentFailed, js.TotalFailed, js.BannedIPs)
		}
	case "ban":
		if len(args) < 3 {
			fail("Usage: revpro fail2ban ban <jail> <ip>")
		}
		if err := f2bBan(args[1], args[2]); err != nil {
			fail("%v", err)
		}
		fireWebhook(c, "fail2ban-ban", map[string]any{"ip": args[2], "jail": args[1]})
		ok("Banned %s in %s", args[2], args[1])
	case "unban":
		if len(args) < 3 {
			fail("Usage: revpro fail2ban unban <jail> <ip>")
		}
		if err := f2bUnban(args[1], args[2]); err != nil {
			fail("%v", err)
		}
		ok("Unbanned %s in %s", args[2], args[1])
	case "report-hook":
		// Called by fail2ban itself (see f2bActionConf) — best-effort, never
		// fails the surrounding ban.
		if len(args) < 3 {
			return
		}
		reportHook(args[1], args[2])
	case "guard":
		res, err := c.guardScan(500)
		if err != nil {
			fail("%v", err)
		}
		info("Checked %d, skipped %d (private/already-banned), blocked %d", res.Checked, res.Skipped, len(res.Banned))
		for _, ip := range res.Banned {
			warn("blocked %s", ip)
		}
	case "-h", "--help", "help":
		fail2banUsage()
	default:
		fail("unknown fail2ban command %q — see 'revpro fail2ban help'", args[0])
	}
}

func fail2banUsage() {
	fmt.Print(`revpro fail2ban — set up and control fail2ban for this box

Usage:
  revpro fail2ban setup                 Install fail2ban, write jail.local, enable+start it
  revpro fail2ban status                Show every jail's current/total banned + failed counts
  revpro fail2ban ban <jail> <ip>       Ban an IP in a jail
  revpro fail2ban unban <jail> <ip>     Unban an IP in a jail
  revpro fail2ban guard                 Check recent visitor IPs against AbuseIPDB, ban anything abusive

Config variables (via 'cmnds config write'):
  REVPRO_F2B_IGNORE_LAN       extra ignoreip entries (default: auto-detected private interfaces)
  REVPRO_F2B_ERROR_HOST       your $error_redirect_base host (templates/nginx.conf), e.g.
                               error.example.tld — every site 302s its 4xx/5xx upstream errors
                               there, so frequent hits are a strong scanner signal. Unset = no
                               error-redirect trap jail.
  REVPRO_ABUSEIPDB_KEY        API key from https://www.abuseipdb.com/account/api — required for
                               outbound reporting and 'guard'
  REVPRO_ABUSEIPDB_THRESHOLD  abuseConfidenceScore that triggers a 'guard' ban (default 50)
`)
}

// ---------- "approaching ban" (not banned yet, but getting close) ----------

// jailThresholds mirrors the findtime/maxretry each jail in f2bJailLocal's
// template is written with. fail2ban-client doesn't expose a per-IP
// breakdown of in-progress (not-yet-banned) failure counts, only the
// aggregate "currently failed" count per jail — so approachingBans instead
// tails fail2ban's own log for "Found <IP>" filter matches and does the
// counting itself, which needs to know each jail's own window. Must be
// kept in sync with f2bJailLocal.
var jailThresholds = map[string]struct {
	findtime time.Duration
	maxretry int
}{
	"sshd":                 {10 * time.Minute, 5},
	"nginx-http-auth":      {10 * time.Minute, 5},
	"nginx-botsearch":      {10 * time.Minute, 5},
	"nginx-http-errors":    {10 * time.Minute, 30},
	"nginx-error-redirect": {3 * time.Minute, 8},
}

// approachingIP is one IP that's partway to tripping a jail's maxretry —
// the web UI's "about to be banned" view.
type approachingIP struct {
	IP    string `json:"ip"`
	Jail  string `json:"jail"`
	Count int    `json:"count"`
	Max   int    `json:"max"`
}

// f2bFoundLineRe matches fail2ban.log's own "Found <IP>" filter-match
// lines, e.g.:
//
//	2026-08-30 14:32:10,123 fail2ban.filter [12345]: INFO [nginx-botsearch] Found 203.0.113.9 - 2026-08-30 14:32:10
var f2bFoundLineRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ .*\[([A-Za-z0-9_-]+)\]\s+Found (\S+)`)

// f2bLogPath is a var (not a literal in approachingBans) so tests can point
// it at a fixture file instead of the real /var/log/fail2ban.log.
var f2bLogPath = "/var/log/fail2ban.log"

// approachingBans tails fail2ban's own log, tallies "Found <IP>" matches
// per (jail, IP) within that jail's own findtime window, and returns
// anything at least halfway to that jail's maxretry but not yet banned.
// Best-effort — a missing/unparseable log yields an empty list, not an
// error, since this is a supplementary view, not a control surface.
func approachingBans() []approachingIP {
	lines, err := tailLines(f2bLogPath, 20000)
	if err != nil {
		return nil
	}
	now := time.Now()
	type key struct{ jail, ip string }
	counts := map[key]int{}
	for _, line := range lines {
		m := f2bFoundLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		th, known := jailThresholds[m[2]]
		if !known {
			continue
		}
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
		if err != nil || now.Sub(ts) > th.findtime {
			continue
		}
		counts[key{jail: m[2], ip: m[3]}]++
	}

	var out []approachingIP
	for k, n := range counts {
		th := jailThresholds[k.jail]
		if n >= th.maxretry || n*2 < th.maxretry {
			continue // already over threshold (will show as banned instead), or not "close" yet
		}
		out = append(out, approachingIP{IP: k.ip, Jail: k.jail, Count: n, Max: th.maxretry})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}
