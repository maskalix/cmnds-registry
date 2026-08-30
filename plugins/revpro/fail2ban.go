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
	"strconv"
	"strings"
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
// every port, not just one service's.
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

// f2bJailLocal renders /etc/fail2ban/jail.local. ignoreLAN is a
// space-separated list of extra CIDRs/IPs to never ban (in addition to
// loopback) — normally this box's own detected private-network address(es).
func f2bJailLocal(logDir, ignoreLAN string) string {
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
`, ignore, action, logDir, logDir, manualJail)
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
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own path for the report-hook action: %w", err)
	}
	if err := os.WriteFile("/etc/fail2ban/action.d/revpro-abuseipdb.conf", []byte(f2bActionConf(exe)), 0o644); err != nil {
		return err
	}

	ignoreLAN := configRead("REVPRO_F2B_IGNORE_LAN")
	if ignoreLAN == "" {
		ignoreLAN = strings.Join(detectLocalCIDRs(), " ")
	}
	content := f2bJailLocal(c.logDir, ignoreLAN)
	if err := os.WriteFile("/etc/fail2ban/jail.local", []byte(content), 0o644); err != nil {
		return err
	}
	ok("Wrote /etc/fail2ban/jail.local (ignoreip: %s)", ignore(content))

	if err := run("systemctl", "enable", "--now", "fail2ban"); err != nil {
		return err
	}
	if err := run("systemctl", "restart", "fail2ban"); err != nil {
		return err
	}
	ok("fail2ban installed and running — jails: sshd, nginx-http-auth, nginx-botsearch, recidive, %s", manualJail)
	fireWebhook(c, "fail2ban-setup", map[string]any{"logDir": c.logDir})
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
  REVPRO_ABUSEIPDB_KEY        API key from https://www.abuseipdb.com/account/api — required for
                               outbound reporting and 'guard'
  REVPRO_ABUSEIPDB_THRESHOLD  abuseConfidenceScore that triggers a 'guard' ban (default 50)
`)
}
