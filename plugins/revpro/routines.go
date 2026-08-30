// routines.go — a lightweight, interval-based scheduler for the periodic
// jobs revpro can run on its own: cert renewal, the AbuseIPDB guard scan,
// health analysis, and cache pruning. Configured entirely from the web UI
// (enable + "every N minutes" per task, not a full cron-expression editor —
// nothing here needs finer control than that). 'revpro routines setup'
// installs a small daemon (revpro-routines.service) that wakes up once a
// minute and runs whatever is due, each as its own subprocess of this
// binary — the same isolation the web UI's streamed actions use, so one
// failing task can't take the scheduler itself down.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type routineTask struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// knownRoutines is the fixed catalog of tasks revpro can schedule.
var knownRoutines = []routineTask{
	{ID: "renew", Name: "Renew certificates", Description: "Renew near-expiry certs, then regenerate + reload"},
	{ID: "regenerate", Name: "Regenerate configs", Description: "Clean, rebuild every site config, reload nginx"},
	{ID: "analyze", Name: "Analyze all sites", Description: "Health check every site: cert, config, upstream reachability"},
	{ID: "f2b-guard", Name: "AbuseIPDB check & block", Description: "Check recent visitor IPs against AbuseIPDB, ban anything abusive"},
	{ID: "prune-cache", Name: "Prune geo/AbuseIPDB caches", Description: "Drop expired entries from the on-disk lookup caches"},
}

func routineArgs(id string) []string {
	switch id {
	case "renew":
		return []string{"renew"}
	case "regenerate":
		return []string{"regenerate"}
	case "analyze":
		return []string{"analyze"}
	case "f2b-guard":
		return []string{"fail2ban", "guard"}
	case "prune-cache":
		return []string{"cache", "prune"}
	default:
		return nil
	}
}

// routineConfig is one task's schedule + last-run bookkeeping, persisted in
// routines.json keyed by task ID.
type routineConfig struct {
	Enabled         bool      `json:"enabled"`
	IntervalMinutes int       `json:"intervalMinutes"`
	LastRun         time.Time `json:"lastRun,omitempty"`
	LastStatus      string    `json:"lastStatus,omitempty"` // "ok" or an error message
}

func (c *proxyConfig) routinesFile() string {
	return filepath.Join(c.mainFolder, "routines.json")
}

func (c *proxyConfig) loadRoutineConfigs() map[string]routineConfig {
	data, err := os.ReadFile(c.routinesFile())
	if err != nil {
		return map[string]routineConfig{}
	}
	m := map[string]routineConfig{}
	if json.Unmarshal(data, &m) != nil {
		return map[string]routineConfig{}
	}
	return m
}

func (c *proxyConfig) saveRoutineConfigs(m map[string]routineConfig) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.routinesFile(), data, 0o644)
}

// dueRoutineIDs reports which known, enabled routines are due to run —
// pure function of the config + now, so it's testable without touching
// subprocesses or the filesystem's mtimes.
func dueRoutineIDs(cfg map[string]routineConfig, now time.Time) []string {
	var due []string
	for _, task := range knownRoutines {
		rc, ok := cfg[task.ID]
		if !ok || !rc.Enabled || rc.IntervalMinutes <= 0 {
			continue
		}
		if rc.LastRun.IsZero() || now.Sub(rc.LastRun) >= time.Duration(rc.IntervalMinutes)*time.Minute {
			due = append(due, task.ID)
		}
	}
	return due
}

// runRoutineNow runs one task immediately as a subprocess of this binary
// (never in-process — several routine targets, like 'renew' and
// 'regenerate', call fail()/os.Exit on error, which must not be able to
// take the long-running scheduler daemon down with them).
func runRoutineNow(id string) error {
	args := routineArgs(id)
	if args == nil {
		return fmt.Errorf("unknown routine %q", id)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.Command(exe, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(lastLines(string(out), 5)))
	}
	return nil
}

// lastLines returns at most n trailing lines of s, so a routine failure's
// recorded status stays a short summary rather than a whole command's output.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// runDueRoutines runs every due, enabled routine, records the result, and
// fires the 'routine-failed' webhook for anything that errored.
func (c *proxyConfig) runDueRoutines() {
	cfg := c.loadRoutineConfigs()
	now := time.Now()
	dirty := false
	for _, id := range dueRoutineIDs(cfg, now) {
		info("routine: running %s", id)
		err := runRoutineNow(id)
		rc := cfg[id]
		rc.LastRun = now
		if err != nil {
			rc.LastStatus = err.Error()
			warn("routine %s failed: %v", id, err)
			fireWebhook(c, "routine-failed", map[string]any{"routine": id, "error": err.Error()})
		} else {
			rc.LastStatus = "ok"
		}
		cfg[id] = rc
		dirty = true
	}
	if dirty {
		if err := c.saveRoutineConfigs(cfg); err != nil {
			warn("save routines.json: %v", err)
		}
	}
}

// routinesSetup installs revpro-routines.service, a small daemon that
// checks once a minute for due routines. Safe to re-run.
func (c *proxyConfig) routinesSetup() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=revpro scheduled routines
After=network.target

[Service]
Type=simple
ExecStart=%s routines daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, exe)
	if err := os.WriteFile("/etc/systemd/system/revpro-routines.service", []byte(unit), 0o644); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", "revpro-routines"); err != nil {
		return err
	}
	ok("revpro-routines.service installed and running (checks every minute for due routines)")
	return nil
}

func routinesServiceInstalled() bool {
	_, err := os.Stat("/etc/systemd/system/revpro-routines.service")
	return err == nil
}

// routinesCmd is 'revpro routines <setup|daemon|run|list>'.
func (c *proxyConfig) routinesCmd(args []string) {
	if len(args) == 0 {
		routinesUsage()
		return
	}
	switch args[0] {
	case "setup":
		if err := c.routinesSetup(); err != nil {
			fail("routines setup: %v", err)
		}
	case "daemon":
		info("routines daemon started — checking every minute for due tasks")
		for {
			c.runDueRoutines()
			time.Sleep(time.Minute)
		}
	case "run":
		if len(args) < 2 {
			fail("Usage: revpro routines run <id>")
		}
		if err := runRoutineNow(args[1]); err != nil {
			fail("%v", err)
		}
		ok("ran %s", args[1])
	case "list":
		for _, t := range knownRoutines {
			info("%-14s %s", t.ID, t.Description)
		}
	case "-h", "--help", "help":
		routinesUsage()
	default:
		fail("unknown routines command %q — see 'revpro routines help'", args[0])
	}
}

func routinesUsage() {
	fmt.Print(`revpro routines — schedule revpro's own periodic maintenance

Usage:
  revpro routines setup       Install the scheduler daemon (revpro-routines.service)
  revpro routines list        List every schedulable task
  revpro routines run <id>    Run one task immediately
  revpro routines daemon      Run the scheduler loop in the foreground (used by the systemd unit)

Enable/disable tasks and set their interval from the web UI's Security → Routines panel.
`)
}

// ---------- cache maintenance ----------

// pruneCaches drops expired entries from the geoIP and AbuseIPDB disk
// caches — the 'prune-cache' routine's target.
func (c *proxyConfig) pruneCaches() {
	geo := c.loadGeoCache()
	before := len(geo)
	for ip, g := range geo {
		if time.Since(g.LookedUpAt) > geoCacheTTL {
			delete(geo, ip)
		}
	}
	if len(geo) != before {
		if err := c.saveGeoCache(geo); err != nil {
			warn("save geoip cache: %v", err)
		}
	}

	abuse := c.loadAbuseCache()
	beforeA := len(abuse)
	const abuseCacheTTL = 30 * 24 * time.Hour
	for ip, a := range abuse {
		if time.Since(a.CheckedAt) > abuseCacheTTL {
			delete(abuse, ip)
		}
	}
	if len(abuse) != beforeA {
		if err := c.saveAbuseCache(abuse); err != nil {
			warn("save abuseipdb cache: %v", err)
		}
	}
	ok("pruned geoip cache %d → %d, abuseipdb cache %d → %d", before, len(geo), beforeA, len(abuse))
}

// cacheCmd is 'revpro cache prune'.
func (c *proxyConfig) cacheCmd(args []string) {
	if len(args) == 0 || args[0] != "prune" {
		fmt.Print("Usage: revpro cache prune\n")
		return
	}
	c.pruneCaches()
}
