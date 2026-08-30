// abuseipdb.go — two directions of AbuseIPDB integration:
//
//  1. Outbound (autoreport): whenever a local fail2ban jail bans an IP for
//     something *we* observed (bad SSH logins, bot-search probing our
//     sites, a manual/guard ban), report it to AbuseIPDB so the community
//     database reflects it too. Wired via the 'revpro-abuseipdb' fail2ban
//     action (see fail2ban.go's f2bActionConf) calling back into
//     'revpro fail2ban report-hook'.
//  2. Inbound (autocheck + autoblock): IPs seen in our own access logs are
//     checked against AbuseIPDB's existing reputation data; anything at or
//     above the configured confidence threshold gets banned into the
//     ban-only 'revpro-manual' jail. This never runs unattended by
//     default — it's the web UI's "Check & block abusive IPs" button
//     (POST /api/security/guard), a deliberate human trigger rather than a
//     background loop that could silently block something important.
//
// Both directions need REVPRO_ABUSEIPDB_KEY (a free AbuseIPDB API key,
// https://www.abuseipdb.com/account/api) — everything here is a no-op
// until that's set.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// abuseIPDBBase is a var (not const) so tests can point it at an
// httptest.Server instead of the real API.
var abuseIPDBBase = "https://api.abuseipdb.com/api/v2"

// defaultAbuseThreshold is AbuseIPDB's own commonly-recommended cutoff for
// "confident enough to act on" — used when REVPRO_ABUSEIPDB_THRESHOLD isn't set.
const defaultAbuseThreshold = 50

func abuseIPDBKey() string { return configRead("REVPRO_ABUSEIPDB_KEY") }

func f2bAbuseIPDBConfigured() bool { return abuseIPDBKey() != "" }

func abuseThreshold() int {
	if n, err := strconv.Atoi(configRead("REVPRO_ABUSEIPDB_THRESHOLD")); err == nil && n > 0 {
		return n
	}
	return defaultAbuseThreshold
}

// abuseCategories maps a fail2ban jail name to AbuseIPDB's report category
// IDs (https://www.abuseipdb.com/categories). Unmapped jails fall back to
// 15 (Hacking) — generic but still meaningful.
var abuseCategories = map[string][]int{
	"sshd":                 {18, 22}, // Brute-Force, SSH
	"nginx-http-auth":      {21},     // Web App Attack
	"nginx-botsearch":      {19, 21}, // Bad Web Bot, Web App Attack
	"nginx-http-errors":    {21},     // Web App Attack (excessive 4xx/5xx — probing/scraping)
	"nginx-error-redirect": {19, 21}, // Bad Web Bot (repeatedly landing on the shared error page)
	"recidive":             {15},     // Hacking (repeat offender, cause already reported once)
	manualJail:             {19},     // Bad Web Bot (manual/guard bans are traffic-pattern driven)
}

func abuseCategoriesFor(jail string) []int {
	if c, ok := abuseCategories[jail]; ok {
		return c
	}
	return []int{15}
}

// ---------- check ----------

type abuseCheckResult struct {
	IP            string    `json:"ip"`
	Score         int       `json:"score"` // abuseConfidenceScore, 0-100
	TotalReports  int       `json:"totalReports"`
	CountryCode   string    `json:"countryCode,omitempty"`
	IsWhitelisted bool      `json:"isWhitelisted"`
	CheckedAt     time.Time `json:"checkedAt"`
}

// abuseCache is a small disk-backed cache (keyed by IP) so the guard scan
// and IP-table view don't re-spend AbuseIPDB's free-tier quota (1000
// checks/day) on the same addresses every time the page loads.
func (c *proxyConfig) abuseCacheFile() string {
	return filepath.Join(c.mainFolder, "abuseipdb-cache.json")
}

func (c *proxyConfig) loadAbuseCache() map[string]abuseCheckResult {
	data, err := os.ReadFile(c.abuseCacheFile())
	if err != nil {
		return map[string]abuseCheckResult{}
	}
	m := map[string]abuseCheckResult{}
	if json.Unmarshal(data, &m) != nil {
		return map[string]abuseCheckResult{}
	}
	return m
}

func (c *proxyConfig) saveAbuseCache(m map[string]abuseCheckResult) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.abuseCacheFile(), data, 0o644)
}

// abuseCheckCached returns a cached result younger than maxAge, fetching
// and caching a fresh one from AbuseIPDB otherwise. A cache-only lookup
// (skip the network entirely) is available by passing maxAge <= 0 with an
// already-populated cache map from the caller.
func abuseCheckCached(cache map[string]abuseCheckResult, ip string, maxAge time.Duration) (abuseCheckResult, error) {
	if r, ok := cache[ip]; ok && time.Since(r.CheckedAt) < maxAge {
		return r, nil
	}
	r, err := abuseCheckLive(ip)
	if err != nil {
		return abuseCheckResult{}, err
	}
	cache[ip] = r
	return r, nil
}

func abuseCheckLive(ip string) (abuseCheckResult, error) {
	key := abuseIPDBKey()
	if key == "" {
		return abuseCheckResult{}, fmt.Errorf("AbuseIPDB is not configured (REVPRO_ABUSEIPDB_KEY unset)")
	}
	return abuseCheckWithKey(ip, key)
}

// abuseCheckWithKey does the actual HTTP call + parsing, key already in
// hand — split out from abuseCheckLive so tests can exercise it without
// going through configRead (which shells out to the real 'cmnds' binary).
func abuseCheckWithKey(ip, key string) (abuseCheckResult, error) {
	req, err := http.NewRequest("GET", abuseIPDBBase+"/check?"+url.Values{
		"ipAddress":    {ip},
		"maxAgeInDays": {"90"},
	}.Encode(), nil)
	if err != nil {
		return abuseCheckResult{}, err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return abuseCheckResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return abuseCheckResult{}, fmt.Errorf("AbuseIPDB check %s: %s: %s", ip, resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			CountryCode          string `json:"countryCode"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return abuseCheckResult{}, fmt.Errorf("AbuseIPDB check %s: bad response: %w", ip, err)
	}
	return abuseCheckResult{
		IP: ip, Score: parsed.Data.AbuseConfidenceScore, TotalReports: parsed.Data.TotalReports,
		CountryCode: parsed.Data.CountryCode, IsWhitelisted: parsed.Data.IsWhitelisted, CheckedAt: time.Now(),
	}, nil
}

// ---------- report ----------

// abuseReport submits a report for ip under the given category IDs. comment
// should not include secrets — it's stored by AbuseIPDB and shown publicly
// alongside the report.
func abuseReport(ip string, categories []int, comment string) error {
	key := abuseIPDBKey()
	if key == "" {
		return fmt.Errorf("AbuseIPDB is not configured (REVPRO_ABUSEIPDB_KEY unset)")
	}
	return abuseReportWithKey(ip, categories, comment, key)
}

// abuseReportWithKey does the actual HTTP call, key already in hand — split
// out from abuseReport for the same testability reason as abuseCheckWithKey.
func abuseReportWithKey(ip string, categories []int, comment, key string) error {
	cats := make([]string, len(categories))
	for i, c := range categories {
		cats[i] = strconv.Itoa(c)
	}
	form := url.Values{"ip": {ip}, "categories": {strings.Join(cats, ",")}, "comment": {comment}}

	req, err := http.NewRequest("POST", abuseIPDBBase+"/report", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AbuseIPDB report %s: %s: %s", ip, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// reportHook is 'revpro fail2ban report-hook <ip> <jail>' — the fail2ban
// action's actionban callback. Best-effort: a reporting failure (rate
// limit, network blip) must never fail the ban itself, so it only warns.
func reportHook(ip, jail string) {
	if !f2bAbuseIPDBConfigured() {
		return
	}
	comment := fmt.Sprintf("Banned by revpro/fail2ban jail '%s'", jail)
	if err := abuseReport(ip, abuseCategoriesFor(jail), comment); err != nil {
		warn("AbuseIPDB report for %s failed: %v", ip, err)
		return
	}
	ok("Reported %s to AbuseIPDB (jail: %s)", ip, jail)
}

// ---------- guard scan (inbound: check our recent visitors, block the abusive ones) ----------

type guardResult struct {
	Checked int      `json:"checked"`
	Skipped int      `json:"skipped"` // private/LAN/already-banned, not sent to AbuseIPDB
	Banned  []string `json:"banned"`
}

// guardScan checks every IP seen in the access logs (via ipAccessStats)
// against AbuseIPDB and bans (into manualJail) anything at or above the
// confidence threshold. Already-banned IPs and private/loopback addresses
// are skipped without spending API quota on them. Human-triggered only
// (see the package doc) — never called from a timer in this codebase.
func (c *proxyConfig) guardScan(limit int) (guardResult, error) {
	if !f2bAvailable() {
		return guardResult{}, fmt.Errorf("fail2ban is not set up yet — run Set up fail2ban first")
	}
	if !f2bAbuseIPDBConfigured() {
		return guardResult{}, fmt.Errorf("AbuseIPDB is not configured — add an API key first")
	}
	stats, err := c.ipAccessStats(limit)
	if err != nil {
		return guardResult{}, err
	}

	alreadyBanned := map[string]bool{}
	if jails, err := f2bListJails(); err == nil {
		for _, jn := range jails {
			if js, err := f2bJailStatus(jn); err == nil {
				for _, ip := range js.BannedIPs {
					alreadyBanned[ip] = true
				}
			}
		}
	}

	cache := c.loadAbuseCache()
	threshold := abuseThreshold()
	res := guardResult{}
	for _, st := range stats {
		if isPrivateOrLoopback(st.IP) || alreadyBanned[st.IP] {
			res.Skipped++
			continue
		}
		check, err := abuseCheckCached(cache, st.IP, 24*time.Hour)
		if err != nil {
			warn("AbuseIPDB check %s: %v", st.IP, err)
			continue
		}
		res.Checked++
		if check.Score >= threshold && !check.IsWhitelisted {
			if err := f2bBan(manualJail, st.IP); err != nil {
				warn("ban %s: %v", st.IP, err)
				continue
			}
			res.Banned = append(res.Banned, st.IP)
			ok("Blocked %s (AbuseIPDB score %d)", st.IP, check.Score)
			fireWebhook(c, "guard-blocked", map[string]any{"ip": st.IP, "score": check.Score})
		}
	}
	if err := c.saveAbuseCache(cache); err != nil {
		warn("save AbuseIPDB cache: %v", err)
	}
	return res, nil
}
