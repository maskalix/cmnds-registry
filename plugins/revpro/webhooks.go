// webhooks.go — outbound notifications fired on specific revpro occasions
// (cert issued/renewed/failed, a site added, a fail2ban ban, fail2ban
// setup completing, a guard-scan block, a routine failing). Configured
// entirely from the web UI: each webhook has a URL, a type (generic JSON
// POST, or Discord's webhook message format), and the set of events it
// subscribes to.
//
// Delivery is synchronous but bounded (an 8s timeout) and best-effort — a
// delivery failure is logged, never returned to the caller. Firing a
// webhook must never be able to fail (or even meaningfully delay) the
// action that triggered it, and most call sites are short-lived CLI
// subprocesses that would drop an unfinished background goroutine on exit,
// so "synchronous but bounded" is the right shape here, not fire-and-forget.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type webhookConfig struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	URL    string   `json:"url"`
	Type   string   `json:"type"` // "generic" or "discord"
	Events []string `json:"events"`
}

// knownWebhookEvents is the fixed set of occasions a webhook can subscribe
// to — surfaced to the web UI as the checklist for each webhook.
var knownWebhookEvents = []string{
	"cert-issued", "cert-issue-failed", "cert-renewed", "cert-renew-failed",
	"site-added", "fail2ban-ban", "fail2ban-setup", "guard-blocked", "routine-failed",
}

func (c *proxyConfig) webhooksFile() string {
	return filepath.Join(c.mainFolder, "webhooks.json")
}

func (c *proxyConfig) loadWebhooks() []webhookConfig {
	data, err := os.ReadFile(c.webhooksFile())
	if err != nil {
		return nil
	}
	var list []webhookConfig
	if json.Unmarshal(data, &list) != nil {
		return nil
	}
	return list
}

func (c *proxyConfig) saveWebhooks(list []webhookConfig) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.webhooksFile(), data, 0o644)
}

// webhookBackoffUntil tracks, per webhook ID, when it's next OK to try
// delivering again after a 429 — process-lifetime, in-memory. A single
// 'revpro fail2ban guard' or bulk-add run can fire dozens of events in a
// tight loop within one process, which is exactly when a chatty target
// like Discord starts rate-limiting; without this, every remaining event
// in that same run would repeat the identical failed call. Keyed by ID
// (not URL) so renaming a webhook doesn't lose its backoff.
var (
	webhookBackoffUntil = map[string]time.Time{}
	webhookBackoffMu    sync.Mutex
)

// fireWebhook records event to the audit log and delivers it to every
// configured webhook subscribed to it. Every occasion revpro cares about
// enough to have an event name for already flows through here, so this one
// call site gives the web UI's Activity log full coverage for free — a
// webhook subscriber isn't required for the event to be recorded.
func fireWebhook(c *proxyConfig, event string, fields map[string]any) {
	c.appendAudit(event, fields)
	for _, wh := range c.loadWebhooks() {
		if !containsStr(wh.Events, event) {
			continue
		}
		if until, backingOff := webhookInBackoff(wh.ID); backingOff {
			warn("webhook %q: skipping (rate-limited until %s)", wh.Name, until.Format(time.TimeOnly))
			continue
		}
		retryAfter, err := deliverWebhook(wh, event, fields)
		if err != nil {
			warn("webhook %q: %v", wh.Name, err)
		}
		if retryAfter > 0 {
			setWebhookBackoff(wh.ID, retryAfter)
		}
	}
}

func webhookInBackoff(id string) (time.Time, bool) {
	webhookBackoffMu.Lock()
	defer webhookBackoffMu.Unlock()
	until, ok := webhookBackoffUntil[id]
	if !ok || time.Now().After(until) {
		return time.Time{}, false
	}
	return until, true
}

func setWebhookBackoff(id string, d time.Duration) {
	webhookBackoffMu.Lock()
	defer webhookBackoffMu.Unlock()
	webhookBackoffUntil[id] = time.Now().Add(d)
}

// ---------- audit log ----------

// auditEntry is one recorded occasion — the web UI's "Activity" log.
type auditEntry struct {
	Time   time.Time      `json:"time"`
	Event  string         `json:"event"`
	Fields map[string]any `json:"fields,omitempty"`
}

func (c *proxyConfig) auditLogFile() string {
	return filepath.Join(c.mainFolder, "audit.log")
}

// maxAuditEntries caps how large audit.log is allowed to grow before
// appendAudit compacts it back down to the most recent entries — cheap
// insurance on a box that might run for years without a restart.
const maxAuditEntries = 5000

// appendAudit records one JSON-lines entry. Best-effort: a logging failure
// must never be visible to (or able to fail) the action being recorded.
func (c *proxyConfig) appendAudit(event string, fields map[string]any) {
	data, err := json.Marshal(auditEntry{Time: time.Now(), Event: event, Fields: fields})
	if err != nil {
		return
	}
	f, err := os.OpenFile(c.auditLogFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	f.Write(append(data, '\n'))
	f.Close()

	if fi, err := os.Stat(c.auditLogFile()); err == nil && fi.Size() > int64(maxAuditEntries)*512 {
		c.compactAuditLog()
	}
}

// compactAuditLog rewrites audit.log to just its most recent
// maxAuditEntries lines, so an old, busy install's log can't grow forever.
func (c *proxyConfig) compactAuditLog() {
	lines, err := tailLines(c.auditLogFile(), maxAuditEntries)
	if err != nil {
		return
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	_ = os.WriteFile(c.auditLogFile(), []byte(content), 0o644)
}

// recentAudit returns the `limit` most recent audit entries, newest first.
func (c *proxyConfig) recentAudit(limit int) ([]auditEntry, error) {
	lines, err := tailLines(c.auditLogFile(), limit)
	if err != nil {
		return nil, err
	}
	out := make([]auditEntry, 0, len(lines))
	for _, line := range lines {
		var e auditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// deliverWebhook POSTs event to wh. The returned duration is only ever
// non-zero on a 429 (rate limited) response — how long the caller should
// back off this webhook before trying again — so a caller firing many
// events in one loop (a guard scan blocking dozens of IPs) can stop
// repeating a call it already knows will fail instead of hammering the
// target with the exact same request over and over.
func deliverWebhook(wh webhookConfig, event string, fields map[string]any) (retryAfter time.Duration, err error) {
	var body []byte
	switch wh.Type {
	case "discord":
		body, err = json.Marshal(discordEmbed(event, fields))
	default:
		payload := map[string]any{"event": event, "time": time.Now().Format(time.RFC3339)}
		for k, v := range fields {
			payload[k] = v
		}
		body, err = json.Marshal(payload)
	}
	if err != nil {
		return 0, fmt.Errorf("encode: %w", err)
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("delivery failed: %s", resp.Status)
	}
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("delivery failed: %s", resp.Status)
	}
	return 0, nil
}

// defaultRetryAfter is used when a 429 response carries no Retry-After
// header at all (or an unparseable one) — a conservative guess.
const defaultRetryAfter = 60 * time.Second

// parseRetryAfter reads a Retry-After header value, which per RFC 9110 is
// either a number of seconds or an HTTP-date.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return defaultRetryAfter
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return defaultRetryAfter
}

// discordEventMeta is the human title + accent color a Discord embed uses
// for one event — a plain "content" string reads as noise next to
// everything else in a busy alerts channel, so revpro always sends a
// proper embed instead.
type discordEventMeta struct {
	Title string
	Color int // decimal RGB, e.g. 0x2ecc71
}

var discordEventInfo = map[string]discordEventMeta{
	"cert-issued":       {"✅ Certificate issued", 0x2ecc71},
	"cert-issue-failed": {"❌ Certificate issue failed", 0xe74c3c},
	"cert-renewed":      {"✅ Certificate renewed", 0x2ecc71},
	"cert-renew-failed": {"❌ Certificate renewal failed", 0xe74c3c},
	"site-added":        {"➕ Site added", 0x3498db},
	"fail2ban-ban":      {"🔒 IP banned", 0xe67e22},
	"fail2ban-unban":    {"🔓 IP unbanned", 0x95a5a6},
	"fail2ban-setup":    {"🛡️ fail2ban set up", 0x2ecc71},
	"guard-blocked":     {"🚫 AbuseIPDB guard blocked an IP", 0xe67e22},
	"routine-failed":    {"⚠️ Routine failed", 0xe74c3c},
	"test":              {"🔔 Test notification", 0x7289da},
}

const discordDefaultColor = 0x7289da // Discord's own "blurple", for unmapped events

// discordEmbed renders event+fields as a single Discord embed: a colored
// title bar (green for success, red for failure/warning, matching the
// event) and one field per data point, so an alerts channel stays scannable
// instead of a wall of plain-text lines.
func discordEmbed(event string, fields map[string]any) map[string]any {
	meta, ok := discordEventInfo[event]
	if !ok {
		meta = discordEventMeta{Title: "revpro — " + event, Color: discordDefaultColor}
	}
	embedFields := make([]map[string]any, 0, len(fields))
	for _, k := range sortedKeysAny(fields) {
		embedFields = append(embedFields, map[string]any{
			"name": fieldTitle(k), "value": fmt.Sprintf("%v", fields[k]), "inline": true,
		})
	}
	return map[string]any{
		"embeds": []map[string]any{{
			"title":     meta.Title,
			"color":     meta.Color,
			"fields":    embedFields,
			"footer":    map[string]any{"text": "revpro"},
			"timestamp": time.Now().Format(time.RFC3339),
		}},
	}
}

// fieldTitle turns a camelCase/snake_case field key into "Title Case" for
// display (jail -> Jail, countryCode -> Country Code).
func fieldTitle(key string) string {
	var b strings.Builder
	for i, r := range key {
		switch {
		case r == '_':
			b.WriteByte(' ')
		case i > 0 && r >= 'A' && r <= 'Z':
			b.WriteByte(' ')
			b.WriteRune(r)
		case i == 0:
			b.WriteRune(unicodeToUpper(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unicodeToUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - ('a' - 'A')
	}
	return r
}

func sortedKeysAny(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
