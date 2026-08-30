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

// fireWebhook delivers event to every configured webhook subscribed to it.
// c may be nil-safe callers should never pass nil, but every call site here
// is a *proxyConfig method or has one in scope, so this stays a plain
// parameter rather than a global for testability.
func fireWebhook(c *proxyConfig, event string, fields map[string]any) {
	for _, wh := range c.loadWebhooks() {
		if !containsStr(wh.Events, event) {
			continue
		}
		if err := deliverWebhook(wh, event, fields); err != nil {
			warn("webhook %q: %v", wh.Name, err)
		}
	}
}

func deliverWebhook(wh webhookConfig, event string, fields map[string]any) error {
	var body []byte
	var err error
	switch wh.Type {
	case "discord":
		body, err = json.Marshal(map[string]any{"content": discordMessage(event, fields)})
	default:
		payload := map[string]any{"event": event, "time": time.Now().Format(time.RFC3339)}
		for k, v := range fields {
			payload[k] = v
		}
		body, err = json.Marshal(payload)
	}
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("delivery failed: %s", resp.Status)
	}
	return nil
}

// discordMessage renders event+fields as a Discord webhook's plain
// "content" string — simple and readable rather than a full embed, since
// the field set varies per event.
func discordMessage(event string, fields map[string]any) string {
	msg := "**revpro** — " + event
	for _, k := range sortedKeysAny(fields) {
		msg += fmt.Sprintf("\n%s: %v", k, fields[k])
	}
	return msg
}

func sortedKeysAny(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
