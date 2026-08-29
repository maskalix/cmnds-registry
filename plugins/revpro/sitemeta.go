// sitemeta.go — a small sidecar file for per-site display name, tags, and
// freeform notes. Kept entirely separate from sites.conf: that file stays the
// single source of truth for routing (and hand-editable/minimal-noise), while
// this is a UI-only overlay the web UI reads and writes.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// siteMeta is one site's UI-layer metadata, keyed by fqdn in the sidecar file.
type siteMeta struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
	Note string   `json:"note,omitempty"`
}

func (sm siteMeta) isEmpty() bool {
	return sm.Name == "" && sm.Note == "" && len(sm.Tags) == 0
}

func (c *proxyConfig) siteMetaFile() string {
	return filepath.Join(c.mainFolder, "site-meta.json")
}

// loadSiteMeta reads the sidecar file. A missing file is not an error — it
// just means nothing has been annotated yet.
func (c *proxyConfig) loadSiteMeta() (map[string]siteMeta, error) {
	data, err := os.ReadFile(c.siteMetaFile())
	if os.IsNotExist(err) {
		return map[string]siteMeta{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]siteMeta{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *proxyConfig) saveSiteMeta(m map[string]siteMeta) error {
	// Drop empty entries so the file doesn't accumulate cruft as sites come
	// and go, or as their last field gets cleared out.
	for k, v := range m {
		if v.isEmpty() {
			delete(m, k)
		}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.mainFolder, 0o755); err != nil {
		return err
	}
	return os.WriteFile(c.siteMetaFile(), data, 0o644)
}

// setSiteMeta upserts one fqdn's metadata (normalizing tags), or removes its
// entry entirely if the result is empty.
func (c *proxyConfig) setSiteMeta(fqdn string, sm siteMeta) error {
	m, err := c.loadSiteMeta()
	if err != nil {
		return err
	}
	sm.Name = strings.TrimSpace(sm.Name)
	sm.Note = strings.TrimSpace(sm.Note)
	sm.Tags = normalizeTags(sm.Tags)
	if sm.isEmpty() {
		delete(m, fqdn)
	} else {
		m[fqdn] = sm
	}
	return c.saveSiteMeta(m)
}

// normalizeTags trims, drops empties, case-insensitively dedupes, and sorts.
func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		key := strings.ToLower(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
