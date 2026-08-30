// geoip.go — best-effort IP → country/city lookup for the IP access table,
// via ipapi.co's free, no-signup API (unlike AbuseIPDB, no key needed).
// Results are cached to disk indefinitely-ish (geo rarely changes for a
// given IP) so the table doesn't re-query the same visitors on every page
// load — ipapi.co's free tier is limited to ~30k requests/month.
//
// This sends visitor IP addresses to a third-party service. That's the
// necessary tradeoff for geolocation without self-hosting a GeoIP database;
// it only fires for addresses actually seen in this box's own access logs.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type geoInfo struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country,omitempty"`
	CountryCode string    `json:"countryCode,omitempty"`
	City        string    `json:"city,omitempty"`
	Local       bool      `json:"local,omitempty"` // private/loopback — never looked up
	LookedUpAt  time.Time `json:"lookedUpAt"`
}

const geoCacheTTL = 30 * 24 * time.Hour

func (c *proxyConfig) geoCacheFile() string {
	return filepath.Join(c.mainFolder, "geoip-cache.json")
}

func (c *proxyConfig) loadGeoCache() map[string]geoInfo {
	data, err := os.ReadFile(c.geoCacheFile())
	if err != nil {
		return map[string]geoInfo{}
	}
	m := map[string]geoInfo{}
	if json.Unmarshal(data, &m) != nil {
		return map[string]geoInfo{}
	}
	return m
}

func (c *proxyConfig) saveGeoCache(m map[string]geoInfo) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.geoCacheFile(), data, 0o644)
}

// geoLookupCached returns a cached entry when fresh, a synthetic "local"
// entry for private/loopback IPs (no network call), or fetches+caches a
// fresh lookup from ipapi.co.
func geoLookupCached(cache map[string]geoInfo, ip string) (geoInfo, error) {
	if g, ok := cache[ip]; ok && time.Since(g.LookedUpAt) < geoCacheTTL {
		return g, nil
	}
	if isPrivateOrLoopback(ip) {
		g := geoInfo{IP: ip, Local: true, LookedUpAt: time.Now()}
		cache[ip] = g
		return g, nil
	}
	g, err := geoLookupLive(ip)
	if err != nil {
		return geoInfo{}, err
	}
	cache[ip] = g
	return g, nil
}

// geoIPBase is a var (not a literal in geoLookupLive) so tests can point it
// at an httptest.Server instead of the real ipapi.co.
var geoIPBase = "https://ipapi.co"

func geoLookupLive(ip string) (geoInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(geoIPBase + "/" + ip + "/json/")
	if err != nil {
		return geoInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return geoInfo{}, fmt.Errorf("ipapi.co %s: %s: %s", ip, resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Country     string `json:"country_name"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		Error       bool   `json:"error"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return geoInfo{}, fmt.Errorf("ipapi.co %s: bad response: %w", ip, err)
	}
	if parsed.Error {
		return geoInfo{}, fmt.Errorf("ipapi.co %s: %s", ip, parsed.Reason)
	}
	return geoInfo{
		IP: ip, Country: parsed.Country, CountryCode: parsed.CountryCode, City: parsed.City,
		LookedUpAt: time.Now(),
	}, nil
}
