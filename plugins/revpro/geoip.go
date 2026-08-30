// geoip.go — best-effort IP → country/city/ISP lookup for the IP access
// table, via ip-api.com's free, no-signup API (unlike AbuseIPDB, no key
// needed — and unlike ipapi.co's free tier, it includes ISP/org data).
// Results are cached to disk indefinitely-ish (geo rarely changes for a
// given IP) so the table doesn't re-query the same visitors on every page
// load — ip-api.com's free tier is limited to 45 requests/minute.
//
// This sends visitor IP addresses to a third-party service, over plain
// HTTP (ip-api.com's free anonymous tier doesn't offer HTTPS) — that's the
// necessary tradeoff for geolocation + ISP data without self-hosting a
// GeoIP database. It only fires for addresses actually seen in this box's
// own access logs, and IP addresses are the only thing sent.
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
	ISP         string    `json:"isp,omitempty"`
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
// fresh lookup from ip-api.com.
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
// at an httptest.Server instead of the real ip-api.com.
var geoIPBase = "http://ip-api.com"

func geoLookupLive(ip string) (geoInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(geoIPBase + "/json/" + ip + "?fields=status,message,country,countryCode,city,isp")
	if err != nil {
		return geoInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return geoInfo{}, fmt.Errorf("ip-api.com %s: %s: %s", ip, resp.Status, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return geoInfo{}, fmt.Errorf("ip-api.com %s: bad response: %w", ip, err)
	}
	if parsed.Status != "success" {
		return geoInfo{}, fmt.Errorf("ip-api.com %s: %s", ip, parsed.Message)
	}
	return geoInfo{
		IP: ip, Country: parsed.Country, CountryCode: parsed.CountryCode, City: parsed.City, ISP: parsed.ISP,
		LookedUpAt: time.Now(),
	}, nil
}
