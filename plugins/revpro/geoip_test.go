package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func withFakeGeoIP(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	old := geoIPBase
	geoIPBase = srv.URL
	t.Cleanup(func() { geoIPBase = old })
}

func TestGeoLookupLiveParsesFields(t *testing.T) {
	withFakeGeoIP(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json/203.0.113.9" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"status":"success","country":"United States","countryCode":"US","city":"Ashburn","isp":"Amazon.com, Inc."}`))
	})
	g, err := geoLookupLive("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if g.Country != "United States" || g.CountryCode != "US" || g.City != "Ashburn" || g.ISP != "Amazon.com, Inc." {
		t.Errorf("parsed = %+v", g)
	}
	if g.LookedUpAt.IsZero() {
		t.Error("expected LookedUpAt to be set")
	}
}

func TestGeoLookupLiveErrorField(t *testing.T) {
	withFakeGeoIP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"fail","message":"reserved range"}`))
	})
	if _, err := geoLookupLive("10.0.0.1"); err == nil {
		t.Error("expected an error when the provider reports status:fail")
	}
}

func TestGeoLookupCachedSkipsNetworkForPrivateIP(t *testing.T) {
	called := false
	withFakeGeoIP(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	cache := map[string]geoInfo{}
	g, err := geoLookupCached(cache, "192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if !g.Local {
		t.Error("expected Local=true for a private IP")
	}
	if called {
		t.Error("expected no network call for a private IP")
	}
	if _, cached := cache["192.168.1.5"]; !cached {
		t.Error("expected the synthetic local entry to be cached too")
	}
}

func TestGeoLookupCachedReturnsFreshEntryWithoutNetworkCall(t *testing.T) {
	called := false
	withFakeGeoIP(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	cache := map[string]geoInfo{
		"203.0.113.9": {IP: "203.0.113.9", Country: "Testland", LookedUpAt: time.Now()},
	}
	g, err := geoLookupCached(cache, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if g.Country != "Testland" {
		t.Errorf("expected the cached entry, got %+v", g)
	}
	if called {
		t.Error("expected no network call for a fresh cache hit")
	}
}

func TestGeoCacheRoundTrip(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	m := map[string]geoInfo{"203.0.113.9": {IP: "203.0.113.9", Country: "Testland", LookedUpAt: time.Now()}}
	if err := c.saveGeoCache(m); err != nil {
		t.Fatal(err)
	}
	got := c.loadGeoCache()
	if got["203.0.113.9"].Country != "Testland" {
		t.Errorf("round-tripped cache = %+v", got)
	}
}

func TestLoadGeoCacheMissingFileIsNotAnError(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	if got := c.loadGeoCache(); len(got) != 0 {
		t.Errorf("expected an empty cache, got %v", got)
	}
}
