package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func withFakeAbuseIPDB(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	old := abuseIPDBBase
	abuseIPDBBase = srv.URL
	t.Cleanup(func() { abuseIPDBBase = old })
}

func TestAbuseCheckWithKeyParsesScore(t *testing.T) {
	withFakeAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-key" {
			t.Errorf("missing/wrong Key header: %q", r.Header.Get("Key"))
		}
		if got := r.URL.Query().Get("ipAddress"); got != "203.0.113.9" {
			t.Errorf("ipAddress query param = %q", got)
		}
		w.Write([]byte(`{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":87,"totalReports":42,"countryCode":"CN","isWhitelisted":false}}`))
	})

	r, err := abuseCheckWithKey("203.0.113.9", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != 87 || r.TotalReports != 42 || r.CountryCode != "CN" || r.IsWhitelisted {
		t.Errorf("parsed = %+v", r)
	}
}

func TestAbuseCheckWithKeyNonOKStatus(t *testing.T) {
	withFakeAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"errors":[{"detail":"Daily rate limit exceeded"}]}`))
	})
	if _, err := abuseCheckWithKey("203.0.113.9", "test-key"); err == nil {
		t.Error("expected an error for a non-200 response")
	}
}

func TestAbuseCheckLiveRequiresKey(t *testing.T) {
	if _, err := abuseCheckLive("203.0.113.9"); err == nil {
		t.Error("expected an error when no API key is configured")
	}
}

func TestAbuseReportRequiresKey(t *testing.T) {
	if err := abuseReport("203.0.113.9", []int{18}, "test"); err == nil {
		t.Error("expected an error when no API key is configured")
	}
}

func TestAbuseReportWithKeySendsCategoriesAndComment(t *testing.T) {
	var gotIP, gotCats, gotComment string
	withFakeAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotIP = r.FormValue("ip")
		gotCats = r.FormValue("categories")
		gotComment = r.FormValue("comment")
		w.Write([]byte(`{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":100}}`))
	})
	if err := abuseReportWithKey("203.0.113.9", []int{18, 22}, "banned by sshd", "test-key"); err != nil {
		t.Fatal(err)
	}
	if gotIP != "203.0.113.9" {
		t.Errorf("ip = %q", gotIP)
	}
	if gotCats != "18,22" {
		t.Errorf("categories = %q, want \"18,22\"", gotCats)
	}
	if gotComment != "banned by sshd" {
		t.Errorf("comment = %q", gotComment)
	}
}

func TestAbuseCheckCachedReturnsFreshEntryWithoutNetworkCall(t *testing.T) {
	called := false
	withFakeAbuseIPDB(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	cache := map[string]abuseCheckResult{
		"203.0.113.9": {IP: "203.0.113.9", Score: 10, CheckedAt: time.Now()},
	}
	r, err := abuseCheckCached(cache, "203.0.113.9", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != 10 {
		t.Errorf("expected the cached score 10, got %d", r.Score)
	}
	if called {
		t.Error("expected no network call for a fresh cache hit")
	}
}
