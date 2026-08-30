package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRedirectHandlerServesAcmeChallenge(t *testing.T) {
	webroot := t.TempDir()
	challengeDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(challengeDir, "token123"), []byte("challenge-response-value"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := redirectHandler(webroot)
	req := httptest.NewRequest(http.MethodGet, "http://lnln.eu/.well-known/acme-challenge/token123", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("challenge request: got %d, want 200", w.Code)
	}
	if w.Body.String() != "challenge-response-value" {
		t.Errorf("challenge body = %q", w.Body.String())
	}
}

func TestRedirectHandlerRedirectsEverythingElse(t *testing.T) {
	h := redirectHandler(t.TempDir())

	for _, path := range []string{"/", "/some/page", "/robots.txt"} {
		req := httptest.NewRequest(http.MethodGet, "http://lnln.eu"+path+"?q=1", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("%s: got status %d, want 302", path, w.Code)
		}
		want := "https://lnln.eu" + path + "?q=1"
		if got := w.Header().Get("Location"); got != want {
			t.Errorf("%s: Location = %q, want %q", path, got, want)
		}
	}
}

func TestRedirectHandlerMissingChallengeFile404s(t *testing.T) {
	h := redirectHandler(t.TempDir())
	req := httptest.NewRequest(http.MethodGet, "http://lnln.eu/.well-known/acme-challenge/does-not-exist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing challenge file: got %d, want 404 (must not redirect to https and hide the real problem)", w.Code)
	}
}

func TestAcmeWebrootDirDefaultsUnderMainFolder(t *testing.T) {
	// No 'cmnds' on PATH here, so configRead("REVPRO_ACME_WEBROOT") returns
	// "" and the function must fall back to $REVPRO/acme-webroot.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", oldPath)

	c := &proxyConfig{mainFolder: "/revpro"}
	want := filepath.Join("/revpro", "acme-webroot")
	if got := acmeWebrootDir(c); got != want {
		t.Errorf("acmeWebrootDir() = %q, want %q", got, want)
	}
}
