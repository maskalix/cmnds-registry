package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestWebServer wires a webServer against a throwaway REVPRO folder, with
// auth disabled so the smoke test never touches real login/OIDC state.
func newTestWebServer(t *testing.T) (*webServer, *proxyConfig) {
	t.Helper()
	dir := t.TempDir()
	sitesConf := "==example.tld <-w>\n@        A:9090\napi      172.17.0.1:7080\n"
	if err := os.WriteFile(filepath.Join(dir, "sites.conf"), []byte(sitesConf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "machines.conf"), []byte("A 192.168.2.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &proxyConfig{
		mainFolder: dir,
		configFile: filepath.Join(dir, "sites.conf"),
		confDir:    filepath.Join(dir, "conf"),
		logDir:     filepath.Join(dir, "logs"),
	}
	auth, err := newWebAuth(true)
	if err != nil {
		t.Fatal(err)
	}
	return &webServer{c: c, auth: auth}, c
}

// TestWebRoutesSmoke exercises the new sites-table endpoints end to end
// (machine/port split, cert-type, view+manualize config, logs) against a real
// HTTP server, and checks the embedded index.html carries the new UI hooks.
func TestWebRoutesSmoke(t *testing.T) {
	ws, c := newTestWebServer(t)
	srv := httptest.NewServer(ws.routes())
	defer srv.Close()

	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	for _, want := range []string{`id="confmodal"`, `id="view-site-detail"`, `id="sitefilterbar"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("index.html missing %s", want)
		}
	}

	res, err = http.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Sites []struct {
			FQDN, Machine, Port, CertType string
		} `json:"sites"`
	}
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	byFQDN := map[string]struct{ Machine, Port, CertType string }{}
	for _, s := range state.Sites {
		byFQDN[s.FQDN] = struct{ Machine, Port, CertType string }{s.Machine, s.Port, s.CertType}
	}
	if got := byFQDN["example.tld"]; got.Machine != "A" || got.Port != "9090" || got.CertType != "http01" {
		t.Errorf("example.tld = %+v", got)
	}
	if got := byFQDN["api.example.tld"]; got.Machine != "172.17.0.1" || got.Port != "7080" {
		t.Errorf("api.example.tld = %+v", got)
	}

	res, err = http.Get(srv.URL + "/api/sites/config?domain=api.example.tld")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Content string `json:"content"`
	}
	json.NewDecoder(res.Body).Decode(&cfg)
	res.Body.Close()
	if !strings.Contains(cfg.Content, "api.example.tld") {
		t.Errorf("expected rendered config to mention the fqdn, got: %s", cfg.Content)
	}

	res, err = http.Post(srv.URL+"/api/sites/manualize", "application/json",
		strings.NewReader(`{"domain":"api.example.tld","content":"server { listen 443; }\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("manualize failed (%d): %s", res.StatusCode, b)
	}
	res.Body.Close()
	if _, err := os.Stat(filepath.Join(c.manconfDir(), "api.example.tld.conf")); err != nil {
		t.Errorf("expected manual config to exist: %v", err)
	}
	sites, _ := c.parseSites()
	for _, s := range sites {
		if s.fqdn == "api.example.tld" {
			t.Error("expected api.example.tld to be gone from sites.conf after manualize")
		}
	}

	res, err = http.Get(srv.URL + "/api/sites/logs?domain=example.tld&which=access")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("logs endpoint status = %d", res.StatusCode)
	}
	res.Body.Close()
}
