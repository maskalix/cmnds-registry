package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// newTestServer builds a webServer with local auth and a temp $REVPRO folder.
func newTestServer(t *testing.T) (*webServer, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "sites.conf"),
		[]byte("==example.tld\n@        10.0.0.1:8443\napp      10.0.0.2:8080\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ports.conf"),
		[]byte("web 3000-3009\n"), 0o644)

	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ws := &webServer{
		c: &proxyConfig{
			mainFolder: dir,
			configFile: filepath.Join(dir, "sites.conf"),
			confDir:    filepath.Join(dir, "conf"),
			logDir:     filepath.Join(dir, "logs"),
		},
		auth: &webAuth{
			localUser: "admin",
			localHash: string(hash),
			sessions:  map[string]*webSession{},
			fails:     map[string]*loginFails{},
		},
	}
	srv := httptest.NewServer(ws.routes())
	t.Cleanup(srv.Close)
	return ws, srv
}

// login performs the local login and returns the session cookie.
func login(t *testing.T, srv *httptest.Server) *http.Cookie {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.PostForm(srv.URL+"/login",
		url.Values{"username": {"admin"}, "password": {"secret123"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/" {
		t.Fatalf("login: got %d → %q, want 302 → /", res.StatusCode, res.Header.Get("Location"))
	}
	for _, ck := range res.Cookies() {
		if ck.Name == sessionCookie {
			return ck
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

func authedGet(t *testing.T, srv *httptest.Server, ck *http.Cookie, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	req.AddCookie(ck)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestWebRequiresAuth(t *testing.T) {
	_, srv := newTestServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	res, err := client.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/state without session: got %d, want 401", res.StatusCode)
	}

	res, err = client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/login" {
		t.Errorf("/ without session: got %d → %q, want 302 → /login", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestLocalLoginAndState(t *testing.T) {
	_, srv := newTestServer(t)
	ck := login(t, srv)

	res := authedGet(t, srv, ck, "/api/state")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/api/state: got %d", res.StatusCode)
	}
	var state struct {
		User  string `json:"user"`
		CSRF  string `json:"csrf"`
		Sites []struct {
			FQDN   string `json:"fqdn"`
			Target string `json:"target"`
		} `json:"sites"`
		Categories []struct{ Name string } `json:"categories"`
	}
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if state.User != "admin" || state.CSRF == "" {
		t.Errorf("state user/csrf = %q/%q", state.User, state.CSRF)
	}
	if len(state.Sites) != 2 || state.Sites[1].FQDN != "app.example.tld" {
		t.Errorf("unexpected sites: %+v", state.Sites)
	}
	if len(state.Categories) != 1 || state.Categories[0].Name != "web" {
		t.Errorf("unexpected categories: %+v", state.Categories)
	}
}

func TestMutationsNeedCSRF(t *testing.T) {
	_, srv := newTestServer(t)
	ck := login(t, srv)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/run", strings.NewReader(`{"action":"list"}`))
	req.AddCookie(ck)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("POST without CSRF header: got %d, want 403", res.StatusCode)
	}
}

func csrfFor(t *testing.T, srv *httptest.Server, ck *http.Cookie) string {
	t.Helper()
	res := authedGet(t, srv, ck, "/api/state")
	defer res.Body.Close()
	var s struct {
		CSRF string `json:"csrf"`
	}
	json.NewDecoder(res.Body).Decode(&s)
	return s.CSRF
}

func postJSON(t *testing.T, srv *httptest.Server, ck *http.Cookie, csrf, path, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	req.AddCookie(ck)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Revpro-CSRF", csrf)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestConfSaveValidatesAndBacksUp(t *testing.T) {
	ws, srv := newTestServer(t)
	ck := login(t, srv)
	csrf := csrfFor(t, srv, ck)

	// A site line before any group header must be rejected untouched.
	res := postJSON(t, srv, ck, csrf, "/api/conf", `{"file":"sites","content":"broken 1.2.3.4:80"}`)
	res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sites.conf save: got %d, want 422", res.StatusCode)
	}
	if data, _ := os.ReadFile(ws.c.configFile); !strings.Contains(string(data), "example.tld") {
		t.Error("rejected save must not touch sites.conf")
	}

	res = postJSON(t, srv, ck, csrf, "/api/conf", `{"file":"sites","content":"==new.tld\n@ 1.2.3.4:80"}`)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("valid sites.conf save: got %d", res.StatusCode)
	}
	if data, _ := os.ReadFile(ws.c.configFile); string(data) != "==new.tld\n@ 1.2.3.4:80\n" {
		t.Errorf("saved content = %q", data)
	}
	if bak, err := os.ReadFile(ws.c.configFile + ".bak"); err != nil || !strings.Contains(string(bak), "example.tld") {
		t.Errorf("backup missing or wrong: %q, %v", bak, err)
	}

	// ports.conf validation path.
	res = postJSON(t, srv, ck, csrf, "/api/conf", `{"file":"ports","content":"web 5-1"}`)
	res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid ports.conf save: got %d, want 422", res.StatusCode)
	}
}

func TestAddSiteRejectsBadInput(t *testing.T) {
	_, srv := newTestServer(t)
	ck := login(t, srv)
	csrf := csrfFor(t, srv, ck)

	for _, body := range []string{
		`{"name":"-x","domain":"example.tld","target":"1.2.3.4:80"}`, // flag-like name
		`{"name":"app","domain":"--force","target":"1.2.3.4:80"}`,    // flag-like domain
		`{"name":"app","domain":"example.tld","target":"1.2.3.4"}`,   // missing port
		`{"name":"app","domain":"example.tld","target":"-h:80"}`,     // flag-like host
	} {
		res := postJSON(t, srv, ck, csrf, "/api/sites/add", body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("add %s: got %d, want 400", body, res.StatusCode)
		}
	}
}

func TestPortSuggestAPI(t *testing.T) {
	_, srv := newTestServer(t)
	ck := login(t, srv)

	// 10.0.0.2 uses 8080 (outside the web range) → suggestion starts at 3000.
	res := authedGet(t, srv, ck, "/api/ports/suggest?machine=10.0.0.2&category=web&probe=0")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("suggest: got %d", res.StatusCode)
	}
	var out struct {
		Suggestions []struct {
			Category string `json:"category"`
			Port     int    `json:"port"`
		} `json:"suggestions"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Suggestions) != 1 || out.Suggestions[0].Port != 3000 {
		t.Errorf("unexpected suggestions: %+v", out.Suggestions)
	}

	res2 := authedGet(t, srv, ck, "/api/ports/suggest?machine=10.0.0.2&category=nope&probe=0")
	res2.Body.Close()
	if res2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown category: got %d, want 404", res2.StatusCode)
	}
}

func TestOIDCIdentityAllowList(t *testing.T) {
	o := &oidcProvider{allow: parseAllowList("Admin@Example.com, ops")}
	if _, err := o.identity(&oidcClaims{Email: "admin@example.com"}); err != nil {
		t.Errorf("allow-listed email rejected: %v", err)
	}
	if _, err := o.identity(&oidcClaims{Username: "ops", Sub: "123"}); err != nil {
		t.Errorf("allow-listed username rejected: %v", err)
	}
	if _, err := o.identity(&oidcClaims{Email: "evil@example.com"}); err == nil {
		t.Error("non-listed user must be rejected")
	}

	open := &oidcProvider{allow: parseAllowList("")}
	if _, err := open.identity(&oidcClaims{Sub: "abc"}); err != nil {
		t.Errorf("empty allow-list should admit any authenticated user: %v", err)
	}
	if _, err := open.identity(&oidcClaims{}); err == nil {
		t.Error("claims without any identity must be rejected")
	}
}

func TestAudContains(t *testing.T) {
	if !audContains(json.RawMessage(`"client-1"`), "client-1") {
		t.Error("string aud should match")
	}
	if !audContains(json.RawMessage(`["other","client-1"]`), "client-1") {
		t.Error("array aud should match")
	}
	if audContains(json.RawMessage(`"other"`), "client-1") ||
		audContains(json.RawMessage(`["other"]`), "client-1") {
		t.Error("mismatched aud must not match")
	}
}
