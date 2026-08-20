// webauth.go — authentication for 'revpro web'.
//
// Two mechanisms, either or both may be configured (via `cmnds config`):
//
//	local login  REVPRO_WEB_USER + REVPRO_WEB_HASH   (set with 'revpro web passwd')
//	OIDC login   REVPRO_WEB_OIDC_ISSUER/CLIENT/SECRET (authorization code flow,
//	             e.g. pocket-id, authentik, keycloak)
//	             REVPRO_WEB_OIDC_ALLOW — optional comma-separated allow-list of
//	             emails/usernames/subs; empty = any authenticated user
//
// Sessions are random in-memory tokens in an HttpOnly cookie; mutating API
// calls additionally require the session's CSRF token in an X-Revpro-CSRF
// header. Failed local logins are rate-limited per client IP.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const (
	sessionCookie   = "revpro_sid"
	oidcStateCookie = "revpro_oidc"
	sessionTTL      = 24 * time.Hour
	maxLoginFails   = 8
	failWindow      = 15 * time.Minute
	lockoutTime     = 5 * time.Minute
)

type webSession struct {
	user    string
	csrf    string
	expires time.Time
}

type loginFails struct {
	count int
	since time.Time
}

type webAuth struct {
	localUser string
	localHash string
	oidc      *oidcProvider // nil when not configured
	baseURL   string        // external base URL, e.g. https://revpro.example.tld
	disabled  bool          // --no-auth

	mu       sync.Mutex
	sessions map[string]*webSession
	fails    map[string]*loginFails
}

func newWebAuth(noAuth bool) (*webAuth, error) {
	a := &webAuth{
		localUser: configRead("REVPRO_WEB_USER"),
		localHash: configRead("REVPRO_WEB_HASH"),
		baseURL:   strings.TrimRight(configRead("REVPRO_WEB_URL"), "/"),
		disabled:  noAuth,
		sessions:  map[string]*webSession{},
		fails:     map[string]*loginFails{},
	}
	if iss := configRead("REVPRO_WEB_OIDC_ISSUER"); iss != "" {
		a.oidc = &oidcProvider{
			issuer:       strings.TrimRight(iss, "/"),
			clientID:     configRead("REVPRO_WEB_OIDC_CLIENT"),
			clientSecret: configRead("REVPRO_WEB_OIDC_SECRET"),
			allow:        parseAllowList(configRead("REVPRO_WEB_OIDC_ALLOW")),
		}
		if a.oidc.clientID == "" || a.oidc.clientSecret == "" {
			return nil, fmt.Errorf("REVPRO_WEB_OIDC_ISSUER is set but REVPRO_WEB_OIDC_CLIENT/SECRET are not")
		}
		if a.baseURL == "" {
			return nil, fmt.Errorf("OIDC needs REVPRO_WEB_URL (external base URL for the redirect URI) — run 'cmnds config write REVPRO_WEB_URL https://revpro.example.tld'")
		}
	}
	if !a.hasLocal() && !a.hasOIDC() && !noAuth {
		return nil, fmt.Errorf(`no auth configured — set up at least one of:
  local login:  revpro web passwd <username>
  OIDC login:   cmnds config write REVPRO_WEB_OIDC_ISSUER https://id.example.tld
                cmnds config write REVPRO_WEB_OIDC_CLIENT <client-id>
                cmnds config write REVPRO_WEB_OIDC_SECRET <client-secret>
                cmnds config write REVPRO_WEB_URL         https://revpro.example.tld
(or run 'revpro web --no-auth' behind a trusted auth proxy)`)
	}
	return a, nil
}

func (a *webAuth) hasLocal() bool { return a.localUser != "" && a.localHash != "" }
func (a *webAuth) hasOIDC() bool  { return a.oidc != nil }

// secureCookies: mark cookies Secure when the site is served over https.
func (a *webAuth) secureCookies() bool { return strings.HasPrefix(a.baseURL, "https://") }

func parseAllowList(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out[p] = true
		}
	}
	return out
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fail("crypto/rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------- sessions ----------

func (a *webAuth) createSession(w http.ResponseWriter, user string) {
	sid := randomToken()
	a.mu.Lock()
	// Opportunistically drop expired sessions so the map can't grow forever.
	for k, s := range a.sessions {
		if time.Now().After(s.expires) {
			delete(a.sessions, k)
		}
	}
	a.sessions[sid] = &webSession{user: user, csrf: randomToken(), expires: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: a.secureCookies(),
		MaxAge: int(sessionTTL / time.Second),
	})
}

func (a *webAuth) session(r *http.Request) *webSession {
	if a.disabled {
		return &webSession{user: "anonymous", csrf: "no-auth"}
	}
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[ck.Value]
	if s == nil || time.Now().After(s.expires) {
		delete(a.sessions, ck.Value)
		return nil
	}
	return s
}

func (a *webAuth) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, ck.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
}

// requireSession gates a handler. API requests get a 401; page requests get a
// redirect to /login. Mutating API requests must also carry the CSRF header.
func (a *webAuth) requireSession(next func(http.ResponseWriter, *http.Request, *webSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.session(r)
		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		if s == nil {
			if isAPI {
				http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		if isAPI && r.Method != http.MethodGet && !a.disabled {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Revpro-CSRF")), []byte(s.csrf)) != 1 {
				http.Error(w, `{"error":"bad CSRF token"}`, http.StatusForbidden)
				return
			}
		}
		next(w, r, s)
	}
}

// ---------- local login ----------

// checkLocal verifies a username/password pair, with per-IP rate limiting.
func (a *webAuth) checkLocal(ip, user, pass string) (bool, error) {
	a.mu.Lock()
	f := a.fails[ip]
	if f != nil && time.Since(f.since) > failWindow {
		delete(a.fails, ip)
		f = nil
	}
	if f != nil && f.count >= maxLoginFails {
		a.mu.Unlock()
		return false, fmt.Errorf("too many failed logins — wait %s", lockoutTime)
	}
	a.mu.Unlock()

	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(a.localUser)) == 1
	okPass := bcrypt.CompareHashAndPassword([]byte(a.localHash), []byte(pass)) == nil
	if okUser && okPass {
		a.mu.Lock()
		delete(a.fails, ip)
		a.mu.Unlock()
		return true, nil
	}

	a.mu.Lock()
	if a.fails[ip] == nil {
		a.fails[ip] = &loginFails{since: time.Now()}
	}
	a.fails[ip].count++
	a.mu.Unlock()
	time.Sleep(700 * time.Millisecond) // slow down brute force
	return false, nil
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ---------- OIDC (authorization code flow) ----------

type oidcProvider struct {
	issuer       string
	clientID     string
	clientSecret string
	allow        map[string]bool // empty = any authenticated user

	once        sync.Once
	discoverErr error
	authURL     string
	tokenURL    string
}

type oidcDiscovery struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
}

// discover fetches the provider metadata once, lazily.
func (o *oidcProvider) discover() error {
	o.once.Do(func() {
		resp, err := http.Get(o.issuer + "/.well-known/openid-configuration")
		if err != nil {
			o.discoverErr = fmt.Errorf("OIDC discovery: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			o.discoverErr = fmt.Errorf("OIDC discovery: %s returned %s", o.issuer, resp.Status)
			return
		}
		var d oidcDiscovery
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
			o.discoverErr = fmt.Errorf("OIDC discovery: %w", err)
			return
		}
		if d.AuthURL == "" || d.TokenURL == "" {
			o.discoverErr = fmt.Errorf("OIDC discovery: metadata missing endpoints")
			return
		}
		o.authURL, o.tokenURL = d.AuthURL, d.TokenURL
	})
	return o.discoverErr
}

func (o *oidcProvider) loginURL(redirectURI, state string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {o.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile email"},
		"state":         {state},
	}
	sep := "?"
	if strings.Contains(o.authURL, "?") {
		sep = "&"
	}
	return o.authURL + sep + q.Encode()
}

type oidcClaims struct {
	Iss      string          `json:"iss"`
	Aud      json.RawMessage `json:"aud"` // string or []string
	Exp      int64           `json:"exp"`
	Sub      string          `json:"sub"`
	Email    string          `json:"email"`
	Username string          `json:"preferred_username"`
	Name     string          `json:"name"`
}

// exchange trades the authorization code for tokens and returns the verified
// ID-token claims. The ID token arrives via direct TLS communication with the
// token endpoint using client authentication, so per OIDC Core §3.1.3.7 the
// TLS server validation stands in for a signature check; issuer, audience and
// expiry are still validated here.
func (o *oidcProvider) exchange(code, redirectURI string) (*oidcClaims, error) {
	if err := o.discover(); err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	req, err := http.NewRequest(http.MethodPost, o.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(o.clientID), url.QueryEscape(o.clientSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return nil, fmt.Errorf("token response missing id_token")
	}

	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed id_token payload: %w", err)
	}
	var claims oidcClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("id_token claims: %w", err)
	}

	if strings.TrimRight(claims.Iss, "/") != o.issuer {
		return nil, fmt.Errorf("id_token issuer %q does not match %q", claims.Iss, o.issuer)
	}
	if !audContains(claims.Aud, o.clientID) {
		return nil, fmt.Errorf("id_token audience does not include this client")
	}
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("id_token expired")
	}
	return &claims, nil
}

func audContains(raw json.RawMessage, clientID string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == clientID
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

// identity picks the display identity and checks it against the allow-list.
func (o *oidcProvider) identity(c *oidcClaims) (string, error) {
	id := c.Email
	if id == "" {
		id = c.Username
	}
	if id == "" {
		id = c.Sub
	}
	if id == "" {
		return "", fmt.Errorf("id_token carries no email/preferred_username/sub")
	}
	if len(o.allow) > 0 &&
		!o.allow[strings.ToLower(c.Email)] &&
		!o.allow[strings.ToLower(c.Username)] &&
		!o.allow[strings.ToLower(c.Sub)] {
		return "", fmt.Errorf("user %q is not on REVPRO_WEB_OIDC_ALLOW", id)
	}
	return id, nil
}

// ---------- 'revpro web passwd' ----------

// webPasswd sets REVPRO_WEB_USER/REVPRO_WEB_HASH via 'cmnds config write'.
func webPasswd(args []string) {
	user := ""
	if len(args) > 0 {
		user = args[0]
	}
	if user == "" {
		fmt.Print("Username: ")
		fmt.Scanln(&user)
	}
	if user == "" {
		fail("username required")
	}

	pass, err := promptPassword("Password: ")
	if err != nil {
		fail("read password: %v", err)
	}
	if len(pass) < 8 {
		fail("password must be at least 8 characters")
	}
	again, err := promptPassword("Repeat password: ")
	if err != nil {
		fail("read password: %v", err)
	}
	if pass != again {
		fail("passwords do not match")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		fail("bcrypt: %v", err)
	}
	if err := configWrite("REVPRO_WEB_USER", user); err != nil {
		fail("write REVPRO_WEB_USER: %v", err)
	}
	if err := configWrite("REVPRO_WEB_HASH", string(hash)); err != nil {
		fail("write REVPRO_WEB_HASH: %v", err)
	}
	ok("Local web login for %q saved. Start the UI with 'revpro web'.", user)
}

// promptPassword reads a password without echo when stdin is a terminal.
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		return string(b), err
	}
	var s string
	_, err := fmt.Scanln(&s)
	return s, err
}
