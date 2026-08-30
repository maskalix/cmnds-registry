// web.go — 'revpro web': a small embedded web UI exposing the revpro
// controls (sites, generate/reload/restart, ACME issue/renew, analyze, cert
// tools, port suggestion, raw config editing) over HTTP.
//
// Mutating operations run the revpro binary itself as a subprocess and stream
// its output to the browser — behavior stays identical to the CLI and a
// failing action can't take the server down. Reads (sites list, port usage)
// are served in-process.
//
// Auth is required by default: local login (bcrypt) and/or OIDC — see
// webauth.go. '--no-auth' skips it for setups behind a trusted auth proxy
// (e.g. a revpro site with the +a flag).
package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html web/login.html
var webFS embed.FS

const (
	defaultWebListen = "127.0.0.1:8675"
	actionTimeout    = 15 * time.Minute
)

type webServer struct {
	c        *proxyConfig
	auth     *webAuth
	actionMu sync.Mutex // one subprocess action at a time
}

func (c *proxyConfig) webCmd(args []string) {
	if len(args) > 0 && args[0] == "passwd" {
		webPasswd(args[1:])
		return
	}

	listen := configRead("REVPRO_WEB_LISTEN")
	if listen == "" {
		listen = defaultWebListen
	}
	noAuth := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			i++
			if i >= len(args) {
				fail("--listen needs an address")
			}
			listen = args[i]
		case "--no-auth":
			noAuth = true
		case "-h", "--help", "help":
			webUsage()
			return
		default:
			fail("unknown web option %q — see 'revpro web help'", args[i])
		}
	}

	auth, err := newWebAuth(noAuth)
	if err != nil {
		fail("%v", err)
	}
	ws := &webServer{c: c, auth: auth}

	modes := []string{}
	if auth.hasLocal() {
		modes = append(modes, "local login ("+auth.localUser+")")
	}
	if auth.hasOIDC() {
		modes = append(modes, "OIDC ("+auth.oidc.issuer+")")
	}
	if auth.disabled {
		warn("auth DISABLED (--no-auth) — only run this behind a trusted auth proxy")
	} else {
		info("auth: %s", strings.Join(modes, " + "))
	}
	info("revpro web UI listening on http://%s", listen)
	if err := http.ListenAndServe(listen, ws.routes()); err != nil {
		fail("web server: %v", err)
	}
}

func (ws *webServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", ws.auth.requireSession(ws.handleIndex))
	mux.HandleFunc("GET /login", ws.handleLoginPage)
	mux.HandleFunc("POST /login", ws.handleLoginPost)
	mux.HandleFunc("GET /oidc/start", ws.handleOIDCStart)
	mux.HandleFunc("GET /oidc/callback", ws.handleOIDCCallback)
	mux.HandleFunc("POST /logout", ws.auth.requireSession(func(w http.ResponseWriter, r *http.Request, _ *webSession) {
		ws.auth.logout(w, r)
		writeJSON(w, map[string]any{"ok": true})
	}))
	mux.HandleFunc("GET /api/state", ws.auth.requireSession(ws.handleState))
	mux.HandleFunc("GET /api/conf", ws.auth.requireSession(ws.handleConfGet))
	mux.HandleFunc("POST /api/conf", ws.auth.requireSession(ws.handleConfSave))
	mux.HandleFunc("POST /api/run", ws.auth.requireSession(ws.handleRun))
	mux.HandleFunc("POST /api/sites/add", ws.auth.requireSession(ws.handleAddSite))
	mux.HandleFunc("POST /api/sites/meta", ws.auth.requireSession(ws.handleSiteMeta))
	mux.HandleFunc("POST /api/groups/save", ws.auth.requireSession(ws.handleGroupSave))
	mux.HandleFunc("POST /api/groups/add", ws.auth.requireSession(ws.handleGroupAdd))
	mux.HandleFunc("POST /api/groups/delete", ws.auth.requireSession(ws.handleGroupDelete))
	mux.HandleFunc("POST /api/wedos", ws.auth.requireSession(ws.handleWedosSave))
	mux.HandleFunc("GET /api/ports/suggest", ws.auth.requireSession(ws.handlePortSuggest))
	mux.HandleFunc("GET /api/ports/check", ws.auth.requireSession(ws.handlePortCheck))
	mux.HandleFunc("GET /api/security-check", ws.auth.requireSession(ws.handleSecurityCheck))
	mux.HandleFunc("POST /api/brand", ws.auth.requireSession(ws.handleBrandSave))
	mux.HandleFunc("POST /api/brand/logo", ws.auth.requireSession(ws.handleBrandLogoUpload))
	mux.HandleFunc("POST /api/brand/logo/remove", ws.auth.requireSession(ws.handleBrandLogoRemove))
	mux.HandleFunc("GET /brand/logo", ws.auth.requireSession(ws.handleBrandLogoGet))
	return mux
}

// ---------- pages ----------

func (ws *webServer) handleIndex(w http.ResponseWriter, _ *http.Request, _ *webSession) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "embedded UI missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

var loginTmpl = template.Must(template.ParseFS(webFS, "web/login.html"))

func (ws *webServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if ws.auth.disabled || ws.auth.session(r) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, map[string]any{
		"Error": r.URL.Query().Get("err"),
		"Local": ws.auth.hasLocal(),
		"OIDC":  ws.auth.hasOIDC(),
	})
}

func (ws *webServer) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if !ws.auth.hasLocal() {
		loginRedirect(w, r, "local login is not configured")
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")
	okLogin, err := ws.auth.checkLocal(clientIP(r), user, pass)
	if err != nil {
		loginRedirect(w, r, err.Error())
		return
	}
	if !okLogin {
		loginRedirect(w, r, "invalid credentials")
		return
	}
	ws.auth.createSession(w, user)
	http.Redirect(w, r, "/", http.StatusFound)
}

func loginRedirect(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?err="+url.QueryEscape(msg), http.StatusFound)
}

// ---------- OIDC handlers ----------

func (ws *webServer) oidcRedirectURI() string {
	return ws.auth.baseURL + "/oidc/callback"
}

func (ws *webServer) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if !ws.auth.hasOIDC() {
		loginRedirect(w, r, "OIDC is not configured")
		return
	}
	if err := ws.auth.oidc.discover(); err != nil {
		loginRedirect(w, r, err.Error())
		return
	}
	state := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: ws.auth.secureCookies(),
		MaxAge: 600,
	})
	http.Redirect(w, r, ws.auth.oidc.loginURL(ws.oidcRedirectURI(), state), http.StatusFound)
}

func (ws *webServer) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !ws.auth.hasOIDC() {
		loginRedirect(w, r, "OIDC is not configured")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		loginRedirect(w, r, "OIDC: "+e+" "+q.Get("error_description"))
		return
	}
	ck, err := r.Cookie(oidcStateCookie)
	if err != nil || ck.Value == "" || q.Get("state") != ck.Value {
		loginRedirect(w, r, "OIDC state mismatch — try again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/", MaxAge: -1})

	claims, err := ws.auth.oidc.exchange(q.Get("code"), ws.oidcRedirectURI())
	if err != nil {
		loginRedirect(w, r, err.Error())
		return
	}
	user, err := ws.auth.oidc.identity(claims)
	if err != nil {
		loginRedirect(w, r, err.Error())
		return
	}
	ws.auth.createSession(w, user)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---------- state ----------

type siteJSON struct {
	FQDN       string   `json:"fqdn"`
	Target     string   `json:"target"`
	RawTarget  string   `json:"rawTarget,omitempty"` // set when a slug was used
	Cert       string   `json:"cert"`
	CertDays   int      `json:"certDays"` // -1 = missing, -2 = unknown (CERTS_SUB unset)
	Auth       bool     `json:"auth"`
	HTTPS      bool     `json:"https"`
	WWW        bool     `json:"www"`
	Local      bool     `json:"local"`
	Group      string   `json:"group"`                // base domain from its ==domain header
	GroupIndex int      `json:"groupIndex"`           // which header block, in file order
	GroupLabel string   `json:"groupLabel,omitempty"` // the '# ...' comment above that header
	Name       string   `json:"name,omitempty"`       // from site-meta.json, UI-only
	Tags       []string `json:"tags,omitempty"`       // from site-meta.json, UI-only
	Note       string   `json:"note,omitempty"`       // from site-meta.json, UI-only
}

func (ws *webServer) handleState(w http.ResponseWriter, _ *http.Request, s *webSession) {
	state := map[string]any{
		"user":          s.user,
		"csrf":          s.csrf,
		"authDisabled":  ws.auth.disabled,
		"revproDir":     ws.c.mainFolder,
		"sitesFile":     ws.c.configFile,
		"portsFile":     ws.c.portsFile(),
		"http3":         ws.c.http3,
		"brand":         ws.c.currentBrand(),
		"wedosReady":    configRead("REVPRO_WEDOS_USER") != "" && configRead("REVPRO_WEDOS_PASSWORD") != "",
		"wedosUser":     configRead("REVPRO_WEDOS_USER"),
		"wildcardCerts": ws.c.loadWildcardCerts(),
	}
	if groups, err := ws.c.listGroups(); err == nil {
		state["groupBlocks"] = groups
	}
	if st, ok := ws.c.loadRenewStatus(); ok {
		state["renewStatus"] = st
	}

	meta, err := ws.c.loadSiteMeta()
	if err != nil {
		meta = map[string]siteMeta{}
	}

	sites, err := ws.c.parseSites()
	if err != nil {
		state["sitesError"] = err.Error()
	} else {
		probe := &issuer{certsSub: ws.c.certsSub}
		seen := map[string]int{} // cert name → days, avoid re-reading shared certs
		out := make([]siteJSON, 0, len(sites))
		for _, st := range sites {
			days := -2
			if ws.c.certsSub != "" {
				if d, cached := seen[st.certName]; cached {
					days = d
				} else if d, have := probe.daysUntilExpiry(st.certName); have {
					days = d
					seen[st.certName] = d
				} else {
					days = -1
					seen[st.certName] = -1
				}
			}
			sj := siteJSON{
				FQDN: st.fqdn, Target: st.target, Cert: st.certName, CertDays: days,
				Auth: st.flags.auth, HTTPS: st.flags.https, WWW: st.flags.www, Local: st.flags.local,
				Group: st.group, GroupIndex: st.groupIndex, GroupLabel: st.groupLabel,
			}
			if m, ok := meta[st.fqdn]; ok {
				sj.Name, sj.Tags, sj.Note = m.Name, m.Tags, m.Note
			}
			if st.rawTarget != st.target {
				sj.RawTarget = st.rawTarget
			}
			out = append(out, sj)
		}
		state["sites"] = out
	}

	if gm, err := ws.c.groupMeta(); err == nil {
		groups := make([]string, 0, len(gm))
		machines := map[string]string{}
		for d, gi := range gm {
			groups = append(groups, d)
			if gi.machine != "" {
				machines[d] = gi.machine
			}
		}
		state["groups"] = groups
		state["groupMachines"] = machines
	}

	manual := ws.c.manconfFiles()
	man := make([]map[string]string, 0, len(manual))
	for _, m := range manual {
		man = append(man, map[string]string{"name": m.name, "path": m.path})
	}
	state["manconf"] = man

	if cats, err := ws.c.parsePortCategories(); err != nil {
		state["portsError"] = err.Error()
	} else {
		list := make([]map[string]string, 0, len(cats))
		for _, c := range cats {
			list = append(list, map[string]string{"name": c.name, "ranges": c.rangesString()})
		}
		state["categories"] = list
	}

	if used, err := ws.c.usedPortsByMachine(); err == nil {
		machines := map[string]map[int][]string{}
		for h, ports := range used {
			machines[h] = ports
		}
		state["machines"] = machines
	}

	// Setup progress for the onboarding checklist: which pieces exist yet.
	dirExists := func(p string) bool {
		st, err := os.Stat(p)
		return err == nil && st.IsDir()
	}
	fileExists := func(p string) bool {
		st, err := os.Stat(p)
		return err == nil && !st.IsDir()
	}
	state["setup"] = map[string]bool{
		"folder":   dirExists(ws.c.mainFolder),
		"sites":    fileExists(ws.c.configFile),
		"ports":    fileExists(ws.c.portsFile()),
		"machines": fileExists(ws.c.machinesFile()),
		"acme":     configRead("REVPRO_ACME_EMAIL") != "",
		"certs":    ws.c.certsSub != "",
	}

	if ms, err := ws.c.parseMachines(); err != nil {
		state["machinesError"] = err.Error()
	} else {
		list := make([]map[string]string, 0, len(ms))
		for _, m := range ms {
			list = append(list, map[string]string{"slug": m.slug, "host": m.host})
		}
		state["slugs"] = list
	}

	writeJSON(w, state)
}

// ---------- raw config read/save ----------

// confPath resolves the editable file keyword to its path.
func (ws *webServer) confPath(file string) (string, bool) {
	switch file {
	case "sites":
		return ws.c.configFile, true
	case "ports":
		return ws.c.portsFile(), true
	case "machines":
		return ws.c.machinesFile(), true
	}
	return "", false
}

func (ws *webServer) handleConfGet(w http.ResponseWriter, r *http.Request, _ *webSession) {
	path, okf := ws.confPath(r.URL.Query().Get("file"))
	if !okf {
		httpErrJSON(w, http.StatusBadRequest, "file must be 'sites', 'ports' or 'machines'")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"path": path, "content": string(data)})
}

func (ws *webServer) handleConfSave(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		File    string `json:"file"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	path, okf := ws.confPath(req.File)
	if !okf {
		httpErrJSON(w, http.StatusBadRequest, "file must be 'sites', 'ports' or 'machines'")
		return
	}
	if !strings.HasSuffix(req.Content, "\n") && req.Content != "" {
		req.Content += "\n"
	}

	// Validate before touching disk so a typo can't wipe a working config.
	switch req.File {
	case "sites":
		tmp, err := os.CreateTemp("", "sites-*.conf")
		if err != nil {
			httpErrJSON(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer os.Remove(tmp.Name())
		tmp.WriteString(req.Content)
		tmp.Close()
		// mainFolder carried over so machine slugs resolve as in production.
		probe := &proxyConfig{configFile: tmp.Name(), mainFolder: ws.c.mainFolder}
		if _, err := probe.parseSites(); err != nil {
			httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	case "ports":
		if _, err := parsePortCategoriesText(req.Content); err != nil {
			httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	case "machines":
		if _, err := parseMachinesText(req.Content); err != nil {
			httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}

	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", old, 0o644); err != nil {
			httpErrJSON(w, http.StatusInternalServerError, "backup failed: "+err.Error())
			return
		}
	}
	if err := os.WriteFile(path, []byte(req.Content), 0o644); err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	msg := "saved (previous version in " + path + ".bak)"
	if req.File == "sites" {
		msg += " — run Regenerate to apply"
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg})
}

// ---------- actions (subprocess, streamed) ----------

var (
	// fqdn/cert/manconf-style names as accepted by analyze/issue targets.
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]*$`)
	domainRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
	labelRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
)

// simpleActions maps UI action names to fixed argument lists.
var simpleActions = map[string][]string{
	"generate":         {"generate"},
	"regenerate":       {"regenerate"},
	"regenerate-renew": {"regenerate", "--renew"},
	"reload":           {"reload"},
	"restart":          {"restart"},
	"clean":            {"clean"},
	"convert":          {"convert"},
	"compose":          {"compose"},
	"renew":            {"renew"},
	"list":             {"list"},
}

func (ws *webServer) handleRun(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		Action    string   `json:"action"`
		Targets   []string `json:"targets"`
		Force     bool     `json:"force"`
		Domain    string   `json:"domain"`
		CertName  string   `json:"certName"`
		CertFlags []string `json:"certFlags"`
		HTTPVer   string   `json:"httpVer"`
		URL       string   `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}

	var args []string
	switch {
	case simpleActions[req.Action] != nil:
		args = append(args, simpleActions[req.Action]...)

	case req.Action == "analyze" || req.Action == "issue":
		args = append(args, req.Action)
		if req.Action == "issue" && req.Force {
			args = append(args, "--force")
		}
		for _, t := range req.Targets {
			if !nameRe.MatchString(t) {
				httpErrJSON(w, http.StatusBadRequest, "bad target name "+t)
				return
			}
			args = append(args, t)
		}

	case req.Action == "issue-wildcard":
		if !domainRe.MatchString(req.Domain) {
			httpErrJSON(w, http.StatusBadRequest, "bad domain")
			return
		}
		args = append(args, "issue", "--wildcard", req.Domain)
		if req.Force {
			args = append(args, "--force")
		}
		if req.CertName != "" {
			if !nameRe.MatchString(req.CertName) {
				httpErrJSON(w, http.StatusBadRequest, "bad cert name")
				return
			}
			args = append(args, "--cert", req.CertName)
		}

	case req.Action == "cert":
		if !domainRe.MatchString(req.Domain) {
			httpErrJSON(w, http.StatusBadRequest, "bad domain")
			return
		}
		allowed := map[string]bool{"-e": true, "-i": true, "-s": true, "-a": true, "-v": true, "-g": true}
		args = append(args, "cert", "-d", req.Domain)
		for _, f := range req.CertFlags {
			if !allowed[f] {
				httpErrJSON(w, http.StatusBadRequest, "bad cert flag "+f)
				return
			}
			args = append(args, f)
		}
		if len(args) == 3 {
			args = append(args, "-e", "-i", "-s")
		}

	case req.Action == "http":
		if req.HTTPVer != "2" && req.HTTPVer != "3" {
			httpErrJSON(w, http.StatusBadRequest, "httpVer must be 2 or 3")
			return
		}
		u, err := url.Parse(req.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			httpErrJSON(w, http.StatusBadRequest, "bad url")
			return
		}
		args = append(args, "http", req.HTTPVer, u.String())

	default:
		httpErrJSON(w, http.StatusBadRequest, "unknown action "+req.Action)
		return
	}

	ws.streamCommand(w, r, args)
}

func (ws *webServer) handleAddSite(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Target string `json:"target"`
		Cert   string `json:"cert"`
		Flags  struct {
			A, S, W, L bool
		} `json:"flags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	if req.Name != "@" && !labelRe.MatchString(req.Name) {
		httpErrJSON(w, http.StatusBadRequest, "bad subdomain name (use '@' for the apex)")
		return
	}
	if !domainRe.MatchString(req.Domain) {
		httpErrJSON(w, http.StatusBadRequest, "bad domain")
		return
	}
	host, port := splitTarget(req.Target)
	if host == "" || strings.HasPrefix(host, "-") || atoiSafe(port) < 1 || atoiSafe(port) > 65535 {
		httpErrJSON(w, http.StatusBadRequest, "target must be host:port")
		return
	}
	if req.Cert != "" && !nameRe.MatchString(req.Cert) {
		httpErrJSON(w, http.StatusBadRequest, "bad cert name")
		return
	}

	// Emit only what differs from the group's defaults, so the written line
	// stays as clean as a hand-written one: flag tokens vs the group flags,
	// and just the port when the machine equals the group's [machine].
	base := defaultFlags()
	target := req.Target
	if gm, err := ws.c.groupMeta(); err == nil {
		if g, okg := gm[req.Domain]; okg {
			base = g.flags
			if g.machine != "" {
				slugs, _ := ws.c.machineSlugs()
				if resolveMachine(slugs, host) == resolveMachine(slugs, g.machine) {
					target = port
				}
			}
		}
	}
	want := siteFlags{auth: req.Flags.A, https: req.Flags.S, www: req.Flags.W, local: req.Flags.L}

	args := []string{"add", req.Name, req.Domain, target}
	args = append(args, diffTokens(base, want)...)
	if req.Cert != "" {
		args = append(args, `--cert=`+req.Cert)
	}
	ws.streamCommand(w, r, args)
}

// handleSiteMeta upserts one site's UI-only name/tags/note in site-meta.json.
// The fqdn must belong to an actual sites.conf entry — this file is metadata
// about real sites, not a place to stash arbitrary keys.
func (ws *webServer) handleSiteMeta(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		FQDN string   `json:"fqdn"`
		Name string   `json:"name"`
		Tags []string `json:"tags"`
		Note string   `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	sites, err := ws.c.parseSites()
	if err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, "sites.conf: "+err.Error())
		return
	}
	found := false
	for _, st := range sites {
		if st.fqdn == req.FQDN {
			found = true
			break
		}
	}
	if !found {
		httpErrJSON(w, http.StatusNotFound, "no such site: "+req.FQDN)
		return
	}
	if len(req.Name) > 128 {
		httpErrJSON(w, http.StatusBadRequest, "name too long")
		return
	}
	if len(req.Note) > 2000 {
		httpErrJSON(w, http.StatusBadRequest, "note too long")
		return
	}
	if len(req.Tags) > 32 {
		httpErrJSON(w, http.StatusBadRequest, "too many tags")
		return
	}
	if err := ws.c.setSiteMeta(req.FQDN, siteMeta{Name: req.Name, Tags: req.Tags, Note: req.Note}); err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// ---------- whole-group management ----------

// groupSaveRequest is shared by the add and save (edit) handlers.
type groupSaveRequest struct {
	Index   int    `json:"index"` // ignored by add
	Domain  string `json:"domain"`
	Machine string `json:"machine"`
	Cert    string `json:"cert"`
	Label   string `json:"label"`
	Flags   struct {
		A, S, W, L bool
	} `json:"flags"`
}

func (req groupSaveRequest) validate() (flags siteFlags, err error) {
	if !domainRe.MatchString(req.Domain) {
		return flags, fmt.Errorf("bad domain")
	}
	if req.Machine != "" && strings.ContainsAny(req.Machine, ": \n") {
		return flags, fmt.Errorf("bad machine (a host or a machines.conf slug, no port)")
	}
	if req.Cert != "" && !nameRe.MatchString(req.Cert) {
		return flags, fmt.Errorf("bad cert name")
	}
	if strings.Contains(req.Label, "\n") {
		return flags, fmt.Errorf("label must be a single line")
	}
	return siteFlags{auth: req.Flags.A, https: req.Flags.S, www: req.Flags.W, local: req.Flags.L}, nil
}

func (ws *webServer) handleGroupSave(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req groupSaveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	flags, err := req.validate()
	if err != nil {
		httpErrJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ws.c.saveGroup(req.Index, req.Domain, req.Machine, req.Cert, req.Label, flags); err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (ws *webServer) handleGroupAdd(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req groupSaveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	flags, err := req.validate()
	if err != nil {
		httpErrJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ws.c.addGroup(req.Domain, req.Machine, req.Cert, req.Label, flags); err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (ws *webServer) handleGroupDelete(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		Index int `json:"index"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	if err := ws.c.deleteGroup(req.Index); err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// ---------- DNS-01 (WEDOS) provider settings ----------

// handleWedosSave persists REVPRO_WEDOS_USER/PASSWORD via 'cmnds config'. The
// password is write-only end to end: it's never read back into /api/state
// (which only ever exposes a wedosReady boolean), and a blank password field
// here means "leave the stored one alone" — only a non-empty value overwrites
// it, so the form doesn't need to round-trip the secret to be re-submitted.
func (ws *webServer) handleWedosSave(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	if err := configWrite("REVPRO_WEDOS_USER", strings.TrimSpace(req.User)); err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Password != "" {
		if err := configWrite("REVPRO_WEDOS_PASSWORD", req.Password); err != nil {
			httpErrJSON(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, map[string]any{
		"ok":         true,
		"wedosReady": configRead("REVPRO_WEDOS_USER") != "" && configRead("REVPRO_WEDOS_PASSWORD") != "",
	})
}

// ---------- branding ----------

func (ws *webServer) handleBrandSave(w http.ResponseWriter, r *http.Request, _ *webSession) {
	var req struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "bad request body")
		return
	}
	// Validate the color before persisting anything, so a bad value doesn't
	// leave the name written but the color rejected.
	if err := ws.c.setBrandColor(req.Color); err != nil {
		httpErrJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ws.c.setBrandName(req.Name); err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, ws.c.currentBrand())
}

// allowedLogoTypes is deliberately short: raster/vector formats a browser
// can render directly in an <img>, nothing that needs server-side decoding.
var allowedLogoTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/webp": true,
	"image/svg+xml": true, "image/gif": true, "image/x-icon": true,
}

const maxLogoSize = 512 << 10 // 512KB — this is an icon-sized mark, not a hero image

func (ws *webServer) handleBrandLogoUpload(w http.ResponseWriter, r *http.Request, _ *webSession) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoSize+4096)
	if err := r.ParseMultipartForm(maxLogoSize + 4096); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "upload too large or malformed (max 512KB)")
		return
	}
	file, header, err := r.FormFile("logo")
	if err != nil {
		httpErrJSON(w, http.StatusBadRequest, "missing 'logo' file")
		return
	}
	defer file.Close()
	if header.Size > maxLogoSize {
		httpErrJSON(w, http.StatusBadRequest, "logo too large (max 512KB)")
		return
	}
	ct := header.Header.Get("Content-Type")
	if !allowedLogoTypes[ct] {
		httpErrJSON(w, http.StatusBadRequest, "unsupported image type: "+ct)
		return
	}
	data := make([]byte, header.Size)
	if _, err := io.ReadFull(file, data); err != nil {
		httpErrJSON(w, http.StatusBadRequest, "failed to read upload")
		return
	}
	if err := ws.c.saveBrandLogo(data, ct); err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, ws.c.currentBrand())
}

func (ws *webServer) handleBrandLogoRemove(w http.ResponseWriter, _ *http.Request, _ *webSession) {
	if err := ws.c.removeBrandLogo(); err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, ws.c.currentBrand())
}

func (ws *webServer) handleBrandLogoGet(w http.ResponseWriter, _ *http.Request, _ *webSession) {
	data, ct, ok := ws.c.loadBrandLogo()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Write(data)
}

// diffTokens renders the +x/-x tokens needed to get from base to want.
func diffTokens(base, want siteFlags) []string {
	var t []string
	tok := func(on bool, letter string) string {
		if on {
			return "+" + letter
		}
		return "-" + letter
	}
	if want.auth != base.auth {
		t = append(t, tok(want.auth, "a"))
	}
	if want.https != base.https {
		t = append(t, tok(want.https, "s"))
	}
	if want.www != base.www {
		t = append(t, tok(want.www, "w"))
	}
	if want.local != base.local {
		t = append(t, tok(want.local, "l"))
	}
	return t
}

// streamCommand runs this binary with args and streams ANSI-stripped output
// as plain text. One action at a time; client disconnect kills the child.
func (ws *webServer) streamCommand(w http.ResponseWriter, r *http.Request, args []string) {
	if !ws.actionMu.TryLock() {
		httpErrJSON(w, http.StatusConflict, "another action is already running")
		return
	}
	defer ws.actionMu.Unlock()

	exe, err := os.Executable()
	if err != nil {
		httpErrJSON(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // let nginx pass the stream through
	w.WriteHeader(http.StatusOK)

	out := &ansiStripWriter{w: w}
	fmt.Fprintf(out, "$ revpro %s\n\n", strings.Join(args, " "))

	ctx, cancel := context.WithTimeout(r.Context(), actionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Stdin = nil // subcommands must never block on a prompt here

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(out, "\n[failed: %v]\n", err)
		return
	}
	fmt.Fprint(out, "\n[done]\n")
}

// ansiStripWriter strips ANSI SGR escape sequences from a byte stream and
// flushes after every write. A partial escape at a chunk boundary is held
// back until the next write completes it.
type ansiStripWriter struct {
	w    http.ResponseWriter
	held []byte
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func (a *ansiStripWriter) Write(p []byte) (int, error) {
	n := len(p)
	buf := append(a.held, p...)
	a.held = nil
	// Hold back a trailing unterminated escape sequence.
	if i := lastIndexByte(buf, 0x1b); i >= 0 && !containsByte(buf[i:], 'm') && len(buf)-i < 16 {
		a.held = append([]byte{}, buf[i:]...)
		buf = buf[:i]
	}
	if _, err := a.w.Write(ansiRe.ReplaceAll(buf, nil)); err != nil {
		return 0, err
	}
	if fl, okf := a.w.(http.Flusher); okf {
		fl.Flush()
	}
	return n, nil
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func containsByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

// ---------- ports API ----------

func (ws *webServer) handlePortSuggest(w http.ResponseWriter, r *http.Request, _ *webSession) {
	q := r.URL.Query()
	machine := q.Get("machine")
	if machine == "" || strings.HasPrefix(machine, "-") {
		httpErrJSON(w, http.StatusBadRequest, "machine required")
		return
	}
	cats, err := ws.c.parsePortCategories()
	if err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	allUsed, err := ws.c.usedPortsByMachine()
	if err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	input := machine
	if slugs, err := ws.c.machineSlugs(); err == nil {
		machine = resolveMachine(slugs, machine)
	}
	used := allUsed[machine]
	if used == nil {
		used = map[int][]string{}
	}
	var probeFn func(int) bool
	if q.Get("probe") != "0" {
		probeFn = func(p int) bool { return probeListening(machine, p) }
	}

	type suggestion struct {
		Category string `json:"category"`
		Ranges   string `json:"ranges"`
		Port     int    `json:"port"`
		Reason   string `json:"reason"`
		Error    string `json:"error,omitempty"`
	}
	var out []suggestion
	for _, cat := range cats {
		if c := q.Get("category"); c != "" && c != cat.name {
			continue
		}
		s := suggestion{Category: cat.name, Ranges: cat.rangesString()}
		port, reason, err := suggestPort(cat, used, probeFn, 25)
		if err != nil {
			s.Error = err.Error()
		} else {
			s.Port, s.Reason = port, reason
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		httpErrJSON(w, http.StatusNotFound, "category not found")
		return
	}
	res := map[string]any{"machine": machine, "probed": q.Get("probe") != "0", "suggestions": out}
	if input != machine {
		res["slug"] = input
	}
	writeJSON(w, res)
}

func (ws *webServer) handlePortCheck(w http.ResponseWriter, r *http.Request, _ *webSession) {
	q := r.URL.Query()
	machine := q.Get("machine")
	port := atoiSafe(q.Get("port"))
	if machine == "" || strings.HasPrefix(machine, "-") || port < 1 || port > 65535 {
		httpErrJSON(w, http.StatusBadRequest, "machine and port required")
		return
	}
	allUsed, err := ws.c.usedPortsByMachine()
	if err != nil {
		httpErrJSON(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	input := machine
	if slugs, err := ws.c.machineSlugs(); err == nil {
		machine = resolveMachine(slugs, machine)
	}
	res := map[string]any{"machine": machine, "port": port}
	if input != machine {
		res["slug"] = input
	}
	if cats, err := ws.c.parsePortCategories(); err == nil {
		if cat, okc := categoryFor(cats, port); okc {
			res["category"] = cat.name
		}
	}
	res["usedBy"] = allUsed[machine][port]
	if q.Get("probe") != "0" {
		res["listening"] = probeListening(machine, port)
	}
	writeJSON(w, res)
}

// handleSecurityCheck runs the security-headers/TLS checklist against a
// caller-supplied https:// URL and returns the result as JSON. Read-only —
// no revpro state is touched — so unlike the mutating actions this is served
// in-process rather than through streamCommand.
func (ws *webServer) handleSecurityCheck(w http.ResponseWriter, r *http.Request, _ *webSession) {
	target := r.URL.Query().Get("url")
	if target == "" {
		httpErrJSON(w, http.StatusBadRequest, "url required")
		return
	}
	writeJSON(w, runSecurityCheck(target))
}

// ---------- small helpers ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErrJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func webUsage() {
	fmt.Print(`revpro web — embedded web UI for revpro

Usage:
  revpro web [--listen host:port] [--no-auth]
  revpro web passwd [username]      Set/replace the local web login

Config variables (via 'cmnds config write'):
  REVPRO_WEB_LISTEN        listen address (default ` + defaultWebListen + `)
  REVPRO_WEB_URL           external base URL (https://revpro.example.tld) —
                           required for OIDC; also turns on Secure cookies
  REVPRO_WEB_USER/_HASH    local login (set with 'revpro web passwd')
  REVPRO_WEB_OIDC_ISSUER   OIDC issuer URL (pocket-id, authentik, keycloak, ...)
  REVPRO_WEB_OIDC_CLIENT   OIDC client id
  REVPRO_WEB_OIDC_SECRET   OIDC client secret
  REVPRO_WEB_OIDC_ALLOW    comma-separated allowed emails/usernames (empty = all)

The OIDC client must allow the redirect URI: <REVPRO_WEB_URL>/oidc/callback

Tip: expose the UI through revpro itself — add a site pointing at this
machine's REVPRO_WEB_LISTEN port, then set REVPRO_WEB_URL to that site.
`)
}
