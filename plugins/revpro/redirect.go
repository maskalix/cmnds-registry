// redirect.go — a small persistent HTTP server for port 80.
//
// Once nginx itself no longer holds :80 (see the standalone-vs-webroot ACME
// note below), *nothing* answers plain http:// requests at all unless
// something else does — this is that something else: it serves ACME HTTP-01
// challenges from a shared webroot, and redirects everything else to
// https://, replacing what nginx's own "listen 80 { return 302 ... }" block
// did back when nginx owned the port.
//
// Pairs with REVPRO_ACME_WEBROOT: point it at the same directory this serves
// challenges from, and 'revpro issue'/'renew' write their challenge files
// here instead of running a competing standalone listener — so issuance
// never needs to contend for :80 with this (or anything else) again.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

const defaultRedirectListen = ":80"

func (c *proxyConfig) redirectCmd(args []string) {
	listen := defaultRedirectListen
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			i++
			if i >= len(args) {
				fail("--listen needs an address")
			}
			listen = args[i]
		case "-h", "--help", "help":
			redirectUsage()
			return
		default:
			fail("unknown redirect option %q — see 'revpro redirect help'", args[i])
		}
	}

	webroot := acmeWebrootDir(c)
	if err := os.MkdirAll(filepath.Join(webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
		fail("create webroot: %v", err)
	}

	info("Serving ACME challenges from %s, redirecting everything else to https://", webroot)
	info("Listening on %s", listen)
	if err := http.ListenAndServe(listen, redirectHandler(webroot)); err != nil {
		fail("redirect server: %v", err)
	}
}

// acmeWebrootDir resolves REVPRO_ACME_WEBROOT, defaulting to $REVPRO/acme-webroot.
func acmeWebrootDir(c *proxyConfig) string {
	if v := configRead("REVPRO_ACME_WEBROOT"); v != "" {
		return v
	}
	return filepath.Join(c.mainFolder, "acme-webroot")
}

// redirectHandler serves ACME challenges verbatim from webroot and redirects
// every other request to the same host+path over https.
func redirectHandler(webroot string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/acme-challenge/", http.FileServer(http.Dir(webroot)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusFound)
	})
	return mux
}

func redirectUsage() {
	fmt.Println(`Usage: revpro redirect [--listen host:port]

Runs a small persistent HTTP server (default :80): serves ACME HTTP-01
challenges from REVPRO_ACME_WEBROOT (or $REVPRO/acme-webroot if unset), and
redirects everything else to https://. Meant to run continuously (e.g. as a
systemd service) once nginx no longer holds :80 itself — so 'revpro
issue'/'renew' never need to stop anything to get the port; point
REVPRO_ACME_WEBROOT at the same directory this serves from and they'll use
the webroot method instead of a competing standalone listener.`)
}
