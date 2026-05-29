// Certificate issuance and renewal via lego v5 (ACME, HTTP-01 standalone).
//
// Driven by site-configs.conf: each site line gives a domain and a certificate
// name. revpro issues an HTTP-01 cert for [domain, www.domain] and writes it as
//
//	$CERTS_SUB/<cert>/<cert>.crt          (fullchain)
//	$CERTS_SUB/<cert>/<cert>.key          (private key)
//	$CERTS_SUB/<cert>/<cert>.issuer.crt   (issuer chain)
//
// which is exactly what the generated nginx server blocks reference. Renewal
// inspects each cert's NotAfter and reissues those within the renew window.
//
// Config (via `cmnds config`):
//
//	REVPRO_ACME_EMAIL    ACME account email (required to issue)
//	REVPRO_ACME_PORT     HTTP-01 challenge listen port (default 5002)
//	REVPRO_ACME_STAGING  "true" → Let's Encrypt staging CA
//	REVPRO_ACME_DIR      account storage dir (default $REVPRO/acme)
//	REVPRO_RENEW_DAYS    renew when fewer than N days remain (default 30)
//	CERTS_SUB            base dir for per-cert output folders
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

const (
	defaultACMEPort  = "5002"
	defaultRenewDays = 30
)

// acmeUser implements lego's registration.User, backed by a persisted account
// key so registration survives across runs.
type acmeUser struct {
	email string
	reg   *acme.ExtendedAccount
	key   crypto.Signer
}

func (u *acmeUser) GetEmail() string                       { return u.email }
func (u *acmeUser) GetRegistration() *acme.ExtendedAccount { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.Signer           { return u.key }

// issuer holds the resolved ACME settings and the lego client.
type issuer struct {
	email    string
	port     string
	staging  bool
	acmeDir  string
	certsSub string
	client   *lego.Client
	user     *acmeUser
}

func (c *proxyConfig) newIssuer() (*issuer, error) {
	email := configRead("REVPRO_ACME_EMAIL")
	if email == "" {
		return nil, fmt.Errorf("REVPRO_ACME_EMAIL is not set — run 'cmnds config write REVPRO_ACME_EMAIL you@example.com'")
	}
	if c.certsSub == "" {
		return nil, fmt.Errorf("CERTS_SUB is not set — run 'cmnds config write CERTS_SUB /path/to/certs'")
	}

	port := configRead("REVPRO_ACME_PORT")
	if port == "" {
		port = defaultACMEPort
	}
	acmeDir := configRead("REVPRO_ACME_DIR")
	if acmeDir == "" {
		acmeDir = filepath.Join(c.mainFolder, "acme")
	}

	iss := &issuer{
		email:    email,
		port:     port,
		staging:  boolConfig("REVPRO_ACME_STAGING"),
		acmeDir:  acmeDir,
		certsSub: c.certsSub,
	}
	if err := iss.connect(); err != nil {
		return nil, err
	}
	return iss, nil
}

func boolConfig(name string) bool {
	v := configRead(name)
	return v == "true" || v == "1" || v == "yes"
}

// connect loads or creates the ACME account and builds the lego client with a
// standalone HTTP-01 provider.
func (iss *issuer) connect() error {
	if err := os.MkdirAll(iss.acmeDir, 0o700); err != nil {
		return fmt.Errorf("create acme dir: %w", err)
	}

	key, err := iss.loadOrCreateAccountKey()
	if err != nil {
		return err
	}
	iss.user = &acmeUser{email: iss.email, key: key}

	cfg := lego.NewConfig(iss.user)
	if iss.staging {
		cfg.CADirURL = lego.DirectoryURLLetsEncryptStaging
	} else {
		cfg.CADirURL = lego.DirectoryURLLetsEncrypt
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("lego client: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", iss.port)); err != nil {
		return fmt.Errorf("http-01 provider: %w", err)
	}
	iss.client = client

	return iss.loadOrRegister()
}

func (iss *issuer) accountKeyPath() string { return filepath.Join(iss.acmeDir, "account.key") }
func (iss *issuer) accountRegPath() string { return filepath.Join(iss.acmeDir, "account.json") }

func (iss *issuer) loadOrCreateAccountKey() (crypto.Signer, error) {
	path := iss.accountKeyPath()
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("malformed account key at %s", path)
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse account key: %w", err)
		}
		return k, nil
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write account key: %w", err)
	}
	return k, nil
}

// loadOrRegister restores a saved registration or registers a new account
// (accepting the ACME terms of service) and persists it.
func (iss *issuer) loadOrRegister() error {
	if data, err := os.ReadFile(iss.accountRegPath()); err == nil {
		var reg acme.ExtendedAccount
		if json.Unmarshal(data, &reg) == nil && reg.Location != "" {
			iss.user.reg = &reg
			return nil
		}
	}

	info("Registering ACME account for %s...", iss.email)
	reg, err := iss.client.Registration.Register(context.Background(),
		registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("acme registration: %w", err)
	}
	iss.user.reg = reg
	if data, err := json.MarshalIndent(reg, "", "  "); err == nil {
		_ = os.WriteFile(iss.accountRegPath(), data, 0o600)
	}
	return nil
}

// obtain issues a certificate for the given domains and writes the three files
// under $CERTS_SUB/<certName>/.
func (iss *issuer) obtain(certName string, domains []string) error {
	res, err := iss.client.Certificate.Obtain(context.Background(), certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return err
	}
	return iss.writeCert(certName, res)
}

func (iss *issuer) writeCert(certName string, res *certificate.Resource) error {
	dir := filepath.Join(iss.certsSub, certName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	files := map[string][]byte{
		certName + ".crt":        res.Certificate,
		certName + ".key":        res.PrivateKey,
		certName + ".issuer.crt": res.IssuerCertificate,
	}
	for name, data := range files {
		if len(data) == 0 {
			continue
		}
		mode := os.FileMode(0o644)
		if filepath.Ext(name) == ".key" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// daysUntilExpiry returns the number of days until the cert named certName
// expires. Returns (0, false) if the cert is missing or unparsable, signalling
// "needs issuance".
func (iss *issuer) daysUntilExpiry(certName string) (int, bool) {
	path := filepath.Join(iss.certsSub, certName, certName+".crt")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, false
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, false
	}
	return int(time.Until(crt.NotAfter).Hours() / 24), true
}

// ---------- subcommands ----------

// site couples a domain with its target certificate name from site-configs.conf.
type certSite struct {
	domain   string
	certName string
}

// certSites parses site-configs.conf into (domain, certName) pairs, deduping by
// certificate name (the first domain seen for a cert is the primary).
func (c *proxyConfig) certSites() []certSite {
	seen := map[string]bool{}
	var sites []certSite
	c.eachSite(func(domain, _, certificate string) {
		if certificate == "" || seen[certificate] {
			return
		}
		// A leading [L] marks local-only; strip it for the cert's CN.
		if len(domain) >= 3 && domain[:3] == "[L]" {
			domain = domain[3:]
		}
		seen[certificate] = true
		sites = append(sites, certSite{domain: domain, certName: certificate})
	})
	return sites
}

// issueCmd issues (or reissues) certs. With no args it processes every site in
// the config; otherwise only the named certificates.
func (c *proxyConfig) issueCmd(args []string) {
	iss, err := c.newIssuer()
	if err != nil {
		fail("%v", err)
	}

	sites := c.certSites()
	if len(args) > 0 {
		want := map[string]bool{}
		for _, a := range args {
			want[a] = true
		}
		var filtered []certSite
		for _, s := range sites {
			if want[s.certName] {
				filtered = append(filtered, s)
			}
		}
		sites = filtered
	}
	if len(sites) == 0 {
		warn("No matching sites with certificates in %s", c.configFile)
		return
	}

	okCount, failCount := 0, 0
	for _, s := range sites {
		domains := []string{s.domain, "www." + s.domain}
		info("Issuing %s for %v ...", s.certName, domains)
		if err := iss.obtain(s.certName, domains); err != nil {
			fail0("issue %s: %v", s.certName, err)
			failCount++
			continue
		}
		ok("Issued %s → %s/%s/", s.certName, iss.certsSub, s.certName)
		okCount++
	}
	fmt.Printf("\nIssued %d, failed %d\n", okCount, failCount)
	if failCount > 0 {
		os.Exit(1)
	}
}

// renewCmd renews certs nearing expiry. One-shot by default; with --daemon it
// loops, waking once a day. After any renewal it regenerates configs + reloads.
func (c *proxyConfig) renewCmd(args []string) {
	daemon := false
	for _, a := range args {
		if a == "--daemon" {
			daemon = true
		}
	}

	renewDays := defaultRenewDays
	if v := configRead("REVPRO_RENEW_DAYS"); v != "" {
		if n := atoiSafe(v); n > 0 {
			renewDays = n
		}
	}

	runOnce := func() {
		iss, err := c.newIssuer()
		if err != nil {
			fail0("%v", err)
			return
		}
		sites := c.certSites()
		renewed := 0
		for _, s := range sites {
			days, ok := iss.daysUntilExpiry(s.certName)
			switch {
			case !ok:
				info("%s: no valid cert, issuing...", s.certName)
			case days >= renewDays:
				info("%s: %dd left (>= %dd) — skip", s.certName, days, renewDays)
				continue
			default:
				info("%s: %dd left (< %dd) — renewing...", s.certName, days, renewDays)
			}
			domains := []string{s.domain, "www." + s.domain}
			if err := iss.obtain(s.certName, domains); err != nil {
				fail0("renew %s: %v", s.certName, err)
				continue
			}
			ok2("Renewed %s", s.certName)
			renewed++
		}
		if renewed > 0 {
			info("%d cert(s) renewed — regenerating + reloading nginx", renewed)
			c.clean()
			c.generate()
			c.reload()
		} else {
			info("Nothing to renew.")
		}
	}

	if !daemon {
		runOnce()
		return
	}

	info("Renewal daemon started (checking daily, renew window %dd).", renewDays)
	for {
		runOnce()
		time.Sleep(24 * time.Hour)
	}
}

// fail0 / ok2 are non-exiting variants of fail/ok used inside loops.
func fail0(format string, a ...any) {
	fmt.Fprintf(os.Stderr, cRed+"✗"+cReset+" "+format+"\n", a...)
}
func ok2(format string, a ...any) {
	fmt.Printf(cGreen+"✓"+cReset+" "+format+"\n", a...)
}
