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
	"strings"
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
//
// Order matters: lego.NewClient captures the account Key ID (KID) from
// user.GetRegistration().Location at creation time (see lego/client.go). So a
// previously-saved registration MUST be loaded onto the user *before* the
// client is built — otherwise every signed request goes out with no KID and
// the CA rejects it ("No Key ID in JWS header").
func (iss *issuer) connect() error {
	if err := os.MkdirAll(iss.acmeDir, 0o700); err != nil {
		return fmt.Errorf("create acme dir: %w", err)
	}

	key, err := iss.loadOrCreateAccountKey()
	if err != nil {
		return err
	}
	iss.user = &acmeUser{email: iss.email, key: key}

	// Load any saved registration first so the KID is present at client build.
	saved := iss.loadSavedAccount()

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

	if saved {
		return nil
	}
	return iss.register()
}

// loadSavedAccount restores a persisted registration onto iss.user and reports
// whether a usable one was found.
func (iss *issuer) loadSavedAccount() bool {
	data, err := os.ReadFile(iss.accountRegPath())
	if err != nil {
		return false
	}
	var reg acme.ExtendedAccount
	if json.Unmarshal(data, &reg) != nil || reg.Location == "" {
		return false
	}
	iss.user.reg = &reg
	return true
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

// register creates a new ACME account (accepting the terms of service) and
// persists it. Register() sets the KID on the client core internally, so it is
// safe to call after the client is built.
func (iss *issuer) register() error {
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

// certSite couples a primary domain with its target certificate name, plus the
// SAN list (domain + www. when the www flag is on).
type certSite struct {
	domain   string
	certName string
	sans     []string
}

// certSites resolves sites.conf into per-certificate issuance jobs, deduping by
// certificate name. SANs aggregate every domain (and its www. variant if the
// www flag is set) that maps to the same cert name.
func (c *proxyConfig) certSites() []certSite {
	index := map[string]*certSite{}
	var order []string
	for _, s := range c.mustSites() {
		cs, ok := index[s.certName]
		if !ok {
			cs = &certSite{domain: s.fqdn, certName: s.certName}
			index[s.certName] = cs
			order = append(order, s.certName)
		}
		cs.sans = append(cs.sans, s.fqdn)
		if s.flags.www && !strings.HasPrefix(s.fqdn, "www.") {
			cs.sans = append(cs.sans, "www."+s.fqdn)
		}
	}
	out := make([]certSite, 0, len(order))
	for _, name := range order {
		out = append(out, *index[name])
	}
	return out
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
		info("Issuing %s for %v ...", s.certName, s.sans)
		if err := iss.obtain(s.certName, s.sans); err != nil {
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

	runOnce := func() int {
		iss, err := c.newIssuer()
		if err != nil {
			fail0("%v", err)
			return 1
		}
		sites := c.certSites()
		renewed, failed, skipped := 0, 0, 0
		for _, s := range sites {
			days, have := iss.daysUntilExpiry(s.certName)
			switch {
			case !have:
				info("%s: no valid cert, issuing...", s.certName)
			case days >= renewDays:
				info("%s: %dd left (>= %dd) — skip", s.certName, days, renewDays)
				skipped++
				continue
			default:
				info("%s: %dd left (< %dd) — renewing...", s.certName, days, renewDays)
			}
			if err := iss.obtain(s.certName, s.sans); err != nil {
				fail0("renew %s: %v", s.certName, err)
				failed++
				continue
			}
			ok2("Renewed %s", s.certName)
			renewed++
		}

		if renewed > 0 {
			info("%d renewed, %d skipped, %d failed — regenerating + reloading nginx", renewed, skipped, failed)
			c.clean()
			c.generate()
			c.reload()
		} else if failed > 0 {
			fail0("%d cert(s) failed, %d up to date — nginx NOT reloaded", failed, skipped)
		} else {
			info("All %d cert(s) up to date — nothing to renew.", skipped)
		}
		return failed
	}

	if !daemon {
		if runOnce() > 0 {
			os.Exit(1)
		}
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
