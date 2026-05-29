// revpro — nginx reverse-proxy manager (Go port of the original bash plugin).
//
// One binary, several subcommands that mirror the legacy scripts:
//
//	revpro generate|add|list|reload|restart|clean|regenerate|edit   (was revpro.sh)
//	revpro init setup|open                                          (was revpro-init.sh)
//	revpro cert  -d <domain> [-e|-i|-s|-a|-v|-g|-comp --CA path]    (was cert.sh)
//	revpro certgen -d <domain> -d <wildcard> --years N ...          (was certgen.sh)
//	revpro http  <2|3> <url>                                        (was revtp.sh)
//
// Configuration is read through `cmnds config read <NAME>`, matching the other
// Go plugins (the bash version shelled out to `cmnds-config read`). The nginx
// include templates are embedded in the binary and written out by `init setup`.
package main

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed templates/*.conf
var templates embed.FS

// ANSI colors, matching the bash scripts' palette.
const (
	cReset  = "\033[0m"
	cRed    = "\033[0;31m"
	cGreen  = "\033[0;32m"
	cYellow = "\033[1;33m"
	cBlue   = "\033[1;34m"
	cCyan   = "\033[0;36m"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
	case "generate":
		mustConfig().generate()
	case "regenerate":
		c := mustConfig()
		// `regenerate --renew` first renews any near-expiry certs, then rebuilds.
		for _, a := range os.Args[2:] {
			if a == "--renew" {
				c.renewCmd(nil)
				return
			}
		}
		c.clean()
		c.generate()
		c.reload()
	case "issue":
		mustConfig().issueCmd(os.Args[2:])
	case "renew":
		mustConfig().renewCmd(os.Args[2:])
	case "add":
		mustConfig().add(os.Args[2:])
	case "list":
		mustConfig().list()
	case "reload":
		mustConfig().reload()
	case "restart":
		mustConfig().restart()
	case "clean":
		mustConfig().clean()
	case "edit":
		mustConfig().edit()
	case "init":
		mustConfig().initCmd(os.Args[2:])
	case "cert":
		certInspect(os.Args[2:])
	case "certgen":
		certGen(os.Args[2:])
	case "http":
		httpCheck(os.Args[2:])
	default:
		fail("unknown command %q", os.Args[1])
	}
}

// ---------- shared helpers ----------

func info(format string, a ...any) { fmt.Printf(cBlue+"●"+cReset+" "+format+"\n", a...) }
func ok(format string, a ...any)   { fmt.Printf(cGreen+"✓"+cReset+" "+format+"\n", a...) }
func warn(format string, a ...any) { fmt.Printf(cYellow+"⚠"+cReset+" "+format+"\n", a...) }
func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, cRed+"✗"+cReset+" "+format+"\n", a...)
	os.Exit(1)
}

// configRead returns the value of a cmnds config variable, or "" if unset or
// cmnds isn't available.
func configRead(name string) string {
	cmnds, err := exec.LookPath("cmnds")
	if err != nil {
		return ""
	}
	out, err := exec.Command(cmnds, "config", "read", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// run executes a command with the current stdio attached.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// ---------- config / paths ----------

// proxyConfig holds the resolved paths and flags the site-generation commands
// need, mirroring the variables at the top of revpro.sh.
type proxyConfig struct {
	mainFolder    string
	configFile    string
	confDir       string
	logDir        string
	authProxyConf string
	certsSub      string
	http3         bool
}

func mustConfig() *proxyConfig {
	main := configRead("REVPRO")
	if main == "" {
		fail("REVPRO folder is not configured — run 'cmnds config write REVPRO /path/to/revpro'")
	}
	return &proxyConfig{
		mainFolder:    main,
		configFile:    filepath.Join(main, "site-configs.conf"),
		confDir:       filepath.Join(main, "conf"),
		logDir:        filepath.Join(main, "logs"),
		authProxyConf: "/etc/nginx/includes/authentik-proxy.conf",
		certsSub:      configRead("CERTS_SUB"),
		http3:         strings.EqualFold(configRead("HTTP3"), "true"),
	}
}

// ---------- site config generation (revpro.sh) ----------

// generateOne writes the per-site nginx config for one (domain, container,
// certificate) triple. It reproduces the prefix grammar of the bash version:
//
//	leading "[L]" on the domain  → local-only (include local.conf)
//	"s:" anywhere in container    → forward over https (else http)
//	leading a:/s:/w: prefixes are stripped to get server:port
//	"a:" / "a:s:" / "s:a:" prefix → authentik proxy block instead of location /
func (c *proxyConfig) generateOne(domain, container, certificate string) {
	confFile := filepath.Join(c.confDir, domain+".conf")
	localOnly := false
	if strings.HasPrefix(domain, "[L]") {
		localOnly = true
		domain = domain[3:]
		confFile = filepath.Join(c.confDir, domain+".conf")
	}

	if err := os.MkdirAll(filepath.Dir(confFile), 0o755); err != nil {
		fail("create conf dir: %v", err)
	}

	forwardScheme := "http"
	if strings.Contains(container, "s:") {
		forwardScheme = "https"
	}

	// Strip any leading a:/s:/w: prefixes to recover server:port.
	cleaned := container
	for len(cleaned) >= 2 && strings.ContainsRune("asw", rune(cleaned[0])) && cleaned[1] == ':' {
		cleaned = cleaned[2:]
	}
	server := cleaned
	port := cleaned
	if i := strings.LastIndex(cleaned, ":"); i >= 0 {
		server = cleaned[:i]
		port = cleaned[i+1:]
	}

	authentik := strings.HasPrefix(container, "a:") ||
		strings.HasPrefix(container, "a:s:") ||
		strings.HasPrefix(container, "s:a:")

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`############
# %s
# autogenerated using >> cmnds revpro
# DON'T EDIT DIRECTLY, revpro OVERWRITES THIS FILE!!!
# github.com/maskalix/cmnds
############
# server listen 80 should be located inside nginx.conf as redirect for all domains... use HTTPS ;)
server {
`, domain))

	if c.http3 {
		b.WriteString("    # Enable HTTP/3\n    listen 443 quic;\n    listen [::]:443 quic;\n    \n")
	}

	b.WriteString(fmt.Sprintf(`    # Enable HTTP/2
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    server_name %s;

    # Logs
    access_log %s/%s_access.log;
    error_log %s/%s_error.log;

    # SSL
    ssl_certificate %s/%s/%s.crt;
    ssl_certificate_key %s/%s/%s.key;
    ssl_trusted_certificate %s/%s/%s.issuer.crt;

    # Includes
    include /etc/nginx/includes/letsencrypt.conf;
    include /etc/nginx/includes/general.conf;
    include /etc/nginx/includes/security.conf;

    # Variables
    set $forward_scheme %s;
    set $server %s;
    set $port %s;
    set $upstream $forward_scheme://$server:$port;
`,
		domain,
		c.logDir, domain, c.logDir, domain,
		c.certsSub, certificate, certificate,
		c.certsSub, certificate, certificate,
		c.certsSub, certificate, certificate,
		forwardScheme, server, port))

	if authentik {
		b.WriteString(fmt.Sprintf("        \n    # Authentik proxy\n    include %s;\n}\n", c.authProxyConf))
	} else {
		b.WriteString("        \n    location / {\n")
		if c.http3 {
			b.WriteString("        # HTTP/3 Support\n        include /etc/nginx/includes/http3.conf;\n")
		}
		b.WriteString("        \n        # Proxy\n        proxy_pass $upstream;\n        include /etc/nginx/includes/proxy.conf;\n")
		if localOnly {
			b.WriteString("            \n        # Local access only\n        include /etc/nginx/includes/local.conf;\n")
		}
		b.WriteString("        \n        # Error redirect\n        include /etc/nginx/includes/error.conf;\n    }\n}\n")
	}

	if err := os.WriteFile(confFile, []byte(b.String()), 0o644); err != nil {
		fail("write %s: %v", confFile, err)
	}
	c.createLogFiles(domain)
	fmt.Printf("🕸️  %s\n", domain)
}

func (c *proxyConfig) createLogFiles(domain string) {
	_ = os.MkdirAll(c.logDir, 0o755)
	for _, suffix := range []string{"_access.log", "_error.log"} {
		f, err := os.OpenFile(filepath.Join(c.logDir, domain+suffix), os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
		}
	}
}

// eachSite reads site-configs.conf and calls fn for every non-comment line.
// Fields are whitespace-separated: domain, container, certificate.
func (c *proxyConfig) eachSite(fn func(domain, container, certificate string)) {
	f, err := os.Open(c.configFile)
	if err != nil {
		fail("Configuration file not found at %s", c.configFile)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		fn(fields[0], fields[1], fields[2])
	}
}

func (c *proxyConfig) generate() {
	info("Generating configs for domains:")
	fmt.Println("-----------------------")
	c.eachSite(c.generateOne)
	fmt.Println("-----------------------")
	ok("Configs generated")
}

func (c *proxyConfig) add(args []string) {
	if len(args) != 3 {
		fail("Usage: revpro add <domain> <container> <certificate>")
	}
	domain, container, certificate := args[0], args[1], args[2]

	f, err := os.OpenFile(c.configFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fail("open config: %v", err)
	}
	fmt.Fprintf(f, "%s    %s    %s\n", domain, container, certificate)
	f.Close()

	c.generateOne(domain, container, certificate)
	c.reload()
}

func (c *proxyConfig) list() {
	f, err := os.Open(c.configFile)
	if err != nil {
		fail("Configuration file not found at %s", c.configFile)
	}
	defer f.Close()

	fmt.Printf("Listing all domains from %s (ignoring comments):\n", c.configFile)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			fmt.Println(fields[0])
		}
	}
}

func (c *proxyConfig) clean() {
	info("Cleaning up configuration and log directories...")
	for _, d := range []string{c.confDir, c.logDir} {
		_ = os.RemoveAll(d)
		_ = os.MkdirAll(d, 0o755)
	}
	ok("Configuration and log directories cleaned and recreated.")
}

func (c *proxyConfig) reload() {
	info("🔃 Reloading Nginx...")
	if err := run("docker", "exec", "-t", "reverseproxy", "nginx", "-t"); err != nil {
		warn("Nginx configuration test failed, please check the errors above.")
		return
	}
	if err := run("docker", "exec", "-t", "reverseproxy", "nginx", "-s", "reload"); err != nil {
		warn("Failed to reload Nginx, please check the container status and logs.")
		return
	}
	ok("Nginx reloaded.")
}

func (c *proxyConfig) restart() {
	if err := run("docker", "container", "restart", "reverseproxy"); err != nil {
		fail("restart failed: %v", err)
	}
	ok("Nginx restarted.")
}

func (c *proxyConfig) edit() {
	if _, err := os.Stat(c.configFile); err != nil {
		fail("Configuration file not found at %s", c.configFile)
	}
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}
	if err := run(editor, c.configFile); err != nil {
		fail("editor failed: %v", err)
	}
}

// ---------- init (revpro-init.sh) ----------

func (c *proxyConfig) initCmd(args []string) {
	if len(args) == 0 {
		fail("No command provided. Use 'revpro init help'.")
	}
	switch args[0] {
	case "setup":
		c.initSetup()
	case "open":
		c.edit()
	case "help":
		fmt.Printf(`Usage: revpro init [command]

Commands:
  open   Open %s in your editor.
  setup  Create/recreate the folder structure (prompts before deleting existing content).
  help   Show this help.
`, c.configFile)
	default:
		fail("Invalid command. Use 'revpro init help'.")
	}
}

func (c *proxyConfig) initSetup() {
	if _, err := os.Stat(c.mainFolder); err == nil {
		fmt.Printf("The folder %s already exists. Do you want to delete its contents? (y/N): ", c.mainFolder)
		var reply string
		fmt.Scanln(&reply)
		if !strings.HasPrefix(strings.ToLower(reply), "y") {
			fail("Exiting setup without making changes.")
		}
		info("Deleting existing content...")
		_ = os.RemoveAll(c.mainFolder)
	}

	info("Creating folder structure...")
	for _, d := range []string{c.confDir, filepath.Join(c.mainFolder, "manconf"), filepath.Join(c.mainFolder, "misc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fail("mkdir %s: %v", d, err)
		}
	}
	ok("Folder structure created successfully in %s.", c.mainFolder)

	// site-configs.conf goes to the main folder; the rest of the embedded
	// templates land in misc/ (matching revpro-init.sh).
	info("Writing template files...")
	misc := filepath.Join(c.mainFolder, "misc")
	entries, _ := fs.ReadDir(templates, "templates")
	for _, e := range entries {
		data, err := templates.ReadFile("templates/" + e.Name())
		if err != nil {
			continue
		}
		dest := filepath.Join(misc, e.Name())
		if e.Name() == "site-configs.conf" {
			dest = filepath.Join(c.mainFolder, e.Name())
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			warn("write %s: %v", dest, err)
		}
	}
	ok("Template files written.")
}

// ---------- cert inspection (cert.sh) ----------

func certInspect(args []string) {
	var (
		domain                                                                  string
		showExpiry, showIssuer, showSubject, showAll, verify, sslCheck, compare bool
		caPath                                                                  string
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			i++
			if i < len(args) {
				domain = args[i]
			}
		case "-e":
			showExpiry = true
		case "-i":
			showIssuer = true
		case "-s":
			showSubject = true
		case "-a":
			showAll = true
		case "-v":
			verify = true
		case "-g":
			sslCheck = true
		case "-comp":
			compare = true
		case "--CA":
			i++
			if i < len(args) {
				caPath = args[i]
			}
		default:
			certUsage()
		}
	}
	if domain == "" {
		certUsage()
	}

	if sslCheck {
		out, err := exec.Command("openssl", "s_client", "-connect", domain+":443", "-servername", domain).CombinedOutput()
		if err == nil && strings.Contains(string(out), "CONNECTED") {
			fmt.Printf(cGreen+"✅ Success: SSL connection to %s is established without ERR_SSL_* errors."+cReset+"\n", domain)
		} else {
			fmt.Printf(cRed+"❌ Error: Could not establish an SSL connection to %s."+cReset+"\n", domain)
			fmt.Println(cCyan + "Details:" + cReset)
			fmt.Println(string(out))
			os.Exit(1)
		}
	} else {
		fmt.Printf(cBlue+"🔍 Fetching SSL certificate information for %s..."+cReset+"\n", domain)
		if showExpiry {
			fmt.Printf(cBlue+"🔍 Certificate expiry date for %s:"+cReset+"\n", domain)
			certInfo(domain, "-dates")
		}
		if showIssuer {
			fmt.Printf(cBlue+"🔍 Certificate issuer for %s:"+cReset+"\n", domain)
			certInfo(domain, "-issuer")
		}
		if showSubject {
			fmt.Printf(cBlue+"🔍 Certificate subject for %s:"+cReset+"\n", domain)
			certInfo(domain, "-subject")
		}
		if showAll {
			fmt.Printf(cBlue+"🔍 Full certificate details for %s:"+cReset+"\n", domain)
			certInfo(domain, "-text")
		}
		if verify {
			fmt.Printf(cBlue+"🔍 Verifying certificate chain for %s:"+cReset+"\n", domain)
			verifyCert(domain)
		}
	}

	if compare {
		if caPath == "" {
			fail("CA certificate path is required with -comp flag.")
		}
		compareCertWithCA(domain, caPath)
	}
}

// certInfo pipes `openssl s_client` into `openssl x509 -noout <field>`.
func certInfo(domain, field string) {
	pem, err := fetchCertPEM(domain)
	if err != nil || pem == "" {
		fmt.Printf(cRed+"❌ Error: Could not retrieve the certificate for %s."+cReset+"\n", domain)
		return
	}
	cmd := exec.Command("openssl", "x509", "-noout", field)
	cmd.Stdin = strings.NewReader(pem)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	fmt.Println()
}

func verifyCert(domain string) {
	pem, err := fetchCertPEM(domain)
	if err != nil || pem == "" {
		fmt.Printf(cRed+"❌ Error: Could not retrieve the certificate for %s."+cReset+"\n", domain)
		return
	}
	tmp, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		fail("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(pem)
	tmp.Close()
	_ = run("openssl", "verify", tmp.Name())
	fmt.Println()
}

func compareCertWithCA(domain, caPath string) {
	pem, err := fetchCertPEM(domain)
	if err != nil || pem == "" {
		fail("Could not retrieve the certificate for %s.", domain)
	}
	tmp, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		fail("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(pem)
	tmp.Close()
	if exec.Command("openssl", "verify", "-CAfile", caPath, tmp.Name()).Run() == nil {
		fmt.Printf(cGreen+"✅ The certificate for %s matches the provided CA certificate."+cReset+"\n", domain)
	} else {
		fmt.Printf(cRed+"❌ The certificate for %s does NOT match the provided CA certificate."+cReset+"\n", domain)
	}
}

// fetchCertPEM retrieves the leaf certificate of a host as PEM by piping
// `openssl s_client` into `openssl x509`.
func fetchCertPEM(domain string) (string, error) {
	sclient := exec.Command("openssl", "s_client", "-connect", domain+":443", "-servername", domain)
	sclient.Stdin = strings.NewReader("")
	raw, err := sclient.Output()
	if err != nil {
		return "", err
	}
	x509 := exec.Command("openssl", "x509")
	x509.Stdin = strings.NewReader(string(raw))
	out, err := x509.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func certUsage() {
	fmt.Printf(cYellow + "Usage: revpro cert -d domain.tld [-e|-i|-s|-a|-v|-g|-comp --CA 'PATH']" + cReset + `
    -d domain     : Specify the domain (required)
    -e            : Show certificate expiry date
    -i            : Show certificate issuer information
    -s            : Show certificate subject information
    -a            : Show all certificate details
    -v            : Verify the certificate chain integrity
    -g            : Check if the site is reachable over SSL
    -comp         : Compare the retrieved certificate with the provided CA certificate
    --CA 'PATH'   : Path to the CA certificate file (required with -comp)
`)
	os.Exit(1)
}

// ---------- self-signed cert generation (certgen.sh) ----------

func certGen(args []string) {
	main := configRead("CERTS")
	sub := configRead("CERTS_SUB")

	var (
		domain, wildcard, years, country, state, organization string
		alts                                                  []string
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			i++
			if i < len(args) {
				if domain == "" {
					domain = args[i]
				} else {
					wildcard = args[i]
				}
			}
		case "--years":
			i++
			if i < len(args) {
				years = args[i]
			}
		case "--country":
			i++
			if i < len(args) {
				country = args[i]
			}
		case "--state":
			i++
			if i < len(args) {
				state = args[i]
			}
		case "--organization":
			i++
			if i < len(args) {
				organization = args[i]
			}
		case "--alt":
			i++
			if i < len(args) {
				alts = append(alts, args[i])
			}
		default:
			fail("Unknown option: %s", args[i])
		}
	}
	if domain == "" || years == "" || country == "" || state == "" || organization == "" {
		fail("Usage: revpro certgen -d <domain> -d <wildcard> --years N --country CC --state ST --organization ORG [--alt domain ...]")
	}

	leDir := filepath.Join(sub, domain)
	rootKey := filepath.Join(main, "rootCA.key")
	rootCrt := filepath.Join(main, "rootCA.crt")

	_ = os.MkdirAll(leDir, 0o755)
	_ = os.MkdirAll(main, 0o755)

	// Server-cert validity: bash computed YEARS*365 days. Keep that arithmetic.
	days := "365"
	if n := atoiSafe(years); n > 0 {
		days = itoa(n * 365)
	}

	if _, err := os.Stat(rootKey); err != nil {
		info("Creating Root Key...")
		if err := run("openssl", "genrsa", "-aes256", "-out", rootKey, "4096"); err != nil {
			fail("root key: %v", err)
		}
	}
	if _, err := os.Stat(rootCrt); err != nil {
		info("Creating and Self-Signing Root Certificate...")
		subj := fmt.Sprintf("/C=%s/ST=%s/O=%s/CN=revpro CA", country, state, organization)
		if err := run("openssl", "req", "-x509", "-new", "-nodes", "-key", rootKey,
			"-sha256", "-days", "1024", "-out", rootCrt, "-subj", subj); err != nil {
			fail("root cert: %v", err)
		}
	}

	key := filepath.Join(leDir, "privkey.pem")
	csr := filepath.Join(leDir, "certificate.csr")
	crt := filepath.Join(leDir, "fullchain.pem")
	cnf := filepath.Join(leDir, "csr_config.cnf")

	info("Creating Certificate Key for %s...", domain)
	if err := run("openssl", "genrsa", "-out", key, "4096"); err != nil {
		fail("cert key: %v", err)
	}

	info("Creating Signing Request (CSR) for %s and %s...", domain, wildcard)
	san := []string{domain}
	if wildcard != "" {
		san = append(san, wildcard)
	}
	san = append(san, alts...)

	var cfg strings.Builder
	cfg.WriteString("[req]\ndefault_bits       = 4096\ndistinguished_name = req_distinguished_name\nreq_extensions     = req_ext\nprompt             = no\n")
	cfg.WriteString(fmt.Sprintf("[req_distinguished_name]\nC = %s\nST = %s\nO = %s\nCN = %s\n", country, state, organization, domain))
	cfg.WriteString("[req_ext]\nsubjectAltName = @alt_names\n[alt_names]\n")
	for i, s := range san {
		cfg.WriteString(fmt.Sprintf("DNS.%d = %s\n", i+1, s))
	}
	if err := os.WriteFile(cnf, []byte(cfg.String()), 0o644); err != nil {
		fail("write csr config: %v", err)
	}

	if err := run("openssl", "req", "-new", "-key", key, "-out", csr, "-sha256", "-config", cnf); err != nil {
		fail("csr: %v", err)
	}

	info("Verifying CSR content for %s...", domain)
	_ = run("openssl", "req", "-in", csr, "-noout", "-text")

	info("Generating Certificate for %s...", domain)
	if err := run("openssl", "x509", "-req", "-in", csr, "-CA", rootCrt, "-CAkey", rootKey,
		"-CAcreateserial", "-out", crt, "-days", days, "-sha256", "-extfile", cnf, "-extensions", "req_ext"); err != nil {
		fail("sign cert: %v", err)
	}

	info("Verifying Certificate content for %s...", domain)
	_ = run("openssl", "x509", "-in", crt, "-text", "-noout")

	ok("Combined Certificate for %s and %s created successfully!", domain, wildcard)
	fmt.Println("All tasks completed.")
}

// ---------- HTTP/2,3 check (revtp.sh) ----------

func httpCheck(args []string) {
	if len(args) != 2 {
		fail("Usage: revpro http <2|3> <url>")
	}
	version, url := args[0], args[1]
	switch version {
	case "2":
		out, _ := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_version}", "--http2", url).Output()
		v := strings.TrimSpace(string(out))
		if v == "2" || v == "2.0" {
			fmt.Println(cGreen + "HTTP/2 Supported" + cReset)
		} else {
			fmt.Println(cRed + "HTTP/2 Not Supported" + cReset)
		}
		fmt.Println("Details:")
		_ = run("curl", "-I", "--http2", url)
	case "3":
		if _, err := exec.LookPath("quick"); err != nil {
			fail("'quick' tool is not installed. Please install it to test HTTP/3.")
		}
		out, _ := exec.Command("quick", "-s", "-o", "/dev/null", "-w", "%H", url).CombinedOutput()
		if strings.Contains(string(out), "HTTP/3") {
			fmt.Println(cGreen + "HTTP/3 Supported" + cReset)
		} else {
			fmt.Println(cRed + "HTTP/3 Not Supported" + cReset)
		}
		fmt.Println("Details:")
		_ = run("quick", "-I", url)
	default:
		fail("First argument must be either '2' for HTTP/2 or '3' for HTTP/3")
	}
}

// ---------- small int helpers (avoid strconv churn in hot spots) ----------

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func usage() {
	fmt.Print(`revpro — nginx reverse-proxy manager

Usage:
  revpro <command> [args]

Site configs (reads $REVPRO/site-configs.conf):
  generate            Generate per-site nginx configs from site-configs.conf
  regenerate [--renew]
                      Clean, regenerate, then reload (--renew: renew due certs first)
  add <domain> <container> <certificate>
                      Append a site and generate+reload it
  list                List configured domains
  reload              docker exec reverseproxy nginx -s reload
  restart             docker restart reverseproxy
  clean               Wipe and recreate conf/ and logs/
  edit                Open site-configs.conf in $EDITOR (default nano)
  init setup|open     Create the folder structure / open the config

Certificates (ACME / Let's Encrypt via lego, HTTP-01):
  issue [cert...]     Issue certs for all sites (or only the named ones).
                      Each cert covers <domain> + www.<domain>, written to
                      $CERTS_SUB/<cert>/<cert>.{crt,key,issuer.crt}.
  renew [--daemon]    Renew certs within the renew window, then regenerate+reload.
                      --daemon loops, checking once a day.

TLS helpers:
  cert -d <domain> [-e|-i|-s|-a|-v|-g|-comp --CA path]
                      Inspect/verify a live certificate (openssl)
  certgen -d <domain> -d <wildcard> --years N --country CC --state ST
          --organization ORG [--alt domain ...]
                      Generate a self-signed root CA + server cert
  http <2|3> <url>    Check HTTP/2 or HTTP/3 support

Config variables (via 'cmnds config'):
  REVPRO              base folder (site-configs.conf, conf/, logs/, acme/)
  CERTS, CERTS_SUB    self-signed CA dir / per-cert output base
  HTTP3               "true" to emit HTTP/3 listeners
  REVPRO_ACME_EMAIL   ACME account email (required for issue/renew)
  REVPRO_ACME_PORT    HTTP-01 challenge port (default 5002)
  REVPRO_ACME_STAGING "true" → Let's Encrypt staging CA
  REVPRO_ACME_DIR     ACME account storage (default $REVPRO/acme)
  REVPRO_RENEW_DAYS   renew when fewer than N days remain (default 30)
`)
}
