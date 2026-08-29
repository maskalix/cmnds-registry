// wildcardcerts.go — a small registry of wildcard certs issued via
// 'revpro issue --wildcard'. Wildcard certs aren't tied to any sites.conf
// entry (they exist independently of any single site), so without this they
// would be invisible to 'issue' and 'renew's normal site-driven loop after
// the first issuance. certSites() folds this registry in, so once
// registered, a wildcard is renewed automatically like any other cert.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type wildcardCert struct {
	Domain string `json:"domain"` // apex, e.g. "lnln.eu" — SANs are [domain, "*."+domain]
	Cert   string `json:"cert"`   // cert folder name under $CERTS_SUB
}

func (c *proxyConfig) wildcardCertsFile() string {
	return filepath.Join(c.mainFolder, "wildcard-certs.json")
}

// loadWildcardCerts returns the registered wildcard certs, or nil if none
// have been registered yet (a missing or unreadable file is not an error —
// it just means nothing to add here).
func (c *proxyConfig) loadWildcardCerts() []wildcardCert {
	data, err := os.ReadFile(c.wildcardCertsFile())
	if err != nil {
		return nil
	}
	var out []wildcardCert
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

// registerWildcardCert adds (domain, cert) to the registry if not already
// present, so future 'issue'/'renew' runs pick it up automatically.
func (c *proxyConfig) registerWildcardCert(domain, cert string) error {
	list := c.loadWildcardCerts()
	for _, w := range list {
		if w.Cert == cert {
			return nil
		}
	}
	list = append(list, wildcardCert{Domain: domain, Cert: cert})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.wildcardCertsFile(), data, 0o644)
}
