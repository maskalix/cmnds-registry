// dns_wedos.go — a DNS-01 challenge provider for WEDOS's WAPI, used to issue
// wildcard certs (which ACME only ever validates via DNS-01, never HTTP-01)
// for domains hosted at WEDOS. Not part of lego's built-in provider set, so
// implemented directly against WEDOS's own JSON-over-HTTP API.
//
// Reference: https://kb.wedos.global/wapi-wdns/
//
// Config (via `cmnds config`):
//
//	REVPRO_WEDOS_USER      WAPI account username (your WEDOS login email)
//	REVPRO_WEDOS_PASSWORD  WAPI password (set in the WEDOS client admin, not
//	                       your regular account password)
package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata" // embed IANA tz data so Europe/Prague resolves without host tzdata installed

	"github.com/go-acme/lego/v5/challenge/dns01"
)

// wedosAPIURL is a var (not const) so tests can point it at a local mock server.
var wedosAPIURL = "https://api.wedos.com/wapi/json"

// wedosProvider implements challenge.Provider (Present/CleanUp) against
// WEDOS's WAPI. One instance per issuance run; propagationWait gives WEDOS's
// nameservers time to pick up the new record before ACME validation proceeds.
type wedosProvider struct {
	user     string
	password string
	// rowIDs remembers which row was added for each FQDN so CleanUp can
	// delete the exact record without a second lookup-by-content pass.
	rowIDs map[string]string
}

func newWedosProvider() (*wedosProvider, error) {
	user := configRead("REVPRO_WEDOS_USER")
	pass := configRead("REVPRO_WEDOS_PASSWORD")
	if user == "" || pass == "" {
		return nil, fmt.Errorf("REVPRO_WEDOS_USER / REVPRO_WEDOS_PASSWORD not set — run " +
			"'cmnds config write REVPRO_WEDOS_USER you@example.com' and " +
			"'cmnds config write REVPRO_WEDOS_PASSWORD <wapi password>'")
	}
	return &wedosProvider{user: user, password: pass, rowIDs: map[string]string{}}, nil
}

// Timeout gives WEDOS's nameservers time to propagate before lego starts
// polling the ACME server to validate — DNS propagation is much slower than
// an HTTP-01 round trip.
func (p *wedosProvider) Timeout() (timeout, interval time.Duration) {
	return 5 * time.Minute, 10 * time.Second
}

func (p *wedosProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	fqdn := dns01.UnFqdn(info.EffectiveFQDN)

	zone, name, err := p.splitZone(fqdn)
	if err != nil {
		return fmt.Errorf("wedos: %w", err)
	}

	if _, err := p.call("dns-row-add", map[string]string{
		"domain": zone,
		"name":   name,
		"ttl":    "300",
		"type":   "TXT",
		"rdata":  info.Value,
	}); err != nil {
		return fmt.Errorf("wedos: add TXT record: %w", err)
	}
	if err := p.commit(zone); err != nil {
		return fmt.Errorf("wedos: %w", err)
	}
	return nil
}

func (p *wedosProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	fqdn := dns01.UnFqdn(info.EffectiveFQDN)

	zone, name, err := p.splitZone(fqdn)
	if err != nil {
		return fmt.Errorf("wedos: %w", err)
	}

	rowID, err := p.findRow(zone, name, info.Value)
	if err != nil {
		return fmt.Errorf("wedos: locate TXT record to remove: %w", err)
	}
	if rowID == "" {
		// Already gone (e.g. a retried issuance) — nothing to clean up.
		return nil
	}
	if _, err := p.call("dns-row-delete", map[string]string{
		"domain": zone,
		"row_id": rowID,
	}); err != nil {
		return fmt.Errorf("wedos: delete TXT record: %w", err)
	}
	return p.commit(zone)
}

// splitZone finds which suffix of fqdn is a zone WEDOS actually hosts for
// this account, by trying dns-rows-list against progressively shorter
// suffixes (WEDOS's own API gives no direct "is this my zone" lookup other
// than a command succeeding or failing for it). Returns the zone and the
// record name relative to it (e.g. "_acme-challenge.sub" for zone "lnln.eu").
func (p *wedosProvider) splitZone(fqdn string) (zone, name string, err error) {
	labels := strings.Split(fqdn, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		if _, err := p.call("dns-rows-list", map[string]string{"domain": candidate}); err == nil {
			rest := strings.Join(labels[:i], ".")
			return candidate, rest, nil
		}
	}
	return "", "", fmt.Errorf("no WEDOS-managed zone found for %s (check REVPRO_WEDOS_USER/PASSWORD have WAPI access to it)", fqdn)
}

// findRow looks up the row ID of a TXT record by exact name+value match.
func (p *wedosProvider) findRow(zone, name, value string) (string, error) {
	data, err := p.call("dns-rows-list", map[string]string{"domain": zone})
	if err != nil {
		return "", err
	}
	rows, _ := data["row"].([]any)
	for _, r := range rows {
		row, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(row["type"]) != "TXT" || fmt.Sprint(row["name"]) != name || fmt.Sprint(row["rdata"]) != value {
			continue
		}
		for _, key := range []string{"ID", "id", "row_id"} {
			if v, ok := row[key]; ok {
				return fmt.Sprint(v), nil
			}
		}
	}
	return "", nil
}

func (p *wedosProvider) commit(zone string) error {
	_, err := p.call("dns-domain-commit", map[string]string{"name": zone})
	return err
}

// authToken implements WEDOS WAPI's auth scheme: sha1(user + sha1(password) +
// current_hour), hour in Europe/Prague time (CET/CEST), zero-padded 24h.
func (p *wedosProvider) authToken() string {
	loc, err := time.LoadLocation("Europe/Prague")
	if err != nil {
		loc = time.UTC
	}
	hour := time.Now().In(loc).Format("15")
	return wedosAuthToken(p.user, p.password, hour)
}

// wedosAuthToken is the pure computation behind authToken, split out so it
// can be tested against a fixed hour instead of the real current time.
func wedosAuthToken(user, password, hour string) string {
	return sha1Hex(user + sha1Hex(password) + hour)
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// call issues one WAPI command and returns its response "data" object. A
// non-1000-family response code is treated as an error.
func (p *wedosProvider) call(command string, data map[string]string) (map[string]any, error) {
	payload := map[string]any{
		"request": map[string]any{
			"user":    p.user,
			"auth":    p.authToken(),
			"command": command,
			"data":    data,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	form := url.Values{"request": {string(body)}}
	req, err := http.NewRequest(http.MethodPost, wedosAPIURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var out struct {
		Response struct {
			Code   int            `json:"code"`
			Result string         `json:"result"`
			Data   map[string]any `json:"data"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unexpected response: %s", strings.TrimSpace(string(raw)))
	}
	// WAPI success codes are the 1000 family (1000 = OK-ish for most
	// commands); anything else is an error condition per WEDOS's own docs.
	if out.Response.Code/1000 != 1 {
		return nil, fmt.Errorf("%s: code=%d result=%s", command, out.Response.Code, out.Response.Result)
	}
	return out.Response.Data, nil
}
