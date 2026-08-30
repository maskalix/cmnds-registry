// securitycheck.go — a security-headers/TLS checklist for a live HTTPS URL,
// covering exactly the items a Seon-style audit flags: cert chain trust and
// completeness, HSTS, CSP, X-Content-Type-Options, OCSP stapling,
// X-Frame-Options, Referrer-Policy, and Permissions-Policy.
//
// Read-only: it just fetches the URL once (no redirects followed, so the
// checked headers are the first hop's own) and inspects the response and TLS
// connection state. No revpro state is touched.
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type secCheck struct {
	Name     string `json:"name"`
	Severity string `json:"severity"` // "critical", "warning", "info"
	Pass     bool   `json:"pass"`
	Value    string `json:"value,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type secCheckResult struct {
	URL    string     `json:"url"`
	Error  string     `json:"error,omitempty"`
	Note   string     `json:"note,omitempty"`
	Checks []secCheck `json:"checks"`
}

// hstsMinAge is the floor Seon's own guide uses (180 days).
const hstsMinAge = 180 * 24 * 3600

func runSecurityCheck(rawURL string) secCheckResult {
	result := secCheckResult{URL: rawURL}

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		result.Error = "URL must be a full https:// address"
		return result
	}

	fetch := func(insecure bool) (*http.Response, error) {
		client := &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}},
		}
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "revpro-security-check/1.0")
		return client.Do(req)
	}

	resp, err := fetch(false)
	var chainErr error
	if err != nil {
		chainErr = err
		resp, err = fetch(true) // fall back so header checks can still run
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if chainErr != nil {
		result.Note = "the certificate itself failed verification (see below) — remaining checks were still " +
			"run over the connection, but nothing here is trustworthy until that's fixed"
	}

	if resp.TLS != nil {
		chainLen := len(resp.TLS.PeerCertificates)
		if chainErr != nil {
			result.Checks = append(result.Checks, secCheck{
				Name: "Certificate chain trust", Severity: "critical", Pass: false,
				Detail: chainErr.Error(),
			})
		} else {
			result.Checks = append(result.Checks, secCheck{
				Name: "Certificate chain trust", Severity: "critical", Pass: true,
				Value: fmt.Sprintf("%d cert(s) in chain", chainLen),
			})
		}
		result.Checks = append(result.Checks, secCheck{
			Name: "Certificate chain completeness", Severity: "warning", Pass: chainLen > 1,
			Value:  fmt.Sprintf("%d cert(s) served", chainLen),
			Detail: pick(chainLen > 1, "", "server should send the leaf cert plus at least one intermediate (fullchain, not just cert)"),
		})
		result.Checks = append(result.Checks, secCheck{
			Name: "OCSP stapling", Severity: "info", Pass: len(resp.TLS.OCSPResponse) > 0,
			Value:  fmt.Sprintf("%d byte(s) stapled", len(resp.TLS.OCSPResponse)),
			Detail: pick(len(resp.TLS.OCSPResponse) > 0, "", "no stapled OCSP response — enable ssl_stapling"),
		})
	} else {
		result.Checks = append(result.Checks, secCheck{Name: "Certificate chain trust", Severity: "critical", Pass: false, Detail: "connection was not over TLS"})
	}

	h := resp.Header

	hsts := h.Get("Strict-Transport-Security")
	result.Checks = append(result.Checks, secCheck{
		Name: "Strict-Transport-Security", Severity: "warning", Pass: hstsMaxAgeOK(hsts),
		Value: hsts, Detail: pick(hsts != "", "", "missing — browsers won't enforce HTTPS on their own"),
	})

	csp := h.Get("Content-Security-Policy")
	cspRO := h.Get("Content-Security-Policy-Report-Only")
	cspVal := csp
	if cspVal == "" {
		cspVal = cspRO
	}
	result.Checks = append(result.Checks, secCheck{
		Name: "Content-Security-Policy", Severity: "warning", Pass: cspVal != "",
		Value: cspVal, Detail: pick(cspVal != "", pick(csp == "" && cspRO != "", "report-only, not enforced yet", ""), "missing"),
	})

	xcto := h.Get("X-Content-Type-Options")
	result.Checks = append(result.Checks, secCheck{
		Name: "X-Content-Type-Options", Severity: "warning", Pass: strings.EqualFold(xcto, "nosniff"),
		Value: xcto, Detail: pick(xcto != "", "", "missing"),
	})

	xfo := h.Get("X-Frame-Options")
	cspHasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	result.Checks = append(result.Checks, secCheck{
		Name: "Clickjacking protection (X-Frame-Options)", Severity: "info", Pass: xfo != "" || cspHasFrameAncestors,
		Value: xfo, Detail: pick(xfo != "" || cspHasFrameAncestors, "", "missing (and no frame-ancestors in an enforced CSP)"),
	})

	ref := h.Get("Referrer-Policy")
	result.Checks = append(result.Checks, secCheck{
		Name: "Referrer-Policy", Severity: "info", Pass: ref != "",
		Value: ref, Detail: pick(ref != "", "", "missing — browser default applies"),
	})

	perm := h.Get("Permissions-Policy")
	permReal := perm != "" && !isOnlyFlocOptOut(perm)
	result.Checks = append(result.Checks, secCheck{
		Name: "Permissions-Policy", Severity: "info", Pass: permReal,
		Value: perm, Detail: pick(permReal, "", pick(perm == "", "missing", "present but only the old FLoC opt-out (interest-cohort=()) — not an actual policy")),
	})

	return result
}

// hstsMaxAgeOK reports whether the header is present with max-age at or
// above Seon's 180-day floor.
func hstsMaxAgeOK(v string) bool {
	if v == "" {
		return false
	}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if age, ok := strings.CutPrefix(part, "max-age="); ok {
			n, err := strconv.Atoi(strings.TrimSpace(age))
			return err == nil && n >= hstsMinAge
		}
	}
	return false
}

// isOnlyFlocOptOut reports whether a Permissions-Policy value is nothing
// more than the old Google FLoC opt-out — a real leftover from ~2021 that
// still shows up copy-pasted into otherwise-empty policies.
func isOnlyFlocOptOut(v string) bool {
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ";"))
	return strings.EqualFold(trimmed, "interest-cohort=()")
}

func pick(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}
