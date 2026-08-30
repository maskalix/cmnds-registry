package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func findCheck(t *testing.T, checks []secCheck, name string) secCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q among %+v", name, checks)
	return secCheck{}
}

func TestSecurityCheckAllGoodHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := runSecurityCheck(srv.URL)
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	// The test server's cert is self-signed, so trust legitimately fails —
	// that's exercised separately below. Here just check the headers that
	// don't depend on a trusted chain.
	for _, name := range []string{
		"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
		"Clickjacking protection (X-Frame-Options)", "Referrer-Policy", "Permissions-Policy",
	} {
		c := findCheck(t, res.Checks, name)
		if !c.Pass {
			t.Errorf("%s: expected pass, got fail (detail: %s)", name, c.Detail)
		}
	}
}

func TestSecurityCheckMissingHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := runSecurityCheck(srv.URL)
	for _, name := range []string{
		"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
		"Clickjacking protection (X-Frame-Options)", "Referrer-Policy", "Permissions-Policy",
	} {
		c := findCheck(t, res.Checks, name)
		if c.Pass {
			t.Errorf("%s: expected fail when header is absent", name)
		}
		if c.Detail == "" {
			t.Errorf("%s: expected a non-empty detail explaining the failure", name)
		}
	}
}

func TestSecurityCheckUntrustedCertStillChecksHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := runSecurityCheck(srv.URL)
	if res.Error != "" {
		t.Fatalf("unexpected top-level error: %s", res.Error)
	}
	trust := findCheck(t, res.Checks, "Certificate chain trust")
	if trust.Pass {
		t.Error("expected chain trust to fail for a self-signed test cert")
	}
	if trust.Detail == "" {
		t.Error("expected the actual verification error in Detail")
	}
	if res.Note == "" {
		t.Error("expected a Note explaining headers were still checked over an unverified connection")
	}
	// Headers must still be visible via the insecure fallback.
	xcto := findCheck(t, res.Checks, "X-Content-Type-Options")
	if !xcto.Pass {
		t.Error("expected X-Content-Type-Options to still be checked despite the untrusted cert")
	}
}

func TestSecurityCheckHSTSMaxAgeTooLow(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=60") // way below the 180-day floor
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := runSecurityCheck(srv.URL)
	hsts := findCheck(t, res.Checks, "Strict-Transport-Security")
	if hsts.Pass {
		t.Error("expected a too-low max-age to fail")
	}
}

func TestSecurityCheckCSPReportOnlyNotedAsSuch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := runSecurityCheck(srv.URL)
	csp := findCheck(t, res.Checks, "Content-Security-Policy")
	if !csp.Pass {
		t.Error("report-only CSP should still count as present")
	}
	if csp.Detail == "" {
		t.Error("expected a detail note distinguishing report-only from enforced")
	}
}

func TestSecurityCheckFlocOnlyPermissionsPolicyFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Permissions-Policy", "interest-cohort=()")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := runSecurityCheck(srv.URL)
	perm := findCheck(t, res.Checks, "Permissions-Policy")
	if perm.Pass {
		t.Error("a permissions-policy that is only the FLoC opt-out should not count as a real policy")
	}
	if perm.Detail == "" {
		t.Error("expected an explanatory detail")
	}
}

func TestSecurityCheckRejectsNonHTTPS(t *testing.T) {
	res := runSecurityCheck("http://example.com")
	if res.Error == "" {
		t.Error("expected an error for a non-https URL")
	}
}

func TestSecurityCheckRejectsUnreachableHost(t *testing.T) {
	res := runSecurityCheck("https://127.0.0.1:1")
	if res.Error == "" {
		t.Error("expected an error for an unreachable host")
	}
}
