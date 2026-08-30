package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookConfigRoundTrip(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	list := []webhookConfig{
		{ID: "1", Name: "ops", URL: "https://example.tld/hook", Type: "generic", Events: []string{"cert-issued"}},
	}
	if err := c.saveWebhooks(list); err != nil {
		t.Fatal(err)
	}
	got := c.loadWebhooks()
	if len(got) != 1 || got[0].Name != "ops" {
		t.Errorf("round-tripped webhooks = %+v", got)
	}
}

func TestLoadWebhooksMissingFileIsNotAnError(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	if got := c.loadWebhooks(); got != nil {
		t.Errorf("expected nil for a missing file, got %v", got)
	}
}

func TestDiscordEmbedKnownEventUsesMappedTitleAndColor(t *testing.T) {
	e := discordEmbed("cert-issue-failed", map[string]any{"cert": "example.tld"})
	embeds, _ := e["embeds"].([]map[string]any)
	if len(embeds) != 1 {
		t.Fatalf("expected exactly one embed, got %+v", e)
	}
	if embeds[0]["title"] != discordEventInfo["cert-issue-failed"].Title {
		t.Errorf("title = %v", embeds[0]["title"])
	}
	if embeds[0]["color"] != discordEventInfo["cert-issue-failed"].Color {
		t.Errorf("color = %v", embeds[0]["color"])
	}
	fields, _ := embeds[0]["fields"].([]map[string]any)
	if len(fields) != 1 || fields[0]["name"] != "Cert" || fields[0]["value"] != "example.tld" {
		t.Errorf("fields = %+v", fields)
	}
}

func TestDiscordEmbedUnknownEventFallsBack(t *testing.T) {
	e := discordEmbed("some-future-event", nil)
	embeds := e["embeds"].([]map[string]any)
	if embeds[0]["color"] != discordDefaultColor {
		t.Errorf("expected the default color for an unmapped event, got %v", embeds[0]["color"])
	}
}

func TestFieldTitleFormatsCamelAndSnakeCase(t *testing.T) {
	cases := map[string]string{
		"jail":        "Jail",
		"countryCode": "Country Code",
		"error_host":  "Error host",
	}
	for in, want := range cases {
		if got := fieldTitle(in); got != want {
			t.Errorf("fieldTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeliverWebhookGeneric(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := webhookConfig{Name: "test", URL: srv.URL, Type: "generic"}
	if _, err := deliverWebhook(wh, "cert-issued", map[string]any{"cert": "example.tld"}); err != nil {
		t.Fatal(err)
	}
	if gotBody["event"] != "cert-issued" || gotBody["cert"] != "example.tld" {
		t.Errorf("delivered body = %+v", gotBody)
	}
}

func TestDeliverWebhookDiscord(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wh := webhookConfig{Name: "test", URL: srv.URL, Type: "discord"}
	if _, err := deliverWebhook(wh, "fail2ban-ban", map[string]any{"ip": "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	embeds, _ := gotBody["embeds"].([]any)
	if len(embeds) != 1 {
		t.Fatalf("expected exactly one embed in the delivered body, got %+v", gotBody)
	}
}

func TestDeliverWebhookNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh := webhookConfig{Name: "test", URL: srv.URL, Type: "generic"}
	if _, err := deliverWebhook(wh, "test", nil); err == nil {
		t.Error("expected an error for a non-2xx response")
	}
}

func TestDeliverWebhook429ReturnsRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	wh := webhookConfig{Name: "test", URL: srv.URL, Type: "generic"}
	retryAfter, err := deliverWebhook(wh, "test", nil)
	if err == nil {
		t.Error("expected an error for a 429 response")
	}
	if retryAfter != 30*time.Second {
		t.Errorf("retryAfter = %v, want 30s", retryAfter)
	}
}

func TestParseRetryAfterVariants(t *testing.T) {
	if got := parseRetryAfter(""); got != defaultRetryAfter {
		t.Errorf("empty header: got %v, want default %v", got, defaultRetryAfter)
	}
	if got := parseRetryAfter("120"); got != 120*time.Second {
		t.Errorf("numeric header: got %v, want 120s", got)
	}
	if got := parseRetryAfter("not-a-valid-value"); got != defaultRetryAfter {
		t.Errorf("garbage header: got %v, want default %v", got, defaultRetryAfter)
	}
}

func TestFireWebhookBacksOffAfter429(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "3600") // long enough not to flake this test
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &proxyConfig{mainFolder: t.TempDir()}
	wh := webhookConfig{ID: "backoff-test-" + t.Name(), Name: "rate-limited", URL: srv.URL, Type: "generic", Events: []string{"guard-blocked"}}
	if err := c.saveWebhooks([]webhookConfig{wh}); err != nil {
		t.Fatal(err)
	}

	// Simulate a guard scan blocking several IPs in a tight loop: the first
	// call should actually hit the server and get 429'd; every call after
	// that must be skipped locally instead of repeating the doomed request.
	for i := 0; i < 5; i++ {
		fireWebhook(c, "guard-blocked", map[string]any{"ip": "203.0.113.9"})
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 actual HTTP call before backing off, got %d", calls)
	}
}

func TestFireWebhookOnlyCallsSubscribedEvents(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &proxyConfig{mainFolder: t.TempDir()}
	if err := c.saveWebhooks([]webhookConfig{
		{ID: "1", Name: "certs-only", URL: srv.URL, Type: "generic", Events: []string{"cert-issued"}},
	}); err != nil {
		t.Fatal(err)
	}

	fireWebhook(c, "site-added", map[string]any{"fqdn": "x.example.tld"})
	if calls != 0 {
		t.Fatalf("expected no delivery for an unsubscribed event, got %d calls", calls)
	}
	fireWebhook(c, "cert-issued", map[string]any{"cert": "example.tld"})
	if calls != 1 {
		t.Fatalf("expected exactly one delivery for the subscribed event, got %d calls", calls)
	}
}

func TestAppendAuditAndRecentAuditNewestFirst(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	c.appendAudit("site-added", map[string]any{"fqdn": "a.example.tld"})
	c.appendAudit("fail2ban-ban", map[string]any{"ip": "203.0.113.9"})

	got, err := c.recentAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Event != "fail2ban-ban" {
		t.Errorf("expected the most recent entry first, got %+v", got[0])
	}
	if got[0].Fields["ip"] != "203.0.113.9" {
		t.Errorf("fields not round-tripped: %+v", got[0].Fields)
	}
}

func TestRecentAuditMissingFileIsNotAnError(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	got, err := c.recentAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected no entries, got %v", got)
	}
}

func TestFireWebhookRecordsAuditEvenWithNoWebhooksConfigured(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	fireWebhook(c, "cert-issued", map[string]any{"cert": "example.tld"})
	got, err := c.recentAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Event != "cert-issued" {
		t.Errorf("expected the event to be audited regardless of webhook config, got %+v", got)
	}
}
