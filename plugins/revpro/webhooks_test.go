package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestDiscordMessageIncludesEventAndFieldsSorted(t *testing.T) {
	msg := discordMessage("cert-issued", map[string]any{"cert": "example.tld", "days": 90})
	want := "**revpro** — cert-issued\ncert: example.tld\ndays: 90"
	if msg != want {
		t.Errorf("discordMessage = %q, want %q", msg, want)
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
	if err := deliverWebhook(wh, "cert-issued", map[string]any{"cert": "example.tld"}); err != nil {
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
	if err := deliverWebhook(wh, "fail2ban-ban", map[string]any{"ip": "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	content, _ := gotBody["content"].(string)
	if content == "" {
		t.Error("expected a non-empty discord 'content' field")
	}
}

func TestDeliverWebhookNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh := webhookConfig{Name: "test", URL: srv.URL, Type: "generic"}
	if err := deliverWebhook(wh, "test", nil); err == nil {
		t.Error("expected an error for a non-2xx response")
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
