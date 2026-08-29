package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

func TestWedosAuthToken(t *testing.T) {
	// sha1("swordfish") then sha1("bob" + that + "14"), computed independently
	// to cross-check the implementation rather than re-deriving the same code.
	passHash := sha1.Sum([]byte("swordfish"))
	want := sha1.Sum([]byte("bob" + hex.EncodeToString(passHash[:]) + "14"))
	got := wedosAuthToken("bob", "swordfish", "14")
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("wedosAuthToken() = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	// Different hour must produce a different token.
	if other := wedosAuthToken("bob", "swordfish", "15"); other == got {
		t.Error("token should differ across hours")
	}
}

// mockWedos is a tiny stand-in for the real WAPI: it tracks rows per domain
// in memory and understands exactly the four commands the provider issues.
type mockWedos struct {
	mu   sync.Mutex
	rows map[string][]map[string]any // domain -> rows
	next int
	// zones lists which domains this fake account "hosts" — dns-rows-list
	// fails for anything else, mirroring how splitZone probes for the zone.
	zones map[string]bool
}

func newMockWedos(zones ...string) *mockWedos {
	m := &mockWedos{rows: map[string][]map[string]any{}, zones: map[string]bool{}}
	for _, z := range zones {
		m.zones[z] = true
	}
	return m
}

func (m *mockWedos) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("mock: parse form: %v", err)
		}
		raw := r.PostForm.Get("request")
		var req struct {
			Request struct {
				Command string            `json:"command"`
				Data    map[string]string `json:"data"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("mock: bad request json: %v", err)
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		resp := struct {
			Response struct {
				Code int            `json:"code"`
				Data map[string]any `json:"data"`
			} `json:"response"`
		}{}

		domain := req.Request.Data["domain"]
		switch req.Request.Command {
		case "dns-rows-list":
			if !m.zones[domain] {
				resp.Response.Code = 4000 // not our zone
				break
			}
			resp.Response.Code = 1000
			resp.Response.Data = map[string]any{"row": m.rows[domain]}
		case "dns-row-add":
			if !m.zones[domain] {
				resp.Response.Code = 4000
				break
			}
			m.next++
			m.rows[domain] = append(m.rows[domain], map[string]any{
				"ID":    strconv.Itoa(m.next),
				"name":  req.Request.Data["name"],
				"type":  req.Request.Data["type"],
				"rdata": req.Request.Data["rdata"],
			})
			resp.Response.Code = 1000
		case "dns-row-delete":
			rowID := req.Request.Data["row_id"]
			var kept []map[string]any
			for _, row := range m.rows[domain] {
				if fmtAny(row["ID"]) != rowID {
					kept = append(kept, row)
				}
			}
			m.rows[domain] = kept
			resp.Response.Code = 1000
		case "dns-domain-commit":
			resp.Response.Code = 1000
		default:
			t.Fatalf("mock: unexpected command %q", req.Request.Command)
		}

		json.NewEncoder(w).Encode(resp)
	}
}

func fmtAny(v any) string {
	s, _ := v.(string)
	return s
}

func TestWedosPresentAndCleanUp(t *testing.T) {
	mock := newMockWedos("lnln.eu")
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	oldURL := wedosAPIURL
	wedosAPIURL = srv.URL
	defer func() { wedosAPIURL = oldURL }()

	p := &wedosProvider{user: "bob", password: "swordfish", rowIDs: map[string]string{}}
	ctx := context.Background()

	if err := p.Present(ctx, "sub.lnln.eu", "token", "keyAuth-value"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(mock.rows["lnln.eu"]) != 1 {
		t.Fatalf("expected 1 row after Present, got %d: %+v", len(mock.rows["lnln.eu"]), mock.rows["lnln.eu"])
	}
	row := mock.rows["lnln.eu"][0]
	if row["name"] != "_acme-challenge.sub" {
		t.Errorf("record name = %v, want _acme-challenge.sub", row["name"])
	}
	if row["type"] != "TXT" {
		t.Errorf("record type = %v, want TXT", row["type"])
	}

	if err := p.CleanUp(ctx, "sub.lnln.eu", "token", "keyAuth-value"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if len(mock.rows["lnln.eu"]) != 0 {
		t.Errorf("expected row removed after CleanUp, still have %+v", mock.rows["lnln.eu"])
	}
}

func TestWedosPresentUnknownZoneFails(t *testing.T) {
	mock := newMockWedos("lnln.eu") // does NOT host example.tld
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	oldURL := wedosAPIURL
	wedosAPIURL = srv.URL
	defer func() { wedosAPIURL = oldURL }()

	p := &wedosProvider{user: "bob", password: "swordfish", rowIDs: map[string]string{}}
	if err := p.Present(context.Background(), "example.tld", "token", "keyAuth-value"); err == nil {
		t.Error("expected an error for a domain this account doesn't host")
	}
}

func TestWedosCleanUpMissingRowIsNotAnError(t *testing.T) {
	mock := newMockWedos("lnln.eu")
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	oldURL := wedosAPIURL
	wedosAPIURL = srv.URL
	defer func() { wedosAPIURL = oldURL }()

	p := &wedosProvider{user: "bob", password: "swordfish", rowIDs: map[string]string{}}
	// Never called Present — nothing to clean up. Should be a no-op, not an error.
	if err := p.CleanUp(context.Background(), "sub.lnln.eu", "token", "keyAuth-value"); err != nil {
		t.Errorf("CleanUp with nothing to remove should not error, got: %v", err)
	}
}
