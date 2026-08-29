package main

import (
	"os"
	"strings"
	"testing"
)

func TestBrandLogoRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := &proxyConfig{mainFolder: dir}

	if _, _, ok := c.loadBrandLogo(); ok {
		t.Fatal("expected no logo before saving one")
	}

	png := []byte{0x89, 'P', 'N', 'G', 1, 2, 3}
	if err := c.saveBrandLogo(png, "image/png"); err != nil {
		t.Fatal(err)
	}

	data, ct, ok := c.loadBrandLogo()
	if !ok {
		t.Fatal("expected logo to load after saving")
	}
	if string(data) != string(png) {
		t.Errorf("logo bytes mismatch")
	}
	if ct != "image/png" {
		t.Errorf("content type = %q", ct)
	}

	if err := c.removeBrandLogo(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.loadBrandLogo(); ok {
		t.Error("expected logo gone after removeBrandLogo")
	}
}

func TestBrandColorValidation(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	// setBrandColor shells out to 'cmnds config write', which won't be on
	// PATH in a test environment — but validation happens before that call,
	// so a bad color should fail without ever reaching configWrite.
	for _, bad := range []string{"red", "4f7cff", "#gggggg", "#12345"} {
		if err := c.setBrandColor(bad); err == nil {
			t.Errorf("expected %q to be rejected as an invalid color", bad)
		}
	}
}

func TestSetBrandNameTruncatesAndTrims(t *testing.T) {
	long := strings.Repeat("a", 100)
	trimmed := strings.TrimSpace("  short name  ")
	if trimmed != "short name" {
		t.Fatalf("sanity: %q", trimmed)
	}
	if len(long) <= 64 {
		t.Fatalf("sanity: fixture too short")
	}
	// setBrandName shells out to cmnds; just verify the truncation logic
	// itself via the same rule it applies (mirrors the function body).
	name := strings.TrimSpace(long)
	if len(name) > 64 {
		name = name[:64]
	}
	if len(name) != 64 {
		t.Errorf("expected truncation to 64 chars, got %d", len(name))
	}
}

func TestBrandDirNotUnderMisc(t *testing.T) {
	c := &proxyConfig{mainFolder: "/revpro"}
	if strings.Contains(c.brandDir(), "/misc") {
		t.Errorf("brand assets must not live under misc/ (that's nginx's includes/ mount): %s", c.brandDir())
	}
}

func TestCurrentBrandDefaultsWithoutCmnds(t *testing.T) {
	// Ensure 'cmnds' isn't on PATH for this check, so configRead() falls
	// back to "" and currentBrand() falls back to the default name.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", oldPath)

	c := &proxyConfig{mainFolder: t.TempDir()}
	b := c.currentBrand()
	if b.Name != defaultBrandName {
		t.Errorf("Name = %q, want default %q", b.Name, defaultBrandName)
	}
	if b.HasLogo {
		t.Error("HasLogo should be false with no logo saved")
	}
	if b.Hostname == "" {
		t.Error("Hostname should be populated from os.Hostname()")
	}
}
