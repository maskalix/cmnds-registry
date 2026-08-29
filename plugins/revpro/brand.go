// brand.go — per-instance branding for the web UI: a display name, accent
// color, and an optional logo image, so multiple revpro instances (e.g.
// across different machines) are easy to tell apart at a glance.
//
// Name and color persist through the normal 'cmnds config' mechanism, same
// as REVPRO/HTTP3/etc. The logo is a small binary asset kept in its own
// folder — deliberately not under misc/, which is nginx's own includes/
// directory (bind-mounted into the reverseproxy container) and shouldn't
// accumulate unrelated UI assets.
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultBrandName = "revpro"

// hexColorRe matches a CSS hex color (#rgb, #rrggbb, or #rrggbbaa) — the only
// format an <input type=color> ever submits, and simple enough to validate
// safely before it's ever written into a style attribute.
var hexColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{3}$|^#[0-9a-fA-F]{6}$|^#[0-9a-fA-F]{8}$`)

type brandInfo struct {
	Name     string `json:"name"`
	Color    string `json:"color,omitempty"` // "" = use the built-in default accent
	Hostname string `json:"hostname"`
	HasLogo  bool   `json:"hasLogo"`
}

func (c *proxyConfig) brandDir() string          { return filepath.Join(c.mainFolder, "web-brand") }
func (c *proxyConfig) brandLogoFile() string     { return filepath.Join(c.brandDir(), "logo") }
func (c *proxyConfig) brandLogoTypeFile() string { return filepath.Join(c.brandDir(), "logo.type") }

// brandInfo reads the current branding: configured name/color (falling back
// to the default name and "no override" color) plus the live OS hostname —
// hostname is never itself configurable, just displayed, so instances are
// identifiable even before anyone bothers setting a custom name.
func (c *proxyConfig) currentBrand() brandInfo {
	name := configRead("REVPRO_BRAND_NAME")
	if name == "" {
		name = defaultBrandName
	}
	host, _ := os.Hostname()
	_, err := os.Stat(c.brandLogoFile())
	return brandInfo{
		Name:     name,
		Color:    configRead("REVPRO_BRAND_COLOR"),
		Hostname: host,
		HasLogo:  err == nil,
	}
}

func (c *proxyConfig) setBrandName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	return configWrite("REVPRO_BRAND_NAME", name)
}

// setBrandColor validates the hex format before persisting; an empty string
// clears the override back to the default accent.
func (c *proxyConfig) setBrandColor(color string) error {
	color = strings.TrimSpace(color)
	if color != "" && !hexColorRe.MatchString(color) {
		return errBadColor
	}
	return configWrite("REVPRO_BRAND_COLOR", color)
}

var errBadColor = brandError("color must be a hex value like #4f7cff")

type brandError string

func (e brandError) Error() string { return string(e) }

func (c *proxyConfig) saveBrandLogo(data []byte, contentType string) error {
	if err := os.MkdirAll(c.brandDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(c.brandLogoFile(), data, 0o644); err != nil {
		return err
	}
	return os.WriteFile(c.brandLogoTypeFile(), []byte(contentType), 0o644)
}

func (c *proxyConfig) removeBrandLogo() error {
	_ = os.Remove(c.brandLogoFile())
	_ = os.Remove(c.brandLogoTypeFile())
	return nil
}

// loadBrandLogo returns the stored logo bytes and content type, if any.
func (c *proxyConfig) loadBrandLogo() (data []byte, contentType string, ok bool) {
	data, err := os.ReadFile(c.brandLogoFile())
	if err != nil {
		return nil, "", false
	}
	ct, _ := os.ReadFile(c.brandLogoTypeFile())
	contentType = strings.TrimSpace(string(ct))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return data, contentType, true
}
