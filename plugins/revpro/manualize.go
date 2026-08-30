// manualize.go — moving one reverse-proxy site out of sites.conf into a
// hand-written manconf/ file. Used by the web UI's per-site config editor:
// once someone edits a site's generated nginx block directly, revpro can no
// longer own it (the next Regenerate would blow the edit away), so the site's
// line is removed from sites.conf and the edited block becomes a manual
// config instead — manconf/ is never touched by revpro's own generation.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// removeSiteLine deletes fqdn's line from its ==domain group block in
// sites.conf, leaving every other line — and every other block — byte-for-
// byte untouched. It fails if the site can't be found, or if the edit would
// leave sites.conf unparseable.
func (c *proxyConfig) removeSiteLine(fqdn string) error {
	sites, err := c.parseSites()
	if err != nil {
		return err
	}
	var target *site
	for i := range sites {
		if sites[i].fqdn == fqdn {
			target = &sites[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no such site: %s", fqdn)
	}

	preamble, blocks, err := c.readConfBlocks()
	if err != nil {
		return err
	}
	if target.groupIndex < 0 || target.groupIndex >= len(blocks) {
		return fmt.Errorf("internal error: group index out of range for %s", fqdn)
	}
	sub := "@"
	if fqdn != target.group {
		sub = strings.TrimSuffix(fqdn, "."+target.group)
	}

	blk := &blocks[target.groupIndex]
	out := make([]string, 0, len(blk.body))
	removed := false
	for _, line := range blk.body {
		trimmed := strings.TrimSpace(stripComment(line))
		if !removed && trimmed != "" {
			if fields := strings.Fields(trimmed); len(fields) > 0 && fields[0] == sub {
				removed = true
				continue
			}
		}
		out = append(out, line)
	}
	if !removed {
		return fmt.Errorf("could not find %s's line in its group block", fqdn)
	}
	blk.body = out
	blk.siteCount--

	return c.writeAndValidateBlocks(preamble, blocks)
}

// convertSiteToManual moves fqdn from sites.conf to a hand-written manconf
// file containing content (normally the site's current generated config,
// possibly edited by the caller first). It refuses to clobber an existing
// manual config of the same name. On success the now-stale generated file
// under conf/ is removed too, since the manual file serves that server_name
// from here on.
func (c *proxyConfig) convertSiteToManual(fqdn, content string) (path string, err error) {
	manDir := c.manconfDir()
	manPath := filepath.Join(manDir, fqdn+".conf")
	if _, statErr := os.Stat(manPath); statErr == nil {
		return "", fmt.Errorf("a manual config already exists at %s — edit it directly under Manual configs", manPath)
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.MkdirAll(manDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(manPath, []byte(content), 0o644); err != nil {
		return "", err
	}

	if err := c.removeSiteLine(fqdn); err != nil {
		_ = os.Remove(manPath)
		return "", err
	}

	_ = os.Remove(filepath.Join(c.confDir, fqdn+".conf"))
	return manPath, nil
}
