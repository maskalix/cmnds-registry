// groups.go — whole-group management for sites.conf: list, edit a group's
// header (domain/machine/cert/flags/label), add a new empty group, or delete
// an empty one. Complements sites.go's line-level parsing with block-level
// read/write that preserves every other group's exact text untouched.
package main

import (
	"fmt"
	"os"
	"strings"
)

// confBlock is one ==domain header block: its label comment (if any), parsed
// header fields, and every raw line between the header and the next one (or
// EOF) — kept verbatim so editing one block never reformats another.
type confBlock struct {
	label     string // the '# ...' comment line directly above the header, if any
	domain    string
	gi        groupInfo
	body      []string // raw lines between this header and the next
	siteCount int      // real (non-blank, non-comment) lines in body
}

// readConfBlocks splits sites.conf into its leading preamble (the tutorial
// text and anything else before the first ==header, preserved verbatim) and
// an ordered list of group blocks. Comment-tracking mirrors parseSites()
// exactly: the most recent full-line comment becomes the next header's label,
// cleared by any blank line or non-comment line first.
func (c *proxyConfig) readConfBlocks() (preamble string, blocks []confBlock, err error) {
	data, err := os.ReadFile(c.configFile)
	if err != nil {
		return "", nil, err
	}
	lines := strings.Split(string(data), "\n")

	// scanUpToHeader appends lines[i:] to acc until a "==" header or EOF,
	// tracking siteCount and pendingComment the same way parseSites() does.
	// The trailing run of consecutive comment lines that produced the final
	// pendingComment value (if any) is stripped back off acc before
	// returning — those lines belong to the NEXT block's label, not to
	// whatever came before them.
	scanUpToHeader := func(i int) (next []string, siteCount int, pendingComment string, newI int) {
		commentRunStart := -1
		for ; i < len(lines); i++ {
			t := strings.TrimSpace(lines[i])
			if strings.HasPrefix(t, "==") {
				break
			}
			switch {
			case strings.HasPrefix(t, "#"):
				pendingComment = strings.TrimSpace(strings.TrimPrefix(t, "#"))
				if commentRunStart == -1 {
					commentRunStart = len(next)
				}
			case t == "":
				pendingComment = ""
				commentRunStart = -1
			default:
				siteCount++
				pendingComment = ""
				commentRunStart = -1
			}
			next = append(next, lines[i])
		}
		if pendingComment != "" && commentRunStart >= 0 {
			next = next[:commentRunStart]
		}
		return next, siteCount, pendingComment, i
	}

	pre, _, pendingComment, i := scanUpToHeader(0)
	if i >= len(lines) {
		// No group headers at all — the whole file is preamble.
		return strings.Join(lines, "\n"), nil, nil
	}
	preamble = strings.Join(pre, "\n")

	for i < len(lines) {
		domain, gi := parseGroupHeader(strings.TrimSpace(stripComment(lines[i])))
		label := pendingComment
		i++

		var body []string
		var siteCount int
		body, siteCount, pendingComment, i = scanUpToHeader(i)
		blocks = append(blocks, confBlock{label: label, domain: domain, gi: gi, body: body, siteCount: siteCount})
	}
	return preamble, blocks, nil
}

// writeConfBlocks renders preamble + blocks back into sites.conf text.
func writeConfBlocks(preamble string, blocks []confBlock) string {
	var b strings.Builder
	b.WriteString(preamble)
	if preamble != "" && !strings.HasSuffix(preamble, "\n") {
		b.WriteString("\n")
	}
	for _, blk := range blocks {
		b.WriteString("\n")
		if blk.label != "" {
			b.WriteString("# " + blk.label + "\n")
		}
		b.WriteString(renderGroupHeader(blk.domain, blk.gi) + "\n")
		for _, line := range trimTrailingBlank(blk.body) {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// trimTrailingBlank drops trailing blank lines so writeConfBlocks's own
// blank-line separator between blocks doesn't compound with whatever blank
// lines a block's body happened to end with.
func trimTrailingBlank(lines []string) []string {
	i := len(lines)
	for i > 0 && strings.TrimSpace(lines[i-1]) == "" {
		i--
	}
	return lines[:i]
}

// renderGroupHeader renders "==domain [machine] <flags> --cert=name", omitting
// each optional part when it's empty/default — matching how convertCmd and
// hand-written groups already look.
func renderGroupHeader(domain string, gi groupInfo) string {
	h := "==" + domain
	if gi.machine != "" {
		h += " [" + gi.machine + "]"
	}
	if toks := flagTokens(gi.flags); toks != "" {
		h += " <" + toks + ">"
	}
	if gi.cert != "" {
		h += ` --cert="` + gi.cert + `"`
	}
	return h
}

// groupJSON is one group's info for the web UI.
type groupJSON struct {
	Index     int    `json:"index"`
	Domain    string `json:"domain"`
	Machine   string `json:"machine,omitempty"`
	Cert      string `json:"cert,omitempty"`
	Label     string `json:"label,omitempty"`
	Auth      bool   `json:"auth"`
	HTTPS     bool   `json:"https"`
	WWW       bool   `json:"www"`
	Local     bool   `json:"local"`
	SiteCount int    `json:"siteCount"`
}

func (c *proxyConfig) listGroups() ([]groupJSON, error) {
	_, blocks, err := c.readConfBlocks()
	if err != nil {
		return nil, err
	}
	out := make([]groupJSON, 0, len(blocks))
	for i, b := range blocks {
		out = append(out, groupJSON{
			Index: i, Domain: b.domain, Machine: b.gi.machine, Cert: b.gi.cert, Label: b.label,
			Auth: b.gi.flags.auth, HTTPS: b.gi.flags.https, WWW: b.gi.flags.www, Local: b.gi.flags.local,
			SiteCount: b.siteCount,
		})
	}
	return out, nil
}

// saveGroup rewrites one existing block's header/label in place (its site
// lines are untouched), validates the result still parses, and writes it —
// backing up the previous sites.conf first, same as the raw config editor.
func (c *proxyConfig) saveGroup(index int, domain, machine, cert, label string, flags siteFlags) error {
	preamble, blocks, err := c.readConfBlocks()
	if err != nil {
		return err
	}
	if index < 0 || index >= len(blocks) {
		return fmt.Errorf("no such group at index %d", index)
	}
	blocks[index].domain = domain
	blocks[index].gi = groupInfo{flags: flags, machine: machine, cert: cert}
	blocks[index].label = label
	return c.writeAndValidateBlocks(preamble, blocks)
}

// addGroup appends a new, empty group at the end of the file.
func (c *proxyConfig) addGroup(domain, machine, cert, label string, flags siteFlags) error {
	preamble, blocks, err := c.readConfBlocks()
	if err != nil {
		return err
	}
	for _, b := range blocks {
		if b.domain == domain && b.gi.machine == machine && groupFlagsEqual(b.gi.flags, flags) {
			return fmt.Errorf("an identical group for %s already exists", domain)
		}
	}
	blocks = append(blocks, confBlock{
		label: label, domain: domain,
		gi: groupInfo{flags: flags, machine: machine, cert: cert},
	})
	return c.writeAndValidateBlocks(preamble, blocks)
}

// deleteGroup removes a group header, refusing if it still has sites — the
// caller must move or remove those first (via the raw sites.conf editor or
// by hand) rather than silently orphaning them.
func (c *proxyConfig) deleteGroup(index int) error {
	preamble, blocks, err := c.readConfBlocks()
	if err != nil {
		return err
	}
	if index < 0 || index >= len(blocks) {
		return fmt.Errorf("no such group at index %d", index)
	}
	if blocks[index].siteCount > 0 {
		return fmt.Errorf("group %s still has %d site(s) — move or remove them first", blocks[index].domain, blocks[index].siteCount)
	}
	blocks = append(blocks[:index], blocks[index+1:]...)
	return c.writeAndValidateBlocks(preamble, blocks)
}

func groupFlagsEqual(a, b siteFlags) bool {
	return a.auth == b.auth && a.https == b.https && a.www == b.www && a.local == b.local
}

// writeAndValidateBlocks renders the blocks, verifies the result still
// parses as valid sites.conf, backs up the current file, and writes it.
func (c *proxyConfig) writeAndValidateBlocks(preamble string, blocks []confBlock) error {
	content := writeConfBlocks(preamble, blocks)

	tmp, err := os.CreateTemp("", "sites-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(content)
	tmp.Close()
	probe := &proxyConfig{configFile: tmp.Name(), mainFolder: c.mainFolder}
	if _, err := probe.parseSites(); err != nil {
		return fmt.Errorf("resulting sites.conf would not parse: %w", err)
	}

	if old, err := os.ReadFile(c.configFile); err == nil {
		_ = os.WriteFile(c.configFile+".bak", old, 0o644)
	}
	return os.WriteFile(c.configFile, []byte(content), 0o644)
}
