package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGroupsConf(t *testing.T, body string) *proxyConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sites.conf")
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return &proxyConfig{configFile: cfg, mainFolder: dir}
}

const sampleGroupsConf = `# tutorial preamble
# more preamble

# lnln.eu - public sites
==lnln.eu <-w>
neaty        A:9203
sct          A:8181

# lnln.eu - local only
==lnln.eu <-w +l>
ad.r         172.17.0.1:7080

==nunissum.eu <-w>
@            A:90
`

func TestReadConfBlocksParsesPreambleAndLabels(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	preamble, blocks, err := c.readConfBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preamble, "tutorial preamble") || strings.Contains(preamble, "lnln.eu - public") {
		t.Errorf("preamble wrong: %q", preamble)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
	if blocks[0].label != "lnln.eu - public sites" || blocks[0].domain != "lnln.eu" || blocks[0].siteCount != 2 {
		t.Errorf("block 0 = %+v", blocks[0])
	}
	if blocks[1].label != "lnln.eu - local only" || !blocks[1].gi.flags.local {
		t.Errorf("block 1 = %+v", blocks[1])
	}
	if blocks[2].label != "" || blocks[2].siteCount != 1 {
		t.Errorf("block 2 = %+v", blocks[2])
	}
}

func TestWriteConfBlocksRoundTripsCleanly(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	preamble, blocks, err := c.readConfBlocks()
	if err != nil {
		t.Fatal(err)
	}
	out := writeConfBlocks(preamble, blocks)

	// Re-parsing the rewritten text must produce the identical block
	// structure — a pure round trip with no edits should be lossless.
	c2 := writeGroupsConf(t, out)
	_, blocks2, err := c2.readConfBlocks()
	if err != nil {
		t.Fatalf("rewritten conf failed to parse: %v\n%s", err, out)
	}
	if len(blocks2) != len(blocks) {
		t.Fatalf("block count changed: %d -> %d", len(blocks), len(blocks2))
	}
	for i := range blocks {
		if blocks[i].domain != blocks2[i].domain || blocks[i].label != blocks2[i].label ||
			blocks[i].siteCount != blocks2[i].siteCount {
			t.Errorf("block %d changed: %+v -> %+v", i, blocks[i], blocks2[i])
		}
	}
}

func TestSaveGroupOnlyTouchesItsOwnBlock(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)

	if err := c.saveGroup(1, "lnln.eu", "", "lnln.eu", "lnln.eu - local only (LAN)", siteFlags{local: true}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(c.configFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)

	// The edited block's new label and cert must appear.
	if !strings.Contains(text, "lnln.eu - local only (LAN)") {
		t.Errorf("expected updated label in output:\n%s", text)
	}
	if !strings.Contains(text, `--cert="lnln.eu"`) {
		t.Errorf("expected cert override in output:\n%s", text)
	}
	// Every site line from every block, including the untouched ones,
	// must survive byte-for-byte.
	for _, line := range []string{"neaty        A:9203", "sct          A:8181", "ad.r         172.17.0.1:7080", "@            A:90"} {
		if !strings.Contains(text, line) {
			t.Errorf("expected untouched site line %q to survive, got:\n%s", line, text)
		}
	}
	// A .bak of the pre-edit file must exist.
	if _, err := os.Stat(c.configFile + ".bak"); err != nil {
		t.Errorf("expected a .bak backup: %v", err)
	}
}

func TestAddGroupAppendsEmptyBlock(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)

	if err := c.addGroup("pressline.app", "", "pressline.app", "pressline.app - all sites", siteFlags{}); err != nil {
		t.Fatal(err)
	}

	groups, err := c.listGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("expected 4 groups after add, got %d", len(groups))
	}
	last := groups[3]
	if last.Domain != "pressline.app" || last.SiteCount != 0 || last.Cert != "pressline.app" {
		t.Errorf("new group = %+v", last)
	}
}

func TestAddGroupRejectsExactDuplicate(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	// Same domain + flags + machine as the existing "public" lnln.eu group.
	if err := c.addGroup("lnln.eu", "", "", "", siteFlags{}); err == nil {
		t.Error("expected an error adding an identical group")
	}
}

func TestDeleteGroupRefusesNonEmpty(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := c.deleteGroup(0); err == nil {
		t.Error("expected deleteGroup to refuse a group with sites in it")
	}
}

func TestDeleteGroupRemovesEmptyOne(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := c.addGroup("empty.tld", "", "", "", siteFlags{}); err != nil {
		t.Fatal(err)
	}
	groups, _ := c.listGroups()
	idx := groups[len(groups)-1].Index

	if err := c.deleteGroup(idx); err != nil {
		t.Fatalf("expected deleting the empty group to succeed: %v", err)
	}
	groups, _ = c.listGroups()
	for _, g := range groups {
		if g.Domain == "empty.tld" {
			t.Error("empty.tld group should have been removed")
		}
	}
}

func TestSaveGroupRejectsInvalidIndex(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	if err := c.saveGroup(99, "lnln.eu", "", "", "", siteFlags{}); err == nil {
		t.Error("expected an error for an out-of-range group index")
	}
}

// TestSequentialEditsDontDuplicateLabels is a regression test: a bug in an
// earlier version of scanUpToHeader let a block's trailing comment line (the
// next block's label) leak into its own body too. That's invisible on a
// single read-modify-write, but compounds with every subsequent edit, since
// each write re-embeds the leaked copy alongside a fresh one.
func TestSequentialEditsDontDuplicateLabels(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)

	if err := c.saveGroup(0, "lnln.eu", "", "", "lnln.eu - public sites, edited", siteFlags{}); err != nil {
		t.Fatal(err)
	}
	if err := c.addGroup("pressline.app", "", "", "pressline.app - all sites", siteFlags{}); err != nil {
		t.Fatal(err)
	}
	if err := c.saveGroup(1, "lnln.eu", "", "", "lnln.eu - local only, edited again", siteFlags{local: true}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(c.configFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)

	// The original "local only" label (superseded by the third edit above)
	// must not survive anywhere in the file, duplicated or otherwise.
	if strings.Count(text, "lnln.eu - local only\n") > 0 {
		t.Errorf("stale label survived edits:\n%s", text)
	}
	// Every label that SHOULD exist must appear exactly once, not N times.
	for _, want := range []string{"lnln.eu - public sites, edited", "pressline.app - all sites", "lnln.eu - local only, edited again"} {
		if n := strings.Count(text, want); n != 1 {
			t.Errorf("label %q appears %d times, want 1:\n%s", want, n, text)
		}
	}
	// And re-parsing must still see the fixture's original 3 groups plus the
	// one just added, each with the right site count.
	_, blocks, err := c.readConfBlocks()
	if err != nil {
		t.Fatalf("final file failed to parse: %v\n%s", err, text)
	}
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks (3 original + 1 added), got %d:\n%s", len(blocks), text)
	}
	wantCounts := []int{2, 1, 1, 0} // public lnln.eu, local lnln.eu, nunissum.eu, new pressline.app
	for i, want := range wantCounts {
		if blocks[i].siteCount != want {
			t.Errorf("block %d siteCount = %d, want %d: %+v", i, blocks[i].siteCount, want, blocks[i])
		}
	}
}

func TestWriteConfBlocksDoesNotAccumulateBlankLines(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)

	if err := c.saveGroup(0, "lnln.eu", "", "", "lnln.eu - edited", siteFlags{}); err != nil {
		t.Fatal(err)
	}
	if err := c.saveGroup(1, "lnln.eu", "", "", "lnln.eu - edited too", siteFlags{local: true}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(c.configFile)
	if err != nil {
		t.Fatal(err)
	}
	// No run of 2+ consecutive blank lines anywhere in the file.
	if strings.Contains(string(data), "\n\n\n") {
		t.Errorf("expected at most a single blank line between blocks, got:\n%s", string(data))
	}
}

func TestRenderGroupHeaderOmitsEmptyParts(t *testing.T) {
	if got := renderGroupHeader("example.tld", groupInfo{flags: defaultFlags()}); got != "==example.tld" {
		t.Errorf("plain group header = %q, want ==example.tld", got)
	}
	got := renderGroupHeader("example.tld", groupInfo{flags: siteFlags{auth: true}, machine: "A", cert: "example.tld"})
	want := `==example.tld [A] <+a -w> --cert="example.tld"`
	if got != want {
		t.Errorf("full group header = %q, want %q", got, want)
	}
}
