package main

import (
	"path/filepath"
	"testing"
)

// TestEditSiteMovesLineToNewGroup exercises editSite's happy path end to
// end (remove + re-add), using the same sampleGroupsConf fixture
// groups_test.go defines. reload()'s docker call is expected to fail in
// this sandbox (no docker/no 'reverseproxy' container) — reload() itself
// only warns on that, it never os.Exit()s, so this stays safe to call
// directly rather than through a subprocess.
func TestEditSiteMovesLineToNewGroup(t *testing.T) {
	c := writeGroupsConf(t, sampleGroupsConf)
	c.confDir = filepath.Join(c.mainFolder, "conf")
	// generateOne() also writes log files via createLogFiles(); an unset
	// logDir would join against "" and write them as *relative* paths —
	// i.e. into the test binary's CWD instead of this tempdir.
	c.logDir = filepath.Join(c.mainFolder, "logs")

	c.editSite([]string{"sct.lnln.eu", "newsct", "nunissum.eu", "192.168.9.9:1234"})

	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	var found *site
	for i := range sites {
		if sites[i].fqdn == "sct.lnln.eu" {
			t.Errorf("expected sct.lnln.eu to be gone, still present: %+v", sites[i])
		}
		if sites[i].fqdn == "newsct.nunissum.eu" {
			found = &sites[i]
		}
	}
	if found == nil {
		t.Fatal("expected newsct.nunissum.eu to exist after the move")
	}
	if found.target != "192.168.9.9:1234" {
		t.Errorf("target = %q, want 192.168.9.9:1234", found.target)
	}
	if found.group != "nunissum.eu" {
		t.Errorf("group = %q, want nunissum.eu", found.group)
	}

	// The other sites in sct's old group must be untouched.
	names := map[string]bool{}
	for _, s := range sites {
		names[s.fqdn] = true
	}
	if !names["neaty.lnln.eu"] {
		t.Error("expected neaty.lnln.eu (same old block) to survive")
	}
}
