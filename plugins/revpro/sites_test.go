package main

import "testing"

func TestParseSitesGroupTracking(t *testing.T) {
	c := writeSites(t, `
# lnln.eu — public sites
==lnln.eu <-w>
api      10.0.0.1:8080

# lnln.eu — local only
==lnln.eu <-w +l>
dash     10.0.0.2:8080
grafana  10.0.0.3:8080

==nunissum.eu <-w>
@        10.0.0.4:8080
`)
	sites, err := c.parseSites()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]site{}
	for _, s := range sites {
		by[s.fqdn] = s
	}

	if got := by["api.lnln.eu"]; got.groupIndex != 0 || got.groupLabel != "lnln.eu — public sites" || got.group != "lnln.eu" {
		t.Errorf("api.lnln.eu: index=%d label=%q group=%q", got.groupIndex, got.groupLabel, got.group)
	}
	if got := by["dash.lnln.eu"]; got.groupIndex != 1 || got.groupLabel != "lnln.eu — local only" {
		t.Errorf("dash.lnln.eu: index=%d label=%q", got.groupIndex, got.groupLabel)
	}
	if got := by["grafana.lnln.eu"]; got.groupIndex != 1 {
		t.Errorf("grafana.lnln.eu should share group 1 with dash, got %d", got.groupIndex)
	}
	if got := by["nunissum.eu"]; got.groupIndex != 2 || got.groupLabel != "" {
		t.Errorf("nunissum.eu: index=%d label=%q (expected no preceding comment)", got.groupIndex, got.groupLabel)
	}
}
