package main

import (
	"testing"
	"time"
)

func TestDueRoutineIDsSkipsDisabledAndZeroInterval(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	cfg := map[string]routineConfig{
		"renew":       {Enabled: true, IntervalMinutes: 60, LastRun: now.Add(-2 * time.Hour)},
		"regenerate":  {Enabled: false, IntervalMinutes: 5},
		"analyze":     {Enabled: true, IntervalMinutes: 0},
		"f2b-guard":   {Enabled: true, IntervalMinutes: 30, LastRun: now.Add(-10 * time.Minute)},
		"prune-cache": {Enabled: true, IntervalMinutes: 1440}, // never run — due immediately
	}
	due := dueRoutineIDs(cfg, now)
	want := map[string]bool{"renew": true, "prune-cache": true}
	if len(due) != len(want) {
		t.Fatalf("due = %v, want keys of %v", due, want)
	}
	for _, id := range due {
		if !want[id] {
			t.Errorf("unexpected due routine %q", id)
		}
	}
}

func TestDueRoutineIDsUnknownIDIgnored(t *testing.T) {
	now := time.Now()
	cfg := map[string]routineConfig{
		"not-a-real-routine": {Enabled: true, IntervalMinutes: 1},
	}
	if due := dueRoutineIDs(cfg, now); len(due) != 0 {
		t.Errorf("expected no due routines for an unknown id, got %v", due)
	}
}

func TestRoutineConfigRoundTrip(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	cfg := map[string]routineConfig{
		"renew": {Enabled: true, IntervalMinutes: 720, LastStatus: "ok"},
	}
	if err := c.saveRoutineConfigs(cfg); err != nil {
		t.Fatal(err)
	}
	got := c.loadRoutineConfigs()
	if !got["renew"].Enabled || got["renew"].IntervalMinutes != 720 {
		t.Errorf("round-tripped config = %+v", got["renew"])
	}
}

func TestLoadRoutineConfigsMissingFileIsNotAnError(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	if got := c.loadRoutineConfigs(); len(got) != 0 {
		t.Errorf("expected an empty config, got %v", got)
	}
}

func TestRoutineArgsKnownAndUnknown(t *testing.T) {
	if a := routineArgs("f2b-guard"); len(a) != 2 || a[0] != "fail2ban" || a[1] != "guard" {
		t.Errorf("routineArgs(f2b-guard) = %v", a)
	}
	if a := routineArgs("not-real"); a != nil {
		t.Errorf("expected nil for an unknown routine, got %v", a)
	}
}

func TestLastLinesCapsOutput(t *testing.T) {
	s := "one\ntwo\nthree\nfour\nfive\n"
	got := lastLines(s, 2)
	if got != "four\nfive" {
		t.Errorf("lastLines = %q", got)
	}
}

func TestRoutinesServiceInstalled(t *testing.T) {
	// Just exercises the stat path against a location that (almost
	// certainly) doesn't have the real unit installed in a test sandbox.
	_ = routinesServiceInstalled()
}

func TestPruneCachesDropsExpiredEntries(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}

	geo := map[string]geoInfo{
		"203.0.113.1": {IP: "203.0.113.1", LookedUpAt: time.Now().Add(-40 * 24 * time.Hour)}, // expired
		"203.0.113.2": {IP: "203.0.113.2", LookedUpAt: time.Now()},                           // fresh
	}
	if err := c.saveGeoCache(geo); err != nil {
		t.Fatal(err)
	}
	abuse := map[string]abuseCheckResult{
		"203.0.113.1": {IP: "203.0.113.1", CheckedAt: time.Now().Add(-40 * 24 * time.Hour)}, // expired
		"203.0.113.2": {IP: "203.0.113.2", CheckedAt: time.Now()},                           // fresh
	}
	if err := c.saveAbuseCache(abuse); err != nil {
		t.Fatal(err)
	}

	c.pruneCaches()

	gotGeo := c.loadGeoCache()
	if _, still := gotGeo["203.0.113.1"]; still {
		t.Error("expected the expired geo entry to be pruned")
	}
	if _, still := gotGeo["203.0.113.2"]; !still {
		t.Error("expected the fresh geo entry to survive")
	}

	gotAbuse := c.loadAbuseCache()
	if _, still := gotAbuse["203.0.113.1"]; still {
		t.Error("expected the expired abuse entry to be pruned")
	}
	if _, still := gotAbuse["203.0.113.2"]; !still {
		t.Error("expected the fresh abuse entry to survive")
	}
}
