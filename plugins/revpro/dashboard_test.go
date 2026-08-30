package main

import "testing"

// TestReadPerfStatsDoesNotPanic is a smoke test — the actual /proc values
// and disk sizes vary by environment (CI sandbox vs. a real box), so
// there's nothing specific to assert beyond "this returns without error".
func TestReadPerfStatsDoesNotPanic(t *testing.T) {
	p := readPerfStats(t.TempDir())
	if p.LoadAvg1 < 0 || p.MemTotalMB < 0 || p.DiskTotalGB < 0 {
		t.Errorf("unexpected negative stat: %+v", p)
	}
}

func TestReadPerfStatsEmptyDataDirSkipsDiskStats(t *testing.T) {
	p := readPerfStats("")
	if p.DiskTotalGB != 0 || p.DiskFreeGB != 0 {
		t.Errorf("expected zero disk stats for an empty dataDir, got %+v", p)
	}
}
