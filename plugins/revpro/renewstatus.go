// renewstatus.go — a small heartbeat file so the web UI can show when the
// renewal check (manual or the --daemon loop) last ran, without depending on
// systemd or any other specific service manager being in front of it.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type renewStatus struct {
	At      time.Time `json:"at"`
	Renewed int       `json:"renewed"`
	Skipped int       `json:"skipped"`
	Failed  int       `json:"failed"`
}

func (c *proxyConfig) renewStatusFile() string {
	return filepath.Join(c.mainFolder, "renew-status.json")
}

func (c *proxyConfig) writeRenewStatus(renewed, skipped, failed int) {
	data, err := json.Marshal(renewStatus{At: time.Now(), Renewed: renewed, Skipped: skipped, Failed: failed})
	if err != nil {
		return
	}
	_ = os.WriteFile(c.renewStatusFile(), data, 0o644)
}

// loadRenewStatus returns the last recorded run, or ok=false if none exists yet.
func (c *proxyConfig) loadRenewStatus() (renewStatus, bool) {
	data, err := os.ReadFile(c.renewStatusFile())
	if err != nil {
		return renewStatus{}, false
	}
	var st renewStatus
	if json.Unmarshal(data, &st) != nil {
		return renewStatus{}, false
	}
	return st, true
}
