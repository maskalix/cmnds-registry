// dashboard.go — lightweight host perf stats (load average, memory, disk
// usage of the REVPRO data dir) for the web UI's "Current" overview page.
// Reads straight from /proc — Linux-only, which matches the rest of
// revpro's assumptions (it already generates systemd units and shells out
// to apt/systemctl).
package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

type perfStats struct {
	LoadAvg1    float64 `json:"loadAvg1"`
	LoadAvg5    float64 `json:"loadAvg5"`
	LoadAvg15   float64 `json:"loadAvg15"`
	MemTotalMB  int64   `json:"memTotalMB"`
	MemAvailMB  int64   `json:"memAvailMB"`
	DiskTotalGB float64 `json:"diskTotalGB"`
	DiskFreeGB  float64 `json:"diskFreeGB"`
}

func readPerfStats(dataDir string) perfStats {
	var p perfStats
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			p.LoadAvg1, _ = strconv.ParseFloat(fields[0], 64)
			p.LoadAvg5, _ = strconv.ParseFloat(fields[1], 64)
			p.LoadAvg15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			switch fields[0] {
			case "MemTotal:":
				p.MemTotalMB = kb / 1024
			case "MemAvailable:":
				p.MemAvailMB = kb / 1024
			}
		}
	}
	if dataDir != "" {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(dataDir, &stat); err == nil {
			const gb = 1024 * 1024 * 1024
			p.DiskTotalGB = float64(stat.Blocks*uint64(stat.Bsize)) / gb
			p.DiskFreeGB = float64(stat.Bavail*uint64(stat.Bsize)) / gb
		}
	}
	return p
}
