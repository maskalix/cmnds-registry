// perf — system performance snapshot: CPU, memory, load, disk usage.
// Pure-Go: reads /proc and uses syscall.Statfs — no external tools required.
package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" {
			fmt.Println(`perf — system performance snapshot

Usage:
  perf            One-shot snapshot
  perf -w         Watch mode (refresh every 2s, Ctrl+C to quit)`)
			return
		}
	}

	watch := len(os.Args) > 1 && (os.Args[1] == "-w" || os.Args[1] == "--watch")
	if watch {
		for {
			fmt.Print("\033[H\033[2J")
			snapshot()
			time.Sleep(2 * time.Second)
		}
	}
	snapshot()
}

func snapshot() {
	header("System")
	fmt.Printf("  host    %s\n", hostname())
	fmt.Printf("  os      %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  uptime  %s\n", uptime())

	header("CPU")
	cpu := cpuPercent()
	bar("usage", cpu, 100)
	fmt.Printf("  cores   %d\n", runtime.NumCPU())
	fmt.Printf("  load    %s\n", loadavg())

	header("Memory")
	mem, used := memUsage()
	bar("used", float64(used), float64(mem))
	fmt.Printf("  total   %s\n", humanBytes(mem*1024))
	fmt.Printf("  used    %s\n", humanBytes(used*1024))

	header("Disk")
	for _, m := range []string{"/"} {
		total, free, ok := disk(m)
		if !ok {
			continue
		}
		used := total - free
		bar(m, float64(used), float64(total))
		fmt.Printf("  %s  %s / %s\n", padRight(m, 6), humanBytes(used), humanBytes(total))
	}
}

func header(s string) {
	fmt.Printf("\n\033[1;35m%s\033[0m\n", s)
}

func bar(label string, v, max float64) {
	pct := 0.0
	if max > 0 {
		pct = v / max * 100
	}
	width := 30
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	color := "\033[0;32m"
	if pct > 75 {
		color = "\033[0;31m"
	} else if pct > 50 {
		color = "\033[0;33m"
	}
	fmt.Printf("  %s  %s[", padRight(label, 6), color)
	for i := 0; i < width; i++ {
		if i < filled {
			fmt.Print("█")
		} else {
			fmt.Print("·")
		}
	}
	fmt.Printf("]\033[0m %5.1f%%\n", pct)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "?"
	}
	return h
}

func uptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "?"
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "?"
	}
	sec, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "?"
	}
	d := time.Duration(sec) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	return fmt.Sprintf("%dh %dm", hours, mins)
}

func loadavg() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "?"
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return "?"
	}
	return fmt.Sprintf("%s %s %s", parts[0], parts[1], parts[2])
}

// cpuPercent samples /proc/stat twice and returns 0..100 idle delta.
func cpuPercent() float64 {
	a, b := readStat(), readStat()
	if a == nil || b == nil {
		return 0
	}
	time.Sleep(150 * time.Millisecond)
	b = readStat()
	if b == nil {
		return 0
	}
	totalDiff := b[0] - a[0]
	idleDiff := b[1] - a[1]
	if totalDiff == 0 {
		return 0
	}
	return float64(totalDiff-idleDiff) / float64(totalDiff) * 100
}

// readStat returns [total, idle] from /proc/stat first "cpu " row.
func readStat() []uint64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		return nil
	}
	line := s.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return nil
	}
	parts := strings.Fields(line)[1:]
	var total, idle uint64
	for i, p := range parts {
		v, _ := strconv.ParseUint(p, 10, 64)
		total += v
		if i == 3 {
			idle = v
		}
	}
	return []uint64{total, idle}
}

func memUsage() (total uint64, used uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	var memTotal, memAvail uint64
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			memTotal = v
		case "MemAvailable:":
			memAvail = v
		}
	}
	return memTotal, memTotal - memAvail
}

func disk(path string) (total uint64, free uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), true
}

func humanBytes(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
