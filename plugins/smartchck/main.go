// smartchck — run smartctl -H on every /dev/sd? disk and print health.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" {
			fmt.Println(`smartchck — check SMART health of all /dev/sd? disks

Usage: smartchck

Requires smartmontools (smartctl). On Debian/Ubuntu: apt install smartmontools`)
			return
		}
	}

	if _, err := exec.LookPath("smartctl"); err != nil {
		fmt.Fprintln(os.Stderr, "\033[0;31m✗ smartctl not found — install smartmontools\033[0m")
		os.Exit(1)
	}

	disks, err := listDisks()
	if err != nil {
		fmt.Fprintln(os.Stderr, "\033[0;31m✗ "+err.Error()+"\033[0m")
		os.Exit(1)
	}
	if len(disks) == 0 {
		fmt.Println("No disks found under /dev/sd?")
		return
	}

	fmt.Printf("\033[1m%-15s  Status\033[0m\n", "Disk")
	fmt.Println(strings.Repeat("-", 32))
	for _, d := range disks {
		status := smartStatus(d)
		color := "\033[0;33m" // yellow / unknown
		switch status {
		case "PASSED":
			color = "\033[0;32m"
		case "FAILED":
			color = "\033[0;31m"
		}
		fmt.Printf("%-15s  %s%s\033[0m\n", d, color, status)
	}
}

func listDisks() ([]string, error) {
	matches, err := filepath.Glob("/dev/sd?")
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

var healthRe = regexp.MustCompile(`(?i)SMART overall-health.*:\s*(\S+)`)

func smartStatus(disk string) string {
	out, _ := exec.Command("smartctl", "-H", disk).CombinedOutput()
	m := healthRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return "UNKNOWN"
	}
	return strings.ToUpper(m[1])
}
