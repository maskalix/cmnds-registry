// system-update — refreshes apt package lists, prints upgradable packages,
// then upgrades after confirmation. Non-interactive with -y.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	yes := false
	for _, a := range os.Args[1:] {
		switch a {
		case "-y", "--yes":
			yes = true
		case "-h", "--help":
			fmt.Println(`system-update — apt update + interactive upgrade

Usage:
  system-update [-y]

Options:
  -y, --yes    Skip confirmation prompt`)
			return
		}
	}

	info("Updating package list...")
	if err := runQuiet("apt-get", "update", "-qq"); err != nil {
		errExit("apt update failed: " + err.Error())
	}

	upgradable, err := listUpgradable()
	if err != nil {
		errExit(err.Error())
	}
	if len(upgradable) == 0 {
		ok("System is up to date.")
		return
	}

	info(fmt.Sprintf("%d upgradable package(s):", len(upgradable)))
	for _, p := range upgradable {
		fmt.Println("  " + p)
	}

	if !yes {
		fmt.Print("\nProceed with upgrade? (y/N): ")
		r := bufio.NewReader(os.Stdin)
		ans, _ := r.ReadString('\n')
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans != "y" && ans != "yes" {
			info("Upgrade cancelled.")
			return
		}
	}

	info("Running apt upgrade -y...")
	cmd := exec.Command("apt-get", "upgrade", "-y")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		errExit("upgrade failed: " + err.Error())
	}
	ok("System update complete.")
}

func listUpgradable() ([]string, error) {
	out, err := exec.Command("apt", "list", "--upgradable").Output()
	if err != nil {
		return nil, fmt.Errorf("apt list --upgradable: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) <= 1 {
		return nil, nil
	}
	return lines[1:], nil
}

func runQuiet(args ...string) error {
	return exec.Command(args[0], args[1:]...).Run()
}

func info(s string) { fmt.Printf("\033[1;34m●\033[0m %s\n", s) }
func ok(s string)   { fmt.Printf("\033[0;32m✓\033[0m %s\n", s) }
func errExit(s string) {
	fmt.Fprintf(os.Stderr, "\033[0;31m✗\033[0m %s\n", s)
	os.Exit(1)
}
