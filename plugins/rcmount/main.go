// rcmount — manage rclone remote mounts declared in ~/.cmnds/rcmount.conf.
// Each line: "<remote>: <mountpoint>"
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "update":
		mustErr(update())
	case "start":
		mustErr(start())
	case "stop":
		mustErr(stop())
	case "restart":
		_ = stop()
		mustErr(start())
	case "state":
		mustErr(state())
	case "edit":
		mustErr(edit())
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`rcmount — manage rclone remote mounts

Usage:
  rcmount update    Refresh ~/.cmnds/rcmount.conf from 'rclone listremotes'
  rcmount start     Mount every entry from the conf
  rcmount stop      Unmount everything
  rcmount restart   stop && start
  rcmount state     Report which remotes are currently mounted
  rcmount edit      Open the conf in $EDITOR

Requires: rclone, fuse (fusermount).`)
}

func confPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cmnds", "rcmount.conf")
}

func ensureConf() error {
	return os.MkdirAll(filepath.Dir(confPath()), 0o755)
}

type entry struct{ Remote, Mount string }

var nameSanitize = regexp.MustCompile(`[^a-z0-9-]`)

func update() error {
	if err := ensureConf(); err != nil {
		return err
	}
	out, err := exec.Command("rclone", "listremotes").Output()
	if err != nil {
		return fmt.Errorf("rclone listremotes: %w", err)
	}
	f, err := os.Create(confPath())
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		remote := strings.TrimSpace(line)
		if remote == "" {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(remote, ":"))
		name = nameSanitize.ReplaceAllString(name, "_")
		fmt.Fprintf(f, "%s /remote/%s\n", remote, name)
	}
	fmt.Printf("\033[0;32m✓ wrote %s\033[0m\n", confPath())
	return nil
}

func loadEntries() ([]entry, error) {
	if err := ensureConf(); err != nil {
		return nil, err
	}
	f, err := os.Open(confPath())
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no config — run 'rcmount update' first")
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []entry
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, entry{Remote: fields[0], Mount: fields[1]})
	}
	return out, nil
}

func start() error {
	entries, err := loadEntries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.MkdirAll(e.Mount, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", e.Mount, err)
			continue
		}
		fmt.Printf("\033[1;34m●\033[0m mounting %s → %s\n", e.Remote, e.Mount)
		cmd := exec.Command("rclone", "mount", e.Remote, e.Mount,
			"--allow-non-empty", "--vfs-cache-mode", "full", "--daemon")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "mount %s failed: %v\n", e.Remote, err)
		}
	}
	return nil
}

func stop() error {
	entries, err := loadEntries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Printf("\033[1;34m●\033[0m unmounting %s\n", e.Mount)
		_ = exec.Command("fusermount", "-u", e.Mount).Run()
	}
	return nil
}

func state() error {
	entries, err := loadEntries()
	if err != nil {
		return err
	}
	mounts, _ := os.ReadFile("/proc/mounts")
	mstr := string(mounts)
	for _, e := range entries {
		if strings.Contains(mstr, " "+e.Mount+" ") {
			fmt.Printf("  %-30s \033[0;32mmounted\033[0m\n", e.Remote)
		} else {
			fmt.Printf("  %-30s \033[0;31mnot mounted\033[0m\n", e.Remote)
		}
	}
	return nil
}

func edit() error {
	if err := ensureConf(); err != nil {
		return err
	}
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}
	c := exec.Command(editor, confPath())
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

func mustErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[0;31m✗ %v\033[0m\n", err)
		os.Exit(1)
	}
}
