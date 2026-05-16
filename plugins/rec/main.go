// rec — create (or recreate) a script, open it in $EDITOR, make it
// executable when appropriate, then run it.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Println("Usage: rec <filename>")
		os.Exit(1)
	}
	name := os.Args[1]

	if _, err := os.Stat(name); err == nil {
		if !confirm(fmt.Sprintf("%q exists. Delete and recreate?", name)) {
			fmt.Println("aborted.")
			return
		}
		if err := os.Remove(name); err != nil {
			fail("remove: " + err.Error())
		}
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}
	if err := run(editor, name); err != nil {
		fail("editor: " + err.Error())
	}

	if !exists(name) {
		fmt.Println("file not saved; nothing to run.")
		return
	}

	if isExecLikely(name) {
		_ = os.Chmod(name, 0o755)
	}

	info, err := os.Stat(name)
	if err != nil {
		fail(err.Error())
	}
	if info.Mode().Perm()&0o111 == 0 {
		fmt.Printf("%q is not executable; skipping run.\n", name)
		return
	}

	target := name
	if !strings.Contains(name, string(os.PathSeparator)) {
		target = "./" + name
	}
	if err := run(target); err != nil {
		fail("run: " + err.Error())
	}
}

func confirm(q string) bool {
	fmt.Printf("%s (y/N): ", q)
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.TrimSpace(strings.ToLower(ans)) {
	case "y", "yes":
		return true
	}
	return false
}

func run(args ...string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func isExecLikely(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".sh", ".bash", ".py":
		return true
	}
	return false
}

func fail(s string) {
	fmt.Fprintf(os.Stderr, "\033[0;31m✗ %s\033[0m\n", s)
	os.Exit(1)
}
