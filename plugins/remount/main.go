// remount — unmount the given path and re-run `mount -a` to bring back
// everything from /etc/fstab.
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Println("Usage: remount <mountpoint>")
		os.Exit(1)
	}
	target := os.Args[1]

	if err := run("umount", target); err != nil {
		fmt.Fprintf(os.Stderr, "\033[0;31m✗ umount %s: %v\033[0m\n", target, err)
		os.Exit(1)
	}
	if err := run("mount", "-a"); err != nil {
		fmt.Fprintf(os.Stderr, "\033[0;31m✗ mount -a: %v\033[0m\n", err)
		os.Exit(1)
	}
	fmt.Printf("\033[0;32m✓ remounted %s\033[0m\n", target)
}

func run(args ...string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
