// reg — build and push a docker image to a configurable registry.
//
// Reads CUSTOM_REGISTRY and CUSTOM_TAG from `cmnds config`. Falls back to
// reg.example.com / latest if neither is set.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	defaultRegistry = "reg.example.com"
	defaultTag      = "latest"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		printUsage()
		os.Exit(0)
	}

	image := os.Args[1]
	registry := configOr("CUSTOM_REGISTRY", defaultRegistry)
	tag := configOr("CUSTOM_TAG", defaultTag)
	remoteName := fmt.Sprintf("%s/%s:%s", registry, image, tag)

	steps := []struct {
		label string
		cmd   []string
	}{
		{"Building image " + image, []string{"docker", "build", "-t", image, "."}},
		{"Tagging as " + remoteName, []string{"docker", "tag", image, remoteName}},
		{"Pushing to " + registry, []string{"docker", "push", remoteName}},
	}

	for _, s := range steps {
		fmt.Printf("\033[1;34m●\033[0m %s\n", s.label)
		if err := run(s.cmd); err != nil {
			fmt.Fprintf(os.Stderr, "\033[0;31m✗ %s\033[0m\n", err)
			os.Exit(1)
		}
	}
	fmt.Println("\033[0;32m✓ Image pushed\033[0m")
}

func run(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// configOr reads a value from `cmnds config read <name>`. Returns fallback
// if cmnds is unavailable or the variable is unset.
func configOr(name, fallback string) string {
	cmnds, err := exec.LookPath("cmnds")
	if err != nil {
		return fallback
	}
	out, err := exec.Command(cmnds, "config", "read", name).Output()
	if err != nil {
		return fallback
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return fallback
	}
	return v
}

func printUsage() {
	fmt.Println(`reg — build and push a docker image

Usage:
  reg <image-name>

Reads CUSTOM_REGISTRY and CUSTOM_TAG via 'cmnds config read'.
Falls back to reg.example.com / latest.`)
}
