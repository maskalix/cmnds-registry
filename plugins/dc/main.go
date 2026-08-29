// dc — quick docker compose shortcuts, ported from cmnds v1's scripts/docker/dc.sh.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const usage = `Usage: dc <command> [args...]

Available Commands:
  u        up
  ud       up -d
  udb      up -d --build
  d        down
  p        pull
  ps       ps
  b        build
  l        logs
  rs       restart
  e        edit docker-compose.yml
  rec      recreate docker-compose.yml
  sh       exec into service shell (dc sh <service>)
  c        config (validate)
  r        recompose (pull → down → up -d)

Examples:
  dc ud              Start containers in detached mode
  dc udb             Build and start containers in detached mode
  dc d               Stop and remove containers
  dc l -f web        Follow logs for 'web' service
  dc sh web          Open shell in 'web' container
  dc r               Full recompose (update and restart)
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "\033[0;31m✗ %s\033[0m\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}

	shortcut := args[0]
	if shortcut == "-h" || shortcut == "--help" || shortcut == "help" {
		fmt.Print(usage)
		return nil
	}
	shortcutArgs := args[1:]

	switch shortcut {
	case "e", "edit":
		return editComposeFile()
	case "rec", "recreate":
		return recreateComposeFile()
	case "r", "recompose":
		return recompose(shortcutArgs)
	case "sh", "shell":
		if len(shortcutArgs) == 0 {
			return fmt.Errorf("service name required for shell command")
		}
		return runCompose([]string{"exec", shortcutArgs[0], "sh"})
	}

	var composeCmd []string
	switch shortcut {
	case "u":
		composeCmd = append([]string{"up"}, shortcutArgs...)
	case "ud":
		composeCmd = append([]string{"up", "-d"}, shortcutArgs...)
	case "udb":
		composeCmd = append([]string{"up", "-d", "--build"}, shortcutArgs...)
	case "d", "down":
		composeCmd = append([]string{"down"}, shortcutArgs...)
	case "p", "pull":
		composeCmd = append([]string{"pull"}, shortcutArgs...)
	case "ps":
		composeCmd = append([]string{"ps"}, shortcutArgs...)
	case "b", "build":
		composeCmd = append([]string{"build"}, shortcutArgs...)
	case "l", "logs":
		composeCmd = append([]string{"logs"}, shortcutArgs...)
	case "rs", "restart":
		composeCmd = append([]string{"restart"}, shortcutArgs...)
	case "c", "config":
		composeCmd = append([]string{"config"}, shortcutArgs...)
	default:
		return fmt.Errorf("unknown command: %s\nUse 'dc help' for usage information", shortcut)
	}

	return runCompose(composeCmd)
}

func runCompose(args []string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found. Please install Docker first")
	}

	fmt.Printf("\033[1;34m●\033[0m Running: docker compose %s\n", strings.Join(args, " "))

	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose command failed: %w", err)
	}
	return nil
}

func editComposeFile() error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}

	const composeFile = "docker-compose.yml"
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		fmt.Printf("\033[1;34m●\033[0m Creating new %s\n", composeFile)
		if err := os.WriteFile(composeFile, []byte(""), 0644); err != nil {
			return fmt.Errorf("failed to create %s: %w", composeFile, err)
		}
	}

	cmd := exec.Command(editor, composeFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to edit %s: %w", composeFile, err)
	}
	return nil
}

func recreateComposeFile() error {
	const composeFile = "docker-compose.yml"

	if err := os.Remove(composeFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing %s: %w", composeFile, err)
	}
	fmt.Printf("\033[1;34m●\033[0m Removed existing %s\n", composeFile)

	return editComposeFile()
}

func recompose(args []string) error {
	fmt.Println("\033[1;34m●\033[0m Running recompose: pull → down → up -d")

	if err := runCompose([]string{"pull"}); err != nil {
		fmt.Fprintln(os.Stderr, "\033[0;31m✗ Pull failed, continuing anyway...\033[0m")
	}

	if err := runCompose([]string{"down"}); err != nil {
		return fmt.Errorf("down failed: %w", err)
	}

	if err := runCompose(append([]string{"up", "-d"}, args...)); err != nil {
		return fmt.Errorf("up failed: %w", err)
	}

	fmt.Println("\033[0;32m✓ Recompose complete!\033[0m")
	return nil
}
