// ssh-init — generate an ed25519 SSH keypair for a target user and add the
// public key to that user's authorized_keys.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	username := flag.String("user", "", "target username (defaults to current user)")
	email := flag.String("email", "", "comment to embed in the key")
	keyType := flag.String("type", "ed25519", "key type: ed25519 or rsa")
	flag.Usage = func() {
		fmt.Println(`ssh-init — create an SSH keypair and add it to authorized_keys

Usage:
  ssh-init [-user NAME] [-email comment] [-type ed25519|rsa]

Without flags you'll be prompted for the missing fields. Defaults to the
current user and an ed25519 key. Requires ssh-keygen.`)
	}
	flag.Parse()

	if *username == "" {
		*username = prompt("Username", currentUser())
	}
	if *email == "" {
		*email = prompt("Email/comment", *username+"@"+hostname())
	}

	u, err := user.Lookup(*username)
	if err != nil {
		fail("lookup user: " + err.Error())
	}
	sshDir := filepath.Join(u.HomeDir, ".ssh")
	keyName := "id_" + *keyType
	keyPath := filepath.Join(sshDir, keyName)

	if err := ensureDir(sshDir, u, 0o700); err != nil {
		fail(err.Error())
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		info("Generating " + *keyType + " key at " + keyPath)
		args := []string{"-t", *keyType, "-C", *email, "-f", keyPath, "-N", ""}
		if *keyType == "rsa" {
			args = append([]string{"-b", "4096"}, args...)
		}
		if err := run(append([]string{"ssh-keygen"}, args...)...); err != nil {
			fail("ssh-keygen: " + err.Error())
		}
		if err := chown(keyPath, u); err == nil {
			_ = chown(keyPath+".pub", u)
		}
	} else {
		info(keyPath + " already exists; reusing it")
	}

	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		fail("read public key: " + err.Error())
	}

	authPath := filepath.Join(sshDir, "authorized_keys")
	if err := appendIfMissing(authPath, string(pub)); err != nil {
		fail("authorized_keys: " + err.Error())
	}
	_ = os.Chmod(authPath, 0o600)
	_ = chown(authPath, u)

	ok("Done")
	fmt.Println()
	fmt.Println("Public key:")
	fmt.Println("  " + strings.TrimSpace(string(pub)))
	fmt.Println()
	fmt.Println("Private key path:")
	fmt.Println("  " + keyPath)
}

func appendIfMissing(path, line string) error {
	line = strings.TrimRight(line, "\n") + "\n"

	if data, err := os.ReadFile(path); err == nil {
		if strings.Contains(string(data), strings.TrimSpace(line)) {
			info("public key already in " + path)
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func ensureDir(path string, u *user.User, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return chown(path, u)
}

func chown(path string, u *user.User) error {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

func prompt(label, fallback string) string {
	fmt.Printf("%s [%s]: ", label, fallback)
	r := bufio.NewReader(os.Stdin)
	s, _ := r.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	return s
}

func run(args ...string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "localhost"
	}
	return h
}

func info(s string) { fmt.Printf("\033[1;34m●\033[0m %s\n", s) }
func ok(s string)   { fmt.Printf("\033[0;32m✓\033[0m %s\n", s) }
func fail(s string) {
	fmt.Fprintf(os.Stderr, "\033[0;31m✗\033[0m %s\n", s)
	os.Exit(1)
}
