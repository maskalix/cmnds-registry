package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManconfFilesRecognizesAndIgnores(t *testing.T) {
	main := t.TempDir()
	manconf := filepath.Join(main, "manconf")
	os.MkdirAll(filepath.Join(manconf, "default"), 0o755)

	write := func(rel, body string) {
		path := filepath.Join(manconf, rel)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("custom.conf", "server { listen 8080; }\n")
	write("skip-me.conf", "#-ignore\nserver { listen 9090; }\n")
	write("not-a-conf.txt", "ignored by extension")
	write(filepath.Join("default", "base.conf"), "server { listen 80; }\n")
	// A comment that merely contains "#-ignore" later, or on a later line,
	// must NOT be treated as the marker — only the first line counts.
	write("late-marker.conf", "server {}\n#-ignore\n")

	c := &proxyConfig{mainFolder: main}
	got := c.manconfFiles()

	names := map[string]bool{}
	for _, m := range got {
		names[m.name] = true
	}
	if !names["custom"] {
		t.Error("expected custom.conf to be recognized")
	}
	if !names["default/base"] {
		t.Error("expected default/base.conf to be recognized")
	}
	if !names["late-marker"] {
		t.Error("expected late-marker.conf to be recognized (marker only counts on line 1)")
	}
	if names["skip-me"] {
		t.Error("expected skip-me.conf to be skipped via #-ignore")
	}
	if len(got) != 3 {
		t.Errorf("expected 3 recognized files, got %d: %+v", len(got), got)
	}
}

func TestManconfFilesMissingDirIsNotAnError(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}
	if got := c.manconfFiles(); len(got) != 0 {
		t.Errorf("expected no files for a missing manconf dir, got %+v", got)
	}
}

func TestIsIgnoredConfig(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]bool{
		"#-ignore\nrest\n":  true,
		"#-ignore":          true,
		" #-ignore\n":       false, // marker must be exact, not indented
		"# -ignore\n":       false,
		"stuff\n#-ignore\n": false,
		"":                  false,
	}
	for body, want := range cases {
		path := filepath.Join(dir, "f.conf")
		os.WriteFile(path, []byte(body), 0o644)
		if got := isIgnoredConfig(path); got != want {
			t.Errorf("isIgnoredConfig(%q) = %v, want %v", body, got, want)
		}
	}
	if isIgnoredConfig(filepath.Join(dir, "does-not-exist.conf")) {
		t.Error("missing file should not be treated as ignored")
	}
}
