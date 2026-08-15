// manconf.go — manually-maintained nginx configs living in $REVPRO/manconf.
//
// nginx.conf includes /etc/nginx/conf.man/default/*.conf and
// /etc/nginx/conf.man/*.conf (bind-mounted from $REVPRO/manconf), so any .conf
// file dropped there is already live in the proxy — it just wasn't visible to
// revpro's own 'list'/'analyze'. A file opts out by making "#-ignore" the very
// first line.
package main

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// manconfIgnoreMarker, as the exact first line of a manconf file, excludes it
// from revpro's view (list/analyze) without removing it from nginx.conf's
// include (nginx still loads it — this only affects revpro's bookkeeping).
const manconfIgnoreMarker = "#-ignore"

func (c *proxyConfig) manconfDir() string {
	return filepath.Join(c.mainFolder, "manconf")
}

// isIgnoredConfig reports whether path opts out via "#-ignore" as its first
// line — exactly, at the very start of the line, not merely present in a
// comment somewhere. Only a trailing \r (Windows line endings) is trimmed.
// Read errors (including a missing file) are treated as not-ignored so
// callers still surface the underlying problem.
func isIgnoredConfig(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	return sc.Scan() && strings.TrimRight(sc.Text(), "\r") == manconfIgnoreMarker
}

// manconfFile is one manually-maintained nginx config recognized by revpro.
type manconfFile struct {
	name string // base filename without .conf (default/ prefixed when under that subdir)
	path string // absolute path
}

// manconfFiles walks $REVPRO/manconf and its default/ subfolder — both are
// `include`d by nginx.conf — for *.conf files, skipping any carrying the
// "#-ignore" marker. A missing manconf dir yields no files, not an error (not
// every install uses it).
func (c *proxyConfig) manconfFiles() []manconfFile {
	dir := c.manconfDir()
	var out []manconfFile
	for _, sub := range []string{"", "default"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			path := filepath.Join(dir, sub, e.Name())
			if isIgnoredConfig(path) {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".conf")
			if sub != "" {
				name = sub + "/" + name
			}
			out = append(out, manconfFile{name: name, path: path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
