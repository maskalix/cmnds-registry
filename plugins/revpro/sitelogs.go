// sitelogs.go — tailing a site's access/error log for the web UI. Read-only,
// pure file I/O; no revpro state is touched.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
)

// maxLogTailBytes caps how much of a log file a single request ever reads
// off disk, so a multi-gigabyte access log can't make the request slow.
const maxLogTailBytes = 512 << 10

// tailLines returns up to n trailing lines of path. A missing file yields no
// lines and no error — a brand-new site just has nothing logged yet.
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if st.Size() > maxLogTailBytes {
		start = st.Size() - maxLogTailBytes
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, err
	}

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if start > 0 && len(lines) > 0 {
		// The byte right after a mid-file seek lands inside some earlier
		// line, not at its start — drop that first (partial) line.
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// siteLogPath resolves a site's access/error log path, matching the naming
// createLogFiles writes (see main.go).
func (c *proxyConfig) siteLogPath(domain, which string) (string, error) {
	switch which {
	case "access":
		return filepath.Join(c.logDir, domain+"_access.log"), nil
	case "error":
		return filepath.Join(c.logDir, domain+"_error.log"), nil
	}
	return "", fmt.Errorf("which must be 'access' or 'error'")
}
