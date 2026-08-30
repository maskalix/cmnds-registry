// iplog.go — aggregates the per-site nginx access logs revpro already
// writes (see main.go's createLogFiles/renderSite) into a single "who's
// hitting this box" view, keyed by client IP. Read-only and bounded (via
// sitelogs.go's tailLines) so scanning every site's log can't make a
// request slow even on a box with a lot of traffic.
package main

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// nginxTimeLayout matches the default combined log format's
// [30/Aug/2026:12:04:08 +0000] timestamp.
const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// ipStat is one client IP's aggregated activity across every site's access log.
type ipStat struct {
	IP       string    `json:"ip"`
	Requests int       `json:"requests"`
	Sites    []string  `json:"sites"`
	LastSeen time.Time `json:"lastSeen"`
}

// maxAccessLinesPerSite caps how many trailing lines of any one site's
// access log are considered, so one very chatty site can't drown out (or
// slow down aggregation across) all the others.
const maxAccessLinesPerSite = 2000

// ipAccessStats scans every *_access.log under c.logDir, aggregates hits by
// client IP, and returns the `limit` most-recently-seen IPs.
func (c *proxyConfig) ipAccessStats(limit int) ([]ipStat, error) {
	entries, err := os.ReadDir(c.logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	byIP := map[string]*ipStat{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_access.log") {
			continue
		}
		site := strings.TrimSuffix(e.Name(), "_access.log")
		lines, err := tailLines(filepath.Join(c.logDir, e.Name()), maxAccessLinesPerSite)
		if err != nil {
			continue // a single unreadable log shouldn't blank the whole table
		}
		for _, line := range lines {
			ip, ts, ok := parseAccessLine(line)
			if !ok {
				continue
			}
			st, have := byIP[ip]
			if !have {
				st = &ipStat{IP: ip}
				byIP[ip] = st
			}
			st.Requests++
			if !ts.IsZero() && ts.After(st.LastSeen) {
				st.LastSeen = ts
			}
			if !containsStr(st.Sites, site) {
				st.Sites = append(st.Sites, site)
			}
		}
	}

	out := make([]ipStat, 0, len(byIP))
	for _, st := range byIP {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// parseAccessLine extracts the client IP and timestamp from one combined-
// format access log line: `IP - - [time] "request" status bytes "ref" "ua"`.
// A line that doesn't start with a parseable IP (a truncated first line
// after a mid-file tail seek, for instance) is simply skipped.
func parseAccessLine(line string) (ip string, ts time.Time, ok bool) {
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return "", time.Time{}, false
	}
	ipPart := line[:sp]
	if net.ParseIP(ipPart) == nil {
		return "", time.Time{}, false
	}
	i := strings.IndexByte(line, '[')
	j := strings.IndexByte(line, ']')
	if i >= 0 && j > i {
		if t, err := time.Parse(nginxTimeLayout, line[i+1:j]); err == nil {
			ts = t
		}
	}
	return ipPart, ts, true
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// isPrivateOrLoopback reports whether ip is loopback, link-local, or an
// RFC1918/ULA private address — used to skip a box's own LAN/management
// traffic from outbound reputation checks and auto-blocking.
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // unparseable — never worth spending API quota on
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// accessEvent is one parsed access-log line, for the Current dashboard's
// recent-activity feed — richer than ipStat, which only needs the IP+time.
type accessEvent struct {
	Site   string    `json:"site"`
	IP     string    `json:"ip"`
	Time   time.Time `json:"time"`
	Method string    `json:"method,omitempty"`
	Path   string    `json:"path,omitempty"`
	Status int       `json:"status,omitempty"`
}

// parseAccessLineFull extracts IP, timestamp, request method/path, and
// status from one combined-format line. Falls back gracefully — a missing
// or malformed request/status section still yields the IP+time.
func parseAccessLineFull(line, site string) (accessEvent, bool) {
	ip, ts, ok := parseAccessLine(line)
	if !ok {
		return accessEvent{}, false
	}
	ev := accessEvent{Site: site, IP: ip, Time: ts}

	i := strings.IndexByte(line, '"')
	if i < 0 {
		return ev, true
	}
	j := strings.IndexByte(line[i+1:], '"')
	if j < 0 {
		return ev, true
	}
	j += i + 1
	if fields := strings.Fields(line[i+1 : j]); len(fields) >= 2 {
		ev.Method, ev.Path = fields[0], fields[1]
	}
	if rest := strings.Fields(strings.TrimSpace(line[j+1:])); len(rest) >= 1 {
		ev.Status = atoiSafe(rest[0])
	}
	return ev, true
}

// maxAccessEventsPerSite bounds how many trailing lines of any one site's
// log feed the recent-activity view, for the same reason as
// maxAccessLinesPerSite — one chatty site shouldn't drown out the rest or
// slow down aggregation.
const maxAccessEventsPerSite = 300

// recentAccessEvents returns the `limit` most recent access-log events
// across every site, newest first.
func (c *proxyConfig) recentAccessEvents(limit int) ([]accessEvent, error) {
	entries, err := os.ReadDir(c.logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var all []accessEvent
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_access.log") {
			continue
		}
		site := strings.TrimSuffix(e.Name(), "_access.log")
		lines, err := tailLines(filepath.Join(c.logDir, e.Name()), maxAccessEventsPerSite)
		if err != nil {
			continue
		}
		for _, line := range lines {
			if ev, ok := parseAccessLineFull(line, site); ok {
				all = append(all, ev)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Time.After(all[j].Time) })
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}
