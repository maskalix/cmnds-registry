package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleF2BStatus = `Status
|- Number of jail:	3
` + "`" + `- Jail list:	sshd, nginx-botsearch, recidive
`

const sampleF2BEmptyJailList = `Status
|- Number of jail:	0
` + "`" + `- Jail list:
`

const sampleF2BJailStatus = `Status for the jail: sshd
|- Filter
|  |- Currently failed:	2
|  |- Total failed:	17
|  ` + "`" + `- Journal matches:	_SYSTEMD_UNIT=ssh.service + _COMM=sshd
` + "`" + `- Actions
   |- Currently banned:	2
   |- Total banned:	5
   ` + "`" + `- Banned IP list:	203.0.113.9 198.51.100.4
`

func TestParseJailList(t *testing.T) {
	got := parseJailList(sampleF2BStatus)
	want := []string{"sshd", "nginx-botsearch", "recidive"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("jail %d = %q, want %q", i, got[i], w)
		}
	}
}

func TestParseJailListEmpty(t *testing.T) {
	if got := parseJailList(sampleF2BEmptyJailList); got != nil {
		t.Errorf("expected nil for an empty jail list, got %v", got)
	}
}

func TestParseJailStatus(t *testing.T) {
	j := parseJailStatus(sampleF2BJailStatus)
	if j.CurrentFailed != 2 || j.TotalFailed != 17 {
		t.Errorf("failed counts = %d/%d, want 2/17", j.CurrentFailed, j.TotalFailed)
	}
	if j.CurrentBanned != 2 || j.TotalBanned != 5 {
		t.Errorf("banned counts = %d/%d, want 2/5", j.CurrentBanned, j.TotalBanned)
	}
	want := []string{"203.0.113.9", "198.51.100.4"}
	if len(j.BannedIPs) != 2 || j.BannedIPs[0] != want[0] || j.BannedIPs[1] != want[1] {
		t.Errorf("banned IPs = %v, want %v", j.BannedIPs, want)
	}
}

func TestF2BJailLocalIncludesIgnoreAndLogDir(t *testing.T) {
	out := f2bJailLocal("/revpro/logs", "192.168.2.0/24", "")
	if !strings.Contains(out, "ignoreip = 127.0.0.1/8 ::1 192.168.2.0/24") {
		t.Errorf("ignoreip line missing/wrong:\n%s", out)
	}
	if !strings.Contains(out, "logpath = /revpro/logs/*_access.log") {
		t.Errorf("botsearch logpath missing:\n%s", out)
	}
	if !strings.Contains(out, "logpath = /revpro/logs/*_error.log") {
		t.Errorf("http-auth logpath missing:\n%s", out)
	}
	if !strings.Contains(out, "["+manualJail+"]") {
		t.Errorf("manual jail section missing:\n%s", out)
	}
	if !strings.Contains(out, "banaction = iptables-allports") {
		t.Errorf("manual jail should ban all ports:\n%s", out)
	}
}

func TestF2BJailLocalManualJailBantimeIsPermanent(t *testing.T) {
	out := f2bJailLocal("/revpro/logs", "", "")
	i := strings.Index(out, "["+manualJail+"]")
	if i < 0 {
		t.Fatalf("manual jail section missing:\n%s", out)
	}
	// The manual jail's own bantime must override the DEFAULT's 1h — a
	// deliberate/AbuseIPDB-driven block must never quietly self-expire.
	if !strings.Contains(out[i:], "bantime = -1") {
		t.Errorf("expected the manual jail to override bantime to permanent (-1):\n%s", out[i:])
	}
}

func TestF2BJailLocalAlwaysIncludesGenericHTTPErrorsJail(t *testing.T) {
	out := f2bJailLocal("/revpro/logs", "", "")
	if !strings.Contains(out, "[nginx-http-errors]") {
		t.Errorf("expected the generic http-errors jail always present:\n%s", out)
	}
	if !strings.Contains(out, "filter = nginx-http-errors") {
		t.Errorf("expected nginx-http-errors filter reference:\n%s", out)
	}
}

func TestF2BJailLocalErrorHostJailOnlyWhenSet(t *testing.T) {
	without := f2bJailLocal("/revpro/logs", "", "")
	if strings.Contains(without, "[nginx-error-redirect]") {
		t.Errorf("expected no error-redirect jail when errorHost is unset:\n%s", without)
	}

	with := f2bJailLocal("/revpro/logs", "", "error.example.tld")
	if !strings.Contains(with, "[nginx-error-redirect]") {
		t.Errorf("expected an error-redirect jail when errorHost is set:\n%s", with)
	}
	if !strings.Contains(with, "logpath = /revpro/logs/error.example.tld_access.log") {
		t.Errorf("expected the trap host's own access log as logpath:\n%s", with)
	}
}

func TestF2BJailLocalNoExtraIgnoreStillHasLoopback(t *testing.T) {
	out := f2bJailLocal("/revpro/logs", "", "")
	if !strings.Contains(out, "ignoreip = 127.0.0.1/8 ::1\n") {
		t.Errorf("expected bare loopback ignoreip, got:\n%s", out)
	}
}

func TestIgnoreExtractsLine(t *testing.T) {
	out := f2bJailLocal("/x/logs", "10.0.0.0/8", "")
	if got := ignore(out); got != "127.0.0.1/8 ::1 10.0.0.0/8" {
		t.Errorf("ignore() = %q", got)
	}
}

func TestF2BActionConfCallsBackIntoRevpro(t *testing.T) {
	out := f2bActionConf("/usr/local/bin/revpro")
	if !strings.Contains(out, "actionban = /usr/local/bin/revpro fail2ban report-hook <ip> <name>") {
		t.Errorf("actionban wrong:\n%s", out)
	}
}

func TestAbuseCategoriesForKnownAndUnknownJail(t *testing.T) {
	if c := abuseCategoriesFor("sshd"); len(c) == 0 {
		t.Error("expected categories for sshd")
	}
	if c := abuseCategoriesFor("some-custom-jail"); len(c) != 1 || c[0] != 15 {
		t.Errorf("expected fallback [15] for an unmapped jail, got %v", c)
	}
}

func TestDetectLocalCIDRsDoesNotPanic(t *testing.T) {
	// Just a smoke test — the actual interfaces present vary by test
	// environment (CI sandbox vs. a real box), so there's nothing specific
	// to assert about the contents.
	_ = detectLocalCIDRs()
}

func TestApproachingBansParsesAndFiltersByThreshold(t *testing.T) {
	old := f2bLogPath
	f2bLogPath = filepath.Join(t.TempDir(), "fail2ban.log")
	defer func() { f2bLogPath = old }()

	now := time.Now()
	fmtLine := func(ago time.Duration, jail, ip string) string {
		ts := now.Add(-ago).Format("2006-01-02 15:04:05")
		return ts + ",123 fail2ban.filter         [111]: INFO    [" + jail + "] Found " + ip + " - " + ts
	}
	var lines []string
	// nginx-http-errors: maxretry=30, findtime=10m — 20 recent hits is "close" (>=15, <30).
	for i := 0; i < 20; i++ {
		lines = append(lines, fmtLine(time.Duration(i)*time.Second, "nginx-http-errors", "203.0.113.9"))
	}
	// sshd: maxretry=5, findtime=10m — 2 hits is well under half, should NOT appear.
	lines = append(lines, fmtLine(1*time.Minute, "sshd", "198.51.100.4"))
	lines = append(lines, fmtLine(2*time.Minute, "sshd", "198.51.100.4"))
	// An old hit outside the findtime window must not count.
	lines = append(lines, fmtLine(20*time.Minute, "nginx-http-errors", "192.0.2.1"))

	if err := os.WriteFile(f2bLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := approachingBans()
	if len(got) != 1 {
		t.Fatalf("expected exactly one approaching IP, got %+v", got)
	}
	if got[0].IP != "203.0.113.9" || got[0].Jail != "nginx-http-errors" || got[0].Count != 20 || got[0].Max != 30 {
		t.Errorf("got %+v", got[0])
	}
}

func TestApproachingBansMissingLogYieldsEmpty(t *testing.T) {
	old := f2bLogPath
	f2bLogPath = filepath.Join(t.TempDir(), "does-not-exist.log")
	defer func() { f2bLogPath = old }()
	if got := approachingBans(); got != nil {
		t.Errorf("expected nil for a missing log, got %v", got)
	}
}
