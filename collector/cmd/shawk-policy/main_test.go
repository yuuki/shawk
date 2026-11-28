package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// policy runs the command and returns its exit status and outputs.
func policy(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestUsage: the help and an invalid command line have the status of
// neither an answer nor a failure, and tell what is wrong on the standard
// error, so that a script that tests for 0 does not take them for COMPLETE.
func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
		code, out, errOut := policy(args...)
		if code != exitUsage || out != "" || !strings.Contains(errOut, "shawk-policy rules    -host NAME") ||
			!strings.Contains(errOut, "Exit status: 0 COMPLETE, or no drift, and nothing else") {
			t.Errorf("%v: exit status %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	for _, c := range []struct{ command, want string }{
		{"rules", "shawk-policy rules -host NAME"}, {"baseline", "shawk-policy baseline (-service NAME"},
		{"drift", "shawk-policy drift [-service NAME"},
	} {
		code, out, errOut := policy(c.command, "-h")
		if code != exitUsage || out != "" || !strings.Contains(errOut, c.want) || !strings.Contains(errOut, "-dsn-file") {
			t.Errorf("%s -h: exit status %d, stdout %q, stderr %q", c.command, code, out, errOut)
		}
		// The connection string, which may hold a password, is not printed
		// as the default of its flag.
		t.Setenv("SHAWK_POSTGRES_DSN", "postgres://shawk:secret@db/shawk")
		if _, _, errOut = policy(c.command, "-h"); strings.Contains(errOut, "secret") {
			t.Errorf("%s -h prints the connection string", c.command)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"apply"}, `unknown command "apply"`},
		{[]string{"rules"}, "-host is required"},
		{[]string{"rules", "-host", "h", "extra"}, `unexpected argument "extra"`},
		{[]string{"rules", "-host", "h", "-unit", ""}, "-unit must not be empty"},
		{[]string{"rules", "-host", "h", "-format", "iptables"}, "-format must be report, nftables, systemd or json"},
		{[]string{"rules", "-host", "h", "-format", "systemd"}, "it needs -unit"},
		{[]string{"rules", "-host", "h", "-format", "systemd", "-unit", "docker/web"}, "is none"},
		{[]string{"rules", "-host", "h", "-format", "systemd", "-unit", "user@1000.service/podman-0123"}, "is none"},
		{[]string{"rules", "-host", "h", "-format", "systemd", "-unit", "a.service", "-ingress", "ports"}, "-ingress is for nftables"},
		{[]string{"rules", "-host", "h", "-format", "nftables", "-unit", "a.service"}, "it takes no -unit"},
		{[]string{"rules", "-host", "h", "-ingress", "all"}, "-ingress must be sources, ports or none"},
		// A file that blocks is asked for in so many words.
		{[]string{"rules", "-host", "h", "-format", "systemd", "-unit", "a.service"}, "-format systemd needs -enforce"},
		{[]string{"rules", "-host", "h", "-enforce"}, "-enforce is for -format nftables or systemd"},
		{[]string{"rules", "-host", "h", "-format", "json", "-enforce"}, "-enforce is for -format nftables or systemd"},
		{[]string{"rules", "-host", "h", "-format", "nftables", "-allow-incomplete"}, "-allow-incomplete is for -enforce"},
		{[]string{"drift", "-hosts-lookback", "soon"}, "-hosts-lookback"},
		{[]string{"rules", "-host", "h", "-limit", "-1"}, "-limit must not be negative"},
		{[]string{"rules", "-host", "h", "-lookback", "3m"}, "-lookback must be from 1h"},
		{[]string{"rules", "-host", "h", "-min-coverage", "99.9"}, "-min-coverage must be a part of the period"},
		{[]string{"rules", "-host", "h", "-until", "yesterday"}, "-until"},
		{[]string{"rules", "-host", "h", "-timeout", "0"}, "-timeout must be positive"},
		{[]string{"baseline"}, "-service or -all is required"},
		{[]string{"baseline", "-all", "-service", "a"}, "-all and -service exclude each other"},
		{[]string{"baseline", "-service", ""}, "-service must not be empty"},
		{[]string{"baseline", "-service", "a", "-lookback", "30m"}, "-lookback must be from 1h"},
		{[]string{"drift", "-service", ""}, "-service must not be empty"},
		{[]string{"drift", "-lookback", "30s"}, "-lookback must be from 1m"},
		{[]string{"drift", "-limit", "-1"}, "-limit must not be negative"},
		{[]string{"drift", "-min-coverage", "1"}, "flag provided but not defined"},
	} {
		code, out, errOut := policy(c.args...)
		if code != exitUsage || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: exit status %d, stdout %q, stderr %q, want %q", c.args, code, out, errOut, c.want)
		}
	}
	// Units that a drop-in can be written for.
	for _, unit := range []string{"nginx.service", "app@1.service", "app@.service", `dev-disk\x2dby.service`, "a:b_c-d.service"} {
		if _, err := parseRules([]string{"-host", "h", "-format", "systemd", "-enforce", "-unit", unit}, new(bytes.Buffer)); err != nil {
			t.Errorf("unit %q: %v", unit, err)
		}
	}
}

// TestNeedsPostgres: a connection string that names a file of SQLite, or
// none at all, fails before anything is written.
func TestNeedsPostgres(t *testing.T) {
	t.Setenv("SHAWK_POSTGRES_DSN", "")
	file := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(file, []byte("SQLite format 3\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{{"rules", "-host", "h"}, {"baseline", "-all"}, {"drift"}} {
		for dsn, want := range map[string]string{
			"/var/lib/shawk/shawk.db": "shawk-policy needs PostgreSQL", "file:shawk.db?mode=ro": "shawk-policy needs PostgreSQL",
			"sqlite:///x": "shawk-policy needs PostgreSQL", file: "shawk-policy needs PostgreSQL",
			"postgres://%zz": "invalid PostgreSQL connection string",
		} {
			code, out, errOut := policy(append(command, "-dsn", dsn)...)
			if code != exitError || out != "" || !strings.Contains(errOut, want) {
				t.Errorf("%v with %q: exit status %d, stdout %q, stderr %q", command, dsn, code, out, errOut)
			}
		}
		if code, out, errOut := policy(command...); code != exitError || out != "" || !strings.Contains(errOut, "set -dsn, -dsn-file or $SHAWK_POSTGRES_DSN") {
			t.Errorf("%v without a connection string: exit status %d, stdout %q, stderr %q", command, code, out, errOut)
		}
		if code, _, errOut := policy(append(command, "-dsn-file", filepath.Join(t.TempDir(), "none"))...); code != exitError ||
			!strings.Contains(errOut, "no such file") {
			t.Errorf("%v without the file of the connection string: exit status %d, stderr %q", command, code, errOut)
		}
	}
	// A file to merge with that is invalid fails before the database is asked.
	bad := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(bad, []byte("services:\n  - service: a\nend: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := policy("baseline", "-service", "a", "-merge", bad, "-dsn", "postgres://127.0.0.1:1/x"); code != exitError ||
		out != "" || !strings.Contains(errOut, "no dependencies") {
		t.Errorf("an invalid file to merge with: exit status %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestParseLookback(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90d":   90 * 24 * time.Hour,
		"12w":   12 * 7 * 24 * time.Hour,
		"1.5d":  36 * time.Hour,
		"36h":   36 * time.Hour,
		"1h30m": 90 * time.Minute,
		"60m":   time.Hour,
	} {
		if got, err := parseLookback(in, time.Hour); err != nil || got != want {
			t.Errorf("parseLookback(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	// Less than the least tells nothing, and 3m is 3 minutes, not 3 months.
	for _, in := range []string{"", "d", "w", "90", "ninety days", "-1d", "0d", "0s", "500ms", "1e9d", "NaNd", "Infw", "40000d",
		"1d2h", "3 d", "3m", "59m59s", "90s", "1s", "0.04d"} {
		if got, err := parseLookback(in, time.Hour); err == nil {
			t.Errorf("parseLookback(%q) = %v, want an error", in, got)
		}
	}
	if got, err := parseLookback("3m", time.Minute); err != nil || got != 3*time.Minute {
		t.Errorf("parseLookback(3m) with a least of a minute = %v, %v", got, err)
	}
}

func FuzzParseLookback(f *testing.F) {
	for _, s := range []string{"90d", "12w", "36h", "1.5d", "-1d", "1e400d", "NaNw", "d", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := parseLookback(s, time.Hour)
		if err == nil && (d < time.Hour || d > maxLookback) {
			t.Errorf("parseLookback(%q) = %v, out of bounds", s, d)
		}
	})
}

func TestParseCoverage(t *testing.T) {
	for in, want := range map[string]string{
		"1": "1.000000000000", "1.0": "1.000000000000", "0.999": "0.999000000000", ".5": "0.500000000000",
		"0.000000000001": "0.000000000001",
	} {
		if got, err := parseCoverage(in); err != nil || got != want {
			t.Errorf("parseCoverage(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A percentage is no part of the period: 99.9 is not taken for 0.999,
	// nor 100 for all of it.
	for _, in := range []string{"", "0", "-1", "1.000001", "1.1", "99.9", "100", "99%", "1/2", "1e-2", "all", "0.00000000000001"} {
		if got, err := parseCoverage(in); err == nil {
			t.Errorf("parseCoverage(%q) = %q, want an error", in, got)
		}
	}
}

func FuzzParseCoverage(f *testing.F) {
	for _, s := range []string{"1", "0.999", "0.1", "0", "1.1", "100", "1/2", "1e-2", "-1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := parseCoverage(s)
		if err != nil {
			return
		}
		if !strings.HasPrefix(c, "0.") && c != "1.000000000000" {
			t.Errorf("parseCoverage(%q) = %q, not above 0 and up to 1", s, c)
		}
	})
}

func TestFormat(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0s", 45 * time.Second: "45s", 90 * 24 * time.Hour: "90d", 3*time.Hour + 28*time.Minute: "3h28m",
		24*time.Hour + 5*time.Minute: "1d", -time.Second: "0s",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
	for in, want := range map[string]string{"1.000000": "1", "0.999800": "0.9998", "0.000000": "0", "": "0", "10": "10"} {
		if got := fraction(in); got != want {
			t.Errorf("fraction(%q) = %q, want %q", in, got, want)
		}
	}
	if got := strings.Join(wrap("a bb ccc dddd eeeee", 6), "|"); got != "a bb|ccc|dddd|eeeee" {
		t.Errorf("wrap = %q", got)
	}
}

// TestCommentName: a name is written in a comment as it is when it is
// plain, and quoted on one line otherwise.
func TestCommentName(t *testing.T) {
	for in, want := range map[string]string{
		"shop/postgres": "shop/postgres", "~external": "~external", "k8s/default/web/app": "k8s/default/web/app",
		"app@1.service": "app@1.service", "": `""`, "a b": `"a b"`, "a\nb": `"a\nb"`, `a\`: `"a\\"`, "é": `"é"`,
		"x\u2028y": `"x\u2028y"`, "\x1b[2J": `"\x1b[2J"`, "a,b": `"a,b"`, `"`: `"\""`,
	} {
		if got := commentName(in); got != want {
			t.Errorf("commentName(%q) = %s, want %s", in, got, want)
		}
	}
}

// oneCommentLine tells whether a line is a comment that neither ends nor
// continues: what a name in a file of rules must stay within.
func oneCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimLeft(line, "\t"), "#") && !strings.ContainsAny(line, "\n\r\x00") && !strings.HasSuffix(line, `\`)
}

// FuzzComment: whatever a name or a line holds, a comment is one line per
// line given, each a comment that the next line does not continue.
func FuzzComment(f *testing.F) {
	for _, s := range []string{"shop/app", "a\nb", `trailing\`, "\r\n accept", "x\u2028y", "", " ", "\\\n", "a\\\r"} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, name, line string) {
		q := commentName(name)
		if strings.ContainsAny(q, "\n\r\x00") || strings.HasSuffix(q, `\`) || !utf8.ValidString(q) {
			t.Fatalf("commentName(%q) = %q", name, q)
		}
		var b strings.Builder
		comment(&b, "\t", "peer "+q, line, "")
		lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("comment(%q, %q) wrote %d lines: %q", name, line, len(lines), b.String())
		}
		for _, l := range lines {
			if !oneCommentLine(l) {
				t.Fatalf("comment(%q, %q) wrote the line %q", name, line, l)
			}
		}
	})
}
