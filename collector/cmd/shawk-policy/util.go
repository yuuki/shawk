package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// maxLookback bounds the period: the retention of the connector is 3 years
// by default, and a period far longer than what is kept only reads as not
// observed.
const maxLookback = 100 * 365 * 24 * time.Hour

// parseLookback parses the length of a period, of min at least: a duration
// of Go, or a number of days (d) or weeks (w). A period shorter than what
// the command can tell anything from is a mistake, as 3m meant as 3 months.
func parseLookback(s string, min time.Duration) (time.Duration, error) {
	var d time.Duration
	unit := time.Duration(0)
	switch {
	case strings.HasSuffix(s, "d"):
		unit = 24 * time.Hour
	case strings.HasSuffix(s, "w"):
		unit = 7 * 24 * time.Hour
	}
	if unit != 0 {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, s[len(s)-1:]), 64)
		if err != nil || n != n || n > float64(maxLookback/unit) || n < -float64(maxLookback/unit) {
			return 0, fmt.Errorf("-lookback: invalid duration %q", s)
		}
		d = time.Duration(n * float64(unit))
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("-lookback: invalid duration %q", s)
		}
	}
	if d < min || d > maxLookback {
		return 0, fmt.Errorf("-lookback must be from %s to 100 years (m is minutes, not months): %q", formatDuration(min), s)
	}
	return d.Truncate(time.Second), nil
}

// parseCoverage parses a part of the period, above 0 and up to 1, and
// returns it as a decimal: what the verdicts take as min_coverage, without
// the rounding of a float. The unit is that of PostgreSQL and of the
// report, so that no value means two things: a percentage, 99.9, is
// refused rather than taken for more than the whole period.
func parseCoverage(s string) (string, error) {
	p, ok := new(big.Rat).SetString(s)
	// A trillionth is the least that 12 decimals tell from 0.
	if !ok || strings.ContainsAny(s, "/eE") || p.Cmp(big.NewRat(1, 1e12)) < 0 || p.Cmp(big.NewRat(1, 1)) > 0 {
		return "", fmt.Errorf("-min-coverage must be a part of the period above 0, up to 1 (0.999 for 99.9%%): %q", s)
	}
	return p.FloatString(12), nil
}

// isSQLite tells whether a connection string names a file of SQLite rather
// than a PostgreSQL database, which a URL or keywords and values name: a
// file: or sqlite: URI, or the path of a file.
func isSQLite(dsn string) bool {
	lower := strings.ToLower(dsn)
	for _, scheme := range []string{"file:", "sqlite:", "sqlite3:"} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	if strings.Contains(dsn, "://") || strings.Contains(dsn, "=") {
		return false
	}
	for _, ext := range []string{".db", ".sqlite", ".sqlite3"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	info, err := os.Stat(dsn) //nolint:gosec // G703: what the command line gives, only to tell a file from a connection string
	return err == nil && !info.IsDir()
}

// printable returns a name with what is not printable escaped. The names
// of hosts and services are what agents send, which may hold control
// characters: written as they are, they could redraw the terminal, or
// start a line of their own in a file of rules.
func printable(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		q := strconv.QuoteRune(r)
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}

// plainName tells whether a name is made of the characters that the names
// of services, units and hosts usually have, none of which means anything
// to the files that the command writes.
func plainName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_.:/@~+-", r):
		default:
			return false
		}
	}
	return true
}

// commentName returns a name as it is written in a comment of a file of
// rules: as it is when it is plain, quoted otherwise, on one line and with
// what is not printable escaped. A name that agents chose can thus neither
// end the comment and start a rule, nor end the line with a backslash,
// which continues it in the files of systemd and nftables.
func commentName(s string) string {
	if plainName(s) {
		return s
	}
	return strconv.Quote(s)
}

// commentNames joins names as commentName writes them.
func commentNames(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = commentName(n)
	}
	return strings.Join(out, ", ")
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// seconds formats a number of seconds as a duration.
func seconds(s float64) string {
	return formatDuration(time.Duration(s * float64(time.Second)))
}

// formatDuration formats a duration in days, hours, minutes and seconds,
// with its two largest units: 90d, 3h28m, 14m, 45s.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	units := []struct {
		name string
		size time.Duration
	}{{"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}}
	var parts []string
	for _, u := range units {
		if n := d / u.size; n > 0 {
			parts = append(parts, strconv.FormatInt(int64(n), 10)+u.name)
			d -= n * u.size
		} else if len(parts) > 0 {
			// The units follow each other: 1d5m is written 1d.
			break
		}
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 0 {
		return "0s"
	}
	return strings.Join(parts, "")
}

// fraction trims a part of the period as PostgreSQL writes a numeric:
// 0.999800 is 0.9998, and 1.000000 is 1.
func fraction(s string) string {
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if s == "" {
		return "0"
	}
	return s
}

// plural formats a count with its noun: "1 gap", "2 gaps". many replaces
// the noun with an s for the counts other than one.
func plural(n int, one string, many ...string) string {
	noun := one + "s"
	if len(many) > 0 {
		noun = many[0]
	}
	if n == 1 {
		noun = one
	}
	return strconv.Itoa(n) + " " + noun
}

// describeShortfall tells a reason or a caveat of a verdict in words. o is
// how the host of the target was observed, nil for a verdict over several
// hosts.
func describeShortfall(code string, o *observation) string {
	if o == nil {
		o = &observation{}
	}
	during := func(s float64) string {
		if s <= 0 {
			return ""
		}
		return " for " + seconds(s) + " of the period"
	}
	switch code {
	case "unknown_host":
		return "no agent ever reported under this name, and the inventory has no such host: check the name"
	case "no_agent":
		return "the host runs no agent: nothing tells what it connects to"
	case "unknown_unit":
		return "no process of the host had this unit in the period: check the name (shawk.unit, as in PostgreSQL)"
	case "unknown_service":
		return "no process had this service in the period: check the name"
	case "not_observed":
		return "not observed by an agent" + during(o.UnobservedSeconds-o.BeforeRetentionSeconds)
	case "before_retention":
		return "the start of the period is before the retention of the connector" + during(o.BeforeRetentionSeconds) +
			": the connections last seen then are deleted"
	case "dropped_flows":
		return "the agent dropped flows" + during(o.PartlyObservedSeconds) + ": connections of that time may be missing"
	case "udp_not_traced":
		return "the agent did not trace UDP" + during(o.UDPUntracedSeconds) + ": connections over UDP, as to a resolver, are missing"
	case "netns_limited":
		return "the agent traced one network namespace only" + during(o.NetnsLimitedSeconds) +
			": the connections of containers are missing"
	}
	return commentName(code)
}
