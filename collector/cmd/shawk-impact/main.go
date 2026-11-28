// Command shawk-impact tells what removing a host, or a service of it,
// would break, from what shawk observed: its dependents and how often they
// use it, how much of the period it was watched, and a verdict. It reads
// the contract of the PostgreSQL schema (shawk_v1.impact_verdict, impact
// and coverage) and writes nothing: run it as a role that reads shawk_v1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

const usage = `shawk-impact tells what removing a host, or a service of it, would break, from
the dependencies and the observation periods that shawk keeps in PostgreSQL.

Usage:
  shawk-impact -host NAME [-service NAME] [-port PORT] [-proto tcp|udp|unix] [flags]

The verdict is SAFE when nothing used the target in the period and the history
tells so for the whole period, UNSAFE when it has dependents, and INCONCLUSIVE
when nothing was seen but the target was not watched enough, or is not known:
a host, a service or a port that no agent reported.

Exit status: 0 SAFE, and nothing else; 3 UNSAFE; 4 INCONCLUSIVE; 1 when the
command fails, also after it printed a verdict; 2 when the command line is
invalid, or asks for this help.

Flags:
`

// Exit statuses.
const (
	exitSafe         = 0
	exitError        = 1 // the command failed
	exitUsage        = 2 // the command line is invalid
	exitUnsafe       = 3
	exitInconclusive = 4
)

func main() {
	// An interrupt cancels the query in PostgreSQL too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// config is the command line.
type config struct {
	options
	dsn, dsnFile string
	asJSON       bool
	limit        int
}

var (
	// errUsage is wrapped by the errors of invalid values of flags and
	// arguments.
	errUsage = errors.New("usage error")
	// errFlags is returned for flags that cannot be parsed, which the flag
	// package reports itself.
	errFlags = errors.New("invalid flags")
)

// parse reads the command line.
func parse(args []string, stderr io.Writer) (*config, error) {
	fs := flag.NewFlagSet("shawk-impact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	var (
		c        config
		lookback = fs.String("lookback", "90d", "how far back the period goes from its end, an hour at least: a number of days (90d) or weeks (12w), or hours and minutes (36h, 1h30m; m is minutes)")
		until    = fs.String("until", "", "end of the period, as 2006-01-02T15:04:05Z (default: now, by the clock of the database)")
		coverage = fs.String("min-coverage", "1", "part of the period, from 0 to 1 as in PostgreSQL, that the history must cover for a verdict of SAFE: 1 is all of it, 0.999 all but 0.1%")
	)
	fs.StringVar(&c.target.Host, "host", "", "host to remove, by the host.name of its agent or its name in the inventory")
	fs.StringVar(&c.target.Service, "service", "", "service of the host to remove alone, as in PostgreSQL ([namespace/]name); without it, the whole host")
	fs.IntVar(&c.target.Port, "port", 0, "port of the host to remove alone, from 1 to 65535")
	fs.StringVar(&c.target.Proto, "proto", "", "transport to look at alone: tcp, udp, or unix with -service")
	fs.IntVar(&c.depth, "depth", 3, "how far the dependents of dependents are followed, from 1 (the clients of the target only) to 10")
	fs.IntVar(&c.cadenceDepth, "cadence-depth", 1, "depth up to which the cadence of the dependents is read, from 0 to 10: it takes a fraction of a millisecond per dependent")
	// The default is not that of the flag, which the usage would print
	// with its password.
	fs.StringVar(&c.dsn, "dsn", "", "PostgreSQL connection string of a role that reads shawk_v1 (default $SHAWK_POSTGRES_DSN)")
	fs.StringVar(&c.dsnFile, "dsn-file", "", "file that holds the connection string")
	fs.BoolVar(&c.asJSON, "json", false, "write the report as JSON")
	fs.IntVar(&c.limit, "limit", 50, "dependents to list in the text report; 0 for all")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Minute, "how long the queries may take; also the statement_timeout of their transaction")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", errFlags, err)
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	// A flag given with no value, as by a script whose variable is empty,
	// would widen the target to the whole host without a word.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var err error
	switch {
	case c.target.Host == "":
		err = errors.New("-host is required")
	case given["service"] && c.target.Service == "":
		err = errors.New("-service must not be empty: leave it out for the whole host")
	case given["port"] && (c.target.Port < 1 || c.target.Port > 65535):
		err = errors.New("-port must be from 1 to 65535: leave it out for every port")
	case given["proto"] && c.target.Proto != "tcp" && c.target.Proto != "udp" && c.target.Proto != "unix":
		err = errors.New("-proto must be tcp, udp or unix")
	case c.target.Proto == "unix" && c.target.Port != 0:
		err = errors.New("a Unix socket has no port: -proto unix cannot be used with -port")
	case c.target.Proto == "unix" && c.target.Service == "":
		err = errors.New("the clients of a Unix socket are on its host: -proto unix needs -service")
	case c.depth < 1 || c.depth > 10:
		err = errors.New("-depth must be from 1 to 10")
	case c.cadenceDepth < 0 || c.cadenceDepth > 10:
		err = errors.New("-cadence-depth must be from 0 to 10")
	case c.limit < 0:
		err = errors.New("-limit must not be negative")
	case c.timeout <= 0:
		err = errors.New("-timeout must be positive")
	}
	if err == nil {
		c.lookback, err = parseLookback(*lookback)
	}
	if err == nil && *until != "" {
		if c.until, err = time.Parse(time.RFC3339, *until); err != nil {
			err = fmt.Errorf("-until: %w", err)
		}
	}
	if err == nil {
		c.minCoverage, err = parseCoverage(*coverage)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	return &c, nil
}

// maxLookback bounds the period: the retention of the connector is 3 years
// by default, and a period far longer than what is kept only reads as not
// observed. minLookback is the least that tells anything, an hour of
// activity being what is recorded: a shorter period is a mistake, as 3m
// meant as 3 months, and would be SAFE for a host used the hour before.
const (
	maxLookback = 100 * 365 * 24 * time.Hour
	minLookback = time.Hour
)

// parseLookback parses the length of a period: a duration of Go, or a
// number of days (d) or weeks (w).
func parseLookback(s string) (time.Duration, error) {
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
	if d < minLookback || d > maxLookback {
		return 0, fmt.Errorf("-lookback must be from an hour to 100 years (m is minutes, not months): %q", s)
	}
	return d.Truncate(time.Second), nil
}

// parseCoverage parses a part of the period, above 0 and up to 1, and
// returns it as a decimal: what impact_verdict takes as min_coverage,
// without the rounding of a float. The unit is that of PostgreSQL and of
// the report, so that no value means two things: a percentage, 99.9, is
// refused rather than taken for more than the whole period.
func parseCoverage(s string) (string, error) {
	p, ok := new(big.Rat).SetString(s)
	// A trillionth is the least that 12 decimals tell from 0.
	if !ok || strings.ContainsAny(s, "/eE") || p.Cmp(big.NewRat(1, 1e12)) < 0 || p.Cmp(big.NewRat(1, 1)) > 0 {
		return "", fmt.Errorf("-min-coverage must be a part of the period above 0, up to 1 (0.999 for 99.9%%): %q", s)
	}
	return p.FloatString(12), nil
}

// run runs the command and returns its exit status.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c, err := parse(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errFlags):
		// The flag package has already printed the usage, with the error
		// if any. The help is no verdict: its status is not that of SAFE,
		// which a script may test for.
		return exitUsage
	case err != nil:
		fmt.Fprintln(stderr, "shawk-impact:", err)
		return exitUsage
	}
	r, err := query(ctx, c)
	return finish(r, err, c, stdout, stderr)
}

// finish writes the report that query returned and returns the exit
// status. A report that an error cut short is written with its verdict,
// which was read first, and the command fails all the same.
func finish(r *report, err error, c *config, stdout, stderr io.Writer) int {
	if r == nil {
		fmt.Fprintln(stderr, "shawk-impact:", err)
		return exitError
	}
	if err != nil {
		r.Incomplete = err.Error()
	}
	var werr error
	if c.asJSON {
		werr = writeJSON(stdout, r)
	} else {
		werr = writeText(stdout, r, c.limit)
	}
	if werr != nil {
		fmt.Fprintln(stderr, "shawk-impact:", werr)
		return exitError
	}
	if err != nil {
		fmt.Fprintln(stderr, "shawk-impact:", err)
		return exitError
	}
	return exitStatus(r.Verdict, stderr)
}

// exitStatus is the exit status of a verdict.
func exitStatus(verdict string, stderr io.Writer) int {
	switch verdict {
	case verdictSafe:
		return exitSafe
	case verdictUnsafe:
		return exitUnsafe
	case verdictInconclusive:
		return exitInconclusive
	}
	// A verdict of a schema newer than this command: not SAFE.
	fmt.Fprintf(stderr, "shawk-impact: unknown verdict %q\n", verdict)
	return exitError
}

// errNeedsPostgres is the answer to a database of the SQLite lightweight
// mode of the connector (docs/design.md §5.8), which keeps the latest
// state that names peers: no dependency of a period, no hour of activity,
// and not when hosts were observed. Nothing in it tells that a host was
// not used, so there is no verdict to give from it, not even a partial
// one.
var errNeedsPostgres = errors.New("the impact report needs PostgreSQL: the SQLite lightweight mode of the connector keeps " +
	"neither the dependencies of a period nor when hosts were observed, so nothing in it tells that a host is unused " +
	"(docs/design.md, section 5.8)")

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

// query connects to PostgreSQL and reads the report. It returns the report
// with an error when the verdict was read and what follows it failed.
func query(ctx context.Context, c *config) (*report, error) {
	dsn := c.dsn
	if dsn == "" {
		dsn = os.Getenv("SHAWK_POSTGRES_DSN")
	}
	if c.dsnFile != "" {
		b, err := os.ReadFile(c.dsnFile) //nolint:gosec // G703: the file that the command line names, read as its user
		if err != nil {
			return nil, err
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		return nil, errors.New("set -dsn, -dsn-file or $SHAWK_POSTGRES_DSN")
	}
	if isSQLite(dsn) {
		return nil, errNeedsPostgres
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// The error may quote the DSN, which may hold a password.
		return nil, errors.New("invalid PostgreSQL connection string")
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["application_name"] = "shawk-impact"
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return build(ctx, conn, c.options)
}
