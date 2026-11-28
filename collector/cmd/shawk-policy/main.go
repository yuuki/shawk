// Command shawk-policy writes, for a person to review, least-privilege
// network rules of a host or a systemd unit and a baseline of the
// dependencies of services, from what shawk observed, and tells what a
// baseline does not hold. It reads the contract of the PostgreSQL schema
// (shawk_v1.policy_flows, policy_verdict, baseline_observed and the
// others of 0006_policy.sql) and writes nothing to the database, to the
// hosts or to their firewalls: run it as a role that reads shawk_v1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const usage = `shawk-policy writes least-privilege network rules and a baseline of dependencies
for review, from the dependencies and the observation periods that shawk keeps in
PostgreSQL, and tells the dependencies that a baseline does not hold. It applies
nothing: it writes to its standard output only.

Usage:
  shawk-policy rules    -host NAME [-unit NAME] [-format report|nftables|systemd|json] [flags]
  shawk-policy baseline (-service NAME ... | -all) [-merge FILE] [flags]
  shawk-policy drift    [-service NAME ...] [flags]

  rules     the connections of a host, or of a systemd unit of it, over a period,
            as an nftables ruleset or a systemd drop-in that allows them and denies
            the rest
  baseline  the dependencies of services over a period as a baseline file, which
            the connector reads once it is approved (baseline_file)
  drift     the dependencies of the services of the baseline that it does not hold

The rules and the baseline are COMPLETE when the history tells every connection of
the target for the whole period, and INCOMPLETE when it does not (a gap of the
agent, a period that reaches before the retention, dropped flows, UDP not traced,
no agent) or the target is not known. Rules made from an incomplete history deny
what was not seen: they are written only with -allow-incomplete, and say so.

Exit status: 0 COMPLETE, or no drift, and nothing else; 3 DRIFT; 4 INCOMPLETE, or
INCONCLUSIVE for a drift that cannot be told; 1 when the command fails; 2 when the
command line is invalid, or asks for this help.

Run shawk-policy COMMAND -h for the flags of a command.
`

// Exit statuses. They are those of shawk-impact: 0 is the answer that
// lets a script go on, and nothing else.
const (
	exitComplete     = 0
	exitError        = 1 // the command failed
	exitUsage        = 2 // the command line is invalid
	exitDrift        = 3
	exitIncomplete   = 4
	exitInconclusive = 4
)

func main() {
	// An interrupt cancels the query in PostgreSQL too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

var (
	// errUsage is wrapped by the errors of invalid values of flags and
	// arguments.
	errUsage = errors.New("usage error")
	// errFlags is returned for flags that cannot be parsed, which the flag
	// package reports itself.
	errFlags = errors.New("invalid flags")
)

// run runs the command and returns its exit status.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	var err error
	code := exitUsage
	switch args[0] {
	case "rules":
		code, err = runRules(ctx, args[1:], stdout, stderr)
	case "baseline":
		code, err = runBaseline(ctx, args[1:], stdout, stderr)
	case "drift":
		code, err = runDrift(ctx, args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		// The help is no answer: its status is not that of COMPLETE, which
		// a script may test for.
		fmt.Fprint(stderr, usage)
		return exitUsage
	default:
		err = fmt.Errorf("%w: unknown command %q: rules, baseline or drift", errUsage, args[0])
	}
	switch {
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errFlags):
		// The flag package has already printed the usage, with the error
		// if any.
		return exitUsage
	case errors.Is(err, errUsage):
		fmt.Fprintln(stderr, "shawk-policy:", err)
		return exitUsage
	case err != nil:
		fmt.Fprintln(stderr, "shawk-policy:", err)
		return exitError
	}
	return code
}

// common are the flags that the commands share: the database and the
// period.
type common struct {
	dsn, dsnFile string
	timeout      time.Duration
	lookback     time.Duration
	until        time.Time // the clock of the database if zero
	minCoverage  string    // from 0 to 1, as a decimal

	lookbackFlag, untilFlag, coverageFlag *string
}

// flags adds the flags of c to fs. lookback is the default length of the
// period, and coverage tells whether the command takes -min-coverage.
func (c *common) flags(fs *flag.FlagSet, lookback string, coverage bool) {
	c.lookbackFlag = fs.String("lookback", lookback, "how far back the period goes from its end: a number of days (90d) or weeks (12w), or hours and minutes (36h, 1h30m; m is minutes)")
	c.untilFlag = fs.String("until", "", "end of the period, as 2006-01-02T15:04:05Z (default: now, by the clock of the database)")
	if coverage {
		c.coverageFlag = fs.String("min-coverage", "1", "part of the period, from 0 to 1 as in PostgreSQL, that the history must cover to be COMPLETE: 1 is all of it, 0.999 all but 0.1%")
	}
	// The default is not that of the flag, which the usage would print
	// with its password.
	fs.StringVar(&c.dsn, "dsn", "", "PostgreSQL connection string of a role that reads shawk_v1 (default $SHAWK_POSTGRES_DSN)")
	fs.StringVar(&c.dsnFile, "dsn-file", "", "file that holds the connection string")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Minute, "how long the queries may take; also the statement_timeout of their transaction")
}

// parse parses the flags of a command into fs and checks those of c.
// minLookback is the shortest period that the command takes.
func (c *common) parse(fs *flag.FlagSet, args []string, minLookback time.Duration) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %w", errFlags, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	var err error
	if c.timeout <= 0 {
		err = errors.New("-timeout must be positive")
	}
	if err == nil {
		c.lookback, err = parseLookback(*c.lookbackFlag, minLookback)
	}
	if err == nil && *c.untilFlag != "" {
		if c.until, err = time.Parse(time.RFC3339, *c.untilFlag); err != nil {
			err = fmt.Errorf("-until: %w", err)
		}
	}
	if err == nil && c.coverageFlag != nil {
		c.minCoverage, err = parseCoverage(*c.coverageFlag)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	return nil
}

// given returns the flags that the command line set.
func given(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// newFlagSet returns the flags of a command, whose help starts with text.
func newFlagSet(name, text string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("shawk-policy "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, text)
		fs.PrintDefaults()
	}
	return fs
}

// names is a flag that may be given several times.
type names []string

func (n *names) String() string { return strings.Join(*n, ",") }

func (n *names) Set(s string) error {
	*n = append(*n, s)
	return nil
}

// errNeedsPostgres is the answer to a database of the SQLite lightweight
// mode of the connector (docs/design.md §5.8), which keeps the latest
// state that names peers: no dependency of a period, and not when hosts
// were observed. Rules made from it would deny whatever it does not hold.
var errNeedsPostgres = errors.New("shawk-policy needs PostgreSQL: the SQLite lightweight mode of the connector keeps " +
	"neither the dependencies of a period nor when hosts were observed, so nothing in it tells which connections " +
	"to allow (docs/design.md, section 5.8)")

// query connects to PostgreSQL and calls read in one read-only
// transaction, so that what it reads is of the same data. The period of c
// ends at its -until, or `delay` before the clock of the database.
func (c *common) query(ctx context.Context, delay time.Duration, read func(ctx context.Context, tx pgx.Tx, since, until time.Time) error) error {
	dsn := c.dsn
	if dsn == "" {
		dsn = os.Getenv("SHAWK_POSTGRES_DSN")
	}
	if c.dsnFile != "" {
		b, err := os.ReadFile(c.dsnFile)
		if err != nil {
			return err
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		return errors.New("set -dsn, -dsn-file or $SHAWK_POSTGRES_DSN")
	}
	if isSQLite(dsn) {
		return errNeedsPostgres
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// The error may quote the DSN, which may hold a password.
		return errors.New("invalid PostgreSQL connection string")
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["application_name"] = "shawk-policy"
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	// Nothing was written: the end of the transaction changes nothing.
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // see above
	// The time limit of the role (30 seconds for shawk_grafana) is a
	// default for dashboards: a period of months over a large fleet takes
	// longer, and -timeout bounds it instead. It is set in the transaction
	// rather than at the connection, which a pooler may refuse.
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`,
		strconv.FormatInt(c.timeout.Milliseconds(), 10)); err != nil {
		return err
	}
	until := c.until
	if until.IsZero() {
		// The period ends at the clock of the database, which the
		// heartbeats of the agents are compared with: a clock ahead of it
		// would add time that nothing observed yet.
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&until); err != nil {
			return err
		}
		until = until.Add(-delay)
	}
	until = until.UTC()
	err = read(ctx, tx, until.Add(-c.lookback), until)
	// A database without the schema, or with one older than the functions
	// of the policy: nothing to make rules from.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "42883" || pgErr.Code == "3F000" || pgErr.Code == "42P01") {
		return fmt.Errorf("the database lacks the functions of shawk-policy: it needs the PostgreSQL schema of shawk, "+
			"migrated by shawk-migrate up to 0006_policy.sql (the SQLite lightweight mode has none): %s", pgErr.Message)
	}
	return err
}
