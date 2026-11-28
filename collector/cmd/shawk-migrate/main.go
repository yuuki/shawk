// Command shawk-migrate applies the PostgreSQL schema of the shawk
// connector. Run it as a role that owns the schemas shawk and shawk_v1
// before starting the collector, or set postgres.migrate in the connector.
//
// A connection string may hold a password: the command never prints it,
// in its usage, its usage errors or its other errors.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yuuki/shawk/collector/shawkconnector"
)

// envDSN is the environment variable of the connection string, used when
// -dsn is not given.
const envDSN = "SHAWK_POSTGRES_DSN"

func main() {
	os.Exit(run(os.Args[0], os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// config is the command line.
type config struct {
	dsn, dsnFile string
	list         bool
	print        string
	timeout      time.Duration
}

// run runs the command and returns its exit status: 0, 1 when it failed,
// or 2 for an invalid command line, as the flag package exits.
func run(name string, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	c, err := parse(name, args, getenv, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if err := migrate(c, stdout); err != nil {
		fmt.Fprintln(stderr, "shawk-migrate:", err)
		return 1
	}
	return 0
}

// parse reads the command line. It writes the usage, and the error of an
// invalid command line, to stderr.
func parse(name string, args []string, getenv func(string) string, stderr io.Writer) (*config, error) {
	var c config
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// The default of -dsn is not $SHAWK_POSTGRES_DSN, which the usage
	// would print with its password.
	fs.StringVar(&c.dsn, "dsn", "", "PostgreSQL connection string (default $"+envDSN+")")
	fs.StringVar(&c.dsnFile, "dsn-file", "", "file that holds the connection string")
	fs.BoolVar(&c.list, "list", false, "print the bundled migrations and exit")
	fs.StringVar(&c.print, "print", "", "print the SQL of a bundled migration, e.g. 0001_schema.sql, and exit")
	fs.DurationVar(&c.timeout, "timeout", time.Minute, "timeout")
	// The flag package would print its errors with the arguments, which
	// may hold a connection string: print them here without it.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	err := fs.Parse(args)
	fs.SetOutput(stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, hideArgs(err.Error(), args))
		}
		fmt.Fprintf(stderr, "Usage of %s:\n", name)
		fs.PrintDefaults()
		return nil, err
	}
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "dsn" })
	if !given {
		c.dsn = getenv(envDSN)
	}
	return &c, nil
}

// hidden replaces the arguments that hideArgs takes out of a message.
const hidden = "(an argument, not shown)"

// hideArgs returns msg without the arguments, and the values of
// -flag=value arguments, that it quotes, unless they are made only of
// letters, digits and the characters -_.+ as names of flags, durations
// and files of migrations are: a connection string never is.
func hideArgs(msg string, args []string) string {
	var parts []string
	for _, a := range args {
		parts = append(parts, a, strings.TrimLeft(a, "-"))
		if _, v, ok := strings.Cut(a, "="); ok {
			parts = append(parts, v)
		}
	}
	// The longest first, so that an argument goes as a whole.
	sort.Slice(parts, func(i, j int) bool { return len(parts[i]) > len(parts[j]) })
	for _, p := range parts {
		if p != "" && !plain(p) {
			msg = strings.ReplaceAll(msg, p, hidden)
		}
	}
	return msg
}

// plain tells whether s is made only of letters, digits and -_.+.
func plain(s string) bool {
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.' || r == '+'
		if !ok {
			return false
		}
	}
	return true
}

func migrate(c *config, stdout io.Writer) error {
	ms, err := shawkconnector.Migrations()
	if err != nil {
		return err
	}
	if c.list {
		for _, m := range ms {
			fmt.Fprintln(stdout, m.Name)
		}
		return nil
	}
	if c.print != "" {
		for _, m := range ms {
			if m.Name == c.print {
				fmt.Fprint(stdout, m.SQL)
				return nil
			}
		}
		return fmt.Errorf("no migration %s", c.print)
	}
	dsn := c.dsn
	if c.dsnFile != "" {
		b, err := os.ReadFile(c.dsnFile) //nolint:gosec // G703: the file that the command line names, read as its user
		if err != nil {
			return err
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		return fmt.Errorf("set -dsn, -dsn-file or $%s", envDSN)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// The error quotes the DSN, and pgx does not hide every form of
		// its password ("password = x", a password with @).
		return errors.New("invalid PostgreSQL connection string")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	applied, err := shawkconnector.Migrate(ctx, conn)
	for _, name := range applied {
		fmt.Fprintln(stdout, "applied", name)
	}
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Fprintln(stdout, "the schema is up to date: version", shawkconnector.SchemaVersion())
	}
	return nil
}
