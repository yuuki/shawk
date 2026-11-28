// Command shawk-migrate applies the PostgreSQL schema of the shawk
// connector. Run it as a role that owns the schemas shawk and shawk_v1
// before starting the collector, or set postgres.migrate in the connector.
//
// A connection string may hold a password: the command prints no text that
// holds a value of the command line or of the environment, in its usage,
// its usage errors or its other errors.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	// The default of -dsn is not $SHAWK_POSTGRES_DSN, which the usage
	// would print with its password.
	flags.StringVar(&c.dsn, "dsn", "", "PostgreSQL connection string (default $"+envDSN+")")
	flags.StringVar(&c.dsnFile, "dsn-file", "", "file that holds the connection string")
	flags.BoolVar(&c.list, "list", false, "print the bundled migrations and exit")
	flags.StringVar(&c.print, "print", "", "print the SQL of a bundled migration, e.g. 0001_schema.sql, and exit")
	flags.DurationVar(&c.timeout, "timeout", time.Minute, "timeout")
	// The flag package would print its errors with the arguments, which
	// may hold a connection string: the command prints its own.
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	err := flags.Parse(args)
	flags.SetOutput(stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, usageError(flags, err))
		}
		fmt.Fprintf(stderr, "Usage of %s:\n", name)
		flags.PrintDefaults()
		return nil, err
	}
	given := false
	flags.Visit(func(f *flag.Flag) { given = given || f.Name == "dsn" })
	if !given {
		c.dsn = getenv(envDSN)
	}
	return &c, nil
}

// usageError returns the message of an error of flags.Parse. The message is
// made of constants and of the name of a flag that flags defines, never of
// text from the error, which quotes the arguments: an argument may be a
// connection string, which escaping or quoting does not hide.
func usageError(flags *flag.FlagSet, err error) string {
	msg := err.Error()
	// The formats of the flag package, in flag.go of Go 1.27; an error of
	// another form gives the general message.
	switch {
	case strings.HasPrefix(msg, "bad flag syntax: "):
		return "bad flag syntax (the argument is not shown)"
	case strings.HasPrefix(msg, "flag provided but not defined: "):
		return "flag provided but not defined (the argument is not shown)"
	case strings.HasPrefix(msg, "flag needs an argument: -"):
		if n := flagName(flags, strings.TrimPrefix(msg, "flag needs an argument: -"), ""); n != "" {
			return "flag needs an argument: -" + n
		}
	case strings.HasPrefix(msg, "invalid boolean flag "):
		if n := flagName(flags, strings.TrimPrefix(msg, "invalid boolean flag "), ": "); n != "" {
			return "invalid value for flag -" + n + " (the value is not shown)"
		}
	case strings.HasPrefix(msg, "invalid value "), strings.HasPrefix(msg, "invalid boolean value "):
		// invalid value %q for flag -%s: %v
		// invalid boolean value %q for -%s: %v
		rest := strings.TrimPrefix(strings.TrimPrefix(msg, "invalid value "), "invalid boolean value ")
		if q, qerr := strconv.QuotedPrefix(rest); qerr == nil {
			rest = strings.TrimPrefix(rest[len(q):], " for ")
			rest = strings.TrimPrefix(rest, "flag ")
			if n := flagName(flags, strings.TrimPrefix(rest, "-"), ": "); n != "" {
				return "invalid value for flag -" + n + " (the value is not shown)"
			}
		}
	}
	return "invalid command line (the arguments are not shown)"
}

// flagName returns the name of the flag of flags that s holds, followed by
// end (or alone if end is empty), or "" if none does.
func flagName(flags *flag.FlagSet, s, end string) string {
	name := ""
	flags.VisitAll(func(f *flag.Flag) {
		if end == "" && s == f.Name || end != "" && strings.HasPrefix(s, f.Name+end) {
			name = f.Name
		}
	})
	return name
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
		// Not the name, which may be anything given on the command line.
		return errors.New("no bundled migration of the name of -print; -list prints them")
	}
	dsn := c.dsn
	if c.dsnFile != "" {
		b, err := os.ReadFile(c.dsnFile) //nolint:gosec // G703: the file that the command line names, read as its user
		if err != nil {
			// Not the path, which may be a connection string given by
			// mistake.
			var pe *fs.PathError
			if errors.As(err, &pe) {
				return fmt.Errorf("reading -dsn-file: %w", pe.Err)
			}
			return errors.New("reading -dsn-file failed")
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
		return connectError(err)
	}
	defer conn.Close(ctx)
	// The errors of the migrations are those of the server and of the
	// connector. They may name the role and the database, which are then
	// those of an existing database that accepted the connection, never a
	// password, which the server does not quote.
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

// connectError returns the message of a failed connection. The error of
// pgconn quotes the user, the database and the hosts of the connection
// string, and the server quotes the user and the database: a malformed
// connection string can put its password there (postgres://u:12/pw@h/d
// is the host u, port 12 and database pw@h/d). The message is made of
// constants, and of the code of an error of the server.
func connectError(err error) error {
	const prefix = "cannot connect to PostgreSQL (the connection string is not shown): "
	var pgErr *pgconn.PgError
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &pgErr):
		code := pgErr.Code
		if len(code) != 5 || strings.Trim(code, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			code = "?????"
		}
		switch code {
		case "28P01", "28000":
			return errors.New(prefix + "authentication failed (SQLSTATE " + code + ")")
		case "3D000":
			return errors.New(prefix + "the database does not exist (SQLSTATE " + code + ")")
		default:
			return errors.New(prefix + "the server refused the connection (SQLSTATE " + code + ")")
		}
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New(prefix + "timed out (-timeout)")
	case errors.Is(err, syscall.ECONNREFUSED):
		return errors.New(prefix + "connection refused")
	case errors.As(err, &dnsErr):
		return errors.New(prefix + "the host is not found")
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return errors.New(prefix + "the certificate of the server is not verified")
	}
	return errors.New(prefix + "the connection failed")
}
