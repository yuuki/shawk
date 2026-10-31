// Command shawk-migrate applies the PostgreSQL schema of the shawk
// connector. Run it as a role that owns the schemas shawk and shawk_v1
// before starting the collector, or set postgres.migrate in the connector.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yuuki/shawk/collector/shawkconnector"
)

func main() {
	var (
		dsn     = flag.String("dsn", os.Getenv("SHAWK_POSTGRES_DSN"), "PostgreSQL connection string (default $SHAWK_POSTGRES_DSN)")
		dsnFile = flag.String("dsn-file", "", "file that holds the connection string")
		list    = flag.Bool("list", false, "print the bundled migrations and exit")
		print   = flag.String("print", "", "print the SQL of a bundled migration, e.g. 0001_init.sql, and exit")
		timeout = flag.Duration("timeout", time.Minute, "timeout")
	)
	flag.Parse()
	if err := run(*dsn, *dsnFile, *list, *print, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "shawk-migrate:", err)
		os.Exit(1)
	}
}

func run(dsn, dsnFile string, list bool, print string, timeout time.Duration) error {
	ms, err := shawkconnector.Migrations()
	if err != nil {
		return err
	}
	if list {
		for _, m := range ms {
			fmt.Println(m.Name)
		}
		return nil
	}
	if print != "" {
		for _, m := range ms {
			if m.Name == print {
				fmt.Print(m.SQL)
				return nil
			}
		}
		return fmt.Errorf("no migration %s", print)
	}
	if dsnFile != "" {
		b, err := os.ReadFile(dsnFile)
		if err != nil {
			return err
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		return fmt.Errorf("set -dsn, -dsn-file or $SHAWK_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	applied, err := shawkconnector.Migrate(ctx, conn)
	for _, name := range applied {
		fmt.Println("applied", name)
	}
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("the schema is up to date: version", shawkconnector.SchemaVersion())
	}
	return nil
}
