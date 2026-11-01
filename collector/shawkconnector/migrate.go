package shawkconnector

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration is a step of the PostgreSQL schema.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Migrations returns the bundled migrations in order.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		name := e.Name()
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("migration %s: no version", name)
		}
		b, err := fs.ReadFile(migrationFS, "migrations/"+name)
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: v, Name: name, SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// migrationLock is the key of the advisory lock that serializes migrations
// run by several connectors.
const migrationLock = 0x73686177 // "shaw"

// Migrate applies the migrations that the database lacks, each in its own
// transaction, and returns the names of those applied.
func Migrate(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	ms, err := Migrations()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock)
	if _, err := conn.Exec(ctx, `
CREATE SCHEMA IF NOT EXISTS shawk;
CREATE TABLE IF NOT EXISTS shawk.schema_migrations (
  version    integer PRIMARY KEY,
  name       text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return nil, err
	}
	var current int
	if err := conn.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM shawk.schema_migrations`).Scan(&current); err != nil {
		return nil, err
	}
	var applied []string
	for _, m := range ms {
		if m.Version <= current {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO shawk.schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.Name, err)
		}
		applied = append(applied, m.Name)
	}
	return applied, nil
}

// SchemaVersion is the version of the schema this connector writes.
func SchemaVersion() int {
	ms, err := Migrations()
	if err != nil || len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].Version
}
