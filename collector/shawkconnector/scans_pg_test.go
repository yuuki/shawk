package shawkconnector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// rowsRead runs a statement in a transaction that it rolls back, and
// returns how many rows of each table it read: by sequential scans of the
// table and from its indexes. The counters of the backend may hold those
// of earlier transactions until it reports them, which it does not do in a
// transaction, so the counts are taken before and after the statement.
func rowsRead(t *testing.T, conn *pgx.Conn, tables []string, sql string, args ...any) []int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	counts := func() []int64 {
		out := make([]int64, len(tables))
		for i, table := range tables {
			if err := tx.QueryRow(ctx, `SELECT (pg_stat_get_xact_tuples_returned($1::regclass)
			  + coalesce((SELECT sum(pg_stat_get_xact_tuples_returned(i.indexrelid)) FROM pg_index i
			              WHERE i.indrelid = $1::regclass), 0))::bigint`, table).Scan(&out[i]); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	before := counts()
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	for rows.Next() {
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	out := counts()
	for i := range out {
		out[i] -= before[i]
	}
	return out
}

// TestPGRecentRowsRead: the queries that run at every write of the
// connector or for every dashboard read the rows of the hosts and of the
// period they need through indexes, not the history of the retention
// (#250).
func TestPGRecentRowsRead(t *testing.T) {
	_, conn := migratedDB(t)
	// 100 hosts whose agents stopped half an hour ago, each with 100
	// sessions and 100 states read from Slurm over the retention before its
	// latest ones, and 30 periods of partial observation, those of h099 the
	// oldest. The times of the hosts differ by minutes.
	execAll(t, conn,
		`INSERT INTO shawk.hosts
		 SELECT 'h' || lpad(i::text, 3, '0'), 'm' || i, 'n' || lpad(i::text, 3, '0'), 'k', 'v', now() - interval '1000 days', now()
		 FROM generate_series(0, 99) i`,
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows, counters_started)
		 SELECT h.id, s.started, s.beat, true, 'all', 5, s.started
		 FROM shawk.hosts h, generate_series(0, 99) j,
		      LATERAL (SELECT now() - make_interval(days => j * 3 + 2, mins => substr(h.id, 2)::int) AS started,
		                      CASE WHEN j = 0 THEN now() - make_interval(mins => 30, secs => substr(h.id, 2)::int)
		                           ELSE now() - make_interval(days => j * 3, mins => substr(h.id, 2)::int) END AS beat) s`,
		`INSERT INTO shawk.node_states (hostname, first_seen, last_seen, state, reason)
		 SELECT h.hostname, now() - make_interval(days => j * 2 + 1, mins => substr(h.id, 2)::int),
		        CASE WHEN j = 0 THEN now() - interval '1 minute'
		             ELSE now() - make_interval(days => j * 2, mins => substr(h.id, 2)::int) END, '{IDLE,POWERED_DOWN}', ''
		 FROM shawk.hosts h, generate_series(0, 99) j`,
		`INSERT INTO shawk.partial_observations (host_id, started_at, period_start, period_end, dropped_flows)
		 SELECT h.id, now() - make_interval(days => j * 3 + 2), now() - make_interval(days => substr(h.id, 2)::int * 30 + j, hours => 1),
		        now() - make_interval(days => substr(h.id, 2)::int * 30 + j), 1
		 FROM shawk.hosts h, generate_series(0, 29) j`,
		`ANALYZE`)
	var started time.Time
	if err := conn.QueryRow(context.Background(), `SELECT max(started_at) FROM shawk.agent_sessions
	  WHERE host_id = 'h099'`).Scan(&started); err != nil {
		t.Fatal(err)
	}
	var hosts, states, reasons []string
	for i := range 100 {
		hosts = append(hosts, fmt.Sprintf("n%03d", i))
		states = append(states, "IDLE+POWERED_DOWN")
		reasons = append(reasons, "")
	}
	for _, c := range []struct {
		name   string
		tables []string
		max    []int64 // of 10000 sessions, 10000 states and 3000 periods
		sql    string
		args   []any
	}{
		{"agents", []string{"shawk.agent_sessions"}, []int64{1000}, `SELECT * FROM shawk_v1.agents`, nil},
		{"unobserved", []string{"shawk.agent_sessions"}, []int64{1000},
			`SELECT * FROM shawk_v1.unobserved(now() - interval '1 hour', now())`, nil},
		{"unobserved_reasons", []string{"shawk.node_states"}, []int64{1000},
			`SELECT * FROM shawk_v1.unobserved_reasons(now() - interval '1 hour', now())`, nil},
		{"node states read again", []string{"shawk.node_states"}, []int64{1000}, continueNodeStatesSQL,
			[]any{hosts, states, reasons, time.Now()}},
		// The sessions of the latest run of h099, and its latest period.
		{"drops of a run", []string{"shawk.agent_sessions", "shawk.partial_observations"}, []int64{20, 100}, sessionDropsSQL,
			[]any{"h099", []time.Time{started}, []time.Time{time.Now()}, []int64{10}, []float64{0}, []*time.Time{&started}}},
	} {
		got := rowsRead(t, conn, c.tables, c.sql, c.args...)
		for i, n := range got {
			if n > c.max[i] {
				t.Errorf("%s read %d rows of %s, want at most %d", c.name, n, c.tables[i], c.max[i])
			}
		}
	}
}
