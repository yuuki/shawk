// Package ledger stores the dependencies observed on a host in SQLite.
//
// An edge is a bundled flow with a resolved process identity. Its activity
// is kept in buckets of three resolutions (minute, hour and day), which are
// updated together at every interval, so that recent activity is detailed
// while the long history stays small.
package ledger

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/yuuki/shawk/internal/api"
)

//go:embed schema.sql
var schema string

// Resolutions of the activity buckets in seconds.
const (
	ResMinute = 60
	ResHour   = 3600
	ResDay    = 86400
)

// Retention configures how long activity buckets and edges are kept.
type Retention struct {
	Minute time.Duration
	Hour   time.Duration
	Day    time.Duration // also the retention of edges and listeners
}

// DefaultRetention keeps minutes for 2 days, hours for 90 days and days
// for 3 years.
var DefaultRetention = Retention{
	Minute: 48 * time.Hour,
	Hour:   90 * 24 * time.Hour,
	Day:    3 * 365 * 24 * time.Hour,
}

// Ledger is a dependency ledger backed by a SQLite database.
type Ledger struct {
	db        *sql.DB
	retention Retention
	mu        sync.Mutex // serializes writers
}

// Open opens or creates a ledger.
func Open(path string, retention Retention) (*Ledger, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return &Ledger{db: db, retention: retention}, nil
}

// Close closes the database.
func (l *Ledger) Close() error { return l.db.Close() }

// Record is a bundled flow to record.
type Record struct {
	Direction  string
	Proto      string
	LocalAddr  string
	RemoteAddr string
	Port       uint16
	NetNS      uint32
	Unit       string
	Comm       string
	Cgroup     string
	Exe        string
	PID        uint32

	Conns     uint64
	ConnFails uint64
	OpenConns uint64
	BytesSent uint64
	BytesRecv uint64
	MsgsSent  uint64
	MsgsRecv  uint64
	Retrans   uint64
	RTTSumUs  uint64
	RTTCount  uint64
}

// ListenerRecord is a listening socket to record.
type ListenerRecord struct {
	Proto  string
	Addr   string
	Port   uint16
	NetNS  uint32
	Unit   string
	Comm   string
	Cgroup string
	Exe    string
	PID    uint32
}

// Write records the flows and listeners observed in the interval ending at
// at.
func (l *Ledger) Write(ctx context.Context, at time.Time, recs []Record, listeners []ListenerRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := at.Unix()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO meta(key, value) VALUES ('ledger_since', ?)`, now); err != nil {
		return err
	}
	upsertEdge, err := tx.PrepareContext(ctx, `
INSERT INTO edges (direction, proto, local_addr, remote_addr, port, netns, unit, comm, cgroup, exe, last_pid, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (direction, proto, local_addr, remote_addr, port, netns, unit, comm) DO UPDATE SET
	cgroup = excluded.cgroup,
	exe = CASE WHEN excluded.exe != '' THEN excluded.exe ELSE edges.exe END,
	last_pid = CASE WHEN excluded.last_pid != 0 THEN excluded.last_pid ELSE edges.last_pid END,
	last_seen = max(edges.last_seen, excluded.last_seen)
RETURNING id`)
	if err != nil {
		return err
	}
	defer upsertEdge.Close()
	upsertActivity, err := tx.PrepareContext(ctx, `
INSERT INTO activity (edge_id, res, ts, conns, conn_fails, max_open_conns, bytes_sent, bytes_recv, msgs_sent, msgs_recv, retrans, rtt_sum_us, rtt_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (edge_id, res, ts) DO UPDATE SET
	conns = conns + excluded.conns,
	conn_fails = conn_fails + excluded.conn_fails,
	max_open_conns = max(max_open_conns, excluded.max_open_conns),
	bytes_sent = bytes_sent + excluded.bytes_sent,
	bytes_recv = bytes_recv + excluded.bytes_recv,
	msgs_sent = msgs_sent + excluded.msgs_sent,
	msgs_recv = msgs_recv + excluded.msgs_recv,
	retrans = retrans + excluded.retrans,
	rtt_sum_us = rtt_sum_us + excluded.rtt_sum_us,
	rtt_count = rtt_count + excluded.rtt_count`)
	if err != nil {
		return err
	}
	defer upsertActivity.Close()

	for i := range recs {
		r := &recs[i]
		var id int64
		err := upsertEdge.QueryRowContext(ctx, r.Direction, r.Proto, r.LocalAddr, r.RemoteAddr, r.Port, r.NetNS,
			r.Unit, r.Comm, r.Cgroup, r.Exe, r.PID, now, now).Scan(&id)
		if err != nil {
			return fmt.Errorf("upserting edge: %w", err)
		}
		for _, res := range []int64{ResMinute, ResHour, ResDay} {
			_, err := upsertActivity.ExecContext(ctx, id, res, now-now%res, r.Conns, r.ConnFails, r.OpenConns,
				r.BytesSent, r.BytesRecv, r.MsgsSent, r.MsgsRecv, r.Retrans, r.RTTSumUs, r.RTTCount)
			if err != nil {
				return fmt.Errorf("upserting activity: %w", err)
			}
		}
	}

	upsertListener, err := tx.PrepareContext(ctx, `
INSERT INTO listeners (proto, addr, port, netns, unit, comm, cgroup, exe, pid, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (proto, addr, port, netns) DO UPDATE SET
	unit = CASE WHEN excluded.comm != '' THEN excluded.unit ELSE listeners.unit END,
	comm = CASE WHEN excluded.comm != '' THEN excluded.comm ELSE listeners.comm END,
	cgroup = CASE WHEN excluded.comm != '' THEN excluded.cgroup ELSE listeners.cgroup END,
	exe = CASE WHEN excluded.exe != '' THEN excluded.exe ELSE listeners.exe END,
	pid = CASE WHEN excluded.pid != 0 THEN excluded.pid ELSE listeners.pid END,
	last_seen = max(listeners.last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer upsertListener.Close()
	for i := range listeners {
		ls := &listeners[i]
		if _, err := upsertListener.ExecContext(ctx, ls.Proto, ls.Addr, ls.Port, ls.NetNS, ls.Unit, ls.Comm,
			ls.Cgroup, ls.Exe, ls.PID, now, now); err != nil {
			return fmt.Errorf("upserting listener: %w", err)
		}
	}
	return tx.Commit()
}

// Prune deletes activity, edges and listeners older than the retention.
func (l *Ledger) Prune(ctx context.Context, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	stmts := []struct {
		q   string
		arg int64
	}{
		{`DELETE FROM activity WHERE res = 60 AND ts < ?`, now.Add(-l.retention.Minute).Unix()},
		{`DELETE FROM activity WHERE res = 3600 AND ts < ?`, now.Add(-l.retention.Hour).Unix()},
		{`DELETE FROM activity WHERE res = 86400 AND ts < ?`, now.Add(-l.retention.Day).Unix()},
		{`DELETE FROM edges WHERE last_seen < ?`, now.Add(-l.retention.Day).Unix()},
		{`DELETE FROM listeners WHERE last_seen < ?`, now.Add(-l.retention.Day).Unix()},
	}
	for _, s := range stmts {
		if _, err := l.db.ExecContext(ctx, s.q, s.arg); err != nil {
			return err
		}
	}
	return nil
}

// Since returns when the ledger started recording, or the zero time if it
// has not recorded anything yet.
func (l *Ledger) Since(ctx context.Context) (time.Time, error) {
	var v sql.NullInt64
	err := l.db.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'ledger_since'`).Scan(&v)
	if err == sql.ErrNoRows || !v.Valid {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(v.Int64, 0), nil
}

// resolution picks the finest bucket resolution still retained for a window
// starting at since.
func (l *Ledger) resolution(now, since time.Time) int64 {
	switch {
	case !since.Before(now.Add(-l.retention.Minute)):
		return ResMinute
	case !since.Before(now.Add(-l.retention.Hour)):
		return ResHour
	}
	return ResDay
}

// Edges returns the edges active in the window of the query with their
// statistics aggregated over the window.
func (l *Ledger) Edges(ctx context.Context, q api.EdgeQuery) ([]api.Edge, error) {
	now := time.Now()
	until := q.Until
	if until.IsZero() {
		until = now
	}
	since := q.Since
	if since.IsZero() {
		since = time.Unix(0, 0)
	}
	res := l.resolution(now, since)

	var (
		where = []string{"e.last_seen >= ?", "e.first_seen <= ?"}
		args  = []any{since.Unix(), until.Unix()}
	)
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if q.Direction != "" {
		add("e.direction = ?", q.Direction)
	}
	if q.Proto != "" {
		add("e.proto = ?", q.Proto)
	}
	if q.LocalAddr != "" {
		add("e.local_addr = ?", q.LocalAddr)
	}
	if q.RemoteAddr != "" {
		add("e.remote_addr = ?", q.RemoteAddr)
	}
	if q.Port != 0 {
		add("e.port = ?", q.Port)
	}
	if q.Unit != "" {
		add("e.unit = ?", q.Unit)
	}
	if q.Comm != "" {
		add("e.comm = ?", q.Comm)
	}
	query := `
SELECT e.direction, e.proto, e.local_addr, e.remote_addr, e.port, e.netns, e.unit, e.comm, e.exe, e.cgroup, e.last_pid,
	e.first_seen, e.last_seen,
	coalesce(sum(a.conns), 0), coalesce(sum(a.conn_fails), 0), coalesce(max(a.max_open_conns), 0),
	coalesce(sum(a.bytes_sent), 0), coalesce(sum(a.bytes_recv), 0), coalesce(sum(a.msgs_sent), 0),
	coalesce(sum(a.msgs_recv), 0), coalesce(sum(a.retrans), 0), coalesce(sum(a.rtt_sum_us), 0), coalesce(sum(a.rtt_count), 0)
FROM edges e
LEFT JOIN activity a ON a.edge_id = e.id AND a.res = ? AND a.ts >= ? AND a.ts <= ?
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY e.id
ORDER BY e.direction, e.port, e.remote_addr, e.unit, e.comm`
	args = append([]any{res, since.Unix() - since.Unix()%res, until.Unix()}, args...)

	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []api.Edge
	for rows.Next() {
		var (
			e                api.Edge
			first, last      int64
			rttSum, rttCount uint64
		)
		if err := rows.Scan(&e.Direction, &e.Proto, &e.LocalAddr, &e.RemoteAddr, &e.Port, &e.NetNS, &e.Unit, &e.Comm,
			&e.Exe, &e.Cgroup, &e.PID, &first, &last,
			&e.Stats.Conns, &e.Stats.ConnFails, &e.Stats.MaxOpenConns, &e.Stats.BytesSent, &e.Stats.BytesRecv,
			&e.Stats.MsgsSent, &e.Stats.MsgsRecv, &e.Stats.Retrans, &rttSum, &rttCount); err != nil {
			return nil, err
		}
		e.FirstSeen = time.Unix(first, 0)
		e.LastSeen = time.Unix(last, 0)
		if rttCount > 0 {
			e.Stats.RTTAvgUs = float64(rttSum) / float64(rttCount)
		}
		edges = append(edges, e)
	}
	return edges, rows.Err()
}

// Listeners returns the listeners seen since the given time.
func (l *Ledger) Listeners(ctx context.Context, since time.Time) ([]api.Listener, error) {
	rows, err := l.db.QueryContext(ctx, `
SELECT proto, addr, port, netns, unit, comm, exe, pid, first_seen, last_seen
FROM listeners WHERE last_seen >= ? ORDER BY proto, port, addr`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []api.Listener
	for rows.Next() {
		var (
			ls          api.Listener
			first, last int64
		)
		if err := rows.Scan(&ls.Proto, &ls.Addr, &ls.Port, &ls.NetNS, &ls.Unit, &ls.Comm, &ls.Exe, &ls.PID, &first, &last); err != nil {
			return nil, err
		}
		ls.FirstSeen = time.Unix(first, 0)
		ls.LastSeen = time.Unix(last, 0)
		out = append(out, ls)
	}
	return out, rows.Err()
}
