package shawkconnector

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// pgNodeStore returns a store on a migrated database.
func pgNodeStore(t *testing.T) (store, func(sql string, args ...any) []string) {
	t.Helper()
	dsn, conn := migratedDB(t)
	st, err := newPGStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.close)
	return st, func(sql string, args ...any) []string { return queryStrings(t, conn, sql, args...) }
}

// TestPGNodeStates: a state read again within the maximum age continues its
// period; another state, or the same one after a gap, starts a new one; a
// reading no later than the latest changes nothing.
func TestPGNodeStates(t *testing.T) {
	st, query := pgNodeStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }
	idle := nodeState{host: "cn001", state: []string{"IDLE"}}
	off := nodeState{host: "cn001", state: []string{"IDLE", "POWERED_DOWN"}}
	for _, w := range []struct {
		m     int
		nodes []nodeState
	}{
		{0, []nodeState{idle}},
		{1, []nodeState{idle}},
		{2, []nodeState{off}},
		{1, []nodeState{idle}}, // older
		{2, []nodeState{idle}}, // the same reading
		{3, []nodeState{off}},
		{20, []nodeState{off}}, // after a gap
		{21, []nodeState{{host: "cn001", state: []string{"IDLE", "POWERED_DOWN"}, reason: "x"}}},
	} {
		if err := st.writeNodeStates(ctx, at(w.m), w.nodes); err != nil {
			t.Fatal(err)
		}
	}
	got := query(`SELECT extract(epoch FROM first_seen - $1)::int / 60, extract(epoch FROM last_seen - $1)::int / 60,
	                     array_to_string(state, '+'), reason
	              FROM shawk.node_states`, base)
	want := []string{"0 1 IDLE ", "2 3 IDLE+POWERED_DOWN ", "20 20 IDLE+POWERED_DOWN ", "21 21 IDLE+POWERED_DOWN x"}
	if !slices.Equal(got, want) {
		t.Errorf("node_states = %v, want %v", got, want)
	}
}

// TestPGMaintenance: windows count from when they were registered, are
// deleted before they start or cut while in progress when removed, and are
// kept as they were once they ended.
func TestPGMaintenance(t *testing.T) {
	st, query := pgNodeStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	h := time.Hour
	ws := []maintenanceWindow{
		{host: "past", start: now.Add(-3 * h), end: now.Add(-2 * h)},        // registered after its end
		{host: "late", start: now.Add(-h), end: now.Add(h), reason: "late"}, // registered after its start
		{host: "future", start: now.Add(h), end: now.Add(2 * h)},
		{host: "kept", start: now.Add(2 * h), end: now.Add(3 * h), reason: "a"},
	}
	if err := st.syncMaintenance(ctx, ws); err != nil {
		t.Fatal(err)
	}
	got := query(`SELECT hostname, reason FROM shawk.maintenance_windows`)
	if !slices.Equal(got, []string{"future ", "kept a", "late late"}) {
		t.Errorf("windows = %v", got)
	}
	got = query(`SELECT hostname, lower(period) > now() - interval '1 minute' FROM shawk.maintenance_periods`)
	if !slices.Equal(got, []string{"future true", "kept true", "late true"}) {
		t.Errorf("periods = %v", got)
	}
	// late counts from when it was registered.
	if got := query(`SELECT hostname FROM shawk.maintenance_periods WHERE lower(period) < now() - interval '1 minute'`); len(got) != 0 {
		t.Errorf("periods from before they were registered: %v", got)
	}
	// late (in progress) and future are removed, kept changes.
	if err := st.syncMaintenance(ctx, []maintenanceWindow{
		{host: "kept", start: now.Add(2 * h), end: now.Add(4 * h), reason: "b"},
	}); err != nil {
		t.Fatal(err)
	}
	got = query(`SELECT hostname, ends_at <= now(), reason FROM shawk.maintenance_windows`)
	if !slices.Equal(got, []string{"kept false b", "late true late"}) {
		t.Errorf("after removal = %v", got)
	}
	// Registered again after it ended, late keeps the row that ended and
	// gets a new one from now: the time in between is not planned.
	if err := st.syncMaintenance(ctx, []maintenanceWindow{
		{host: "late", start: now.Add(-h), end: now.Add(5 * h), reason: "again"},
	}); err != nil {
		t.Fatal(err)
	}
	got = query(`SELECT hostname, ends_at <= now(), reason FROM shawk.maintenance_windows`)
	if !slices.Equal(got, []string{"late false again", "late true late"}) {
		t.Errorf("registered again = %v", got)
	}
	if got := query(`SELECT count(*) FROM shawk.maintenance_periods WHERE hostname = 'late' AND period @> now()`); !slices.Equal(got, []string{"1"}) {
		t.Errorf("periods of late in progress = %v", got)
	}
	// A window in progress whose end is moved to the past ends now (and
	// late, no longer registered, too).
	early := maintenanceWindow{host: "early", start: now.Add(-h), end: now.Add(h)}
	if err := st.syncMaintenance(ctx, []maintenanceWindow{early}); err != nil {
		t.Fatal(err)
	}
	early.end = now.Add(-h / 2)
	if err := st.syncMaintenance(ctx, []maintenanceWindow{early}); err != nil {
		t.Fatal(err)
	}
	got = query(`SELECT hostname, ends_at <= now() FROM shawk.maintenance_windows`)
	if !slices.Equal(got, []string{"early true", "late true", "late true"}) {
		t.Errorf("ended early = %v", got)
	}
}

// TestPGUnobservedReasons: the gaps of unobserved() are cut by the windows
// and the states of their time; DOWN, DRAIN and stale states are not
// planned.
func TestPGUnobservedReasons(t *testing.T) {
	_, conn := migratedDB(t)
	// cn001 was observed until 10 hours ago and from 1 hour ago. Its states
	// over the gap (hours ago, by first and last read): powered down from
	// 9.5 to 8, then nothing read until 7, DOWN with a flag of power saving
	// from 7 to 6, DRAIN and powered down from 6 to 5, powered down again
	// from 5 to 1. A maintenance window from 4 to 3 takes precedence.
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h1','m','cn001','k','v',now()-interval '1 day',now())`,
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope) VALUES
		   ('h1', now()-interval '20 hours', now()-interval '10 hours', true, 'all'),
		   ('h1', now()-interval '1 hour', now(), true, 'all')`,
		`INSERT INTO shawk.node_states (hostname, first_seen, last_seen, state, reason) VALUES
		   ('cn001', now()-interval '570 minutes', now()-interval '8 hours', '{IDLE,POWERED_DOWN}', ''),
		   ('cn001', now()-interval '7 hours', now()-interval '6 hours' - shawk.node_state_max_age(), '{DOWN,POWERED_DOWN}', 'ResumeTimeout'),
		   ('cn001', now()-interval '6 hours', now()-interval '5 hours' - shawk.node_state_max_age(), '{DRAIN,IDLE,POWERED_DOWN}', 'disk'),
		   ('cn001', now()-interval '5 hours', now()-interval '1 hour', '{IDLE,POWERING_DOWN}', '')`,
		`INSERT INTO shawk.maintenance_windows VALUES
		   ('cn001', now()-interval '4 hours', now()-interval '3 hours', 'firmware', now()-interval '1 day')`)
	got := queryStrings(t, conn, `
SELECT round(extract(epoch FROM now() - gap_start) / 60)::int, round(extract(epoch FROM now() - gap_end) / 60)::int,
       coalesce(cause, '-'), coalesce(node_state, '-'), coalesce(reason, '-')
FROM shawk_v1.unobserved_reasons(now() - interval '12 hours', now(), '0')`)
	want := []string{
		"600 570 - - -",
		"570 475 power_saving IDLE+POWERED_DOWN -", // until 5 minutes after the last read
		"475 420 - - -",
		"420 360 - DOWN+POWERED_DOWN ResumeTimeout",
		"360 300 - DRAIN+IDLE+POWERED_DOWN disk",
		"300 240 power_saving IDLE+POWERING_DOWN -",
		"240 180 maintenance - firmware",
		"180 60 power_saving IDLE+POWERING_DOWN -",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("unobserved_reasons =\n%v\nwant\n%v", got, want)
	}
	// unobserved() is unchanged: one gap.
	if got := queryStrings(t, conn, `SELECT host FROM shawk_v1.unobserved(now() - interval '12 hours', now(), '0')`); len(got) != 1 {
		t.Errorf("unobserved = %v", got)
	}
}

// TestPGPlannedStops: hosts in a planned stop now, by the latest state if it
// is fresh and planned (powering up too, but not once up), or a window in
// progress; MAINT for 30 days since it started, whatever the other flags
// (longmaint); and the silent agent alert does not name them.
func TestPGPlannedStops(t *testing.T) {
	_, conn := migratedDB(t)
	hosts := []string{"off", "stale", "down", "resuming", "booted", "maint", "maintflag", "longmaint", "remaint", "nothing"}
	for _, h := range hosts {
		execAll(t, conn,
			fmt.Sprintf(`INSERT INTO shawk.hosts VALUES ('%[1]s','m','%[1]s','k','v',now()-interval '30 days',now()-interval '2 days')`, h),
			fmt.Sprintf(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope)
			             VALUES ('%[1]s', now()-interval '30 days', now()-interval '2 days', true, 'all')`, h))
	}
	execAll(t, conn,
		`INSERT INTO shawk.node_states (hostname, first_seen, last_seen, state) VALUES
		   ('off', now()-interval '2 days', now()-interval '1 minute', '{IDLE,POWERED_DOWN}'),
		   ('stale', now()-interval '2 days', now()-interval '10 minutes', '{IDLE,POWERED_DOWN}'),
		   ('down', now()-interval '2 days', now()-interval '1 minute', '{DOWN,POWERED_DOWN}'),
		   ('resuming', now()-interval '2 days', now()-interval '3 minutes', '{IDLE,POWERED_DOWN}'),
		   ('resuming', now()-interval '2 minutes', now()-interval '1 minute', '{ALLOCATED,POWERING_UP}'),
		   ('booted', now()-interval '2 days', now()-interval '10 minutes', '{IDLE,POWERING_UP}'),
		   ('booted', now()-interval '9 minutes', now()-interval '1 minute', '{IDLE}'),
		   ('maintflag', now()-interval '1 hour', now(), '{DOWN,MAINT}'),
		   ('longmaint', now()-interval '40 days', now()-interval '20 days', '{IDLE,MAINT}'),
		   ('longmaint', now()-interval '20 days', now()-interval '1 minute', '{DOWN,MAINT}'),
		   ('remaint', now()-interval '40 days', now()-interval '10 days', '{IDLE}'),
		   ('remaint', now()-interval '10 days', now()-interval '1 minute', '{IDLE,MAINT}')`,
		`INSERT INTO shawk.maintenance_windows VALUES
		   ('maint', now()-interval '1 hour', now()+interval '1 hour', 'firmware', now()-interval '2 hours'),
		   ('nothing', now()-interval '3 hours', now()-interval '1 hour', '', now()-interval '4 hours')`)
	got := queryStrings(t, conn, `SELECT host, cause FROM shawk_v1.planned_stops`)
	if !slices.Equal(got, []string{"maint maintenance", "maintflag maintenance", "off power_saving", "remaint maintenance",
		"resuming power_saving"}) {
		t.Errorf("planned_stops = %v", got)
	}
	q := packagedSQL(t)["shawk-rules.yaml/shawk-agents/shawk agent silent/A/A#0"]
	rows, err := conn.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var silent []string
	for rows.Next() {
		vals, _ := rows.Values()
		silent = append(silent, fmt.Sprint(vals[1]))
	}
	rows.Close()
	slices.Sort(silent)
	if !slices.Equal(silent, []string{"booted", "down", "longmaint", "nothing", "stale"}) {
		t.Errorf("silent agents = %v", silent)
	}
}

// TestPGPruneNodeStates: states and windows older than the retention are
// deleted with the rest.
func TestPGPruneNodeStates(t *testing.T) {
	st, query := pgNodeStore(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	if err := st.writeNodeStates(ctx, old, []nodeState{{host: "cn001", state: []string{"IDLE"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.writeNodeStates(ctx, time.Now(), []nodeState{{host: "cn001", state: []string{"IDLE", "POWERED_DOWN"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.prune(ctx, 24*time.Hour, 100); err != nil {
		t.Fatal(err)
	}
	if got := query(`SELECT array_to_string(state, '+') FROM shawk.node_states`); !slices.Equal(got, []string{"IDLE+POWERED_DOWN"}) {
		t.Errorf("after prune = %v", got)
	}
}
