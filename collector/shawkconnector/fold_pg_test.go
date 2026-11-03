package shawkconnector

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
)

// PostgreSQL tests of folded peers and partly observed periods (#96).

// TestPGFoldedEdges: the edges of folded peers are written as the networks
// 0.0.0.0/0 and ::/0, match no edge of another host, and the contract
// names them ~external like the connector.
func TestPGFoldedEdges(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	web := tAgent{host: "web-01", machineID: "m-web", addrs: []string{"203.0.113.10", "2001:db8::10"}, time: now,
		segment: now.Add(-time.Hour), fold: foldAll, internal: []string{"10.0.0.0/8"},
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 443, svc: "nginx", comm: "nginx"}},
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "203.0.113.10", peer: "0.0.0.0", folded: true, port: 443, svc: "nginx", comm: "nginx", opened: 100},
			{role: "server", proto: "tcp", local: "2001:db8::10", peer: "::", folded: true, port: 443, svc: "nginx", comm: "nginx", opened: 10},
			{role: "client", proto: "tcp", local: "203.0.113.10", peer: "0.0.0.0", folded: true, port: 443, svc: "nginx", comm: "nginx", opened: 3},
		}}
	// A client with an agent at a public address outside the internal
	// ranges of web-01: web-01 folds it.
	app := tAgent{host: "app-01", machineID: "m-app", addrs: []string{"198.51.100.7"}, time: now, segment: now.Add(-time.Hour),
		edges: []tEdge{{role: "client", proto: "tcp", local: "198.51.100.7", peer: "203.0.113.10", port: 443, svc: "app", comm: "app", opened: 1}}}
	consume(t, c, sink, web)
	consume(t, c, sink, app)
	c.flush(ctx)

	got := queryStrings(t, conn, `SELECT role, remote_addr::text, family(remote_addr), masklen(remote_addr) FROM shawk.edges e
	  JOIN shawk.hosts h ON h.id = e.host_id WHERE h.hostname = 'web-01'`)
	if want := []string{"client 0.0.0.0/0 4 0", "server 0.0.0.0/0 4 0", "server ::/0 6 0"}; !slices.Equal(got, want) {
		t.Errorf("edges = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `SELECT coalesce(client_host, '-'), client_addr::text, coalesce(server_host, '-'),
	  server_addr::text, port, observed_by FROM shawk_v1.dependencies`)
	want := []string{
		"- 0.0.0.0/0 web-01 203.0.113.10/32 443 server",
		"- ::/0 web-01 2001:db8::10/128 443 server",
		"app-01 198.51.100.7/32 - 203.0.113.10/32 443 client",
		"web-01 203.0.113.10/32 - 0.0.0.0/0 443 client",
	}
	if !slices.Equal(got, want) {
		t.Errorf("dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The client with an agent and the server that folds it are not
	// matched: each names the other ~external.
	wantSvc := []string{"app ~external 443", "nginx ~external 443", "~external nginx 443"}
	for _, q := range []string{
		`SELECT client_service, server_service, port FROM shawk.service_dependencies`,
		`SELECT client_service, server_service, port FROM shawk.service_dependencies_between(now() - interval '1 hour', now())`,
	} {
		if got := queryStrings(t, conn, q); !slices.Equal(got, wantSvc) {
			t.Errorf("%s = %q, want %q", q, got, wantSvc)
		}
	}
	if got := queryStrings(t, conn, `SELECT source, target FROM shawk_v1.graph_edges_between(now() - interval '1 hour', now())`); !slices.Equal(got,
		[]string{"app ~external", "nginx ~external", "~external nginx"}) {
		t.Errorf("graph_edges_between = %q", got)
	}
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	if got := queryStrings(t, conn, `SELECT client_service, server_service, port FROM shawk.known_dependencies`); !slices.Equal(got, wantSvc) {
		t.Errorf("known_dependencies = %q, want %q", got, wantSvc)
	}
	if got := queryStrings(t, conn, `SELECT shawk_v1.peer_class('0.0.0.0/0'), shawk_v1.peer_class('::/0'), shawk_v1.peer_class('0.0.0.0')`); !slices.Equal(got,
		[]string{"~external ~external ~unresolved"}) {
		t.Errorf("peer_class = %q", got)
	}
	// A range of peer_cidrs that holds the whole network names it, as in the
	// connector.
	execAll(t, conn, `INSERT INTO shawk.peer_cidrs VALUES ('0.0.0.0/0', 'internet')`)
	if got := queryStrings(t, conn, `SELECT shawk_v1.peer_class('0.0.0.0/0'), shawk_v1.peer_class('::/0')`); !slices.Equal(got,
		[]string{"internet ~external"}) {
		t.Errorf("peer_class with peer_cidrs = %q", got)
	}
	r := newResolver(must(parsePeerCIDRs(map[string]string{"internet": "0.0.0.0/0"})), nil)
	if a, b := r.classifyFolded(addrOf("0.0.0.0")), r.classifyFolded(addrOf("::")); a != "internet" || b != peerExternal {
		t.Errorf("connector names %s %s", a, b)
	}

	// What the agents fold is kept with their sessions, and loaded by the
	// connector.
	got = queryStrings(t, conn, `SELECT host, coalesce(peer_fold, '-'), coalesce(peer_internal::text, '-') FROM shawk_v1.agents`)
	if want := []string{"app-01 none -", "web-01 all {10.0.0.0/8}"}; !slices.Equal(got, want) {
		t.Errorf("agents = %q, want %q", got, want)
	}
	rows, err := c.store.peers(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var agents []string
	for _, a := range rows.agents {
		agents = append(agents, fmt.Sprint(a.addr, " ", a.agent.name, " ", a.agent.fold, " ", a.agent.internal))
	}
	slices.Sort(agents)
	if want := []string{"198.51.100.7 app-01 none []", "2001:db8::10 web-01 all [10.0.0.0/8]",
		"203.0.113.10 web-01 all [10.0.0.0/8]"}; !slices.Equal(agents, want) {
		t.Errorf("agents loaded = %q, want %q", agents, want)
	}
	// A folded client edge names no server edge.
	for _, cl := range rows.clients {
		if cl.key.server.IsUnspecified() {
			t.Errorf("client endpoint of a folded edge loaded: %+v", cl)
		}
	}
	if len(rows.clients) != 1 {
		t.Errorf("client endpoints = %+v", rows.clients)
	}
}

// sessionChanges returns the changes of a session of a host: started (by
// the clock of the agent), its heartbeat, the dropped flows and the start of
// their counter (by the clock of the connector, which is skew ahead of that
// of the agent), as offsets from base.
func sessionChanges(host string, base time.Time, started, beat time.Duration, dropped int64, counter, skew time.Duration) *hostChanges {
	h := newHostChanges(host)
	h.setHost("m", host, "k", "v", base.Add(beat))
	h.addSession(base.Add(started), sessionRow{lastHeartbeat: base.Add(beat), netnsScope: "all", dropped: dropped,
		countersStarted: base.Add(counter).Add(-skew), clockSkew: skew, peerFold: foldNone})
	return h
}

// partialStore returns a store and a function that writes a session of a
// host like sessionChanges.
func partialStore(t *testing.T, dsn string, base time.Time) (store, func(host string, started, beat time.Duration, dropped int64, counter, skew time.Duration)) {
	t.Helper()
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.close)
	return st, func(host string, started, beat time.Duration, dropped int64, counter, skew time.Duration) {
		t.Helper()
		if err := st.write(ctx, sessionChanges(host, base, started, beat, dropped, counter, skew)); err != nil {
			t.Fatal(err)
		}
	}
}

// periods returns the partly observed periods of host as minutes from base:
// session start, period start, period end, dropped flows.
func periods(t *testing.T, conn *pgx.Conn, base time.Time) []string {
	t.Helper()
	min := func(c string) string { return `round(extract(epoch FROM ` + c + ` - $1) / 60)::int` }
	return queryStrings(t, conn, `SELECT host_id, `+min("started_at")+`, `+min("period_start")+`, `+min("period_end")+`, dropped_flows
FROM shawk.partial_observations`, base)
}

// TestPGPartialObservations: increases of the dropped flows of a session are
// recorded as the periods between heartbeats, by comparing with what
// PostgreSQL holds, so that restarts of the connector and of the agent are
// told apart.
func TestPGPartialObservations(t *testing.T) {
	dsn, conn := migratedDB(t)
	base := time.Now().UTC().Truncate(time.Minute)
	_, write := partialStore(t, dsn, base)
	m := func(n int) time.Duration { return time.Duration(n) * time.Minute }
	steps := []struct {
		started, beat int
		dropped       int64
		counter       int
		skew          time.Duration
	}{
		{-60, -50, 0, -60, 0},
		{-60, -49, 5, -60, 0},  // a period [-50, -49]
		{-60, -48, 8, -60, 0},  // extends it to -48
		{-60, -47, 8, -60, 0},  // nothing dropped
		{-60, -46, 10, -60, 0}, // a period [-47, -46]
		{-60, -48, 8, -60, 0},  // a late write changes nothing
		// The connector restarted: the session starts again from its floor,
		// with the counter of the same agent.
		{-47, -45, 10, -60, 0},
		{-47, -44, 12, -60, 0},
		// The agent restarted with fewer drops so far, at a clock ten minutes
		// behind the connector.
		{-40, -29, 3, -30, 10 * time.Minute},
		// The agent restarted with more drops so far than before.
		{-20, -19, 50, -20, 0},
		// A new segment of the same agent, after failed requests.
		{-10, -9, 55, -20, 0},
		// A new session without drops.
		{-5, -4, 0, -5, 0},
	}
	for _, s := range steps {
		write("h1", m(s.started), m(s.beat), s.dropped, m(s.counter), s.skew)
	}
	want := []string{
		"h1 -20 -20 -19 50",
		"h1 -40 -30 -29 3",
		"h1 -47 -45 -44 2",
		"h1 -60 -47 -46 2",
		"h1 -60 -50 -48 8",
		"h1 -10 -10 -9 5",
	}
	slices.Sort(want)
	if got := periods(t, conn, base); !slices.Equal(got, want) {
		t.Errorf("periods:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The contract cuts them to the period asked.
	got := queryStrings(t, conn, `SELECT host, round(extract(epoch FROM gap_start - $1) / 60)::int,
	  round(extract(epoch FROM gap_end - $1) / 60)::int, dropped_flows FROM shawk_v1.partly_observed($2, $3)`,
		base, base.Add(m(-49)), base.Add(m(-25)))
	if want := []string{"h1 -45 -44 2", "h1 -47 -46 2", "h1 -49 -48 8", "h1 -30 -29 3"}; !slices.Equal(got, sorted(want)) {
		t.Errorf("partly_observed = %q, want %q", got, sorted(want))
	}
	// unobserved() is unchanged.
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.unobserved($1, $2)`, base.Add(m(-49)), base.Add(m(-45))); !slices.Equal(got, []string{"0"}) {
		t.Errorf("unobserved within sessions = %q", got)
	}

	// Periods go with the retention, and hosts once nothing refers to them.
	execAll(t, conn, `SELECT shawk.prune(now() - interval '35 minutes')`)
	if got := periods(t, conn, base); len(got) != 3 {
		t.Errorf("periods after prune = %q", got)
	}
	execAll(t, conn, `SELECT shawk.prune(now() + interval '1 hour')`)
	if got := queryStrings(t, conn, `SELECT (SELECT count(*) FROM shawk.partial_observations), (SELECT count(*) FROM shawk.hosts)`); !slices.Equal(got,
		[]string{"0 0"}) {
		t.Errorf("rows after pruning everything = %q", got)
	}
}

func sorted(ss []string) []string {
	out := slices.Clone(ss)
	slices.Sort(out)
	return out
}

// TestPGPartialObservationsConcurrent: two connectors write the same host
// at once. The second compares with what the first wrote, rather than with
// what it read before the first committed.
func TestPGPartialObservationsConcurrent(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Minute)
	m := func(n int) time.Duration { return time.Duration(n) * time.Minute }
	st, write := partialStore(t, dsn, base)
	write("h1", m(-60), m(-3), 0, m(-60), 0)

	first, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(ctx)
	tx, err := first.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHost(ctx, tx, sessionChanges("h1", base, m(-60), m(-2), 5, m(-60), 0)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- st.write(ctx, sessionChanges("h1", base, m(-60), m(-1), 7, m(-60), 0)) }()
	time.Sleep(300 * time.Millisecond) // the second write waits for the first
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := periods(t, conn, base); !slices.Equal(got, []string{"h1 -60 -3 -1 7"}) {
		t.Errorf("periods = %q", got)
	}
}

// TestPGPartialObservationsConnector: the connector records the periods in
// which an agent dropped flows, and a new instance of the connector does not
// record the drops counted before it again.
func TestPGPartialObservationsConnector(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	at := func(minutes int, c *shawkConnector, sink *consumertest.MetricsSink, dropped int64) {
		t.Helper()
		ts := base.Add(time.Duration(minutes) * time.Minute)
		c.now = func() time.Time { return ts }
		consume(t, c, sink, tAgent{host: "h1", machineID: "m1", addrs: []string{"10.0.0.1"}, time: ts,
			segment: base.Add(-time.Hour), dropped: dropped, droppedSince: base.Add(-time.Hour)})
		c.flush(ctx)
	}
	at(0, c, sink, 2)
	at(1, c, sink, 2)
	at(2, c, sink, 7)
	at(3, c, sink, 7)

	// Another instance of the connector, as after a restart.
	cfg := *c.cfg
	cfg.Postgres.Migrate = false
	sink2 := new(consumertest.MetricsSink)
	c2, err := newConnector(connectortest.NewNopSettings(Type), &cfg, sink2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c2.Shutdown(ctx) })
	at(5, c2, sink2, 7)
	at(6, c2, sink2, 8)

	got := queryStrings(t, conn, `SELECT host, round(extract(epoch FROM gap_start - $1) / 60)::int,
	  round(extract(epoch FROM gap_end - $1) / 60)::int, dropped_flows FROM shawk_v1.partly_observed($2, $3)`,
		base, base.Add(-2*time.Hour), base.Add(time.Hour))
	// The first session starts with 2 drops counted: from its start (the
	// floor of the connector, 2 minutes before) to its first heartbeat.
	want := []string{"h1 -2 0 2", "h1 1 2 5", "h1 5 6 1"}
	if !slices.Equal(got, want) {
		t.Errorf("partly_observed = %q, want %q", got, want)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.agent_sessions`); !slices.Equal(got, []string{"2"}) {
		t.Errorf("sessions = %q", got)
	}
}

// TestPGAgentsFold: a session keeps what its agent folds as of its latest
// heartbeat, and shawk_v1.agents tells it.
func TestPGAgentsFold(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	write := func(beat time.Time, s sessionRow) {
		t.Helper()
		h := newHostChanges("h1")
		h.setHost("m", "h1", "k", "v", beat)
		s.lastHeartbeat, s.netnsScope = beat, "all"
		h.addSession(now.Add(-2*time.Hour), s)
		if err := st.write(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	session := func() []string {
		t.Helper()
		return queryStrings(t, conn, `SELECT peer_fold, array_to_string(peer_internal, ',') FROM shawk.agent_sessions
		  WHERE started_at = $1`, now.Add(-2*time.Hour))
	}
	internal := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fc00::/7")}
	write(now.Add(-time.Minute), sessionRow{peerFold: foldIn, peerInternal: internal})
	write(now.Add(-90*time.Second), sessionRow{peerFold: foldAll}) // older
	if got := session(); !slices.Equal(got, []string{"in 10.0.0.0/8,fc00::/7"}) {
		t.Errorf("session = %q", got)
	}
	write(now, sessionRow{peerFold: foldNone})
	if got := session(); !slices.Equal(got, []string{"none <nil>"}) {
		t.Errorf("session after a newer heartbeat = %q", got)
	}
	if got := queryStrings(t, conn, `SELECT peer_fold, peer_internal IS NULL FROM shawk_v1.agents`); !slices.Equal(got, []string{"none true"}) {
		t.Errorf("agents = %q", got)
	}
}

// TestPGPartialObservationsRuns: the drops of one run of the agent are
// recorded once, whatever sessions carry them: two connectors that write
// the run under different sessions, a connector whose clock is ahead of
// the other, and two sessions of the run in one batch, as after a step of
// the clock of the agent.
func TestPGPartialObservationsRuns(t *testing.T) {
	m := func(n int) time.Duration { return time.Duration(n) * time.Minute }
	total := func(t *testing.T, conn *pgx.Conn) string {
		t.Helper()
		return queryStrings(t, conn, `SELECT coalesce(sum(dropped_flows), 0)::bigint FROM shawk.partial_observations`)[0]
	}
	t.Run("two connectors", func(t *testing.T) {
		dsn, conn := migratedDB(t)
		base := time.Now().UTC().Truncate(time.Minute)
		_, write := partialStore(t, dsn, base)
		write("h1", m(-60), m(-10), 0, m(-60), 0) // connector A, under the start of the segment
		write("h1", m(-12), m(-8), 0, m(-60), 0)  // connector B, under its floor
		write("h1", m(-60), m(-7), 10, m(-60), 0) // A: 10 drops since B saw none
		write("h1", m(-12), m(-6), 10, m(-60), 0) // B: the same 10 drops
		if got := periods(t, conn, base); !slices.Equal(got, []string{"h1 -60 -8 -7 10"}) {
			t.Errorf("periods = %q", got)
		}
	})
	t.Run("connector clock ahead", func(t *testing.T) {
		dsn, conn := migratedDB(t)
		base := time.Now().UTC().Truncate(time.Minute)
		_, write := partialStore(t, dsn, base)
		write("h1", m(-60), m(-10), 0, m(-60), 0)
		write("h1", m(-60), m(-8), 5, m(-60), 0) // connector A, a minute ahead
		// Connector B, on time, receives the next request, with 3 drops more,
		// stamped before the heartbeat A wrote.
		write("h1", m(-60), m(-9)+30*time.Second, 8, m(-60), 0)
		write("h1", m(-60), m(-7), 8, m(-60), 0)
		if got := total(t, conn); got != "8" {
			t.Errorf("recorded %s dropped flows, want 8; periods = %q", got, periods(t, conn, base))
		}
	})
	t.Run("one batch", func(t *testing.T) {
		dsn, conn := migratedDB(t)
		ctx := context.Background()
		base := time.Now().UTC().Truncate(time.Minute)
		st, write := partialStore(t, dsn, base)
		write("h1", m(-60), m(-10), 2, m(-60), 0)
		h := sessionChanges("h1", base, m(-60), m(-9), 6, m(-60), 0)
		h.addSession(base.Add(m(-50)), sessionRow{lastHeartbeat: base.Add(m(-8)), netnsScope: "all", dropped: 7,
			countersStarted: base.Add(m(-60)), peerFold: foldNone})
		if err := st.write(ctx, h); err != nil {
			t.Fatal(err)
		}
		if got := total(t, conn); got != "7" {
			t.Errorf("recorded %s dropped flows, want 7 (2 at start, then 5); periods = %q", got, periods(t, conn, base))
		}
	})
}
