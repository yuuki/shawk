package shawkconnector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// PostgreSQL tests of translations of addresses (#107).

// translationDeps is the query of the rows of dependencies the tests
// compare.
const translationDeps = `SELECT coalesce(client_host, '-'), coalesce(client_service, '-'), host(client_addr),
  coalesce(server_host, '-'), coalesce(server_service, '-'), host(server_addr), port, observed_by,
  coalesce(host(virtual_addr), '-'), coalesce(virtual_port::text, '-'), coalesce(translation, '-')`

// TestPGTranslations: the client edges to a virtual address are matched
// with the server edges of its backends, on their port and over the period
// both were active; behind a relay with sources, the server edges keep a
// row of their own.
func TestPGTranslations(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, translationConfig)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	app, db1, db2, web := translationAgents(now)
	app.edges[0].first, app.edges[1].first = now.Add(-time.Hour), now.Add(-time.Hour)
	app2 := tAgent{host: "app-02", addrs: []string{"127.0.0.1", "10.0.0.12"}, time: now,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.12", peer: "10.0.100.2", port: 80, svc: "app2", comm: "app2", opened: 1},
			// It used the database through the virtual address before db-01
			// served it; db-01 serves it directly since.
			{role: "client", proto: "tcp", local: "10.0.0.12", peer: "10.0.100.1", port: 5432, svc: "app2", comm: "app2", opened: 1,
				first: now.Add(-5 * time.Hour), last: now.Add(-4 * time.Hour)},
		}}
	// A client without an agent that connects to db-01 directly.
	db1.edges = append(db1.edges, tEdge{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.50", port: 5432,
		svc: "postgres", unit: "postgresql.service", comm: "postgres", opened: 1},
		tEdge{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.12", port: 5432,
			svc: "postgres", unit: "postgresql.service", comm: "postgres", opened: 1, first: now.Add(-2 * time.Hour)})
	// db-01 served the client for an hour before the client edge to the
	// virtual address was active, so its server edge keeps a row of its
	// own; that of db-02 is within the client edge.
	db1.edges[0].first, db2.edges[0].first = now.Add(-2*time.Hour), now.Add(-30*time.Minute)
	web.edges[0].first = now.Add(-2 * time.Hour)
	// A former backend, which served the client before the client edge to
	// the virtual address was active.
	old := tAgent{host: "db-old", addrs: []string{"127.0.0.1", "10.0.1.12"}, time: now,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.12", peer: "10.0.0.11", port: 5432, svc: "postgres",
			unit: "postgresql.service", comm: "postgres", opened: 1, first: now.Add(-5 * time.Hour), last: now.Add(-3 * time.Hour)}}}
	for _, a := range []tAgent{db1, db2, web, old, app, app2} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)

	want := []string{
		"- - 10.0.0.11 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.0.11 db-old postgres 10.0.1.12 5432 server - - -",
		"- - 10.0.0.12 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.0.50 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.100.250 web-01 web 10.0.1.20 8080 server - - -",
		"app-01 shop/app 10.0.0.11 - - 10.0.100.3 443 client - - -",
		"app-01 shop/app 10.0.0.11 db-01 postgres 10.0.1.10 5432 both 10.0.100.1 5432 postgres-vip",
		"app-01 shop/app 10.0.0.11 db-02 postgres 10.0.1.11 5432 both 10.0.100.1 5432 postgres-vip",
		"app-01 shop/app 10.0.0.11 web-01 web 10.0.1.20 8080 both 10.0.100.2 80 web-lb",
		"app-02 app2 10.0.0.12 - - 10.0.100.1 5432 client - - -",
		"app-02 app2 10.0.0.12 web-01 web 10.0.1.20 8080 both 10.0.100.2 80 web-lb",
	}
	for _, q := range []string{
		translationDeps + ` FROM shawk_v1.dependencies`,
		translationDeps + ` FROM shawk_v1.dependencies_between('-infinity', 'infinity')`,
	} {
		if got := queryStrings(t, conn, q); !slices.Equal(got, want) {
			t.Errorf("%s:\n%s\nwant:\n%s", q, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	// A matched row has the period both edges were active in.
	got := queryStrings(t, conn, `SELECT server_host, first_seen = $1, last_seen = $2 FROM shawk_v1.dependencies
	  WHERE client_host = 'app-01' AND translation = 'postgres-vip'`, now.Add(-time.Hour), now)
	if want := []string{"db-01 true true", "db-02 false true"}; !slices.Equal(got, want) {
		t.Errorf("periods = %q", got)
	}
	// Over the last hour, the former backend and the former client edge of
	// app-02 are out of the period, and the server edge of db-01 is covered
	// by its row through the translation.
	got = queryStrings(t, conn, translationDeps+` FROM shawk_v1.dependencies_between(now() - interval '1 hour', now())`)
	var wantHour []string
	for _, w := range want {
		if !strings.Contains(w, "db-old") && !strings.HasPrefix(w, "app-02 app2 10.0.0.12 - -") &&
			!strings.HasPrefix(w, "- - 10.0.0.11 db-01") {
			wantHour = append(wantHour, w)
		}
	}
	if !slices.Equal(got, wantHour) {
		t.Errorf("dependencies_between:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantHour, "\n"))
	}

	// Between services, the relay is named after its range of peer_cidrs.
	wantSvc := []string{
		"app2 web 8080", "app2 ~unresolved 5432", "lb web 8080", "shop/app postgres 5432", "shop/app web 8080", "shop/app ~unresolved 443",
		"~unresolved postgres 5432",
	}
	for _, q := range []string{
		`SELECT client_service, server_service, port FROM shawk.service_dependencies`,
		`SELECT client_service, server_service, port FROM shawk.service_dependencies_between(now() - interval '6 hours', now())`,
	} {
		if got := queryStrings(t, conn, q); !slices.Equal(got, wantSvc) {
			t.Errorf("%s = %q, want %q", q, got, wantSvc)
		}
	}
	got = queryStrings(t, conn, `SELECT source, target, mainstat FROM shawk_v1.graph_edges_between(now() - interval '6 hours', now())
	  WHERE source = 'shop/app'`)
	if want := []string{"shop/app postgres 5432/tcp", "shop/app web 8080/tcp", "shop/app ~unresolved 443/tcp"}; !slices.Equal(got, want) {
		t.Errorf("graph_edges_between = %q", got)
	}
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	if got := queryStrings(t, conn, `SELECT client_service, server_service, port FROM shawk.known_dependencies`); !slices.Equal(got, wantSvc) {
		t.Errorf("known_dependencies = %q, want %q", got, wantSvc)
	}

	// The translations are kept as the configuration has them, and replaced
	// when it changes: without the translation, the two sides of the
	// connections to the database are apart again.
	got = queryStrings(t, conn, `SELECT name, side, proto, addr::text, port FROM shawk.translations WHERE name = 'web-lb' AND proto = 'tcp'`)
	if want := []string{"web-lb backend tcp 10.0.1.20/32 8080", "web-lb source tcp 10.0.100.250/32 0",
		"web-lb virtual tcp 10.0.100.2/32 80"}; !slices.Equal(got, want) {
		t.Errorf("translations = %q", got)
	}
	delete(c.cfg.Translations, "postgres-vip")
	if err := c.store.syncConfig(ctx, c.cidrs, must(parseTranslations(c.cfg.Translations))); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT DISTINCT name FROM shawk.translations`); !slices.Equal(got, []string{"api-lb", "web-lb"}) {
		t.Errorf("translations after the change = %q", got)
	}
	got = queryStrings(t, conn, translationDeps+` FROM shawk_v1.dependencies WHERE port = 5432`)
	wantApart := []string{
		"- - 10.0.0.11 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.0.11 db-02 postgres 10.0.1.11 5432 server - - -",
		"- - 10.0.0.11 db-old postgres 10.0.1.12 5432 server - - -",
		"- - 10.0.0.12 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.0.50 db-01 postgres 10.0.1.10 5432 server - - -",
		"app-01 shop/app 10.0.0.11 - - 10.0.100.1 5432 client - - -",
		"app-02 app2 10.0.0.12 - - 10.0.100.1 5432 client - - -",
	}
	if !slices.Equal(got, wantApart) {
		t.Errorf("without the translation:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantApart, "\n"))
	}
}

// TestPGTranslationPrecedence: a client edge that a server edge at the
// virtual address matches is not matched through the translation; a
// relay with an agent is a service of its own.
func TestPGTranslationPrecedence(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, translationConfig)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	app, db1, _, _ := translationAgents(now)
	app.edges = app.edges[:1]
	lb := tAgent{host: "lb-01", addrs: []string{"127.0.0.1", "10.0.100.1"}, time: now,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.100.1", peer: "10.0.0.11", port: 5432, svc: "haproxy", comm: "haproxy", opened: 4}}}
	for _, a := range []tAgent{db1, lb, app} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	got := queryStrings(t, conn, translationDeps+` FROM shawk_v1.dependencies`)
	want := []string{
		"- - 10.0.0.11 db-01 postgres 10.0.1.10 5432 server - - -",
		"app-01 shop/app 10.0.0.11 lb-01 haproxy 10.0.100.1 5432 both - - -",
	}
	if !slices.Equal(got, want) {
		t.Errorf("dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGTranslationScope: a client address that several hosts hold at once,
// such as the gateway of a container bridge, is matched through a
// translation within its host only.
func TestPGTranslationScope(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"vip": {Virtual: []string{"10.0.100.1:80"}, Backends: []string{"172.17.0.0/16:8080"}},
		}
	})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	// Two Docker hosts: a container on each connects from the bridge to the
	// virtual address, and the backend on h1 sees the bridge address.
	h := func(name, addr string, edges ...tEdge) tAgent {
		return tAgent{host: name, addrs: []string{"127.0.0.1", addr, "172.17.0.1"}, time: now, edges: edges}
	}
	consume(t, c, sink, h("h1", "10.0.0.1",
		tEdge{role: "client", proto: "tcp", local: "172.17.0.1", peer: "10.0.100.1", port: 80, svc: "a", comm: "a", opened: 1},
		tEdge{role: "server", proto: "tcp", local: "172.17.0.2", peer: "172.17.0.1", port: 8080, svc: "web", comm: "web", opened: 1}))
	consume(t, c, sink, h("h2", "10.0.0.2",
		tEdge{role: "client", proto: "tcp", local: "172.17.0.1", peer: "10.0.100.1", port: 80, svc: "b", comm: "b", opened: 1}))
	c.flush(ctx)
	// The addresses count as shared once both hosts held them for a while.
	execAll(t, conn, `UPDATE shawk.host_addrs SET first_seen = first_seen - interval '1 hour'`)
	got := queryStrings(t, conn, translationDeps+` FROM shawk_v1.dependencies`)
	want := []string{
		"h1 a 172.17.0.1 h1 web 172.17.0.2 8080 both 10.0.100.1 80 vip",
		"h2 b 172.17.0.1 - - 10.0.100.1 80 client - - -",
	}
	if !slices.Equal(got, want) {
		t.Errorf("dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGTranslationPeriods: an edge matched through a translation keeps a
// row of its own over the time its rows do not cover, in the view and in
// the periods asked for.
func TestPGTranslationPeriods(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			// The client still connects; the backend left 65 minutes ago.
			"a": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10"}},
			// The backend still serves; the client edge ended 65 minutes ago.
			"b": {Virtual: []string{"10.0.100.2:5432"}, Backends: []string{"10.0.1.11"}},
			// The agent of the backend started 55 minutes ago.
			"c": {Virtual: []string{"10.0.100.3:5432"}, Backends: []string{"10.0.1.12"}},
		}
	})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	long, ended := now.Add(-10*time.Hour), now.Add(-65*time.Minute)
	client := func(vip string, last time.Time) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: vip, port: 5432, svc: "app", comm: "app",
			opened: 1, first: long, last: last}
	}
	server := func(addr string, first, last time.Time) tEdge {
		return tEdge{role: "server", proto: "tcp", local: addr, peer: "10.0.0.11", port: 5432, svc: "postgres",
			comm: "postgres", opened: 1, first: first, last: last}
	}
	for _, a := range []tAgent{
		{host: "db-a", addrs: []string{"10.0.1.10"}, time: now, edges: []tEdge{server("10.0.1.10", long, ended)}},
		{host: "db-b", addrs: []string{"10.0.1.11"}, time: now, edges: []tEdge{server("10.0.1.11", long, now)}},
		{host: "db-c", addrs: []string{"10.0.1.12"}, time: now, edges: []tEdge{server("10.0.1.12", now.Add(-55*time.Minute), now)}},
		{host: "app-01", addrs: []string{"10.0.0.11"}, time: now, edges: []tEdge{
			client("10.0.100.1", now), client("10.0.100.2", ended), client("10.0.100.3", now)}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)

	q := `SELECT coalesce(client_host, '-'), coalesce(server_host, '-'), host(server_addr), observed_by, coalesce(translation, '-')`
	for _, c := range []struct {
		from string
		want []string
	}{
		{"shawk_v1.dependencies", []string{
			"- db-b 10.0.1.11 server -",
			"app-01 - 10.0.100.1 client -",
			"app-01 - 10.0.100.3 client -",
			"app-01 db-a 10.0.1.10 both a",
			"app-01 db-b 10.0.1.11 both b",
			"app-01 db-c 10.0.1.12 both c",
		}},
		// In the last hour, only the rows of their own tell that the client
		// of a and the server of b were active; c was observed on both sides
		// for 55 minutes of it.
		{"shawk_v1.dependencies_between(now() - interval '1 hour', now())", []string{
			"- db-b 10.0.1.11 server -",
			"app-01 - 10.0.100.1 client -",
			"app-01 - 10.0.100.3 client -",
			"app-01 db-c 10.0.1.12 both c",
		}},
		// Hours ago, a and b were observed on both sides, and c on the client
		// side only.
		{"shawk_v1.dependencies_between(now() - interval '3 hours', now() - interval '2 hours')", []string{
			"app-01 - 10.0.100.3 client -",
			"app-01 db-a 10.0.1.10 both a",
			"app-01 db-b 10.0.1.11 both b",
		}},
	} {
		if got := queryStrings(t, conn, q+" FROM "+c.from); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n%s\nwant:\n%s", c.from, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}

// TestPGConcurrentTranslationSyncs: connectors that write different
// translations and peer_cidrs at once leave those of one of them, not a mix
// of both, also when the database defaults to REPEATABLE READ.
func TestPGConcurrentTranslationSyncs(t *testing.T) {
	dsn, conn := testDB(t)
	ctx := context.Background()
	if _, err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	execAll(t, conn, `ALTER DATABASE `+conn.Config().Database+` SET default_transaction_isolation = 'repeatable read'`)
	stores := make([]store, 2)
	for i := range stores {
		st, err := newPGStore(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.close)
		stores[i] = st
	}
	configs := [][]translation{
		must(parseTranslations(map[string]TranslationConfig{
			"lb": {Virtual: []string{"10.0.100.1:80"}, Backends: []string{"10.0.1.20"}, Transport: "tcp"}})),
		must(parseTranslations(map[string]TranslationConfig{
			"lb": {Virtual: []string{"10.0.100.1:80"}, Backends: []string{"10.0.1.30"}, Sources: []string{"10.0.100.250"},
				Transport: "tcp"}})),
	}
	// Each connector also has its own peer_cidrs, which are written with the
	// translations.
	cidrs := [][]namedPrefix{
		must(parsePeerCIDRs(map[string]string{"a": "10.1.0.0/16"})),
		must(parsePeerCIDRs(map[string]string{"b": "10.2.0.0/16"})),
	}
	rows := func(ts []translation) []string {
		var out []string
		for _, r := range translationRows(ts) {
			out = append(out, strings.Join([]string{r.name, r.side, r.proto, r.prefix.String(), fmt.Sprint(r.port)}, " "))
		}
		slices.Sort(out)
		return out
	}
	initial := must(parseTranslations(map[string]TranslationConfig{
		"lb": {Virtual: []string{"10.0.100.1:80"}, Backends: []string{"10.0.1.10"}, Transport: "tcp"}}))
	for round := range 20 {
		if err := stores[0].syncConfig(ctx, nil, initial); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range stores {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = stores[i].syncConfig(ctx, cidrs[i], configs[i])
			}()
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Fatal(err)
		}
		got := queryStrings(t, conn, `SELECT name, side, proto, addr::text, port FROM shawk.translations`)
		ranges := queryStrings(t, conn, `SELECT name FROM shawk.peer_cidrs`)
		if !(slices.Equal(got, rows(configs[0])) && slices.Equal(ranges, []string{"a"})) &&
			!(slices.Equal(got, rows(configs[1])) && slices.Equal(ranges, []string{"b"})) {
			t.Fatalf("round %d: translations = %q, peer_cidrs = %q", round, got, ranges)
		}
	}
}

// TestPGTranslationDirectRouting: with LVS direct routing, the backends hold
// the virtual address themselves and accept the connections on it; as
// several hosts hold it, the edges do not match by address, and the virtual
// address is its own backend.
func TestPGTranslationDirectRouting(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"dr": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.100.1"}},
		}
	})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	db := func(host, addr string) tAgent {
		return tAgent{host: host, addrs: []string{addr, "10.0.100.1"}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.100.1", peer: "10.0.0.11", port: 5432,
				svc: "postgres", comm: "postgres", opened: 1}}}
	}
	for _, a := range []tAgent{db("db-01", "10.0.1.10"), db("db-02", "10.0.1.11"),
		{host: "app-01", addrs: []string{"10.0.0.11"}, time: now, edges: []tEdge{{role: "client", proto: "tcp",
			local: "10.0.0.11", peer: "10.0.100.1", port: 5432, svc: "app", comm: "app", opened: 2}}}} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	// Both hosts held the address for a while.
	execAll(t, conn, `UPDATE shawk.host_addrs SET first_seen = first_seen - interval '1 hour'`)
	got := queryStrings(t, conn, translationDeps+` FROM shawk_v1.dependencies`)
	want := []string{
		"app-01 app 10.0.0.11 db-01 postgres 10.0.100.1 5432 both 10.0.100.1 5432 dr",
		"app-01 app 10.0.0.11 db-02 postgres 10.0.100.1 5432 both 10.0.100.1 5432 dr",
	}
	if !slices.Equal(got, want) {
		t.Errorf("dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGTranslationStoppedAgent: a dependency matched through a translation
// does not disappear when the agent of one side stops; it does when the
// side that ended its row is still observed.
func TestPGTranslationStoppedAgent(t *testing.T) {
	for _, c := range []struct {
		name    string
		stopped string // the host whose agent stopped 20 minutes ago
		ended   string // the edge that ended then: client or server
		want    []string
	}{
		{"the agent of the server stopped", "db-01", "server", nil},
		{"the agent of the client stopped", "app-01", "client", nil},
		// db-01 still reports, and no longer serves the client.
		{"the backend left", "", "server", []string{"disappeared app postgres 5432"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cn, sink, conn := pgConnectorWith(t, func(cfg *Config) {
				cfg.Translations = map[string]TranslationConfig{
					"vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10"}},
				}
			})
			now := time.Now().UTC().Truncate(time.Second)
			lastC, lastS := now, now
			if c.ended == "client" {
				lastC = now.Add(-20 * time.Minute)
			} else {
				lastS = now.Add(-20 * time.Minute)
			}
			consume(t, cn, sink, tAgent{host: "db-01", addrs: []string{"10.0.1.10"}, time: now,
				edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.11", port: 5432,
					svc: "postgres", comm: "postgres", opened: 1, first: now.Add(-2 * time.Hour), last: lastS}}})
			consume(t, cn, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now,
				edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.1", port: 5432,
					svc: "app", comm: "app", opened: 1, first: now.Add(-2 * time.Hour), last: lastC}}})
			cn.flush(context.Background())
			if c.stopped != "" {
				execAll(t, conn, `UPDATE shawk.agent_sessions s SET last_heartbeat = now() - interval '20 minutes'
				  FROM shawk.hosts h WHERE h.id = s.host_id AND h.hostname = '`+c.stopped+`'`)
			}
			for _, q := range []string{
				`SELECT change, client_service, server_service, port FROM shawk_v1.dependency_changes_between(now() - interval '1 hour', now())
				  WHERE server_service = 'postgres'`,
				`SELECT change, client_service, server_service, port FROM shawk_v1.dependency_changes
				  WHERE server_service = 'postgres' AND change = 'disappeared'`,
			} {
				if got := queryStrings(t, conn, q); !slices.Equal(got, c.want) {
					t.Errorf("%s = %q, want %q", q, got, c.want)
				}
			}
		})
	}
}

// TestPGTranslationPrecedencePeriods: a relay with an agent that served the
// virtual address before a relay without one takes precedence over the
// translation in its period only, whatever the period asked for.
func TestPGTranslationPrecedencePeriods(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10"}},
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	for _, a := range []tAgent{
		{host: "lb-01", addrs: []string{"10.0.0.5"}, time: now, edges: []tEdge{{role: "server", proto: "tcp",
			local: "10.0.100.1", peer: "10.0.0.11", port: 5432, svc: "haproxy", comm: "haproxy", opened: 1,
			first: now.Add(-10 * day), last: now.Add(-2 * day)}}},
		{host: "db-01", addrs: []string{"10.0.1.10"}, time: now, edges: []tEdge{{role: "server", proto: "tcp",
			local: "10.0.1.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 1,
			first: now.Add(-2*day + 10*time.Minute), last: now}}},
		{host: "app-01", addrs: []string{"10.0.0.11"}, time: now, edges: []tEdge{{role: "client", proto: "tcp",
			local: "10.0.0.11", peer: "10.0.100.1", port: 5432, svc: "app", comm: "app", opened: 1,
			first: now.Add(-10 * day), last: now}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	q := `SELECT client_service, server_service, last_seen > now() - interval '1 day'`
	for _, c := range []struct {
		from string
		want []string
	}{
		{"shawk.service_dependencies", []string{"app haproxy false", "app postgres true"}},
		{"shawk.service_dependencies_between(now() - interval '1 day', now())", []string{"app postgres true"}},
		{"shawk.service_dependencies_between(now() - interval '3 days', now())", []string{"app haproxy false", "app postgres true"}},
	} {
		if got := queryStrings(t, conn, q+" FROM "+c.from); !slices.Equal(got, c.want) {
			t.Errorf("%s = %q, want %q", c.from, got, c.want)
		}
	}
}

// TestPGTranslationGap: an edge matched through translations keeps a row of
// its own until the end of the last part its matched rows leave, such as a
// failover from one backend to another, and shown only in the periods that
// part is in; the row does not disappear while the client is observed. An
// edge with its times out of order does not break the view.
func TestPGTranslationGap(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10", "10.0.1.11"}},
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	failover := now.Add(-72 * time.Hour)
	server := func(host, addr string, first, last time.Time) tAgent {
		return tAgent{host: host, addrs: []string{addr}, time: now, edges: []tEdge{{role: "server", proto: "tcp",
			local: addr, peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 1, first: first, last: last}}}
	}
	for _, a := range []tAgent{
		server("db-01", "10.0.1.10", now.Add(-240*time.Hour), failover),
		server("db-02", "10.0.1.11", failover.Add(10*time.Minute), now),
		{host: "app-01", addrs: []string{"10.0.0.11"}, time: now, edges: []tEdge{{role: "client", proto: "tcp",
			local: "10.0.0.11", peer: "10.0.100.1", port: 5432, svc: "app", comm: "app", opened: 1,
			first: now.Add(-240 * time.Hour), last: now}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	got := queryStrings(t, conn, `SELECT coalesce(server_host, '-'), observed_by, first_seen = $1, last_seen = $2
	  FROM shawk_v1.dependencies WHERE observed_by = 'client'`, now.Add(-240*time.Hour), failover.Add(8*time.Minute))
	if want := []string{"- client true true"}; !slices.Equal(got, want) {
		t.Errorf("row of the client edge = %q, want %q", got, want)
	}
	for _, c := range []struct {
		since, until string
		want         []string
	}{
		{"now() - interval '1 hour'", "now()", []string{"db-02 both"}},
		{"now() - interval '73 hours'", "now() - interval '71 hours'", []string{"- client", "db-01 both", "db-02 both"}},
		{"now() - interval '100 hours'", "now() - interval '80 hours'", []string{"db-01 both"}},
	} {
		q := `SELECT coalesce(server_host, '-'), observed_by FROM shawk_v1.dependencies_between(` + c.since + `, ` + c.until + `)`
		if got := queryStrings(t, conn, q); !slices.Equal(got, c.want) {
			t.Errorf("%s = %q, want %q", q, got, c.want)
		}
	}

	if got := queryStrings(t, conn, `SELECT change, client_service, server_service FROM shawk_v1.dependency_changes
	  WHERE change = 'disappeared'`); len(got) != 0 {
		t.Errorf("dependency_changes = %q", got)
	}

	execAll(t, conn, `UPDATE shawk.edges SET first_seen = last_seen + interval '1 minute' WHERE role = 'client'`)
	for _, q := range []string{
		`SELECT count(*) FROM shawk_v1.dependencies`,
		`SELECT count(*) FROM shawk_v1.dependencies_between('-infinity', 'infinity')`,
		`SELECT count(*) FROM shawk_v1.dependency_changes`,
	} {
		queryStrings(t, conn, q)
	}
}
