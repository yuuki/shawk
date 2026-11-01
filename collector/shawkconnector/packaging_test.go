package shawkconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/collector/confmap"
	"go.yaml.in/yaml/v3"
)

// These tests check the examples in packaging/ against the connector and
// the schema.

const packaging = "../../packaging"

func TestPackagedCollectorConfig(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(packaging, "collector/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Receivers  map[string]any `yaml:"receivers"`
		Processors map[string]any `yaml:"processors"`
		Exporters  map[string]any `yaml:"exporters"`
		Connectors map[string]any `yaml:"connectors"`
		Service    struct {
			Pipelines map[string]struct {
				Receivers  []string `yaml:"receivers"`
				Processors []string `yaml:"processors"`
				Exporters  []string `yaml:"exporters"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	raw, ok := doc.Connectors["shawk"].(map[string]any)
	if !ok {
		t.Fatal("no shawk connector")
	}
	cfg := createDefaultConfig()
	if err := confmap.NewFromStringMap(raw).Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}
	if cfg.Postgres.DSNFile == "" || cfg.WriteInterval != time.Minute || cfg.IdleTTL != 15*time.Minute ||
		cfg.MaxPeers != 50 || cfg.PeerCIDRs["office-lan"] != "192.168.10.0/24" || cfg.Retention != 3*365*24*time.Hour {
		t.Errorf("config = %+v", cfg)
	}
	// Both receivers require client certificates; the receiver of agents
	// accepts the largest requests of an agent.
	for _, r := range []string{"otlp/shawk", "otlp"} {
		protocols, _ := doc.Receivers[r].(map[string]any)["protocols"].(map[string]any)
		for _, proto := range []string{"grpc", "http"} {
			p, _ := protocols[proto].(map[string]any)
			tls, _ := p["tls"].(map[string]any)
			if tls["client_ca_file"] == nil || tls["cert_file"] == nil || tls["key_file"] == nil {
				t.Errorf("%s %s: no TLS with client certificates: %v", r, proto, p)
			}
			if r != "otlp/shawk" {
				continue
			}
			if proto == "grpc" && p["max_recv_msg_size_mib"] != 16 {
				t.Errorf("%s: max_recv_msg_size_mib = %v", r, p["max_recv_msg_size_mib"])
			}
			if proto == "http" && p["max_request_body_size"] != 16<<20 {
				t.Errorf("%s: max_request_body_size = %v", r, p["max_request_body_size"])
			}
		}
	}
	for name, p := range doc.Service.Pipelines {
		// Points of other sources carry the clocks of their hosts; batched,
		// one host with a wrong clock makes Prometheus drop the others.
		if slicesContains(p.Receivers, "otlp") && slicesContains(p.Processors, "batch") &&
			slicesContains(p.Exporters, "otlp_http/prometheus") {
			t.Errorf("%s: batches points of several hosts for Prometheus", name)
		}
		for _, r := range p.Receivers {
			if doc.Receivers[r] == nil && doc.Connectors[r] == nil {
				t.Errorf("%s: undefined receiver %s", name, r)
			}
		}
		for _, x := range p.Processors {
			if _, ok := doc.Processors[x]; !ok {
				t.Errorf("%s: undefined processor %s", name, x)
			}
			if x == "batch" && slicesContains(p.Exporters, "shawk") {
				t.Errorf("%s: a batch processor before the connector merges requests of agents", name)
			}
		}
		for _, e := range p.Exporters {
			if doc.Exporters[e] == nil && doc.Connectors[e] == nil {
				t.Errorf("%s: undefined exporter %s", name, e)
			}
		}
	}
}

func slicesContains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// packagedSQL returns the SQL queries of the Grafana dashboards and alert
// rules, by file and title.
func packagedSQL(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(packaging, "grafana/dashboards/*.json"))
	if len(files) == 0 {
		t.Fatal("no dashboards")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		collectSQL(filepath.Base(f), v, out)
	}
	b, err := os.ReadFile(filepath.Join(packaging, "grafana/provisioning/alerting/shawk-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	collectSQL("shawk-rules.yaml", v, out)
	return out
}

func collectSQL(path string, v any, out map[string]string) {
	switch v := v.(type) {
	case map[string]any:
		name := path
		for _, k := range []string{"title", "name", "uid", "refId"} {
			if s, ok := v[k].(string); ok {
				name = path + "/" + s
				break
			}
		}
		if s, ok := v["rawSql"].(string); ok {
			for i := 0; ; i++ {
				k := fmt.Sprintf("%s#%d", name, i)
				if _, dup := out[k]; !dup {
					out[k] = s
					break
				}
			}
		}
		for _, x := range v {
			collectSQL(name, x, out)
		}
	case []any:
		for _, x := range v {
			collectSQL(path, x, out)
		}
	}
}

// expandMacros replaces the Grafana macros and variables the queries use.
func expandMacros(sql string, from, to time.Time) string {
	ts := func(t time.Time) string { return "'" + t.UTC().Format(time.RFC3339) + "'::timestamptz" }
	r := strings.NewReplacer(
		"$__timeFrom()", ts(from),
		"$__timeTo()", ts(to),
		"${service:singlequote}", "'postgres', 'shop/app'",
		"${src:singlequote}", "'shop/app'",
		"${dst:singlequote}", "'postgres'",
		"'$direction'", "'both'",
		"$depth", "2",
	)
	sql = r.Replace(sql)
	sql = regexp.MustCompile(`\$__timeFilter\((\w+)\)`).ReplaceAllString(sql, "$1 BETWEEN "+ts(from)+" AND "+ts(to))
	sql = regexp.MustCompile(`\$__timeGroupAlias\((\w+), '1h'\)`).ReplaceAllString(sql, "date_bin('1 hour', $1, 'epoch') AS time")
	return sql
}

// TestPGPackaged writes dependencies through the connector, applies
// grants.sql and runs every SQL query of the dashboards and alerts as
// shawk_grafana; it also reads and writes as shawk_connector.
func TestPGPackaged(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	consume(t, c, sink, tAgent{host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.10"}, time: now.Add(-time.Minute),
		segment:   now.Add(-2 * time.Hour),
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", comm: "postgres", unit: "postgresql.service"}},
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres",
			unit: "postgresql.service", opened: 1}}})
	consume(t, c, sink, tAgent{host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11"}, time: now.Add(-time.Minute),
		segment: now.Add(-2 * time.Hour),
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", ns: "shop", comm: "puma", opened: 1,
				first: now.Add(-10 * time.Minute)},
			// A dependency that ended 20 minutes ago.
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.20", port: 6379, svc: "app", ns: "shop", comm: "puma", opened: 1,
				first: now.Add(-time.Hour), last: now.Add(-20 * time.Minute)},
			// A second new dependency: alerts must handle several rows.
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.30", port: 11211, svc: "app", ns: "shop", comm: "puma", opened: 1,
				first: now.Add(-8 * time.Minute)},
		}})
	c.flush(ctx)

	for _, q := range []string{
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_connector') THEN CREATE ROLE shawk_connector NOLOGIN; END IF;
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_grafana') THEN CREATE ROLE shawk_grafana NOLOGIN; END IF;
		 END $$`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	grants, err := os.ReadFile(filepath.Join(packaging, "postgres/grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(grants)); err != nil {
		t.Fatalf("grants.sql: %v", err)
	}
	t.Cleanup(func() {
		conn.Exec(ctx, "RESET ROLE")
		conn.Exec(ctx, "DROP OWNED BY shawk_connector, shawk_grafana")
	})

	// The connector role writes and names peers.
	if _, err := conn.Exec(ctx, "SET ROLE shawk_connector"); err != nil {
		t.Fatal(err)
	}
	h := newHostChanges(hostKey("m-x", "x-01"))
	h.setHost("m-x", "x-01", "5.14", "test", now)
	h.addSession(now.Add(-time.Hour), sessionRow{lastHeartbeat: now, netnsScope: "all"})
	h.addAddr(addrOf("10.0.0.30"), span{now, now})
	h.addProcess(procKey{"x.service", "x", "x"}, "/usr/bin/x", span{now, now})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.30"), peer: addrOf("10.0.0.10"), port: 5432,
		netns: 1, procKey: procKey{"x.service", "x", "x"}}, span{now, now})
	h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: 9000, netns: 1}, procKey{"x.service", "x", "x"}, span{now, now})
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) }); err != nil {
		t.Errorf("writing as shawk_connector: %v", err)
	}
	for _, q := range []string{`SELECT count(*) FROM shawk_v1.service_endpoints`, `SELECT count(*) FROM shawk_v1.agent_addrs`,
		`SELECT count(*) FROM shawk_v1.client_endpoints`, `SELECT shawk.prune(now() - interval '3 years')`,
		`SELECT shawk.schema_version()`, `SELECT shawk.refresh_known_dependencies(interval '0')`} {
		var n int
		if err := conn.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Errorf("%s as shawk_connector: %v", q, err)
		}
	}

	if _, err := conn.Exec(ctx, "RESET ROLE; SET ROLE shawk_grafana"); err != nil {
		t.Fatal(err)
	}
	queries := packagedSQL(t)
	if len(queries) < 15 {
		t.Errorf("only %d queries found", len(queries))
	}
	rows := map[string]int{}
	for name, q := range queries {
		sql := expandMacros(q, now.Add(-6*time.Hour), now)
		if i := strings.Index(sql, "$"); i >= 0 && !strings.Contains(sql, "$$") {
			t.Errorf("%s: unexpanded variable in %q", name, sql[i:min(len(sql), i+30)])
			continue
		}
		r, err := conn.Query(ctx, sql)
		if err != nil {
			t.Errorf("%s: %v\n%s", name, err, sql)
			continue
		}
		n := 0
		var times []any
		labels := map[string]bool{}
		for r.Next() {
			n++
			vals, err := r.Values()
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(name, "shawk-rules.yaml") {
				// Grafana turns the rows into one series per label set and
				// needs every series to have a value at the last time.
				times = append(times, vals[0])
				l := fmt.Sprint(vals[1 : len(vals)-1])
				if labels[l] {
					t.Errorf("%s: label set %s twice", name, l)
				}
				labels[l] = true
			}
		}
		if err := r.Err(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, sql)
		}
		r.Close()
		rows[name] = n
		for _, tm := range times {
			if tm != times[0] {
				t.Errorf("%s: rows at different times %v", name, times)
				break
			}
		}
	}
	if n := rows["shawk-rules.yaml/shawk-dependencies/New dependency/A/A#0"]; n < 2 {
		t.Errorf("new dependency alert: %d rows, want several", n)
	}
	// Queries that must find the data above.
	for _, want := range []string{
		"shawk-map.json/shawk / Dependency map/Dependencies of $service/edges#0",
		"shawk-map.json/shawk / Dependency map/Dependencies of $service/nodes#0",
		"shawk-map.json/shawk / Dependency map/Edges/A#0",
		"shawk-fleet.json/shawk / Fleet/Agents/A#0",
		"shawk-fleet.json/shawk / Fleet/Dependencies that appeared today/A#0",
		"shawk-rules.yaml/shawk-dependencies/New dependency/A/A#0",
		"shawk-rules.yaml/shawk-dependencies/Disappeared dependency/A/A#0",
		"shawk-dependency.json/shawk / Dependency details/Dependencies in PostgreSQL/A#0",
		"shawk-changes.json/shawk / Changes/Changes/A#0",
		"shawk-changes.json/shawk / Changes/Changes per hour/A#0",
	} {
		if _, ok := rows[want]; !ok {
			t.Errorf("no query %s; have %v", want, keys(rows))
		} else if rows[want] == 0 {
			t.Errorf("%s returned no rows", want)
		}
	}
	if n, ok := rows["shawk-rules.yaml/shawk-agents/shawk agent silent/A/A#0"]; !ok || n != 0 {
		t.Error("the silent agent alert fires for live agents")
	}
}

func keys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestPGGrantsAsOwner runs the documented setup: the schema applied and
// grants.sql run by the owner of the database, not by a superuser.
func TestPGGrantsAsOwner(t *testing.T) {
	_, conn := testDB(t)
	ctx := context.Background()
	owner := fmt.Sprintf("shawk_owner_%d", time.Now().UnixNano())
	var db string
	conn.QueryRow(ctx, "SELECT current_database()").Scan(&db)
	execAll(t, conn,
		"CREATE ROLE "+owner+" NOLOGIN",
		"GRANT CREATE ON DATABASE "+db+" TO "+owner,
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_connector') THEN CREATE ROLE shawk_connector NOLOGIN; END IF;
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_grafana') THEN CREATE ROLE shawk_grafana NOLOGIN; END IF;
		 END $$`)
	t.Cleanup(func() {
		conn.Exec(ctx, "RESET ROLE")
		conn.Exec(ctx, "DROP OWNED BY "+owner+" CASCADE")
		conn.Exec(ctx, "DROP ROLE "+owner)
	})
	execAll(t, conn, "SET ROLE "+owner)
	if _, err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrating as the owner: %v", err)
	}
	grants, err := os.ReadFile(filepath.Join(packaging, "postgres/grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(grants)); err != nil {
		t.Fatalf("grants.sql as the owner: %v", err)
	}
	execAll(t, conn, "RESET ROLE", "SET ROLE shawk_connector")
	if _, err := conn.Exec(ctx, "INSERT INTO shawk.schema_migrations (version, name) VALUES (999, 'x')"); err == nil {
		t.Error("the connector can write the history of migrations")
	}
	now := time.Now()
	h := newHostChanges("h1")
	h.setHost("m", "h1", "k", "v", now)
	h.addSession(now.Add(-time.Hour), sessionRow{lastHeartbeat: now, netnsScope: "all"})
	h.addProcess(procKey{"a.service", "a", "a"}, "/usr/bin/a", span{now, now})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.0.2"), port: 80,
		netns: 1, procKey: procKey{"a.service", "a", "a"}}, span{now, now})
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) }); err != nil {
		t.Errorf("writing as the connector: %v", err)
	}
	var n int64
	if err := conn.QueryRow(ctx, "SELECT shawk.prune(now() - interval '3 years')").Scan(&n); err != nil {
		t.Errorf("pruning as the connector: %v", err)
	}
	execAll(t, conn, "RESET ROLE", "SET ROLE shawk_grafana")
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM shawk_v1.dependencies_between(now() - interval '1 hour', now())").Scan(&n); err != nil || n != 1 {
		t.Errorf("reading as Grafana: %d, %v", n, err)
	}
	if _, err := conn.Exec(ctx, "SELECT count(*) FROM shawk.edges"); err == nil {
		t.Error("Grafana can read the tables")
	}
	execAll(t, conn, "RESET ROLE")
}
