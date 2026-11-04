package shawkconnector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
		cfg.MaxPeers != 50 || cfg.MaxServices != 200 || cfg.PeerCIDRs["office-lan"] != "192.168.10.0/24" ||
		cfg.Retention != 3*365*24*time.Hour || cfg.HostIdentity != hostIdentityCertificate ||
		cfg.MaxHosts != 10000 || cfg.MaxSeriesPerHost != 100000 || cfg.MaxPendingRows != 10000000 {
		t.Errorf("config = %+v", cfg)
	}
	// Both receivers require client certificates, each from its own CA, so
	// that a certificate of OBI is refused by the receiver of agents; the
	// receiver of agents accepts the largest requests of an agent, over gRPC
	// only, which passes the client certificate on to the connector
	// (host_identity).
	clientCAs := map[string][]any{}
	for _, r := range []string{"otlp/shawk", "otlp"} {
		protocols, _ := doc.Receivers[r].(map[string]any)["protocols"].(map[string]any)
		for _, proto := range []string{"grpc", "http"} {
			if r == "otlp/shawk" && proto == "http" {
				if protocols[proto] != nil {
					t.Errorf("%s: HTTP carries no client certificate to the connector", r)
				}
				continue
			}
			p, _ := protocols[proto].(map[string]any)
			tls, _ := p["tls"].(map[string]any)
			if tls["client_ca_file"] == nil || tls["cert_file"] == nil || tls["key_file"] == nil {
				t.Errorf("%s %s: no TLS with client certificates: %v", r, proto, p)
			}
			clientCAs[r] = append(clientCAs[r], tls["client_ca_file"])
			if r != "otlp/shawk" {
				continue
			}
			if proto == "grpc" && p["max_recv_msg_size_mib"] != 16 {
				t.Errorf("%s: max_recv_msg_size_mib = %v", r, p["max_recv_msg_size_mib"])
			}
		}
	}
	for _, agents := range clientCAs["otlp/shawk"] {
		for _, obi := range clientCAs["otlp"] {
			if agents != nil && agents == obi {
				t.Errorf("otlp/shawk and otlp trust the same client CA %v: a certificate of OBI can send as an agent", agents)
			}
		}
	}
	// The exporters push over TLS, verify the server and authenticate:
	// whoever can push to Prometheus can write shawk_agent_up and silence
	// the alerts on agents. Secrets come from the environment, which the
	// unit of the collector reads from collector.env, not from this file.
	env, err := os.ReadFile(filepath.Join(packaging, "systemd/collector.env"))
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range doc.Exporters {
		e, _ := e.(map[string]any)
		endpoint, _ := e["endpoint"].(string)
		if endpoint == "" {
			continue // debug
		}
		tls, _ := e["tls"].(map[string]any)
		typ, _, _ := strings.Cut(name, "/")
		cleartext := strings.HasPrefix(endpoint, "http://") ||
			(typ == "otlp_http" || typ == "otlphttp") && !strings.HasPrefix(endpoint, "https://")
		if cleartext || tls["insecure"] == true || tls["insecure_skip_verify"] == true {
			t.Errorf("%s: pushes in cleartext or to an unverified server: %v", name, e)
		}
		headers, _ := e["headers"].(map[string]any)
		auth, _ := headers["Authorization"].(string)
		if auth == "" && (tls["cert_file"] == nil || tls["key_file"] == nil) {
			t.Errorf("%s: neither an Authorization header nor a client certificate: %v", name, e)
		}
		if auth == "" {
			continue
		}
		m := regexp.MustCompile(`^\$\{env:(\w+)\}$`).FindStringSubmatch(auth)
		if m == nil {
			t.Errorf("%s: the Authorization header is not taken from the environment: %q", name, auth)
		} else if !regexp.MustCompile(`(?m)^` + m[1] + `=`).Match(env) {
			t.Errorf("%s: %s is not in collector.env", name, m[1])
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

// dashboardVars are the values of the dashboard variables the queries are
// run with.
var dashboardVars = map[string][]string{
	"service":   {"postgres", "shop/app"},
	"src":       {"shop/app"},
	"dst":       {"postgres"},
	"direction": {"both"},
	"depth":     {"2"},
}

var sqlstringVar = regexp.MustCompile(`\$\{(\w+):sqlstring\}`)

// expandVars replaces ${name:sqlstring} of the variables in vars like
// Grafana does: each value in single quotes, with ' doubled and " escaped
// by a backslash, and the values separated by commas.
func expandVars(sql string, vars map[string][]string) string {
	escape := strings.NewReplacer("'", "''", `"`, `\"`)
	return sqlstringVar.ReplaceAllStringFunc(sql, func(s string) string {
		values, ok := vars[sqlstringVar.FindStringSubmatch(s)[1]]
		if !ok {
			return s
		}
		quoted := make([]string, len(values))
		for i, v := range values {
			quoted[i] = "'" + escape.Replace(v) + "'"
		}
		return strings.Join(quoted, ",")
	})
}

// expandMacros replaces the Grafana macros the queries use, and their
// variables with the values of dashboardVars.
func expandMacros(sql string, from, to time.Time) string {
	ts := func(t time.Time) string { return "'" + t.UTC().Format(time.RFC3339) + "'::timestamptz" }
	r := strings.NewReplacer(
		"$__timeFrom()", ts(from),
		"$__timeTo()", ts(to),
	)
	sql = r.Replace(expandVars(sql, dashboardVars))
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
	h.addSession(now.Add(-time.Hour), sessionRow{lastHeartbeat: now.Add(-time.Minute), netnsScope: "all",
		peerFold: foldIn, peerInternal: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	h.addAddr(addrOf("10.0.0.30"), span{now, now})
	h.addProcess(procKey{"x.service", "x", "x", ""}, "/usr/bin/x", span{now, now})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.30"), peer: addrOf("10.0.0.10"), port: 5432,
		netns: 1, procKey: procKey{"x.service", "x", "x", ""}}, span{now, now})
	h.addEdge(edgeRowKey{role: "server", proto: "tcp", local: addrOf("10.0.0.30"), peer: addrOf("0.0.0.0"), folded: true,
		port: 9000, netns: 1, procKey: procKey{"x.service", "x", "x", ""}}, span{now, now})
	h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: 9000, netns: 1, procKey: procKey{"x.service", "x", "x", ""}}, span{now, now})
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) }); err != nil {
		t.Errorf("writing as shawk_connector: %v", err)
	}
	// The agent dropped flows in the minute since: a partly observed period.
	h = newHostChanges(hostKey("m-x", "x-01"))
	h.setHost("m-x", "x-01", "5.14", "test", now)
	h.addSession(now.Add(-time.Hour), sessionRow{lastHeartbeat: now, netnsScope: "all", dropped: 3, peerFold: foldIn})
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) }); err != nil {
		t.Errorf("writing dropped flows as shawk_connector: %v", err)
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
		"shawk-fleet.json/shawk / Fleet/Partly observed/Anno#0",
		"shawk-fleet.json/shawk / Fleet/Partly observed periods in the time range/A#0",
		"shawk-dependency.json/shawk / Dependency details/Partly observed/Anno#0",
		"shawk-changes.json/shawk / Changes/Partly observed/Anno#0",
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

// TestPGGrantsAsOwner runs the documented setup: what setup.sql runs in the
// database as a superuser, then the schema applied and grants.sql run by
// the owner of the database, not by a superuser. Neither the connector nor
// Grafana may then create objects in the database.
func TestPGGrantsAsOwner(t *testing.T) {
	_, conn := testDB(t)
	ctx := context.Background()
	owner := fmt.Sprintf("shawk_owner_%d", time.Now().UnixNano())
	var db string
	conn.QueryRow(ctx, "SELECT current_database()").Scan(&db)
	execAll(t, conn,
		"CREATE ROLE "+owner+" NOLOGIN",
		"ALTER DATABASE "+db+" OWNER TO "+owner,
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_connector') THEN CREATE ROLE shawk_connector NOLOGIN; END IF;
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_grafana') THEN CREATE ROLE shawk_grafana NOLOGIN; END IF;
		 END $$`,
		// The schema public as PostgreSQL 14 has it: the superuser owns it
		// and every role may create objects in it.
		"ALTER SCHEMA public OWNER TO CURRENT_USER",
		"GRANT CREATE ON SCHEMA public TO PUBLIC")
	t.Cleanup(func() {
		conn.Exec(ctx, "RESET ROLE")
		conn.Exec(ctx, "ALTER DATABASE "+db+" OWNER TO CURRENT_USER")
		conn.Exec(ctx, "DROP OWNED BY "+owner+" CASCADE")
		conn.Exec(ctx, "DROP ROLE "+owner)
	})
	setup, err := os.ReadFile(filepath.Join(packaging, "postgres/setup.sql"))
	if err != nil {
		t.Fatal(err)
	}
	_, inDB, ok := strings.Cut(string(setup), "\n\\connect shawk\n")
	if !ok {
		t.Fatal("setup.sql does not connect to the database shawk")
	}
	// The commands of psql, such as \password, are not SQL.
	var sql []string
	for _, line := range strings.Split(inDB, "\n") {
		if !strings.HasPrefix(line, "\\") {
			sql = append(sql, line)
		}
	}
	inDB = strings.Join(sql, "\n")
	execAll(t, conn, inDB, "SET ROLE "+owner)
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
	h.addProcess(procKey{"a.service", "a", "a", ""}, "/usr/bin/a", span{now, now})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.0.2"), port: 80,
		netns: 1, procKey: procKey{"a.service", "a", "a", ""}}, span{now, now})
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) }); err != nil {
		t.Errorf("writing as the connector: %v", err)
	}
	var n int64
	if err := conn.QueryRow(ctx, "SELECT shawk.prune(now() - interval '3 years')").Scan(&n); err != nil {
		t.Errorf("pruning as the connector: %v", err)
	}
	// The connector writes the inventory (store.go).
	inv := must(parseInventory([]byte(testInventory)))
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return replaceInventory(ctx, tx, inv) }); err != nil {
		t.Errorf("writing the inventory as the connector: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO shawk.inventory_state (digest, read_at) VALUES ('d', now())
	    ON CONFLICT (singleton) DO UPDATE SET read_at = excluded.read_at`); err != nil {
		t.Errorf("writing the state of the inventory as the connector: %v", err)
	}
	execAll(t, conn, "RESET ROLE", "SET ROLE shawk_grafana")
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM shawk_v1.dependencies_between(now() - interval '1 hour', now())").Scan(&n); err != nil || n != 1 {
		t.Errorf("reading as Grafana: %d, %v", n, err)
	}
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM shawk_v1.never_observed()) + (SELECT count(*) FROM shawk_v1.inventory)
	    + (SELECT count(*) FROM shawk_v1.inventory_addrs) + (SELECT count(*) FROM shawk_v1.inventory_status)`).Scan(&n); err != nil || n != 2+3+6+1 {
		t.Errorf("reading the inventory as Grafana: %d, %v", n, err)
	}
	if _, err := conn.Exec(ctx, "SELECT count(*) FROM shawk.edges"); err == nil {
		t.Error("Grafana can read the tables")
	}
	execAll(t, conn, "RESET ROLE")
	// Neither role may create objects of its own, even in a transaction
	// that is not read-only: no table or function in public, no temporary
	// table, no large object.
	for _, role := range []string{"shawk_connector", "shawk_grafana"} {
		var public, temp, largeObjects bool
		if err := conn.QueryRow(ctx, `SELECT has_schema_privilege($1, 'public', 'CREATE'),
		    has_database_privilege($1, current_database(), 'TEMPORARY'),
		    has_function_privilege($1, 'lo_creat(integer)', 'EXECUTE') OR has_function_privilege($1, 'lo_create(oid)', 'EXECUTE')
		      OR has_function_privilege($1, 'lo_from_bytea(oid, bytea)', 'EXECUTE')`, role).Scan(&public, &temp, &largeObjects); err != nil {
			t.Fatal(err)
		}
		if public || temp || largeObjects {
			t.Errorf("%s may create objects in public: %v, temporary tables: %v, large objects: %v", role, public, temp, largeObjects)
		}
	}
}

// TestPGDetailsFilterPeerCIDRs: the dependency details panel finds the
// dependencies with a peer named by peer_cidrs, which Prometheus offers.
func TestPGDetailsFilterPeerCIDRs(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("web-01", "web")
	execAll(t, conn, `INSERT INTO shawk.peer_cidrs VALUES ('192.168.10.0/24', 'office-lan')`)
	f.edge("web-01", "web", "client", "10.0.0.11", "192.168.10.5", 389, "now()-interval '1 hour'", "now()")
	q := packagedSQL(t)["shawk-dependency.json/shawk / Dependency details/Dependencies in PostgreSQL/A#0"]
	if q == "" {
		t.Fatal("no query")
	}
	now := time.Now()
	sql := expandMacros(expandVars(q, map[string][]string{"src": {"web"}, "dst": {"office-lan"}}), now.Add(-6*time.Hour), now)
	if got := queryStrings(t, conn, sql); len(got) != 1 {
		t.Errorf("rows = %v", got)
	}
}

// TestPGSilentAlertReinstall: the silent agent alert does not name a host
// that was reinstalled under a new host id and is alive, nor fire together
// with the Prometheus alert in the first 24 hours.
func TestPGSilentAlertReinstall(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES
		   ('old','m1','web-1','k','v',now()-interval '30 days',now()-interval '2 days'),
		   ('new','m2','web-1','k','v',now()-interval '2 days',now()),
		   ('dead','m3','web-2','k','v',now()-interval '30 days',now()-interval '2 days'),
		   ('recent','m4','web-3','k','v',now()-interval '30 days',now()-interval '1 hour')`,
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope) VALUES
		   ('old', now()-interval '30 days', now()-interval '2 days', true, 'all'),
		   ('new', now()-interval '2 days', now(), true, 'all'),
		   ('dead', now()-interval '30 days', now()-interval '2 days', true, 'all'),
		   ('recent', now()-interval '30 days', now()-interval '1 hour', true, 'all')`)
	q := packagedSQL(t)["shawk-rules.yaml/shawk-agents/shawk agent silent/A/A#0"]
	rows, err := conn.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		vals, _ := rows.Values()
		got = append(got, fmt.Sprint(vals[1:len(vals)-1]))
	}
	rows.Close()
	if !slices.Equal(got, []string{"[web-2 dead]"}) {
		t.Errorf("silent agents = %v", got)
	}
}

// TestPGMapWalkHubs: the map walks every service once rather than every
// path, which would explode around shared services at a depth of 5.
func TestPGMapWalkHubs(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("hub1", "postgres")
	f.host("hub2", "dns")
	for i := range 300 {
		host, svc, addr := fmt.Sprintf("h%d", i), fmt.Sprintf("s%d", i), fmt.Sprintf("10.1.%d.%d", i/250, i%250+1)
		f.host(host, svc)
		f.conn2(host, svc, addr, "hub1", "postgres", "10.0.0.1", 5432, "now()-interval '1 hour'", "now()")
		f.conn2(host, svc, addr, "hub2", "dns", "10.0.0.2", 53, "now()-interval '1 hour'", "now()")
	}
	q := packagedSQL(t)["shawk-map.json/shawk / Dependency map/Dependencies of $service/nodes#0"]
	now := time.Now()
	sql := expandMacros(expandVars(q, map[string][]string{"service": {"s1"}, "depth": {"5"}}), now.Add(-6*time.Hour), now)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	rows, err := conn.Query(ctx, sql)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		n++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	d := time.Since(start)
	t.Logf("%d nodes in %s", n, d)
	if d > 3*time.Second || n != 302 {
		t.Errorf("%d nodes in %s", n, d)
	}
}

// TestPGMapCraftedVariables: the values of the variables of the map, which
// a link can set (?var-service=, ?var-direction=, ?var-depth=), stay
// values: a quote does not end a string, and a depth that is not a number
// fails the query.
func TestPGMapCraftedVariables(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("db-01", "postgres")
	f.host("app-01", "app")
	f.conn2("app-01", "app", "10.0.0.11", "db-01", "postgres", "10.0.0.10", 5432, "now()-interval '1 hour'", "now()")
	all := packagedSQL(t)
	const nodes = "shawk-map.json/shawk / Dependency map/Dependencies of $service/nodes#0"
	queries := []string{nodes,
		"shawk-map.json/shawk / Dependency map/Dependencies of $service/edges#0",
		"shawk-map.json/shawk / Dependency map/Edges/A#0"}
	now := time.Now()
	// run runs a query with the values of vars, or else those of a walk
	// from postgres, and returns the first column.
	run := func(name string, vars map[string][]string) ([]string, error) {
		sql := expandVars(expandVars(all[name], vars), map[string][]string{"service": {"postgres"}, "direction": {"both"}, "depth": {"2"}})
		rows, err := conn.Query(context.Background(), expandMacros(sql, now.Add(-6*time.Hour), now))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				return nil, err
			}
			out = append(out, fmt.Sprint(vals[0]))
		}
		return out, rows.Err()
	}
	if got, err := run(nodes, nil); err != nil || !slices.Equal(got, []string{"app", "postgres"}) {
		t.Fatalf("nodes = %v, %v; want app and postgres", got, err)
	}
	// Quoted, the values name neither a direction nor a service.
	if got, err := run(nodes, map[string][]string{"direction": {"downstream' OR 'x' = 'x"}}); err != nil || !slices.Equal(got, []string{"postgres"}) {
		t.Errorf("crafted direction: nodes = %v, %v; want postgres", got, err)
	}
	if got, err := run(nodes, map[string][]string{"service": {`postgres' OR "x" = 'x`}}); err != nil || len(got) != 0 {
		t.Errorf("crafted service: nodes = %v, %v; want none", got, err)
	}
	for _, depth := range []string{"1 OR true", "(SELECT 9)", "1) SELECT 1 --", "1; SELECT 1"} {
		for _, name := range queries {
			got, err := run(name, map[string][]string{"depth": {depth}})
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "22P02" {
				t.Errorf("%s: depth %q: %v, %v; want invalid input syntax for type integer", name, depth, got, err)
			}
		}
	}
}
