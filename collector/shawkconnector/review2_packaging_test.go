package shawkconnector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// PostgreSQL tests of the dashboards and alerts in packaging/ for the
// findings of a second adversarial review.

// TestPGDetailsFilterPeerCIDRs: the dependency details panel found no
// dependency with a peer named by peer_cidrs, which Prometheus offers.
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
	sql := expandMacros(strings.NewReplacer("${src:singlequote}", "'web'", "${dst:singlequote}", "'office-lan'").Replace(q),
		now.Add(-6*time.Hour), now)
	if got := queryStrings(t, conn, sql); len(got) != 1 {
		t.Errorf("rows = %v", got)
	}
}

// TestPGSilentAlertReinstall: the silent agent alert named a host that had
// been reinstalled under a new host id and was alive; it also fired
// together with the Prometheus alert in the first 24 hours.
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

// TestPGMapWalkHubs: the map walked every path rather than every service,
// which explodes around shared services at a depth of 5.
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
	sql := strings.Replace(expandMacros(strings.ReplaceAll(q, "$depth", "5"), now.Add(-6*time.Hour), now),
		"'postgres', 'shop/app'", "'s1'", 1)
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
