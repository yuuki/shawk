package shawkconnector

import (
	"fmt"
	"slices"
	"testing"
)

// TestPGUnobservedClockAhead: with an agent clock ahead of the connector, a
// young session whose start, by the clock of the agent, is after its
// heartbeat, by the clock of the connector, is converted with the clock
// skew: the host was not observed until the session started.
func TestPGUnobservedClockAhead(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h1','m','h1','k','v',now()-interval '1 day',now()),
		                                ('h2','m','h2','k','v',now()-interval '1 day',now())`,
		// h1's clock is 9 minutes ahead; its session started 1 minute ago.
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope, clock_skew)
		 VALUES ('h1', now() + interval '8 minutes', now(), true, 'all', interval '-9 minutes'),
		        ('h2', now() - interval '2 hours', now(), true, 'all', '0')`)
	got := queryStrings(t, conn, `SELECT host, round(extract(epoch FROM gap_end - now()) / 60)::int
		FROM shawk_v1.unobserved(now() - interval '1 hour', now())`)
	// h1 was not observed until a minute ago; h2 all along.
	if !slices.Equal(got, []string{"h1 -1"}) {
		t.Errorf("unobserved = %v", got)
	}
}

// TestPGSharedAddressReuse: an address reused by another host within 5
// minutes does not count as shared.
func TestPGSharedAddressReuse(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('old','m','old','k','v',now()-interval '60 days',now()-interval '30 days'),
		  ('new','m','new','k','v',now()-interval '30 days',now()),
		  ('a','m','a','k','v',now()-interval '1 day',now()), ('b','m','b','k','v',now()-interval '1 day',now())`,
		`INSERT INTO shawk.host_addrs VALUES
		  ('old','10.0.0.2',now()-interval '60 days',now()-interval '30 days 2 minutes'),
		  ('new','10.0.0.2',now()-interval '30 days',now()),
		  ('a','172.17.0.1',now()-interval '1 day',now()), ('b','172.17.0.1',now()-interval '1 day',now())`)
	got := queryStrings(t, conn, `SELECT host(addr) FROM shawk.shared_addrs`)
	if !slices.Equal(got, []string{"172.17.0.1"}) {
		t.Errorf("shared_addrs = %v", got)
	}
}

// TestPGEndpointsCurrentAddresses: a listener on 0.0.0.0 is expanded to the
// current addresses of its host only, and endpoints tell whether they were
// observed on a socket.
func TestPGEndpointsCurrentAddresses(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h','m','portal-01','k','v',now()-interval '400 days',now())`,
		`INSERT INTO shawk.host_addrs VALUES ('h','10.0.0.50',now()-interval '400 days',now()-interval '365 days'),
		  ('h','10.0.1.50',now()-interval '365 days',now())`,
		`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
		 VALUES ('h','portal.service','portal','','portal',now()-interval '400 days',now())`,
		`INSERT INTO shawk.listeners VALUES ('h',(SELECT id FROM shawk.processes),'tcp','0.0.0.0',443,1,now()-interval '400 days',now())`,
		`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		 VALUES ('h',(SELECT id FROM shawk.processes),'server','tcp','10.0.1.50','10.0.9.9',443,1,now()-interval '1 day',now())`)
	got := queryStrings(t, conn, `SELECT host(addr), port, exact FROM shawk_v1.service_endpoints`)
	if !slices.Equal(got, []string{"10.0.1.50 443 true"}) {
		t.Errorf("service_endpoints = %v", got)
	}
}

// TestPGAgentAddrsCoverage: agent_addrs tells what the agent traces.
func TestPGAgentAddrsCoverage(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h','m','h','k','v',now(),now())`,
		`INSERT INTO shawk.host_addrs VALUES ('h','10.0.0.1',now(),now())`,
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope)
		 VALUES ('h', now()-interval '2 days', now()-interval '1 day', true, 'all'),
		        ('h', now()-interval '1 hour', now(), false, '4026532001')`)
	got := queryStrings(t, conn, `SELECT host(addr), udp_traced, netns_scope FROM shawk_v1.agent_addrs`)
	if !slices.Equal(got, []string{"10.0.0.1 false 4026532001"}) {
		t.Errorf("agent_addrs = %v", got)
	}
}

// TestPGReturningDependencyIsNotNew: a dependency idle for a while that comes
// back on new edges, e.g. from a new container, is not reported as appeared.
func TestPGReturningDependencyIsNotNew(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("report-01", "report")
	f.host("report-02", "report")
	f.host("db-01", "postgres")
	f.host("cache-01", "memcached")
	f.conn2("report-01", "report", "10.0.0.21", "db-01", "postgres", "10.0.0.10", 5432,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 hour'")
	// The history is built from all edges, as when the schema is migrated
	// over existing data.
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	// It comes back from another host, and a dependency never seen appears.
	f.conn2("report-02", "report", "10.0.0.22", "db-01", "postgres", "10.0.0.10", 5432,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	f.conn2("report-02", "report", "10.0.0.22", "cache-01", "memcached", "10.0.0.30", 11211,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	got := queryStrings(t, conn, `SELECT change, client_service, server_service
		FROM shawk_v1.dependency_changes_between(now() - interval '15 minutes', now())`)
	if !slices.Equal(got, []string{"appeared report memcached"}) {
		t.Errorf("changes = %v", got)
	}
}

// TestPGRotatingAddressesFold: a peer without a service is named by
// peer_class rather than by its address, so that a new address of a cloud
// API is not a new dependency, nor an address it stops using a disappeared
// one.
func TestPGRotatingAddressesFold(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("web-01", "web")
	execAll(t, conn, `INSERT INTO shawk.peer_cidrs VALUES ('192.168.10.0/24', 'office-lan')`)
	for i := range 6 {
		f.edge("web-01", "web", "client", "10.0.0.11", fmt.Sprintf("3.5.%d.20", i), 443,
			fmt.Sprintf("now()-interval '%d minutes'", 60-i*5), fmt.Sprintf("now()-interval '%d minutes'", 30-i*5))
	}
	f.edge("web-01", "web", "client", "10.0.0.11", "192.168.10.5", 389, "now()-interval '1 day'", "now()")
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	got := queryStrings(t, conn, `SELECT change, client_service, server_service
		FROM shawk_v1.dependency_changes_between(now() - interval '40 minutes', now())`)
	if len(got) != 0 {
		t.Errorf("changes = %v", got)
	}
	got = queryStrings(t, conn, `SELECT source, target FROM shawk_v1.graph_edges_between(now() - interval '1 day', now())`)
	if !slices.Equal(got, []string{"web office-lan", "web ~external"}) {
		t.Errorf("graph_edges = %v", got)
	}
}

// TestPGWindowEdgeSides: at the edges of a period both sides of a
// connection are matched, rather than one left out and the other coming out
// alone named after its address.
func TestPGWindowEdgeSides(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("web-01", "web")
	f.host("db-01", "postgres")
	f.edge("web-01", "web", "client", "10.0.0.11", "10.0.0.10", 5432, "now()-interval '2 hours'", "now()-interval '29 minutes 40 seconds'")
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.11", 5432, "now()-interval '2 hours'", "now()-interval '30 minutes 20 seconds'")
	got := queryStrings(t, conn, `SELECT client_service, server_service, observed_by
		FROM shawk_v1.dependencies_between(now() - interval '30 minutes', now())`)
	if !slices.Equal(got, []string{"web postgres both"}) {
		t.Errorf("dependencies_between = %v", got)
	}
	// A connection active only before the period is not in it.
	got = queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.dependencies_between(now() - interval '20 minutes', now())`)
	if !slices.Equal(got, []string{"0"}) {
		t.Errorf("dependencies in the last 20 minutes = %v", got)
	}
}
