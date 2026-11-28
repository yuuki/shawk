package shawkconnector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The tests in this file run the functions of 0006_policy.sql against
// PostgreSQL (SHAWK_TEST_POSTGRES_DSN): the flows that rules are made
// from, the verdicts on what the history tells, and the drift from a
// baseline.

// days is the length of a day, for the times of the fixtures.
const days = 24 * time.Hour

// policyFixture writes rows of the schema at times before T, the end of
// the periods of a test: the start of the current hour, so that the last
// known endpoints of hosts (shawk_v1.service_endpoints), which are read
// as of now, hold.
type policyFixture struct {
	t    *testing.T
	conn *pgx.Conn
	T    time.Time
}

func newPolicyFixture(t *testing.T) policyFixture {
	t.Helper()
	_, conn := migratedDB(t)
	return policyFixture{t, conn, time.Now().UTC().Truncate(time.Hour)}
}

// ago is the time d before T, as SQL.
func (f policyFixture) ago(d time.Duration) string { return ts(f.T.Add(-d)) }

func (f policyFixture) exec(format string, args ...any) {
	f.t.Helper()
	execAll(f.t, f.conn, fmt.Sprintf(format, args...))
}

// host adds a host with an address whose agent observed everything from
// 100 days before T to T.
func (f policyFixture) host(name, addr string) {
	f.t.Helper()
	f.hostObserved(name, addr, 100*days, 0)
}

// hostObserved adds a host with an address whose agent observed from
// `from` to `to` before T.
func (f policyFixture) hostObserved(name, addr string, from, to time.Duration) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.hosts VALUES ('%[1]s', 'm-%[1]s', '%[1]s', 'k', 'v', %[2]s, %[3]s)`, name, f.ago(from), f.ago(to))
	f.session(name, from, to, "true", "'all'")
	if addr != "" {
		f.exec(`INSERT INTO shawk.host_addrs VALUES ('%s', '%s', %s, %s)`, name, addr, f.ago(from), f.ago(to))
	}
}

// session adds a session of the agent of a host.
func (f policyFixture) session(host string, from, to time.Duration, udp, netns string) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
	        VALUES ('%s', %s, %s, %s, true, %s)`, host, f.ago(from), f.ago(to), udp, netns)
}

// proc adds a process of a unit and a service on a host, seen all along.
func (f policyFixture) proc(host, unit, service string) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('%s', '%s', 'c', '', '%s', %s, %s)`, host, unit, service, f.ago(100*days), f.ago(0))
}

// edge adds an edge of the process of a service on a host, in network
// namespace 1, first and last seen `first` and `last` before T.
func (f policyFixture) edge(host, service, role, proto, local, remote string, port int, first, last time.Duration) {
	f.t.Helper()
	f.edgeIn(1, host, service, role, proto, local, remote, port, first, last)
}

func (f policyFixture) edgeIn(netns int, host, service, role, proto, local, remote string, port int, first, last time.Duration) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
	        VALUES ('%[1]s', (SELECT id FROM shawk.processes WHERE host_id = '%[1]s' AND service_name = '%[2]s'),
	                '%[3]s', '%[4]s', '%[5]s', '%[6]s', %[7]d, %[8]d, %[9]s, %[10]s)`,
		host, service, role, proto, local, remote, port, netns, f.ago(first), f.ago(last))
}

// pair adds both sides of a TCP connection, active from `first` to `last`
// before T.
func (f policyFixture) pair(clientHost, clientSvc, clientAddr, serverHost, serverSvc, serverAddr string, port int, first, last time.Duration) {
	f.t.Helper()
	f.edge(clientHost, clientSvc, "client", "tcp", clientAddr, serverAddr, port, first, last)
	f.edge(serverHost, serverSvc, "server", "tcp", serverAddr, clientAddr, port, first, last)
}

// listener adds a listener of the process of a service on a host, with
// its owner, seen all along; chosen is when the kernel chose its port,
// "NULL" if it did not.
func (f policyFixture) listener(host, service, addr string, port int, chosen string) {
	f.t.Helper()
	f.exec(`
WITH p AS (SELECT id FROM shawk.processes WHERE host_id = '%[1]s' AND service_name = '%[2]s'),
l AS (INSERT INTO shawk.listeners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
      SELECT '%[1]s', p.id, 'tcp', '%[3]s', %[4]d, 1, %[5]s, %[6]s FROM p)
INSERT INTO shawk.listener_owners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen, kernel_chosen_seen)
SELECT '%[1]s', p.id, 'tcp', '%[3]s', %[4]d, 1, %[5]s, %[6]s, %[7]s FROM p`,
		host, service, addr, port, f.ago(100*days), f.ago(0), chosen)
}

// query returns the rows of a query over the period of `lookback` before
// T, which the query names $1 and $2, as strings.
func (f policyFixture) query(lookback time.Duration, sql string, args ...any) []string {
	f.t.Helper()
	return queryStrings(f.t, f.conn, sql, append([]any{f.T.Add(-lookback), f.T}, args...)...)
}

const flowColumns = `direction, in_period, service, proto, peer_addr::text, port_from, port_to, peer, coalesce(peer_host, '-'),
	translated, kernel_chosen`

// TestPGPolicyFlows: the flows of a host are the addresses and ports its
// sockets saw, each with the name of its peer, and the flows last seen
// before the period are listed apart.
func TestPGPolicyFlows(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("db-01", "10.0.0.10")
	f.host("web-01", "10.0.0.12")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("app-01", "backup.service", "backup")
	f.proc("app-01", "~unknown", "~unknown")
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.proc("web-01", "nginx.service", "nginx")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "shop/postgres", "10.0.0.10", 5432, 80*days, 0)
	f.pair("web-01", "nginx", "10.0.0.12", "app-01", "shop/app", "10.0.0.11", 8080, 80*days, 0)
	// A resolver without an agent, over UDP; the folded peers of a client
	// and of a server; and a job that last ran before the period.
	f.edge("app-01", "shop/app", "client", "udp", "10.0.0.11", "10.0.0.53", 53, 80*days, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "0.0.0.0/0", 443, 80*days, days)
	f.edge("app-01", "shop/app", "server", "tcp", "10.0.0.11", "0.0.0.0/0", 8080, 80*days, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.9.9", 9000, 99*days, 95*days)
	// Another unit of the host, and a socket whose owner is not known.
	f.edge("app-01", "backup", "client", "tcp", "10.0.0.11", "10.0.0.20", 873, 80*days, 0)
	f.edge("app-01", "~unknown", "client", "tcp", "10.0.0.11", "10.0.0.30", 9999, 80*days, 0)
	// The same flow from two addresses of the host is one flow.
	f.edge("app-01", "shop/app", "client", "tcp", "10.1.0.11", "10.0.0.20", 873, 10*days, 5*days)
	f.edge("app-01", "shop/app", "client", "tcp", "10.2.0.11", "10.0.0.20", 873, 4*days, 2*days)

	want := []string{
		"egress false shop/app tcp 10.0.9.9/32 9000 9000 ~unresolved - false false",
		"egress true backup tcp 10.0.0.20/32 873 873 ~unresolved - false false",
		"egress true shop/app tcp 0.0.0.0/0 443 443 ~external - false false",
		"egress true shop/app tcp 10.0.0.10/32 5432 5432 shop/postgres db-01 false false",
		"egress true shop/app tcp 10.0.0.20/32 873 873 ~unresolved - false false",
		"egress true shop/app udp 10.0.0.53/32 53 53 ~unresolved - false false",
		"egress true ~unknown tcp 10.0.0.30/32 9999 9999 ~unresolved - false false",
		"ingress true shop/app tcp 0.0.0.0/0 8080 8080 ~external - false false",
		"ingress true shop/app tcp 10.0.0.12/32 8080 8080 nginx web-01 false false",
	}
	if got := f.query(90*days, `SELECT `+flowColumns+` FROM shawk_v1.policy_flows('app-01', $1, $2)`); !slices.Equal(got, want) {
		t.Errorf("flows of app-01:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Those of a unit: its processes, and the sockets without a known
	// owner of the host, which may be its own.
	want = slices.DeleteFunc(want, func(s string) bool { return strings.Contains(s, " backup ") })
	if got := f.query(90*days, `SELECT `+flowColumns+` FROM shawk_v1.policy_flows('app-01', $1, $2, 'app.service')`); !slices.Equal(got, want) {
		t.Errorf("flows of app.service:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A flow is listed with when it was seen, over all its edges.
	got := f.query(90*days, `SELECT first_seen = `+f.ago(10*days)+`, last_seen = `+f.ago(2*days)+`
		FROM shawk_v1.policy_flows('app-01', $1, $2) WHERE service = 'shop/app' AND port = 873`)
	if !slices.Equal(got, []string{"true true"}) {
		t.Errorf("the times of a flow of two edges: %v", got)
	}
	// A period that the job is in has it; one that nothing is in, a host
	// that no agent reported under and an empty period have no flow.
	if got := f.query(98*days, `SELECT in_period FROM shawk_v1.policy_flows('app-01', $1, $2) WHERE port = 9000`); !slices.Equal(got, []string{"true"}) {
		t.Errorf("the job in a period that holds it: %v", got)
	}
	for _, q := range []string{
		`SELECT count(*) FROM shawk_v1.policy_flows('app-O1', $1, $2)`,
		`SELECT count(*) FROM shawk_v1.policy_flows('app-01', $2, $1)`,
		`SELECT count(*) FROM shawk_v1.policy_flows('app-01', $1, $2, 'nginx.service') WHERE service <> '~unknown'`,
	} {
		if got := f.query(90*days, q); !slices.Equal(got, []string{"0"}) {
			t.Errorf("%s = %v, want 0", q, got)
		}
	}
}

// TestPGPolicyFlowsPorts: under the rules of ports a flow allows the range
// of the rule, or every port of a server that listens on another one at
// every run, and a port that the kernel chose and no rule covers is told.
func TestPGPolicyFlowsPorts(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("login-01", "10.0.0.60")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("login-01", "session.scope", "srun")
	f.proc("login-01", "x.service", "x")
	f.exec(`INSERT INTO shawk.port_agnostic_services VALUES ('srun')`)
	f.exec(`INSERT INTO shawk.dynamic_ports VALUES ('nodeports', 'tcp', '10.0.0.0/24', 30000, 32767), ('wide', 'tcp', '10.0.0.0/8', 31000, 33000)`)
	// A server of port_agnostic_services, one in a range of dynamic_ports,
	// one on a port the kernel chose that no rule covers, and one outside
	// the addresses of the ranges.
	f.pair("app-01", "shop/app", "10.0.0.11", "login-01", "srun", "10.0.0.60", 41000, 20*days, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.70", 31500, 20*days, 0)
	f.pair("app-01", "shop/app", "10.0.0.11", "login-01", "x", "10.0.0.60", 45678, 20*days, 0)
	f.listener("login-01", "x", "0.0.0.0", 45678, f.ago(days))
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "192.0.2.7", 31500, 20*days, 0)
	// The same for the servers of the host itself.
	f.proc("app-01", "session.scope", "srun")
	f.edge("app-01", "srun", "server", "tcp", "10.0.0.11", "10.0.0.60", 52000, 20*days, 0)
	f.edge("app-01", "shop/app", "server", "tcp", "10.0.0.11", "10.0.0.60", 30080, 20*days, 0)
	f.edge("app-01", "shop/app", "server", "tcp", "10.0.0.11", "10.0.0.60", 46000, 20*days, 0)
	f.listener("app-01", "shop/app", "0.0.0.0", 46000, f.ago(days))
	want := []string{
		"egress true shop/app tcp 10.0.0.60/32 1 65535 srun login-01 false false",
		"egress true shop/app tcp 10.0.0.60/32 45678 45678 x login-01 false true",
		"egress true shop/app tcp 10.0.0.70/32 30000 33000 ~unresolved - false false",
		"egress true shop/app tcp 192.0.2.7/32 31500 31500 ~external - false false",
		"ingress true shop/app tcp 10.0.0.60/32 30000 32767 ~unresolved - false false",
		"ingress true shop/app tcp 10.0.0.60/32 46000 46000 ~unresolved - false true",
		"ingress true srun tcp 10.0.0.60/32 1 65535 ~unresolved - false false",
	}
	if got := f.query(30*days, `SELECT `+flowColumns+` FROM shawk_v1.policy_flows('app-01', $1, $2)`); !slices.Equal(got, want) {
		t.Errorf("flows of app-01:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGPolicyFlowsTranslated: a connection that the host itself
// translates, in the network namespace of its socket, also allows the
// backend, which is where its packets leave for; one that a pod of the
// host opens is translated in another namespace, after what filters it.
func TestPGPolicyFlowsTranslated(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("node-01", "10.0.0.11")
	f.proc("node-01", "kubelet.service", "kubelet")
	f.proc("node-01", "k8s/default/web/app", "web")
	f.edge("node-01", "kubelet", "client", "tcp", "10.0.0.11", "10.96.0.1", 443, 20*days, 0)
	f.edgeIn(7, "node-01", "web", "client", "tcp", "10.244.1.5", "10.96.0.1", 443, 20*days, 0)
	f.exec(`INSERT INTO shawk.learned_translations VALUES
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.96.0.1', 443, '10.0.0.11', '10.0.0.40', 6443, %[1]s, %[2]s),
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.96.0.1', 443, '10.0.0.11', '10.0.0.41', 6443, %[1]s, %[2]s),
	  ('node-01', 'tcp', 1, '10.244.1.5', '10.96.0.1', 443, '10.244.1.5', '10.0.0.42', 6443, %[1]s, %[2]s),
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.96.0.9', 443, '10.0.0.11', '10.0.0.43', 6443, %[1]s, %[2]s),
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.96.0.1', 443, '10.0.0.11', '10.0.0.44', 6443, %[3]s, %[4]s)`,
		f.ago(20*days), f.ago(0), f.ago(99*days), f.ago(95*days))
	want := []string{
		"egress true kubelet tcp 10.0.0.40/32 6443 6443 ~unresolved - true false",
		"egress true kubelet tcp 10.0.0.41/32 6443 6443 ~unresolved - true false",
		"egress true kubelet tcp 10.96.0.1/32 443 443 ~unresolved - false false",
		"egress true web tcp 10.96.0.1/32 443 443 ~unresolved - false false",
	}
	if got := f.query(30*days, `SELECT `+flowColumns+` FROM shawk_v1.policy_flows('node-01', $1, $2)`); !slices.Equal(got, want) {
		t.Errorf("flows of node-01:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The sockets of the flows are in two network namespaces: a host of
	// containers.
	if got := f.query(30*days, `SELECT status, network_namespaces FROM shawk_v1.policy_verdict('node-01', $1, $2)`); !slices.Equal(got, []string{"COMPLETE 2"}) {
		t.Errorf("verdict of node-01: %v", got)
	}
	if got := f.query(30*days, `SELECT status, network_namespaces FROM shawk_v1.policy_verdict('node-01', $1, $2, 'kubelet.service')`); !slices.Equal(got, []string{"COMPLETE 1"}) {
		t.Errorf("verdict of kubelet.service: %v", got)
	}
}

const verdictColumns = `status, reasons, caveats, coverage::text, extract(epoch FROM unobserved)::integer, gaps`

// TestPGPolicyVerdict: the flows are complete only when the history tells
// all of them for the whole period, and a target that is not known is
// never complete.
func TestPGPolicyVerdict(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.proc("app-01", "app.service", "shop/app")
	// An hour without an agent 10 days ago.
	f.exec(`INSERT INTO shawk.hosts VALUES ('gap-01', 'm', 'gap-01', 'k', 'v', %s, %s)`, f.ago(100*days), f.ago(0))
	f.session("gap-01", 100*days, 10*days, "true", "'all'")
	f.session("gap-01", 10*days-time.Hour-3*time.Minute, 0, "true", "'all'")
	// An agent that did not trace UDP for the last 9 days, one that traced
	// one network namespace, and one that dropped flows for an hour.
	f.exec(`INSERT INTO shawk.hosts VALUES ('udp-01', 'm', 'udp-01', 'k', 'v', %s, %s)`, f.ago(100*days), f.ago(0))
	f.session("udp-01", 100*days, 9*days, "true", "'all'")
	f.session("udp-01", 9*days, 0, "false", "'all'")
	f.exec(`INSERT INTO shawk.hosts VALUES ('ns-01', 'm', 'ns-01', 'k', 'v', %s, %s)`, f.ago(100*days), f.ago(0))
	f.session("ns-01", 100*days, 0, "true", "'4026531840'")
	f.host("drop-01", "10.0.0.15")
	f.exec(`INSERT INTO shawk.partial_observations VALUES ('drop-01', %s, %s, %s, 42)`, f.ago(100*days), f.ago(2*days), f.ago(2*days-time.Hour))
	// A host first seen 9 days ago, and one of the inventory without an agent.
	f.hostObserved("new-01", "10.0.0.16", 9*days, 0)
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('sfa-01', false)`)

	for _, c := range []struct{ target, want string }{
		{`'app-01', $1, $2`, "COMPLETE [] [] 1.000000 0 0"},
		{`'app-01', $1, $2, 'app.service'`, "COMPLETE [] [] 1.000000 0 0"},
		// No process of the host had the unit: a name mistyped tells nothing.
		{`'app-01', $1, $2, 'ap.service'`, "INCOMPLETE [unknown_unit] [] 1.000000 0 0"},
		{`'gap-01', $1, $2`, "INCOMPLETE [not_observed] [] 0.999537 3600 1"},
		{`'gap-01', $1, $2, NULL, 0.999`, "COMPLETE [] [not_observed] 0.999537 3600 1"},
		{`'gap-01', $1, $2, NULL, 0.9996`, "INCOMPLETE [not_observed] [] 0.999537 3600 1"},
		{`'udp-01', $1, $2`, "INCOMPLETE [udp_not_traced] [] 0.900000 0 0"},
		{`'ns-01', $1, $2`, "INCOMPLETE [netns_limited] [] 0.000000 0 0"},
		{`'drop-01', $1, $2`, "INCOMPLETE [dropped_flows] [] 0.999537 0 0"},
		{`'new-01', $1, $2`, "INCOMPLETE [not_observed] [] 0.100000 6998400 1"},
		{`'sfa-01', $1, $2`, "INCOMPLETE [no_agent] [] 0.000000 7776000 1"},
		{`'app-O1', $1, $2`, "INCOMPLETE [unknown_host] [] 0.000000 7776000 1"},
	} {
		if got := f.query(90*days, `SELECT `+verdictColumns+` FROM shawk_v1.policy_verdict(`+c.target+`)`); !slices.Equal(got, []string{c.want}) {
			t.Errorf("policy_verdict(%s) = %v, want %s", c.target, got, c.want)
		}
	}
	// Within what its agent saw, the new host is complete.
	if got := f.query(8*days, `SELECT status FROM shawk_v1.policy_verdict('new-01', $1, $2)`); !slices.Equal(got, []string{"COMPLETE"}) {
		t.Errorf("new-01 over 8 days: %v", got)
	}
	// The time before the retention of the connector tells nothing: the
	// flows last seen then are deleted.
	f.exec(`SELECT shawk.prune(%s)`, f.ago(45*days))
	want := "INCOMPLETE [before_retention] [] 0.500000 3888000 1"
	if got := f.query(90*days, `SELECT `+verdictColumns+` FROM shawk_v1.policy_verdict('app-01', $1, $2)`); !slices.Equal(got, []string{want}) {
		t.Errorf("app-01 after a prune = %v, want %s", got, want)
	}
	// Arguments that widen the question, or that mean nothing, are refused.
	for _, args := range []string{
		`'app-01', $2, $1`, `'', $1, $2`, `NULL, $1, $2`, `'app-01', $1, $2, ''`, `'app-01', $1, $2, NULL, 0`,
		`'app-01', $1, $2, NULL, 1.01`, `'app-01', $1, $2, NULL, 1, interval '2 hours'`, `'app-01', $1, NULL`,
	} {
		if _, err := f.conn.Exec(context.Background(), `SELECT * FROM shawk_v1.policy_verdict(`+args+`)`, f.T.Add(-90*days), f.T); err == nil {
			t.Errorf("policy_verdict(%s) is accepted", args)
		}
	}
}

// TestPGPolicyVerdictSockets: the verdict tells whether the target used
// Unix sockets, which the rules of addresses do not cover.
func TestPGPolicyVerdictSockets(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("app-01", "other.service", "other")
	f.exec(`INSERT INTO shawk.unix_edges (host_id, process_id, path, netns, first_seen, last_seen)
	        SELECT 'app-01', id, '/run/x.sock', 1, %s, %s FROM shawk.processes WHERE service_name = 'other'`, f.ago(5*days), f.ago(0))
	for target, want := range map[string]string{`'app-01', $1, $2`: "true", `'app-01', $1, $2, 'app.service'`: "false",
		`'app-01', $1, $2, 'other.service'`: "true"} {
		if got := f.query(30*days, `SELECT unix_sockets FROM shawk_v1.policy_verdict(`+target+`)`); !slices.Equal(got, []string{want}) {
			t.Errorf("unix_sockets of %s = %v, want %s", target, got, want)
		}
	}
}

const observedColumns = `service, peer, port, proto, hosts, addrs::text[], named_by`

// TestPGBaselineObserved: the dependencies of a service as a baseline
// lists them, by the names of their servers and the ports of the
// dependencies between services.
func TestPGBaselineObserved(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.host("db-01", "10.0.0.10")
	f.host("login-01", "10.0.0.60")
	for _, h := range []string{"app-01", "app-02"} {
		f.proc(h, "app.service", "shop/app")
	}
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.proc("login-01", "session.scope", "srun")
	f.exec(`INSERT INTO shawk.port_agnostic_services VALUES ('srun')`)
	f.exec(`INSERT INTO shawk.peer_cidrs VALUES ('192.0.2.0/24', 'partner')`)
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "shop/postgres", "10.0.0.10", 5432, 20*days, 0)
	f.pair("app-02", "shop/app", "10.0.0.21", "db-01", "shop/postgres", "10.0.0.10", 5432, 20*days, 0)
	f.pair("app-01", "shop/app", "10.0.0.11", "login-01", "srun", "10.0.0.60", 41000, 20*days, 0)
	f.pair("app-01", "shop/app", "10.0.0.11", "login-01", "srun", "10.0.0.60", 41001, 20*days, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "192.0.2.7", 443, 20*days, 0)
	f.edge("app-02", "shop/app", "client", "tcp", "10.0.0.21", "192.0.2.9", 443, 20*days, 0)
	f.edge("app-02", "shop/app", "client", "tcp", "10.0.0.21", "0.0.0.0/0", 443, 20*days, 0)
	f.edge("app-02", "shop/app", "client", "udp", "10.0.0.21", "10.0.0.53", 53, 20*days, 0)
	// A Unix socket is no part of a baseline.
	f.exec(`INSERT INTO shawk.unix_edges (host_id, process_id, path, netns, first_seen, last_seen)
	        SELECT 'app-01', id, '/run/x.sock', 1, %s, %s FROM shawk.processes WHERE host_id = 'app-01'`, f.ago(5*days), f.ago(0))
	want := []string{
		"shop/app partner 443 tcp [app-01 app-02] [192.0.2.7/32 192.0.2.9/32] address",
		"shop/app shop/postgres 5432 tcp [app-01 app-02] [10.0.0.10/32] edge",
		"shop/app srun 0 tcp [app-01] [10.0.0.60/32] edge",
		"shop/app ~external 443 tcp [app-02] [0.0.0.0/0] address",
		"shop/app ~unresolved 53 udp [app-02] [10.0.0.53/32] address",
	}
	if got := f.query(30*days, `SELECT `+observedColumns+` FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("observed:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := f.query(30*days, `SELECT `+observedColumns+` FROM shawk_v1.baseline_observed($1, $2, ARRAY['shop/app'])`); !slices.Equal(got, want) {
		t.Errorf("observed of shop/app:\n%s", strings.Join(got, "\n"))
	}
	if got := f.query(30*days, `SELECT count(*) FROM shawk_v1.baseline_observed($1, $2, ARRAY['shop/postgres', 'nope'])`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("observed of services without dependencies: %v", got)
	}
}

// TestPGNamedByEndpoint: a server that no agent saw the side of keeps the
// name of the service that listens at its address, so that a stopped
// agent, or one that folds its clients, does not make the dependencies on
// its host look like others, on ~unresolved.
func TestPGNamedByEndpoint(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("web-01", "10.0.0.12")
	// The agent of db-01 stopped two days ago; the service goes on.
	f.hostObserved("db-01", "10.0.0.10", 100*days, 2*days)
	f.hostObserved("db-02", "10.0.0.20", 100*days, 2*days)
	f.proc("app-01", "app.service", "shop/app")
	f.proc("app-01", "redis.service", "redis")
	f.proc("web-01", "redis.service", "other-redis")
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.proc("db-02", "postgresql.service", "shop/postgres")
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, 20*days, 0)
	f.edge("db-01", "shop/postgres", "server", "tcp", "10.0.0.10", "10.0.0.11", 5432, 20*days, 2*days)
	f.listener("db-01", "shop/postgres", "0.0.0.0", 5432, "NULL")
	f.listener("db-02", "shop/postgres", "10.0.0.20", 5432, "NULL")
	// A virtual address of a translation whose backends are those hosts.
	f.exec(`INSERT INTO shawk.translations VALUES ('pg', 'virtual', 'tcp', '10.0.0.100', 5432),
	        ('pg', 'backend', 'tcp', '10.0.0.20', 0)`)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.100", 5432, 20*days, 0)
	// A loopback address names the server on the host of the client only,
	// and nothing listens on 6380 there.
	f.listener("app-01", "redis", "127.0.0.1", 6379, "NULL")
	f.listener("web-01", "other-redis", "127.0.0.1", 6379, "NULL")
	f.listener("web-01", "other-redis", "127.0.0.1", 6380, "NULL")
	f.edge("app-01", "shop/app", "client", "tcp", "127.0.0.1", "127.0.0.1", 6379, 20*days, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "127.0.0.1", "127.0.0.1", 6380, 20*days, 0)
	// Nothing is known to listen there.
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.99", 5432, 20*days, 0)

	want := []string{
		"shop/app redis 6379 tcp [app-01] [127.0.0.1/32] endpoint",
		"shop/app shop/postgres 5432 tcp [app-01] [10.0.0.10/32 10.0.0.100/32] endpoint",
		"shop/app ~unresolved 5432 tcp [app-01] [10.0.0.99/32] address",
		"shop/app ~unresolved 6380 tcp [app-01] [127.0.0.1/32] address",
	}
	if got := f.query(time.Hour, `SELECT `+observedColumns+` FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("observed over the last hour:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Over a period in which the agent of the server observed, the name is
	// that of the edge it saw.
	if got := f.query(30*days, `SELECT named_by FROM shawk_v1.baseline_observed($1, $2) WHERE peer = 'shop/postgres'`); !slices.Equal(got, []string{"edge"}) {
		t.Errorf("named over 30 days by %v", got)
	}
	// The flows of the host have the same names.
	want = []string{"10.0.0.10/32 shop/postgres", "10.0.0.100/32 shop/postgres", "10.0.0.99/32 ~unresolved", "127.0.0.1/32 redis",
		"127.0.0.1/32 ~unresolved"}
	if got := f.query(time.Hour, `SELECT peer_addr::text, peer FROM shawk_v1.policy_flows('app-01', $1, $2)`); !slices.Equal(got, want) {
		t.Errorf("flows over the last hour: %v, want %v", got, want)
	}
}

// TestPGBaselineVerdict: the dependencies of a service are complete when
// every host that ran it was observed for the whole period.
func TestPGBaselineVerdict(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.hostObserved("app-03", "10.0.0.31", 9*days, 0)
	f.exec(`INSERT INTO shawk.hosts VALUES ('app-04', 'm', 'app-04', 'k', 'v', %s, %s)`, f.ago(100*days), f.ago(0))
	f.session("app-04", 100*days, 0, "false", "'all'")
	for _, h := range []string{"app-01", "app-02"} {
		f.proc(h, "app.service", "shop/app")
	}
	for _, h := range []string{"app-01", "app-03", "app-04"} {
		f.proc(h, "worker.service", "shop/worker")
	}
	want := []string{
		"nope INCOMPLETE [unknown_service] [] 0 0.000000 []",
		"shop/app COMPLETE [] [] 2 1.000000 []",
		"shop/worker INCOMPLETE [not_observed udp_not_traced] [] 3 0.000000 [app-04 app-03]",
	}
	q := `SELECT service, status, reasons, caveats, hosts, coverage::text, short_hosts
		FROM shawk_v1.baseline_verdict(ARRAY['shop/app', 'shop/worker', 'nope', 'shop/app', NULL], $1, $2`
	if got := f.query(90*days, q+`)`); !slices.Equal(got, want) {
		t.Errorf("verdicts:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A caller who accepts a tenth of the period: the host that was first
	// seen 9 days ago is the caveat, the one without UDP the reason.
	want[2] = "shop/worker INCOMPLETE [udp_not_traced] [not_observed] 3 0.000000 [app-04]"
	if got := f.query(90*days, q+`, 0.1)`); !slices.Equal(got, want) {
		t.Errorf("verdicts with min_coverage 0.1:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := f.conn.Exec(context.Background(), q+`, 1.5)`, f.T.Add(-days), f.T); err == nil {
		t.Error("a min_coverage above 1 is accepted")
	}
}

// approve writes a baseline as the connector does.
func (f policyFixture) approve(yaml string) {
	f.t.Helper()
	b, err := ParseBaseline([]byte(yaml))
	if err != nil {
		f.t.Fatal(err)
	}
	st, err := newPGStore(context.Background(), f.conn.Config().ConnString())
	if err != nil {
		f.t.Fatal(err)
	}
	defer st.close()
	if err := st.syncBaseline(context.Background(), b, f.T); err != nil {
		f.t.Fatal(err)
	}
}

const driftColumns = `service, peer, port, proto, hosts, addrs::text[], named_by`

// TestPGBaselineDrift: the drift is what the services with a baseline did
// that it does not hold; a service without one is not judged.
func TestPGBaselineDrift(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.host("db-01", "10.0.0.10")
	f.host("login-01", "10.0.0.60")
	for _, h := range []string{"app-01", "app-02"} {
		f.proc(h, "app.service", "shop/app")
		f.proc(h, "cron.service", "cron")
	}
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.proc("db-01", "billing.service", "billing/api")
	f.proc("login-01", "session.scope", "srun")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "shop/postgres", "10.0.0.10", 5432, 20*days, 0)
	f.pair("app-02", "shop/app", "10.0.0.21", "db-01", "shop/postgres", "10.0.0.10", 5432, 20*days, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "0.0.0.0/0", 443, 20*days, 0)
	f.edge("app-01", "shop/app", "client", "udp", "10.0.0.11", "10.0.0.53", 53, 20*days, 0)
	f.pair("app-01", "cron", "10.0.0.11", "db-01", "billing/api", "10.0.0.10", 8443, 20*days, 0)

	// Without a baseline nothing is judged.
	if got := f.query(time.Hour, `SELECT count(*) FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("drift without a baseline: %v", got)
	}
	f.approve(`
services:
  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~external, port: 443, proto: tcp}
      - {peer: ~unresolved, port: 53, proto: udp}
`)
	if got := f.query(time.Hour, `SELECT count(*) FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("drift of what the baseline holds: %v", got)
	}
	if got := queryStrings(t, f.conn, `SELECT service, coalesce(peer, '-'), coalesce(port, -1) FROM shawk_v1.baseline`); len(got) != 3 {
		t.Errorf("baseline = %v", got)
	}
	if got := queryStrings(t, f.conn, `SELECT read_at = `+f.ago(0)+`, failed_at IS NULL, services, dependencies FROM shawk_v1.baseline_status`); !slices.Equal(got, []string{"true true 1 3"}) {
		t.Errorf("baseline_status = %v", got)
	}

	// A release of shop/app on both hosts opens connections to billing, and
	// one host to an external address on another port, to a host without an
	// agent, and to postgres over UDP.
	// (billing already serves cron of app-01 from the same address.)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.10", 8443, 20*time.Minute, 0)
	f.pair("app-02", "shop/app", "10.0.0.21", "db-01", "billing/api", "10.0.0.10", 8443, 20*time.Minute, 0)
	f.edge("app-02", "shop/app", "client", "tcp", "10.0.0.21", "0.0.0.0/0", 8443, 20*time.Minute, 10*time.Minute)
	f.edge("app-02", "shop/app", "client", "tcp", "10.0.0.21", "10.0.7.7", 22, 20*time.Minute, 10*time.Minute)
	f.edge("app-02", "shop/app", "client", "udp", "10.0.0.21", "10.0.0.10", 5432, 20*time.Minute, 10*time.Minute)
	f.edge("db-01", "shop/postgres", "server", "udp", "10.0.0.10", "10.0.0.21", 5432, 20*time.Minute, 10*time.Minute)
	want := []string{
		"shop/app billing/api 8443 tcp [app-01 app-02] [10.0.0.10/32] edge",
		"shop/app shop/postgres 5432 udp [app-02] [10.0.0.10/32] edge",
		"shop/app ~external 8443 tcp [app-02] [0.0.0.0/0] address",
		"shop/app ~unresolved 22 tcp [app-02] [10.0.7.7/32] address",
	}
	if got := f.query(time.Hour, `SELECT `+driftColumns+` FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("drift:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// cron has no baseline: its dependency on billing is not judged. Those
	// of the services asked for only.
	if got := f.query(time.Hour, `SELECT count(*) FROM shawk_v1.baseline_drift($1, $2, ARRAY['cron', 'nope'])`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("drift of services without a baseline: %v", got)
	}
	// A period that ended before the release has no drift, and one that
	// starts after the connections ended has only those that go on.
	if got := queryStrings(t, f.conn, `SELECT count(*) FROM shawk_v1.baseline_drift($1, $2)`, f.T.Add(-days), f.T.Add(-time.Hour)); !slices.Equal(got, []string{"0"}) {
		t.Errorf("drift before the release: %v", got)
	}
	if got := queryStrings(t, f.conn, `SELECT peer FROM shawk_v1.baseline_drift($1, $2)`, f.T.Add(-5*time.Minute), f.T); !slices.Equal(got, []string{"billing/api"}) {
		t.Errorf("drift of the last 5 minutes: %v", got)
	}

	// Approved: port 0 stands for every port of the peer.
	f.approve(`
services:
  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 0, proto: tcp}
      - {peer: shop/postgres, port: 5432, proto: udp}
      - {peer: ~external, port: 0, proto: tcp}
      - {peer: ~unresolved, port: 53, proto: udp}
      - {peer: billing/api, port: 8443, proto: tcp}
  - service: cron
    dependencies: []
`)
	want = []string{
		"cron billing/api 8443 tcp [app-01] [10.0.0.10/32] edge",
		"shop/app ~unresolved 22 tcp [app-02] [10.0.7.7/32] address",
	}
	if got := f.query(time.Hour, `SELECT `+driftColumns+` FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("drift after the approval:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A baseline of no service: nothing is judged again.
	f.approve("services: []\n")
	if got := f.query(time.Hour, `SELECT count(*) FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("drift with a baseline of no service: %v", got)
	}
}

// TestPGBaselineDriftPortRules: a rule of ports added or removed after a
// baseline was approved makes no drift of what the baseline holds.
func TestPGBaselineDriftPortRules(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("login-01", "10.0.0.60")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("login-01", "session.scope", "srun")
	f.pair("app-01", "shop/app", "10.0.0.11", "login-01", "srun", "10.0.0.60", 41000, 20*days, 0)
	f.approve(`
services:
  - service: shop/app
    dependencies:
      - {peer: srun, port: 41000, proto: tcp}
`)
	drift := func() []string {
		return f.query(time.Hour, `SELECT peer, port FROM shawk_v1.baseline_drift($1, $2)`)
	}
	if got := drift(); len(got) != 0 {
		t.Errorf("drift: %v", got)
	}
	// The rule is added: the dependency has port 0 between services, and
	// the port of the server is still the one approved. Another run, on
	// another port, is a drift on port 0 until port 0 is approved.
	f.exec(`INSERT INTO shawk.port_agnostic_services VALUES ('srun')`)
	if got := drift(); len(got) != 0 {
		t.Errorf("drift after the rule was added: %v", got)
	}
	f.pair("app-01", "shop/app", "10.0.0.11", "login-01", "srun", "10.0.0.60", 41777, 20*time.Minute, 0)
	if got := drift(); !slices.Equal(got, []string{"srun 0"}) {
		t.Errorf("drift of a run on another port: %v", got)
	}
	f.approve(`
services:
  - service: shop/app
    dependencies:
      - {peer: srun, port: 0, proto: tcp}
`)
	if got := drift(); len(got) != 0 {
		t.Errorf("drift with port 0 approved: %v", got)
	}
	// The rule is removed: port 0 stands for every port.
	f.exec(`DELETE FROM shawk.port_agnostic_services`)
	if got := drift(); len(got) != 0 {
		t.Errorf("drift after the rule was removed: %v", got)
	}
}

// TestPGBaselineDriftStoppedAgent: when the agent of a server stops, the
// dependencies on its services are still those of the baseline, not new
// ones on ~unresolved.
func TestPGBaselineDriftStoppedAgent(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.hostObserved("db-01", "10.0.0.10", 100*days, 3*time.Hour)
	f.proc("app-01", "app.service", "shop/app")
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, 20*days, 0)
	f.edge("db-01", "shop/postgres", "server", "tcp", "10.0.0.10", "10.0.0.11", 5432, 20*days, 3*time.Hour)
	f.listener("db-01", "shop/postgres", "0.0.0.0", 5432, "NULL")
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n")
	if got := f.query(time.Hour, `SELECT `+driftColumns+` FROM shawk_v1.baseline_drift($1, $2)`); len(got) != 0 {
		t.Errorf("drift while the agent of the server is stopped: %v", got)
	}
	// A server at another address that nothing is known of is a drift.
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.66", 5432, 20*time.Minute, 0)
	want := []string{"shop/app ~unresolved 5432 tcp [app-01] [10.0.0.66/32] address"}
	if got := f.query(time.Hour, `SELECT `+driftColumns+` FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("drift = %v, want %v", got, want)
	}
}

// TestPGBaselineNewServices: a service without a baseline that was first
// seen in the period and opened connections is told, since no baseline
// judges it; the processes of Slurm jobs and sockets without an owner are
// not.
func TestPGBaselineNewServices(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.proc("app-01", "app.service", "shop/app")
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, 20*days, 0)
	newProc := func(host, unit, service string, first time.Duration) {
		f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
		        VALUES ('%s', '%s', 'c', '', '%s', %s, %s)`, host, unit, service, f.ago(first), f.ago(0))
	}
	// curl runs in the unit of the application on two hosts; a listener
	// that opened no connection; a job; a socket without an owner; a
	// service that has a baseline; one seen on another host before.
	newProc("app-01", "app.service", "curl", 30*time.Minute)
	newProc("app-02", "app.service", "curl", 20*time.Minute)
	newProc("app-01", "listen.service", "listener", 30*time.Minute)
	newProc("app-01", "slurm/batch", "python3", 30*time.Minute)
	newProc("app-01", "~unknown", "~unknown", 30*time.Minute)
	newProc("app-01", "locked.service", "locked", 30*time.Minute)
	newProc("app-01", "old.service", "old", 30*time.Minute)
	newProc("app-02", "old.service", "old", 30*days)
	for _, e := range []struct{ host, service, role string }{
		{"app-01", "curl", "client"}, {"app-02", "curl", "client"}, {"app-01", "listener", "server"},
		{"app-01", "python3", "client"}, {"app-01", "~unknown", "client"}, {"app-01", "locked", "client"}, {"app-01", "old", "client"},
	} {
		f.edge(e.host, e.service, e.role, "tcp", "10.0.0.11", "10.0.0.99", 80, 10*time.Minute, 0)
	}
	f.approve("services:\n  - service: locked\n    dependencies: []\n")
	want := []string{"curl [app-01 app-02] true"}
	if got := f.query(time.Hour, `SELECT service, hosts, first_seen = `+f.ago(30*time.Minute)+` FROM shawk_v1.baseline_new_services($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("new services = %v, want %v", got, want)
	}
	if got := f.query(10*time.Minute, `SELECT count(*) FROM shawk_v1.baseline_new_services($1, $2)`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("new services of the last 10 minutes: %v", got)
	}
}

// TestPGBaselineConnector: the connector writes its baseline_file to
// PostgreSQL, as the role of the connector, and tells Prometheus the drift
// that the contract gives.
func TestPGBaselineConnector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(path, []byte(testBaseline), 0o600); err != nil {
		t.Fatal(err)
	}
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) { cfg.BaselineFile = path })
	ctx := context.Background()
	want := []string{"batch/report <nil> <nil> <nil>", "shop/app resolver 53 udp", "shop/app shop/postgres 5432 tcp", "shop/app ~external 443 tcp"}
	if got := queryStrings(t, conn, `SELECT service, peer, port, proto FROM shawk_v1.baseline`); !slices.Equal(got, want) {
		t.Fatalf("baseline = %v, want %v", got, want)
	}
	// A dependency of shop/app that the baseline does not hold, 10 minutes
	// ago, on two hosts.
	now := time.Now().UTC()
	for _, h := range []string{"app-01", "app-02"} {
		execAll(t, conn, fmt.Sprintf(`
INSERT INTO shawk.hosts VALUES ('%[1]s', 'm', '%[1]s', 'k', 'v', now() - interval '1 day', now());
INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope)
VALUES ('%[1]s', now() - interval '1 day', now(), true, 'all');
INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
VALUES ('%[1]s', 'app.service', 'c', '', 'shop/app', now() - interval '1 day', now());
INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
SELECT '%[1]s', id, 'client', 'tcp', '10.0.0.1', '10.0.0.9', 8443, 1, now() - interval '20 minutes', now() - interval '10 minutes'
FROM shawk.processes WHERE host_id = '%[1]s'`, h))
	}
	c.now = func() time.Time { return now }
	sink.Reset()
	c.evaluateBaselineIfDue(ctx)
	c.emitBaseline(ctx)
	var out []series
	for _, md := range sink.AllMetrics() {
		out = append(out, flatten(md)...)
	}
	wantSeries := []string{
		"shawk.baseline.dependencies{batch/report} 0",
		"shawk.baseline.dependencies{shop/app} 3",
		"shawk.baseline.drift.hosts{shop/app,~unresolved,8443,tcp} 2",
		"shawk.baseline.drift.truncated{shawk-connector} 0",
		"shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(now.Add(-baselineDelay).Unix()),
		"shawk.baseline.file.failed{shawk-connector} 0",
		"shawk.baseline.new_services{shawk-connector} 0",
	}
	if got := baselineSeries(out); !slices.Equal(got, wantSeries) {
		t.Errorf("series:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantSeries, "\n"))
	}

	// A file that an edit broke keeps the baseline, and the failure is
	// recorded, for every connector and for Prometheus.
	if err := os.WriteFile(path, []byte("services:\n  - service: shop/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.syncBaseline(ctx)
	if got := queryStrings(t, conn, `SELECT failed_at IS NOT NULL, error LIKE '%no dependencies%', services, dependencies
		FROM shawk_v1.baseline_status`); !slices.Equal(got, []string{"true true 2 3"}) {
		t.Errorf("baseline_status after an invalid file = %v", got)
	}
	r, err := c.store.baselineReport(ctx, now.Add(-time.Hour), now, 1)
	if err != nil || !r.read || !r.failed || len(r.drift) != 1 || r.truncated != 0 {
		t.Errorf("report = %+v, %v", r, err)
	}
	// More drift than the bound: the rest is counted.
	execAll(t, conn, `
INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
SELECT 'app-01', id, 'client', 'tcp', '10.0.0.1', '10.0.0.9', p, 1, now() - interval '20 minutes', now() - interval '10 minutes'
FROM shawk.processes, generate_series(9000, 9004) p WHERE host_id = 'app-01'`)
	if r, err = c.store.baselineReport(ctx, now.Add(-time.Hour), now, 2); err != nil || len(r.drift) != 2 || r.truncated != 4 ||
		r.drift[0].port != 8443 || r.drift[1].port != 9000 {
		t.Errorf("report with a bound of 2 = %+v, %v", r, err)
	}
	// The file is valid again, and approves what was seen.
	if err := os.WriteFile(path, []byte("services:\n  - service: shop/app\n    dependencies:\n      - {peer: ~unresolved, port: 0, proto: tcp}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.syncBaseline(ctx)
	if r, err = c.store.baselineReport(ctx, now.Add(-time.Hour), now, 10); err != nil || r.failed || len(r.drift) != 0 || len(r.services) != 1 ||
		r.services[0] != (baselineCount{"shop/app", 1}) {
		t.Errorf("report after the approval = %+v, %v", r, err)
	}
}

// TestPGBaselineReader: a role that reads the contract only, as Grafana
// and shawk-policy do, reads the flows, the verdicts and the drift, and
// not the tables of the baseline.
func TestPGBaselineReader(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.proc("app-01", "app.service", "shop/app")
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, 20*days, 0)
	f.approve("services:\n  - service: shop/app\n    dependencies: []\n")
	ctx := context.Background()
	role := fmt.Sprintf("shawk_policy_reader_%d", time.Now().UnixNano())
	execAll(t, f.conn, "CREATE ROLE "+role+" NOLOGIN", "GRANT USAGE ON SCHEMA shawk_v1 TO "+role,
		"GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO "+role)
	t.Cleanup(func() {
		f.conn.Exec(ctx, "RESET ROLE")
		f.conn.Exec(ctx, "DROP OWNED BY "+role)
		f.conn.Exec(ctx, "DROP ROLE "+role)
	})
	execAll(t, f.conn, "SET ROLE "+role)
	for q, want := range map[string]string{
		`SELECT count(*) FROM shawk_v1.policy_flows('app-01', $1, $2)`:                          "1",
		`SELECT status FROM shawk_v1.policy_verdict('app-01', $1, $2)`:                          "COMPLETE",
		`SELECT count(*) FROM shawk_v1.baseline_observed($1, $2)`:                               "1",
		`SELECT status FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2)`:               "COMPLETE",
		`SELECT count(*) FROM shawk_v1.baseline_drift($1, $2)`:                                  "1",
		`SELECT count(*) FROM shawk_v1.baseline_new_services($1, $2)`:                           "0",
		`SELECT count(*) FROM shawk_v1.baseline WHERE $1::timestamptz < $2::timestamptz`:        "1",
		`SELECT services FROM shawk_v1.baseline_status WHERE $1::timestamptz < $2::timestamptz`: "1",
	} {
		if got := f.query(30*days, q); !slices.Equal(got, []string{want}) {
			t.Errorf("%s = %v, want %s", q, got, want)
		}
	}
	for _, q := range []string{`SELECT count(*) FROM shawk.baseline_services`, `SELECT count(*) FROM shawk.baseline_dependencies`,
		`SELECT count(*) FROM shawk.named_dependencies(now() - interval '1 day', now())`,
		`INSERT INTO shawk.baseline_services VALUES ('x')`} {
		if _, err := f.conn.Exec(ctx, q); err == nil {
			t.Errorf("the reader may run %s", q)
		}
	}
}
