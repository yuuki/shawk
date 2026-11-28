package shawkconnector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tests in this file run, against PostgreSQL (SHAWK_TEST_POSTGRES_DSN),
// what decides whether a verdict of 0006_policy.sql may be trusted: which
// machines and which processes it is about, and what it says where the
// history cannot tell.

// TestPGPolicyUnits: the flows of a unit are those of its processes, of
// the units under it, which a limit of systemd on the unit holds too, and
// of the sockets without a known owner, which have no unit; not those of
// a process of another unit that names itself ~unknown.
func TestPGPolicyUnits(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("app-01", "app.service/podman-0123456789ab", "worker")
	f.proc("app-01", "app.service2", "other")
	f.proc("app-01", "", "~unknown")
	f.proc("app-01", "user-1000.slice/session.scope", "~unknown")
	f.proc("app-01", "pods.service/docker-0123456789ab", "pod")
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, 20*days, 0)
	f.edge("app-01", "worker", "client", "tcp", "10.0.0.11", "10.0.0.77", 6379, 20*days, 0)
	f.edge("app-01", "other", "client", "tcp", "10.0.0.11", "10.0.0.88", 1, 20*days, 0)
	f.edgeOf("app-01", "", "~unknown", "client", "tcp", "10.0.0.11", "10.0.0.30", 9999, 20*days, 0)
	f.edgeOf("app-01", "user-1000.slice/session.scope", "~unknown", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, 20*days, 0)
	f.edge("app-01", "pod", "client", "tcp", "10.0.0.11", "10.0.0.99", 80, 20*days, 0)

	want := []string{
		"app.service shop/app 10.0.0.10/32 5432",
		"app.service/podman-0123456789ab worker 10.0.0.77/32 6379",
		" ~unknown 10.0.0.30/32 9999",
	}
	slices.Sort(want)
	got := f.query(30*days, `SELECT unit, service, peer_addr::text, port FROM shawk_v1.policy_flows('app-01', $1, $2, 'app.service')`)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("flows of app.service:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A unit that has processes under it only is known, and its flows are
	// theirs; one that starts with the same letters is another unit.
	for target, want := range map[string]string{
		`'pods.service'`:                    "COMPLETE []",
		`'app.service/podman-0123456789ab'`: "COMPLETE []",
		`'app.servic'`:                      "INCOMPLETE [unknown_unit]",
		`'pods'`:                            "INCOMPLETE [unknown_unit]",
	} {
		if got := f.query(30*days, `SELECT status, reasons FROM shawk_v1.policy_verdict('app-01', $1, $2, `+target+`)`); !slices.Equal(got, []string{want}) {
			t.Errorf("verdict of %s = %v, want %s", target, got, want)
		}
	}
	if got := f.query(30*days, `SELECT service FROM shawk_v1.policy_flows('app-01', $1, $2, 'pods.service') WHERE unit <> ''`); !slices.Equal(got, []string{"pod"}) {
		t.Errorf("flows of pods.service: %v", got)
	}
	// A unit whose processes were last seen long before the period is not
	// known in it.
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE unit = 'app.service2'`, f.ago(60*days))
	if got := f.query(30*days, `SELECT status, reasons FROM shawk_v1.policy_verdict('app-01', $1, $2, 'app.service2')`); !slices.Equal(got, []string{"INCOMPLETE [unknown_unit]"}) {
		t.Errorf("verdict of a unit last seen before the period = %v", got)
	}
}

// TestPGPolicySeveralMachines: the history of a host name is that of each
// machine that reported under it. Two machines of one name are never
// complete, and the time that one was observed does not cover the other.
func TestPGPolicySeveralMachines(t *testing.T) {
	f := newPolicyFixture(t)
	// The first machine was not observed for 20 of the last 30 days; the
	// second was observed all along.
	f.exec(`INSERT INTO shawk.hosts VALUES ('id-1', 'm-1', 'app-01', 'k', 'v', %[1]s, %[2]s), ('id-2', 'm-2', 'app-01', 'k', 'v', %[1]s, %[2]s)`,
		f.ago(100*days), f.ago(0))
	f.session("id-1", 100*days, 25*days, "true", "'all'")
	f.session("id-1", 5*days, 0, "true", "'all'")
	f.session("id-2", 100*days, 0, "true", "'all'")
	const columns = `status, reasons, coverage::text, machines, extract(epoch FROM unobserved)::integer`
	// The gap is 20 days less the 3 minutes after the last report that
	// count as observed.
	want := "INCOMPLETE [several_machines not_observed] 0.333402 2 1727820"
	if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('app-01', $1, $2)`); !slices.Equal(got, []string{want}) {
		t.Errorf("two machines, one with a gap = %v, want %s", got, want)
	}
	// The coverage by name, which takes either machine, would tell 1.
	if got := f.query(30*days, `SELECT observed::text FROM shawk_v1.coverage($1, $2, ARRAY['app-01'])`); !slices.Equal(got, []string{"1.000000"}) {
		t.Errorf("coverage by name = %v", got)
	}
	// The gap is that of the machine.
	gap := "id-1 " + ts2(f.T.Add(-25*days+3*time.Minute)) + " " + ts2(f.T.Add(-5*days)) + " agent"
	if got := f.query(30*days, `SELECT machine, to_char(gap_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'),
		to_char(gap_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'), cause FROM shawk_v1.policy_gaps('app-01', $1, $2)`); !slices.Equal(got, []string{gap}) {
		t.Errorf("gaps = %v, want %s", got, gap)
	}
	// No min_coverage accepts two machines: the flows are of both.
	if got := f.query(30*days, `SELECT status FROM shawk_v1.policy_verdict('app-01', $1, $2, NULL, 0.1)`); !slices.Equal(got, []string{"INCOMPLETE"}) {
		t.Errorf("two machines with min_coverage 0.1 = %v", got)
	}
	// Both observed all along: still two machines.
	f.exec(`DELETE FROM shawk.agent_sessions WHERE host_id = 'id-1'`)
	f.session("id-1", 100*days, 0, "true", "'all'")
	want = "INCOMPLETE [several_machines] 1.000000 2 0"
	if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('app-01', $1, $2)`); !slices.Equal(got, []string{want}) {
		t.Errorf("two machines observed = %v, want %s", got, want)
	}
	// A machine that another replaced before the period is not in it.
	f.exec(`DELETE FROM shawk.agent_sessions WHERE host_id = 'id-1'`)
	f.session("id-1", 100*days, 40*days, "true", "'all'")
	want = "COMPLETE [] 1.000000 1 0"
	if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('app-01', $1, $2)`); !slices.Equal(got, []string{want}) {
		t.Errorf("a machine replaced before the period = %v, want %s", got, want)
	}
	// A name whose only machine stopped reporting before the period: the
	// gap is the whole period, of no machine.
	f.exec(`DELETE FROM shawk.agent_sessions WHERE host_id = 'id-2'`)
	want = "INCOMPLETE [not_observed] 0.000000 0 2592000"
	if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('app-01', $1, $2)`); !slices.Equal(got, []string{want}) {
		t.Errorf("no machine in the period = %v, want %s", got, want)
	}
	if got := f.query(30*days, `SELECT machine IS NULL, gap_end - gap_start = interval '30 days', cause
		FROM shawk_v1.policy_gaps('app-01', $1, $2)`); !slices.Equal(got, []string{"true true agent"}) {
		t.Errorf("gaps of a name without a machine = %v", got)
	}
}

// ts2 formats a time as the gaps are compared.
func ts2(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05") }

// TestPGPolicyTranslationsNotLearned: where an agent of the host did not
// learn every address that the host rewrites its connections to, the
// flows may lack what the packets leave for, and are not complete.
func TestPGPolicyTranslationsNotLearned(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	const columns = `status, reasons, coverage::text, translations_traced`
	verdict := func(args string) []string {
		t.Helper()
		return f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('app-01', $1, $2`+args+`)`)
	}
	if got := verdict(""); !slices.Equal(got, []string{"COMPLETE [] 1.000000 true"}) {
		t.Fatalf("an agent that learns the translations: %v", got)
	}
	want := []string{"INCOMPLETE [translations_not_learned] 1.000000 false"}
	// The default of the agent: it folds the clients of its servers, and
	// learns no translation to a backend outside its internal ranges.
	for _, set := range []string{`peer_fold = 'in'`, `peer_fold = 'all'`, `peer_fold = 'none', translations_traced = NULL`,
		`translations_traced = false`} {
		f.exec(`UPDATE shawk.agent_sessions SET %s`, set)
		if got := verdict(""); !slices.Equal(got, want) {
			t.Errorf("with %s: %v, want %v", set, got, want)
		}
		// Time that was not observed is what min_coverage accepts; this
		// is not.
		if got := verdict(", NULL, 0.01"); !slices.Equal(got, want) {
			t.Errorf("with %s and min_coverage 0.01: %v, want %v", set, got, want)
		}
	}
	// A session that did not learn them and ended before the period does
	// not count; one of an hour within it does.
	f.exec(`DELETE FROM shawk.agent_sessions`)
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, peer_fold, translations_traced)
	        VALUES ('app-01', %s, %s, true, true, 'all', 'in', true)`, f.ago(100*days), f.ago(40*days))
	f.session("app-01", 40*days, 0, "true", "'all'")
	if got := verdict(""); !slices.Equal(got, []string{"COMPLETE [] 1.000000 true"}) {
		t.Errorf("folding that ended before the period: %v", got)
	}
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s WHERE peer_fold = 'in'`, f.ago(30*days-time.Hour))
	f.exec(`UPDATE shawk.agent_sessions SET started_at = %s WHERE peer_fold = 'none'`, f.ago(30*days-time.Hour))
	if got := verdict(""); !slices.Equal(got, want) {
		t.Errorf("folding for the first hour of the period: %v, want %v", got, want)
	}
}

// TestPGPolicyTolerated: a stretch without a report that is within the
// tolerance counts as observed, and is told with the verdict.
func TestPGPolicyTolerated(t *testing.T) {
	f := newPolicyFixture(t)
	const columns = `status, coverage::text, extract(epoch FROM unobserved)::integer, gaps,
		extract(epoch FROM tolerated)::integer, tolerated_gaps`
	for name, c := range map[string]struct {
		gap  time.Duration
		want string
	}{
		"none":  {0, "COMPLETE 1.000000 0 0 0 0"},
		"short": {170 * time.Second, "COMPLETE 1.000000 0 0 170 1"},
		"long":  {190 * time.Second, "INCOMPLETE 0.999996 10 1 180 1"},
	} {
		f.exec(`INSERT INTO shawk.hosts VALUES ('%[1]s', 'm-%[1]s', '%[1]s', 'k', 'v', %[2]s, %[3]s)`, name, f.ago(100*days), f.ago(0))
		f.session(name, 100*days, 10*days, "true", "'all'")
		f.session(name, 10*days-c.gap, 0, "true", "'all'")
		if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('`+name+`', $1, $2)`); !slices.Equal(got, []string{c.want}) {
			t.Errorf("a restart of %s = %v, want %s", c.gap, got, c.want)
		}
	}
	// The latest report of an agent is not the end of the period: what
	// follows it counts for the tolerance, and is told too.
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s WHERE host_id = 'none'`, f.ago(time.Minute))
	if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.policy_verdict('none', $1, $2)`); !slices.Equal(got, []string{"COMPLETE 1.000000 0 0 60 1"}) {
		t.Errorf("a last report of a minute ago = %v", got)
	}
}

// TestPGPolicyFlowsEdges: the edges of the flows at the borders of what
// policy_flows() takes.
func TestPGPolicyFlowsEdges(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("node-01", "10.0.0.11")
	f.proc("node-01", "kubelet.service", "kubelet")
	f.proc("node-01", "web.service", "web")
	// A translation of the port alone, to the address that the socket
	// connected to; one that was last seen in the middle of the period;
	// and one that ended before it.
	f.edge("node-01", "kubelet", "client", "tcp", "10.0.0.11", "10.0.0.40", 443, 20*days, 0)
	f.edge("node-01", "kubelet", "client", "tcp", "10.0.0.11", "10.96.0.1", 443, 20*days, 0)
	f.exec(`INSERT INTO shawk.learned_translations VALUES
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.0.0.40', 443, '10.0.0.11', '10.0.0.40', 6443, %[1]s, %[2]s),
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.96.0.1', 443, '10.0.0.11', '10.0.0.41', 6443, %[1]s, %[3]s),
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.96.0.1', 443, '10.0.0.11', '10.0.0.42', 6443, %[4]s, %[5]s),
	  ('node-01', 'tcp', 1, '10.0.0.11', '10.0.0.40', 443, '10.0.0.11', '10.0.0.40', 443, %[1]s, %[2]s)`,
		f.ago(20*days), f.ago(0), f.ago(12*days), f.ago(99*days), f.ago(40*days))
	want := []string{"10.0.0.40/32 6443", "10.0.0.41/32 6443"}
	if got := f.query(30*days, `SELECT peer_addr::text, port FROM shawk_v1.policy_flows('node-01', $1, $2) WHERE translated`); !slices.Equal(got, want) {
		t.Errorf("translated flows = %v, want %v", got, want)
	}
	// A flow first seen after the period is not of it.
	f.edge("node-01", "kubelet", "client", "tcp", "10.0.0.11", "10.0.0.50", 8080, days, 0)
	if got := queryStrings(t, f.conn, `SELECT count(*) FROM shawk_v1.policy_flows('node-01', $1, $2) WHERE port = 8080`,
		f.T.Add(-30*days), f.T.Add(-2*days)); !slices.Equal(got, []string{"0"}) {
		t.Errorf("a flow first seen after the period: %v", got)
	}
	if got := f.query(30*days, `SELECT count(*) FROM shawk_v1.policy_flows('node-01', $1, $2) WHERE port = 8080`); !slices.Equal(got, []string{"1"}) {
		t.Errorf("the same flow in a period that holds it: %v", got)
	}
	// A range of dynamic_ports holds an ingress flow by the address of the
	// host, which is the server, not by that of its client.
	f.exec(`INSERT INTO shawk.dynamic_ports VALUES ('nodeports', 'tcp', '10.0.0.11/32', 30000, 32767),
	        ('clients', 'tcp', '192.0.2.0/24', 20000, 29999)`)
	f.edge("node-01", "web", "server", "tcp", "10.0.0.11", "192.0.2.50", 30080, 20*days, 0)
	f.edge("node-01", "web", "server", "tcp", "10.0.0.11", "192.0.2.50", 20080, 20*days, 0)
	want = []string{"20080 20080 20080", "30080 30000 32767"}
	if got := f.query(30*days, `SELECT port, port_from, port_to FROM shawk_v1.policy_flows('node-01', $1, $2) WHERE direction = 'ingress'`); !slices.Equal(got, want) {
		t.Errorf("ports of the ingress flows = %v, want %v", got, want)
	}
}

// TestPGNamedByEndpointChoice: among the endpoints that could name a
// server whose agent is stopped, one observed on a socket wins over one
// inferred from a listener on every address, and the most recent of
// those.
func TestPGNamedByEndpointChoice(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.hostObserved("srv-01", "10.0.0.30", 100*days, 2*days)
	f.proc("app-01", "app.service", "shop/app")
	f.proc("srv-01", "wild.service", "wild")
	f.proc("srv-01", "exact.service", "exact")
	f.proc("srv-01", "old.service", "exact-old")
	f.listener("srv-01", "wild", "0.0.0.0", 7000, "NULL")
	f.listener("srv-01", "exact", "10.0.0.30", 7000, "NULL")
	f.edge("srv-01", "exact-old", "server", "tcp", "10.0.0.30", "10.0.0.99", 7000, 20*days, 3*days)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.30", 7000, 20*days, 0)
	if got := f.query(time.Hour, `SELECT peer, named_by FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, []string{"exact endpoint"}) {
		t.Errorf("the server is named %v, want exact, by its endpoint", got)
	}
}

const hostsColumns = `status, reasons, hosts, unobserved_hosts, short_hosts`

// TestPGBaselineHosts: the drift of a service is known only when every
// host that runs it was observed. A host whose agent went silent, with
// every process of it, runs the service for as long as the caller says:
// it is not observed, rather than out of the question.
func TestPGBaselineHosts(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("app-02", "app.service", "shop/app")
	verdict := func(hostsSince string) []string {
		t.Helper()
		return f.query(time.Hour, `SELECT `+hostsColumns+` FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2, 1, '3 minutes', `+hostsSince+`)`)
	}
	week := f.ago(7 * days)
	if got := verdict(week); !slices.Equal(got, []string{"COMPLETE [] 2 0 []"}) {
		t.Fatalf("every host observed: %v", got)
	}
	// The agent of app-02 stopped 3 hours ago: its session, and the
	// processes it reported, were last seen then.
	silent := func(host string, ago time.Duration) {
		f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %[2]s WHERE host_id = '%[1]s';
		        UPDATE shawk.processes SET last_seen = %[2]s WHERE host_id = '%[1]s'`, host, f.ago(ago))
	}
	silent("app-02", 3*time.Hour)
	if got := verdict(week); !slices.Equal(got, []string{"INCOMPLETE [not_observed] 2 1 [app-02]"}) {
		t.Errorf("a host silent for 3 hours: %v", got)
	}
	// The hosts of a period alone, as a baseline is made from, are those
	// that ran the service within it.
	if got := verdict("NULL"); !slices.Equal(got, []string{"COMPLETE [] 1 0 []"}) {
		t.Errorf("without hosts_since: %v", got)
	}
	// A host is forgotten when hosts_since is after its last process.
	if got := verdict(f.ago(2 * time.Hour)); !slices.Equal(got, []string{"COMPLETE [] 1 0 []"}) {
		t.Errorf("hosts since 2 hours ago: %v", got)
	}
	// Every host silent: nothing was there to see a drift.
	silent("app-01", 3*time.Hour)
	if got := verdict(week); !slices.Equal(got, []string{"INCOMPLETE [not_observed] 2 2 [app-01 app-02]"}) {
		t.Errorf("every host silent: %v", got)
	}
	// Past the memory no host runs the service, and the hosts that ran it
	// last are silent: it may run there still.
	if got := verdict(f.ago(2 * time.Hour)); !slices.Equal(got, []string{"INCOMPLETE [last_hosts_not_observed] 0 2 [app-01 app-02]"}) {
		t.Errorf("no host since 2 hours ago: %v", got)
	}
	// A host whose clock is 2 hours behind reports now, and what it does
	// now is dated 2 hours ago: the last hour is not observed.
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s, clock_skew = interval '2 hours' WHERE host_id = 'app-01'`, f.ago(0))
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s WHERE host_id = 'app-02'`, f.ago(0))
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE host_id = 'app-02'`, f.ago(0))
	if got := verdict(week); !slices.Equal(got, []string{"INCOMPLETE [not_observed] 2 1 [app-01]"}) {
		t.Errorf("a host whose clock is behind: %v", got)
	}
	// A hosts_since that is after the start of the period is taken as
	// the start: a host that ran the service in the period runs it. The
	// connector asks so when its memory of hosts is shorter than the
	// period that it evaluates.
	// The process of app-01 was last seen 3 hours ago: only app-02 ran the
	// service in the period.
	for _, at := range []string{f.ago(0), f.ago(30 * time.Minute), f.ago(time.Hour), "NULL"} {
		if got := verdict(at); !slices.Equal(got, []string{"COMPLETE [] 1 0 []"}) {
			t.Errorf("hosts since %s: %v", at, got)
		}
	}
}

// TestPGBaselineIdle: a service of the baseline that runs nowhere is told
// apart by the hosts that ran it before. When one of them is observed,
// the service does not run and nothing of it was missed; when none is,
// or no process of it was ever seen, nothing tells.
func TestPGBaselineIdle(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.proc("app-01", "app.service", "curl")
	f.proc("app-02", "cron.service", "batch/monthly")
	f.exec(`UPDATE shawk.processes SET last_seen = %s`, f.ago(8*days))
	const columns = `service, status, reasons, caveats, hosts, idle_hosts, coverage::text`
	verdict := func() []string {
		t.Helper()
		return f.query(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_verdict(ARRAY['curl', 'batch/monthly', 'ngimx'], $1, $2, 1,
			'3 minutes', `+f.ago(7*days)+`)`)
	}
	want := []string{
		"batch/monthly COMPLETE [] [not_running] 0 1 1.000000",
		"curl COMPLETE [] [not_running] 0 1 1.000000",
		"ngimx INCOMPLETE [unknown_service] [] 0 0 0.000000",
	}
	if got := verdict(); !slices.Equal(got, want) {
		t.Errorf("services that do not run:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The host that ran curl is silent: curl may run there, and nothing
	// tells what it did.
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s WHERE host_id = 'app-01'`, f.ago(3*time.Hour))
	want[1] = "curl INCOMPLETE [last_hosts_not_observed] [] 0 1 0.000000"
	if got := verdict(); !slices.Equal(got, want) {
		t.Errorf("with the host of curl silent:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The dependencies of a period are those of the hosts that ran the
	// service in it: without hosts_since, a service that did not run is
	// not known.
	if got := f.query(time.Hour, `SELECT status, reasons FROM shawk_v1.baseline_verdict(ARRAY['batch/monthly'], $1, $2)`); !slices.Equal(got, []string{"INCOMPLETE [unknown_service]"}) {
		t.Errorf("without hosts_since: %v", got)
	}
}

// TestPGBaselineLastHosts: a service that no host runs is idle only when
// the hosts that ran it last are observed. One that runs on a host whose
// agent went silent longer ago than the memory of hosts has no process
// within the memory either: an earlier run on a host that is observed
// tells nothing of where it ran since, and the answer is not that it did
// nothing.
func TestPGBaselineLastHosts(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("web-01", "10.0.0.12")
	f.host("web-02", "10.0.0.13")
	// The agent of job-01 stopped 8 days ago, with the service running.
	f.hostObserved("job-01", "10.0.0.31", 100*days, 8*days)
	f.proc("job-01", "report.service", "batch/report")
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE host_id = 'job-01'`, f.ago(8*days))
	const columns = `status, reasons, caveats, hosts, idle_hosts, unobserved_hosts, short_hosts, short_seconds`
	verdict := func(service string) []string {
		t.Helper()
		return f.query(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_verdict(ARRAY['`+service+`'], $1, $2, 1, '3 minutes', `+f.ago(7*days)+`)`)
	}
	silent := []string{"INCOMPLETE [last_hosts_not_observed] [] 0 1 1 [job-01] [3600]"}
	if got := verdict("batch/report"); !slices.Equal(got, silent) {
		t.Errorf("a service whose only host is silent for longer than the memory: %v, want %v", got, silent)
	}
	// 200 days ago the service was tried for a day on web-01, which is
	// observed: it changes nothing.
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('web-01', 'report.service', 'c', '', 'batch/report', %s, %s)`, f.ago(200*days), f.ago(199*days))
	if got := verdict("batch/report"); !slices.Equal(got, silent) {
		t.Errorf("with an earlier run on a host that is observed: %v, want %v", got, silent)
	}
	// A host that ran it within the length of the memory before it was
	// last seen anywhere ran it last too: both count, and one is observed.
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('web-02', 'report.service', 'c', '', 'batch/report', %s, %s)`, f.ago(30*days), f.ago(12*days))
	if got, want := verdict("batch/report"), []string{"INCOMPLETE [last_hosts_not_observed] [] 0 2 1 [job-01] [3600]"}; !slices.Equal(got, want) {
		t.Errorf("with a second host that ran it last: %v, want %v", got, want)
	}
	// Once the host that ran it last is observed again, without the
	// service, the service is idle.
	f.session("job-01", 2*time.Hour, 0, "true", "'all'")
	if got, want := verdict("batch/report"), []string{"COMPLETE [] [not_running] 0 2 0 [] []"}; !slices.Equal(got, want) {
		t.Errorf("with the hosts that ran it last observed: %v, want %v", got, want)
	}
	// The case that must stay idle: a tool that ran once, on a host that
	// is observed.
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('web-01', 'app.service', 'c', '', 'curl', %s, %s)`, f.ago(8*days+time.Hour), f.ago(8*days))
	if got, want := verdict("curl"), []string{"COMPLETE [] [not_running] 0 1 0 [] []"}; !slices.Equal(got, want) {
		t.Errorf("a tool that ran once on a host that is observed: %v, want %v", got, want)
	}
}

// TestPGBaselineReplaced: a machine whose last report is before the first
// report of another machine of its host name was replaced by it, as a
// host that was installed again: it is gone, not unobserved.
func TestPGBaselineReplaced(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.exec(`INSERT INTO shawk.hosts VALUES ('old', 'm-old', 'app-02', 'k', 'v', %[1]s, %[2]s), ('new', 'm-new', 'app-02', 'k', 'v', %[3]s, %[4]s)`,
		f.ago(100*days), f.ago(2*days), f.ago(2*days-20*time.Minute), f.ago(0))
	f.session("old", 100*days, 2*days, "true", "'all'")
	f.session("new", 2*days-20*time.Minute, 0, "true", "'all'")
	for _, h := range []string{"app-01", "old", "new"} {
		f.proc(h, "app.service", "shop/app")
	}
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE host_id = 'old'`, f.ago(2*days))
	week := f.ago(7 * days)
	verdict := func() []string {
		t.Helper()
		return f.query(time.Hour, `SELECT `+hostsColumns+` FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2, 1, '3 minutes', `+week+`)`)
	}
	if got := verdict(); !slices.Equal(got, []string{"COMPLETE [] 2 0 []"}) {
		t.Errorf("a host installed again 2 days ago: %v", got)
	}
	// Two machines that report at the same time are two: the one that is
	// silent is not covered by the other.
	f.exec(`UPDATE shawk.agent_sessions SET started_at = %s WHERE host_id = 'new'`, f.ago(50*days))
	if got := verdict(); !slices.Equal(got, []string{"INCOMPLETE [not_observed] 2 1 [app-02]"}) {
		t.Errorf("two machines of one name at the same time, one silent: %v", got)
	}
	// A host that was removed, with no machine after it, is not observed
	// for as long as it counts.
	f.exec(`DELETE FROM shawk.processes WHERE host_id = 'new'; DELETE FROM shawk.agent_sessions WHERE host_id = 'new'`)
	if got := verdict(); !slices.Equal(got, []string{"INCOMPLETE [not_observed] 2 1 [app-02]"}) {
		t.Errorf("a host removed 2 days ago: %v", got)
	}
	// How long each host that is listed was not observed: here the hour.
	if got := f.query(time.Hour, `SELECT short_hosts, short_seconds FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2, 1, '3 minutes', `+week+`)`); !slices.Equal(got, []string{"[app-02] [3600]"}) {
		t.Errorf("the time that the host was not observed: %v", got)
	}
}

// TestPGBaselineHostsMargin: a process last seen within 15 minutes before
// the period is of it, as the dependencies of the period are matched.
func TestPGBaselineHostsMargin(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.host("app-03", "10.0.0.31")
	for _, h := range []string{"app-01", "app-02", "app-03"} {
		f.proc(h, "app.service", "shop/app")
	}
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE host_id = 'app-02'`, f.ago(time.Hour+10*time.Minute))
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE host_id = 'app-03'`, f.ago(time.Hour+20*time.Minute))
	if got := f.query(time.Hour, `SELECT hosts FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2)`); !slices.Equal(got, []string{"2"}) {
		t.Errorf("hosts of the period = %v, want 2", got)
	}
}

// TestPGBaselineMachines: the hosts that run a service are machines: of
// two that report under one name, the one that is silent is not covered
// by the other.
func TestPGBaselineMachines(t *testing.T) {
	f := newPolicyFixture(t)
	f.exec(`INSERT INTO shawk.hosts VALUES ('id-1', 'm-1', 'app-01', 'k', 'v', %[1]s, %[2]s), ('id-2', 'm-2', 'app-01', 'k', 'v', %[1]s, %[2]s)`,
		f.ago(100*days), f.ago(0))
	f.session("id-1", 100*days, 3*time.Hour, "true", "'all'")
	f.session("id-2", 100*days, 0, "true", "'all'")
	f.proc("id-1", "app.service", "shop/app")
	f.proc("id-2", "app.service", "shop/app")
	want := "INCOMPLETE [not_observed] 1 1 [app-01]"
	if got := f.query(time.Hour, `SELECT `+hostsColumns+` FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2)`); !slices.Equal(got, []string{want}) {
		t.Errorf("two machines of one name, one silent = %v, want %s", got, want)
	}
	// The machine that does not run the service does not count for it.
	f.exec(`DELETE FROM shawk.processes WHERE host_id = 'id-1'`)
	if got := f.query(time.Hour, `SELECT `+hostsColumns+` FROM shawk_v1.baseline_verdict(ARRAY['shop/app'], $1, $2)`); !slices.Equal(got, []string{"COMPLETE [] 1 0 []"}) {
		t.Errorf("the silent machine without the service = %v", got)
	}
}

const judgedColumns = `service, peer, port, proto, hosts, processes`

// TestPGBaselineUnit: a process of another name in a unit that runs a
// service of the baseline is judged as that service, unless its own name
// has a baseline: a connection out of the unit is not out of every
// baseline because its process has another executable, or names itself.
func TestPGBaselineUnit(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("web-01", "10.0.0.12")
	f.host("db-01", "10.0.0.10")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "shop/postgres", "10.0.0.10", 5432, 20*days, 0)
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n")
	// In the unit of shop/app: curl, and a process that names itself
	// ~unknown, connect out 20 minutes ago. An administrator ran curl on
	// web-01 too, in a login session.
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen) VALUES
	  ('app-01', 'app.service', 'curl', '/usr/bin/curl', 'curl', %[1]s, %[1]s),
	  ('app-01', 'app.service', 'python3', '/usr/bin/python3', '~unknown', %[1]s, %[1]s),
	  ('web-01', 'user-0.slice/session.scope', 'curl', '/usr/bin/curl', 'curl', %[1]s, %[1]s)`, f.ago(20*time.Minute))
	m := 20 * time.Minute
	f.edgeOf("app-01", "app.service", "curl", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, m, m)
	f.edgeOf("app-01", "app.service", "~unknown", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, m, m)
	f.edgeOf("web-01", "user-0.slice/session.scope", "curl", "client", "tcp", "10.0.0.12", "198.51.100.1", 443, m, m)
	// One that uses what the service is approved for is no drift.
	f.edgeOf("app-01", "app.service", "curl", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, m, m)
	drift := func(args string) []string {
		t.Helper()
		return f.query(time.Hour, `SELECT `+judgedColumns+` FROM shawk_v1.baseline_drift($1, $2`+args+`)`)
	}
	want := []string{"shop/app ~external 4444 tcp [app-01] [curl ~unknown]"}
	if got := drift(""); !slices.Equal(got, want) {
		t.Errorf("drift:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The baseline of the service lists what its drift is judged on.
	want = []string{"shop/app shop/postgres 5432 tcp [app-01] [curl]", "shop/app ~external 4444 tcp [app-01] [curl ~unknown]"}
	if got := f.query(time.Hour, `SELECT `+judgedColumns+` FROM shawk_v1.baseline_observed($1, $2, ARRAY['shop/app'])`); !slices.Equal(got, want) {
		t.Errorf("observed of shop/app:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Every service on its own, as shawk-policy baseline -all asks.
	want = []string{"curl shop/postgres 5432 tcp [app-01] []", "curl ~external 443 tcp [web-01] []", "curl ~external 4444 tcp [app-01] []",
		"shop/app shop/postgres 5432 tcp [app-01] []", "~unknown ~external 4444 tcp [app-01] []"}
	if got := f.query(time.Hour, `SELECT `+judgedColumns+` FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("observed of every service:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The drift of a service asked for holds what is judged as it.
	if got := drift(", ARRAY['shop/app']"); len(got) != 1 {
		t.Errorf("drift of shop/app: %v", got)
	}
	if got := drift(", ARRAY['curl']"); len(got) != 0 {
		t.Errorf("drift of curl, which has no baseline: %v", got)
	}
	// With a baseline of its own, curl is judged by it, wherever it runs.
	// The process without one in the unit is judged by the two services of
	// the unit together, and told once, under the first of them.
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n" +
		"  - service: curl\n    dependencies: []\n")
	want = []string{"curl shop/postgres 5432 tcp [app-01] []", "curl ~external 443 tcp [web-01] []",
		"curl ~external 4444 tcp [app-01] [~unknown]"}
	if got := drift(""); !slices.Equal(got, want) {
		t.Errorf("drift with a baseline of curl:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A unit runs a service for as long as the caller says: after the
	// process of the service was last seen, 2 days ago, what stays in its
	// unit is still judged with members_since, and not without.
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n")
	f.exec(`UPDATE shawk.processes SET last_seen = %s WHERE service_name = 'shop/app'`, f.ago(2*days))
	f.exec(`UPDATE shawk.edges SET last_seen = %s WHERE process_id = (SELECT id FROM shawk.processes WHERE service_name = 'shop/app')`, f.ago(2*days))
	if got := drift(""); len(got) != 0 {
		t.Errorf("drift without members_since, of a unit whose service stopped: %v", got)
	}
	want = []string{"shop/app ~external 4444 tcp [app-01] [curl ~unknown]"}
	if got := drift(", NULL, " + f.ago(7*days)); !slices.Equal(got, want) {
		t.Errorf("drift with members_since:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGBaselineKernelChosen: a server on a port that the kernel chose
// has another one at its next run. A baseline does not pin it: the
// dependency is on every port of the server, and is marked.
func TestPGBaselineKernelChosen(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("db-01", "10.0.0.10")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("db-01", "rpc.service", "rpcd")
	f.proc("db-01", "postgresql.service", "shop/postgres")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "rpcd", "10.0.0.10", 40123, 20*days, 0)
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "shop/postgres", "10.0.0.10", 5432, 20*days, 0)
	f.listener("db-01", "rpcd", "0.0.0.0", 40123, f.ago(0))
	f.listener("db-01", "shop/postgres", "0.0.0.0", 5432, "NULL")
	const columns = `peer, port, proto, kernel_chosen, ports`
	want := []string{"rpcd 0 tcp true [40123]", "shop/postgres 5432 tcp false [5432]"}
	if got := f.query(30*days, `SELECT `+columns+` FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("observed = %v, want %v", got, want)
	}
	// The rules of the host still pin the port, and mark it.
	if got := f.query(30*days, `SELECT port_from, port_to, kernel_chosen FROM shawk_v1.policy_flows('app-01', $1, $2) WHERE port = 40123`); !slices.Equal(got, []string{"40123 40123 true"}) {
		t.Errorf("the flow of the host = %v", got)
	}
	// The server runs again, on another port: no drift from the baseline
	// that holds every port of it.
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: rpcd, port: 0, proto: tcp}\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "rpcd", "10.0.0.10", 40999, 30*time.Minute, 0)
	f.listener("db-01", "rpcd", "0.0.0.0", 40999, f.ago(0))
	if got := f.query(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_drift($1, $2)`); len(got) != 0 {
		t.Errorf("drift after the server ran again: %v", got)
	}
	// A baseline written by hand that pins the old port tells a drift,
	// which is marked: one row, whatever the ports.
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: rpcd, port: 40123, proto: tcp}\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n")
	if got := f.query(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, []string{"rpcd 0 tcp true [40999]"}) {
		t.Errorf("drift from a baseline that pins the port: %v", got)
	}
}

// TestPGBaselineReportShares: the series of the drift are bounded per
// service and in all, so that one service does not use up the share of
// the others: a service that tries a thousand ports cuts its own rows,
// and the rows on a named peer come before those on ~unresolved.
func TestPGBaselineReportShares(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("app-02", "scan.scope", "aaa/first")
	f.proc("app-02", "web.service", "shop/web")
	f.approve("services:\n  - {service: aaa/first, dependencies: []}\n  - {service: shop/app, dependencies: []}\n  - {service: shop/web, dependencies: []}\n")
	m := 20 * time.Minute
	// aaa/first tries 1001 ports of a private address, one more than the
	// series of the connector; shop/app connects to a public address and
	// to two private ones; shop/web to a public one.
	f.exec(`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
	        SELECT 'app-02', (SELECT id FROM shawk.processes WHERE service_name = 'aaa/first'), 'client', 'tcp', '10.0.0.21', '10.0.0.250',
	               p, 1, %[1]s, %[1]s FROM generate_series(1, 1001) p`, f.ago(m))
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, m, m)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.250", 7, m, m)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.0.250", 8, m, m)
	f.edge("app-02", "shop/web", "client", "tcp", "10.0.0.21", "203.0.113.67", 443, m, m)
	st, err := newPGStore(context.Background(), f.conn.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	// A baseline that only ever failed to be read is none: nothing is
	// judged, and the failure is told.
	f.exec(`UPDATE shawk.baseline_state SET read_at = NULL, digest = NULL, failed_at = %s, error = 'no services'`, f.ago(0))
	if r, err := st.baselineReport(context.Background(), f.T.Add(-time.Hour), f.T, f.T.Add(-7*days), 10, 10); err != nil || r.read ||
		!r.failed || len(r.drift) != 0 || len(r.services) != 0 {
		t.Errorf("report of a baseline that was never read = %+v, %v", r, err)
	}
	f.exec(`UPDATE shawk.baseline_state SET read_at = %s, digest = 'x', failed_at = NULL, error = NULL`, f.ago(0))
	report := func(maxDrift, perService int) (rows []string, named, unresolved int) {
		t.Helper()
		r, err := st.baselineReport(context.Background(), f.T.Add(-time.Hour), f.T, f.T.Add(-7*days), maxDrift, perService)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range r.drift {
			rows = append(rows, d.service+" "+d.peer+" "+itoa(int64(d.port)))
		}
		return rows, r.truncatedNamed, r.truncatedUnresolved
	}
	// The bounds of the connector: the flood is cut to its share, and the
	// drift of the others is all there.
	rows, named, unresolved := report(maxDriftSeries, maxDriftSeriesPerService)
	if len(rows) != 24 || named != 0 || unresolved != 981 || !slices.Contains(rows, "shop/app ~external 4444") ||
		!slices.Contains(rows, "shop/web ~external 443") || !slices.Contains(rows, "shop/app ~unresolved 8") {
		t.Errorf("with the shares of the connector: %d rows, %d and %d cut: %v", len(rows), named, unresolved, rows)
	}
	// A bound in all that is smaller than the drift: the named peers
	// first, then the first row of each service before the second of any.
	rows, named, unresolved = report(4, 20)
	want := []string{"shop/app ~external 4444", "shop/web ~external 443", "aaa/first ~unresolved 1", "shop/app ~unresolved 7"}
	if !slices.Equal(rows, want) || named != 0 || unresolved != 1001 {
		t.Errorf("with a bound of 4: %v, %d and %d cut, want %v", rows, named, unresolved, want)
	}
	// What is cut of the named peers is counted apart: it is critical.
	rows, named, unresolved = report(1, 20)
	if !slices.Equal(rows, []string{"shop/app ~external 4444"}) || named != 1 || unresolved != 1003 {
		t.Errorf("with a bound of 1: %v, %d and %d cut", rows, named, unresolved)
	}
	// Within the share of a service, the rows on a named peer come before
	// those on ~unresolved whatever the name is: one that is no ASCII
	// follows "~unresolved" in the order of bytes, and would lose its
	// place to the ports that nobody can name.
	f.host("db-01", "10.0.0.31")
	f.proc("db-01", "db.service", "\u00fcbersee/db")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "\u00fcbersee/db", "10.0.0.31", 5432, m, m)
	rows, named, unresolved = report(maxDriftSeries, 2)
	var app []string
	for _, row := range rows {
		if strings.HasPrefix(row, "shop/app ") {
			app = append(app, row)
		}
	}
	if want := []string{"shop/app ~external 4444", "shop/app \u00fcbersee/db 5432"}; !slices.Equal(app, want) || named != 0 || unresolved != 999+2 {
		t.Errorf("with a share of 2 rows a service: %v of shop/app, %d and %d cut, want %v", app, named, unresolved, want)
	}
}

// inOrder returns the rows of a query over the period of `lookback` before
// T as strings, in the order of the query: queryStrings sorts them, and
// cannot tell the order that a function returns them in.
func (f policyFixture) inOrder(lookback time.Duration, sql string) []string {
	f.t.Helper()
	rows, err := f.conn.Query(context.Background(), sql, f.T.Add(-lookback), f.T)
	if err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			f.t.Fatal(err)
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = fmt.Sprint(v)
		}
		out = append(out, strings.Join(parts, " "))
	}
	if err := rows.Err(); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// TestPGPolicyOrder: the order of what the contract returns is that of
// the bytes of the names, whatever the collation of the database: with
// en_US.UTF-8, the default of the PostgreSQL image, a capital sorts after
// the small letters and marks such as ~ and - are skipped at first, so
// that a list ordered by the database would differ from one database to
// another with the same contents, and with it the files of shawk-policy
// and what the connector keeps under its bounds. The names of this test
// are in another order in the two collations: by bytes -dash, Bravo,
// alpha, ~tilde; in en_US.UTF-8 alpha, Bravo, -dash, ~tilde.
func TestPGPolicyOrder(t *testing.T) {
	f := newPolicyFixture(t)
	names := []string{"-dash", "Bravo", "alpha", "~tilde"}
	f.host("srv-01", "10.0.0.9")
	for i, n := range names {
		h := n + "-01"
		f.host(h, "")
		for _, svc := range names {
			f.proc(h, svc+".service", svc)
			f.edge(h, svc, "client", "tcp", "10.0.0.1", "10.0.0.9", 80, 20*time.Minute, 0)
		}
		// The servers of srv-01, on a port each, named as the clients are.
		f.proc("srv-01", n+".service", "srv/"+n)
		f.pair(h, "alpha", "10.0.0.1", "srv-01", "srv/"+n, "10.0.0.9", 9000+i, 20*time.Minute, 0)
	}
	hosts := "[-dash-01 Bravo-01 alpha-01 ~tilde-01]"
	// alpha depends on four servers: its rows are by the bytes of the peer.
	want := []string{
		"-dash ~unresolved " + hosts, "Bravo ~unresolved " + hosts,
		"alpha srv/-dash [-dash-01]", "alpha srv/Bravo [Bravo-01]", "alpha srv/alpha [alpha-01]", "alpha srv/~tilde [~tilde-01]",
		"alpha ~unresolved " + hosts, "~tilde ~unresolved " + hosts,
	}
	if got := f.inOrder(time.Hour, `SELECT service, peer, hosts FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("observed, in its order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	f.approve("services:\n  - {service: \"-dash\", dependencies: []}\n  - {service: Bravo, dependencies: []}\n" +
		"  - {service: alpha, dependencies: []}\n  - {service: ~tilde, dependencies: []}\n")
	if got := f.inOrder(time.Hour, `SELECT service, peer, hosts FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("drift, in its order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// What the connector keeps of the drift of a service under its share
	// is the same in every database: the first two peers by bytes.
	st, err := newPGStore(context.Background(), f.conn.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	r, err := st.baselineReport(context.Background(), f.T.Add(-time.Hour), f.T, f.T.Add(-7*days), 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, d := range r.drift {
		kept = append(kept, d.service+" "+d.peer)
	}
	wantKept := []string{"-dash ~unresolved", "Bravo ~unresolved", "alpha srv/-dash", "alpha srv/Bravo", "~tilde ~unresolved"}
	slices.Sort(kept)
	if !slices.Equal(kept, wantKept) || r.truncatedNamed != 2 || r.truncatedUnresolved != 1 {
		t.Errorf("the connector keeps %v, and cuts %d and %d; want %v", kept, r.truncatedNamed, r.truncatedUnresolved, wantKept)
	}
	var services []string
	for _, c := range r.services {
		services = append(services, c.service)
	}
	if !slices.Equal(services, names) {
		t.Errorf("the services of the report, in its order: %v, want %v", services, names)
	}
	// The flows of a host: by service, then by peer.
	want = []string{"-dash ~unresolved", "Bravo ~unresolved", "alpha ~unresolved", "~tilde ~unresolved", "alpha srv/alpha"}
	if got := f.inOrder(time.Hour, `SELECT service, peer FROM shawk_v1.policy_flows('alpha-01', $1, $2)`); !slices.Equal(got, want) {
		t.Errorf("flows, in their order: %v, want %v", got, want)
	}
	// The hosts that were not observed, of which the first are listed, and
	// the services of a verdict.
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s WHERE host_id <> 'srv-01'`, f.ago(3*time.Hour))
	want = nil
	for _, n := range names {
		want = append(want, n+" "+hosts)
	}
	if got := f.inOrder(time.Hour, `SELECT service, short_hosts FROM shawk_v1.baseline_verdict(ARRAY['alpha', '~tilde', 'Bravo', '-dash'], $1, $2)`); !slices.Equal(got, want) {
		t.Errorf("verdicts, in their order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := f.inOrder(time.Hour, `SELECT (short_hosts)[1:2] FROM shawk_v1.baseline_verdict(ARRAY['alpha'], $1, $2)`); !slices.Equal(got, []string{"[-dash-01 Bravo-01]"}) {
		t.Errorf("the first two hosts that were not observed: %v", got)
	}
	// The new services.
	f.approve("services: []\n")
	f.exec(`UPDATE shawk.processes SET first_seen = %s WHERE host_id <> 'srv-01'`, f.ago(30*time.Minute))
	if got := f.inOrder(time.Hour, `SELECT service, hosts FROM shawk_v1.baseline_new_services($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("new services, in their order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The gaps of two machines of one name, by the ids of the machines.
	f.exec(`INSERT INTO shawk.hosts VALUES ('Bravo-id', 'm1', 'twin', 'k', 'v', %[1]s, %[2]s), ('alpha-id', 'm2', 'twin', 'k', 'v', %[1]s, %[2]s)`,
		f.ago(100*days), f.ago(0))
	f.session("Bravo-id", 100*days, 30*time.Minute, "true", "'all'")
	f.session("alpha-id", 100*days, 30*time.Minute, "true", "'all'")
	if got := f.inOrder(time.Hour, `SELECT machine FROM shawk_v1.policy_gaps('twin', $1, $2)`); !slices.Equal(got, []string{"Bravo-id", "alpha-id"}) {
		t.Errorf("the gaps, in their order: %v", got)
	}
}

// TestPGBaselineSharedUnits: a unit that unrelated processes share by its
// kind (the Slurm jobs of every user, login sessions) judges nothing: a
// baseline of one of its processes is not a baseline of the others. What
// is next to a baseline there is listed, once per unit, process and peer,
// and is no drift. In a unit of a workload, several services of the
// baseline judge a process together, and tell it once.
func TestPGBaselineSharedUnits(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("web-01", "10.0.0.12")
	f.host("web-02", "10.0.0.13")
	m := 20 * time.Minute
	// python3 has a baseline, and ran in a Slurm job and in a login session
	// of web-01; a.out of another user and rsync of an administrator run
	// there now. python3 runs nowhere on web-02, where the same units hold
	// other processes.
	for _, p := range [][3]string{
		{"web-01", "slurm/batch", "python3"}, {"web-01", "slurm/batch", "a.out"},
		{"web-01", "user-1000.slice/session.scope", "python3"}, {"web-01", "user-1000.slice/session.scope", "rsync"},
		{"web-01", "run.scope", "python3"}, {"web-01", "run.scope", "tool"},
		{"web-02", "slurm/batch", "b.out"},
		// Without a unit, two processes share nothing: what one of them
		// does is not next to the other.
		{"web-01", "", "python3"}, {"web-01", "", "stray"},
	} {
		f.proc(p[0], p[1], p[2])
	}
	f.edgeOf("web-01", "", "stray", "client", "tcp", "10.0.0.12", "10.0.7.7", 9, m, m)
	f.edgeOf("web-01", "slurm/batch", "a.out", "client", "tcp", "10.0.0.12", "10.0.5.5", 27000, m, m)
	f.edgeOf("web-01", "slurm/batch", "a.out", "client", "tcp", "10.0.0.12", "10.0.5.5", 27001, m, m)
	f.edgeOf("web-01", "user-1000.slice/session.scope", "rsync", "client", "tcp", "10.0.0.12", "10.0.6.6", 873, m, m)
	f.edgeOf("web-01", "run.scope", "tool", "client", "udp", "10.0.0.12", "203.0.113.9", 53, m, m)
	f.edgeOf("web-02", "slurm/batch", "b.out", "client", "tcp", "10.0.0.13", "10.0.5.5", 27000, m, m)
	f.approve("services:\n  - service: python3\n    dependencies:\n      - {peer: ~unresolved, port: 8000, proto: tcp}\n")
	if got := f.inOrder(time.Hour, `SELECT service, peer, port FROM shawk_v1.baseline_drift($1, $2)`); len(got) != 0 {
		t.Errorf("drift in units that unrelated processes share: %v", got)
	}
	want := []string{
		"run.scope tool ~external udp [53] [web-01] [python3] 3",
		"slurm/batch a.out ~unresolved tcp [27000 27001] [web-01] [python3] 3",
		"user-1000.slice/session.scope rsync ~unresolved tcp [873] [web-01] [python3] 3",
	}
	const columns = `unit, process, peer, proto, ports, hosts, services, total`
	if got := f.inOrder(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_unjudged($1, $2, `+f.ago(7*days)+`)`); !slices.Equal(got, want) {
		t.Errorf("next to a baseline in shared units:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The list is bounded, and counts what it leaves out.
	if got := f.inOrder(time.Hour, `SELECT unit, total FROM shawk_v1.baseline_unjudged($1, $2, `+f.ago(7*days)+`, 1)`); !slices.Equal(got, []string{"run.scope 3"}) {
		t.Errorf("the first of the list: %v", got)
	}
	for unit, want := range map[string]string{"": "true", "slurm/batch": "true", "slurm/step": "true", "session.scope": "true",
		"user-1000.slice/session.scope": "true", "run.scope": "true", "run.service": "true", "user@1000.service": "true",
		"user@1000.service/foo.service": "false", "user@1000.service/podman-0123456789ab": "false", "app.service": "false",
		"run-backup.service": "false", "cron.service": "false", "docker/shop/app": "false", "k8s/default/web/app": "false",
		"app.service/podman-0123456789ab": "false", "xsession.scope": "false"} {
		if got := queryStrings(t, f.conn, `SELECT shawk.shared_unit($1)`, unit); !slices.Equal(got, []string{want}) {
			t.Errorf("shared_unit(%q) = %v, want %s", unit, got, want)
		}
	}
}

// TestPGBaselineUnitOfSeveral: in a unit of a workload that runs several
// services of the baseline, a process without a baseline is judged by
// them together and told once, not once per service; a unit of the same
// name on a host where none of them runs judges nothing; and a process
// in a container under the unit is judged as the unit is.
func TestPGBaselineUnitOfSeveral(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("app-02", "10.0.0.21")
	f.host("app-03", "10.0.0.31")
	m := 20 * time.Minute
	for _, p := range [][3]string{
		{"app-01", "app.service", "shop/app"}, {"app-01", "app.service", "envoy"}, {"app-01", "app.service", "agent"},
		{"app-01", "app.service", "curl"}, {"app-01", "app.service/podman-0123456789ab", "wget"},
		{"app-01", "app.service2", "nc"},
		// app.service of app-02 runs none of the services of the baseline.
		{"app-02", "app.service", "curl"},
		// app.service of app-03 runs another service, with a baseline that
		// holds what curl does on app-01: a unit is of its host, and the
		// services of a unit of the same name elsewhere judge nothing here.
		{"app-03", "app.service", "other/app"},
	} {
		f.proc(p[0], p[1], p[2])
	}
	f.edge("app-01", "curl", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, m, m)
	f.edge("app-01", "curl", "client", "tcp", "10.0.0.11", "10.0.0.70", 9901, m, m)
	f.edge("app-01", "curl", "client", "tcp", "10.0.0.11", "10.0.0.10", 5432, m, m)
	f.edge("app-01", "wget", "client", "tcp", "10.0.0.11", "203.0.113.67", 80, m, m)
	f.edge("app-01", "nc", "client", "tcp", "10.0.0.11", "203.0.113.68", 1, m, m)
	f.edge("app-02", "curl", "client", "tcp", "10.0.0.21", "203.0.113.66", 4444, m, m)
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: ~unresolved, port: 5432, proto: tcp}\n" +
		"  - service: envoy\n    dependencies:\n      - {peer: ~unresolved, port: 9901, proto: tcp}\n" +
		"  - {service: agent, dependencies: []}\n" +
		"  - service: other/app\n    dependencies:\n      - {peer: ~external, port: 4444, proto: tcp}\n")
	// What one of the services of the unit approves is no drift of the
	// process; the rest is told once, under the first of them.
	want := []string{"agent ~external 80 [app-01] [wget]", "agent ~external 4444 [app-01] [curl]"}
	if got := f.inOrder(time.Hour, `SELECT service, peer, port, hosts, processes FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, want) {
		t.Errorf("drift:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Asked for a service of the unit, it is told under that service.
	want = []string{"shop/app ~external 80 [app-01] [wget]", "shop/app ~external 4444 [app-01] [curl]"}
	if got := f.inOrder(time.Hour, `SELECT service, peer, port, hosts, processes FROM shawk_v1.baseline_drift($1, $2, ARRAY['shop/app', 'nope'])`); !slices.Equal(got, want) {
		t.Errorf("drift of shop/app:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The baseline of one of them, written again, holds what the processes
	// without a baseline did, and not what the other services of the unit
	// have of their own.
	want = []string{"shop/app ~external 80 [wget]", "shop/app ~external 4444 [curl]", "shop/app ~unresolved 5432 [curl]",
		"shop/app ~unresolved 9901 [curl]"}
	if got := f.inOrder(time.Hour, `SELECT service, peer, port, processes FROM shawk_v1.baseline_observed($1, $2, ARRAY['shop/app'],
		ARRAY['shop/app', 'envoy', 'agent'])`); !slices.Equal(got, want) {
		t.Errorf("observed of shop/app:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGBaselineKernelChosenScope: a dependency on a port that the kernel
// chose approves the ports that the kernel chose for a server of the
// name, and no other: another server of the same name on a port of its
// own is a drift. Names are those of executables by default, and many
// servers share them.
func TestPGBaselineKernelChosenScope(t *testing.T) {
	f := newPolicyFixture(t)
	f.host("app-01", "10.0.0.11")
	f.host("db-01", "10.0.0.10")
	f.host("web-01", "10.0.0.12")
	f.proc("app-01", "app.service", "shop/app")
	f.proc("db-01", "mgmt.service", "java")
	f.proc("web-01", "search.service", "java")
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "java", "10.0.0.10", 40123, 20*days, 0)
	f.listener("db-01", "java", "0.0.0.0", 40123, f.ago(0))
	const columns = `peer, port, proto, kernel_chosen, ports`
	if got := f.inOrder(30*days, `SELECT `+columns+` FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, []string{"java 0 tcp true [40123]"}) {
		t.Fatalf("observed = %v", got)
	}
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: java, port: kernel-chosen, proto: tcp}\n")
	if got := queryStrings(t, f.conn, `SELECT peer, port, proto, kernel_chosen FROM shawk_v1.baseline WHERE peer IS NOT NULL`); !slices.Equal(got, []string{"java 0 tcp true"}) {
		t.Errorf("the baseline in PostgreSQL: %v", got)
	}
	// The server runs again, on another port that the kernel chose: no
	// drift. A server of the same name on a fixed port, which the service
	// never used: a drift.
	f.pair("app-01", "shop/app", "10.0.0.11", "db-01", "java", "10.0.0.10", 40999, 30*time.Minute, 0)
	f.listener("db-01", "java", "0.0.0.0", 40999, f.ago(0))
	if got := f.inOrder(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_drift($1, $2)`); len(got) != 0 {
		t.Errorf("drift after the server ran again: %v", got)
	}
	f.pair("app-01", "shop/app", "10.0.0.11", "web-01", "java", "10.0.0.12", 9200, 20*time.Minute, 0)
	if got := f.inOrder(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_drift($1, $2)`); !slices.Equal(got, []string{"java 9200 tcp false [9200]"}) {
		t.Errorf("drift on a fixed port of another server of the name: %v", got)
	}
	// Port 0 written by hand is every port of every server of the name.
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: java, port: 0, proto: tcp}\n")
	if got := f.inOrder(time.Hour, `SELECT `+columns+` FROM shawk_v1.baseline_drift($1, $2)`); len(got) != 0 {
		t.Errorf("drift with every port approved: %v", got)
	}
	// A server under a rule of ports is every port by that rule, whoever
	// chose its port: its row is not one of the kernel.
	f.exec(`INSERT INTO shawk.port_agnostic_services VALUES ('java')`)
	if got := f.inOrder(30*days, `SELECT `+columns+` FROM shawk_v1.baseline_observed($1, $2)`); !slices.Equal(got, []string{"java 0 tcp false [9200 40123 40999]"}) {
		t.Errorf("observed under a rule of ports = %v", got)
	}
}
