package packaging

import (
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/promql/promqltest"
)

const rulesFile = "../../packaging/prometheus/shawk-rules.yml"

// loadRules returns the expressions of the recording rules and alerts.
func loadRules(t *testing.T) (records, alerts map[string]string) {
	t.Helper()
	rgs, errs := rulefmt.ParseFile(rulesFile, false, model.UTF8Validation, parser.NewParser(parser.Options{}), slog.New(slog.DiscardHandler))
	for _, err := range errs {
		t.Error(err)
	}
	if rgs == nil {
		t.FailNow()
	}
	records, alerts = map[string]string{}, map[string]string{}
	for _, g := range rgs.Groups {
		for _, r := range g.Rules {
			if r.Record != "" {
				records[r.Record] = r.Expr
			} else {
				alerts[r.Alert] = r.Expr
			}
		}
	}
	return records, alerts
}

var space = regexp.MustCompile(`\s+`)

// inline replaces the names of recording rules in expr with their
// expressions and puts it on one line, as promqltest wants.
func inline(expr string, records map[string]string) string {
	for name, e := range records {
		expr = strings.ReplaceAll(expr, name, "("+e+")")
	}
	return strings.TrimSpace(space.ReplaceAllString(expr, " "))
}

// The series as Prometheus stores what the shawk connector sends: the app
// on two hosts connects to postgres, whose host also runs an agent and also
// serves an office PC without an agent.
const series = `
load 1m
  shawk_connection_opened_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+60x10
  shawk_connection_opened_total{job="shop/app", instance="app-02", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+60x10
  shawk_connection_opened_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="shop/app", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+120x10
  shawk_connection_opened_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="office-lan", shawk_peer_agent="false", server_port="5432", network_transport="tcp"} 0+180x10
  shawk_connection_failed_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+30x10
  shawk_connection_count{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 4x10
  shawk_connection_count{job="postgres", instance="db-01", shawk_role="server", service_peer_name="shop/app", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 4x10
  shawk_connection_count{job="postgres", instance="db-01", shawk_role="server", service_peer_name="office-lan", shawk_peer_agent="false", server_port="5432", network_transport="tcp"} 1x10
  shawk_network_io_bytes_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp", network_io_direction="transmit"} 0+600x10
  shawk_network_io_bytes_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp", network_io_direction="receive"} 0+6000x10
  shawk_network_io_bytes_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="shop/app", shawk_peer_agent="true", server_port="5432", network_transport="tcp", network_io_direction="receive"} 0+600x10
  shawk_network_io_bytes_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="shop/app", shawk_peer_agent="true", server_port="5432", network_transport="tcp", network_io_direction="transmit"} 0+6000x10
  shawk_network_io_bytes_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="office-lan", shawk_peer_agent="false", server_port="5432", network_transport="tcp", network_io_direction="receive"} 0+300x10
  shawk_network_io_bytes_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="office-lan", shawk_peer_agent="false", server_port="5432", network_transport="tcp", network_io_direction="transmit"} 0+3000x10
  shawk_tcp_rtt_seconds_sum{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+0.06x10
  shawk_tcp_rtt_seconds_count{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+60x10
  shawk_tcp_retransmits_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+60x10
  shawk_tcp_retransmits_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="office-lan", shawk_peer_agent="false", server_port="5432", network_transport="tcp"} 0+120x10
  shawk_tcp_retransmits_total{job="postgres", instance="db-01", shawk_role="server", service_peer_name="shop/app", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+180x10
  shawk_tcp_handshake_seconds_sum{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+1.2x10
  shawk_tcp_handshake_seconds_count{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+60x10
  shawk_tcp_handshake_seconds_sum{job="shop/app", instance="app-02", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+0.6x10
  shawk_tcp_handshake_seconds_count{job="shop/app", instance="app-02", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+60x10
  shawk_tcp_syn_retransmits_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"} 0+12x10
  shawk_connection_failed_by_reason_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp", error_type="timeout"} 0+18x10
  shawk_connection_failed_by_reason_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp", error_type="refused"} 0+12x10
  shawk_udp_datagrams_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="~external", shawk_peer_agent="false", server_port="53", network_transport="udp", network_io_direction="transmit"} 0+60x10
  shawk_udp_datagrams_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="~external", shawk_peer_agent="false", server_port="53", network_transport="udp", network_io_direction="receive"} 0+120x10
  shawk_agent_up{job="shawk-agent", host_name="app-01"} 1x30
  shawk_agent_up{job="shawk-agent", host_name="app-02"} 1x10
  shawk_agent_flows_dropped_total{job="shawk-agent", host_name="app-01"} 0 0 0 0 0 5 5 5 5 5 5
`

func TestRecordingRules(t *testing.T) {
	records, _ := loadRules(t)
	r := func(name string) string {
		e, ok := records[name]
		if !ok {
			t.Fatalf("no recording rule %s", name)
		}
		return inline(e, nil)
	}
	app := `src="shop/app", dst="postgres", server_port="5432", network_transport="tcp"`
	office := `src="office-lan", dst="postgres", server_port="5432", network_transport="tcp"`
	script := series + `
# The server side of the app's connections (shawk_peer_agent="true") is not
# counted twice.
eval instant at 10m ` + r("shawk:dependency_connections:rate5m") + `
  {` + app + `} 2
  {` + office + `} 3

eval instant at 10m ` + r("shawk:dependency_connection_failures:rate5m") + `
  {` + app + `} 0.5

eval instant at 10m ` + r("shawk:dependency_connection_failures_by_reason:rate5m") + `
  {` + app + `, error_type="timeout"} 0.3
  {` + app + `, error_type="refused"} 0.2

# 20 ms on app-01 and 10 ms on app-02, which open as many connections.
eval instant at 10m ` + r("shawk:dependency_handshake_seconds_sum:rate5m") + " / " + r("shawk:dependency_handshake_seconds_count:rate5m") + `
  {` + app + `} 0.015

eval instant at 10m ` + r("shawk:dependency_syn_retransmits:rate5m") + `
  {` + app + `} 0.2

eval instant at 10m ` + r("shawk:dependency_open_connections") + `
  {` + app + `} 4
  {` + office + `} 1

eval instant at 10m ` + r("shawk:dependency_request_bytes:rate5m") + `
  {` + app + `} 10
  {` + office + `} 5

eval instant at 10m ` + r("shawk:dependency_response_bytes:rate5m") + `
  {` + app + `} 100
  {` + office + `} 50

eval instant at 10m ` + r("shawk:dependency_rtt_seconds_sum:rate5m") + " / " + r("shawk:dependency_rtt_seconds_count:rate5m") + `
  {` + app + `} 0.001

# Each side's own retransmissions; the server names the client service.
eval instant at 10m ` + r("shawk:dependency_retransmits:rate5m") + `
  {` + app + `, shawk_role="client"} 1
  {` + app + `, shawk_role="server"} 3
  {` + office + `, shawk_role="server"} 2

eval instant at 10m ` + r("shawk:dependency_request_datagrams:rate5m") + `
  {src="shop/app", dst="~external", server_port="53", network_transport="udp"} 1

eval instant at 10m ` + r("shawk:dependency_response_datagrams:rate5m") + `
  {src="shop/app", dst="~external", server_port="53", network_transport="udp"} 2
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}

// TestUnixRecordingRules: the dependencies over Unix sockets, which the
// connector sends from their client side only, with port 0 and without
// bytes, are counted by the same rules, apart from those over TCP.
func TestUnixRecordingRules(t *testing.T) {
	records, alerts := loadRules(t)
	r := func(name string) string {
		e, ok := records[name]
		if !ok {
			t.Fatalf("no recording rule %s", name)
		}
		return inline(e, nil)
	}
	app := `src="shop/app", dst="postgres", server_port="5432", network_transport="tcp"`
	office := `src="office-lan", dst="postgres", server_port="5432", network_transport="tcp"`
	unix := `src="shop/app", dst="postgres", server_port="0", network_transport="unix"`
	// cron tries the socket of nscd, which does not run, at every job.
	nscd := `src="cron", dst="~unresolved", server_port="0", network_transport="unix"`
	script := series + `
load 1m
  shawk_connection_opened_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="0", network_transport="unix"} 0+60x10
  shawk_connection_failed_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="0", network_transport="unix"} 0+60x10
  shawk_connection_failed_by_reason_total{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="0", network_transport="unix", error_type="refused"} 0+60x10
  shawk_connection_count{job="shop/app", instance="app-01", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="0", network_transport="unix"} 3x10
  shawk_connection_opened_total{job="cron", instance="app-01", shawk_role="client", service_peer_name="~unresolved", shawk_peer_agent="true", server_port="0", network_transport="unix"} 0x10
  shawk_connection_failed_total{job="cron", instance="app-01", shawk_role="client", service_peer_name="~unresolved", shawk_peer_agent="true", server_port="0", network_transport="unix"} 0+2x10

eval instant at 10m ` + r("shawk:dependency_connections:rate5m") + `
  {` + app + `} 2
  {` + office + `} 3
  {` + unix + `} 1
  {` + nscd + `} 0

eval instant at 10m ` + r("shawk:dependency_connection_failures_by_reason:rate5m") + `
  {` + app + `, error_type="timeout"} 0.3
  {` + app + `, error_type="refused"} 0.2
  {` + unix + `, error_type="refused"} 1

eval instant at 10m ` + r("shawk:dependency_open_connections") + `
  {` + app + `} 4
  {` + office + `} 1
  {` + unix + `} 3

# No bytes: a Unix socket keeps no count of them.
eval instant at 10m ` + r("shawk:dependency_request_bytes:rate5m") + `
  {` + app + `} 10
  {` + office + `} 5

# Connects to Unix sockets that no listener serves are not alerted.
eval instant at 10m ` + inline(alerts["ShawkConnectionFailureRate"], records) + `
  {` + app + `} 0.2
  {` + unix + `} 0.5
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}

// The family per peer host as Prometheus stores what the shawk connector
// sends with peer_hosts: slurmctld on ctl-01 connects to the slurmd of
// node-01, which runs an agent, and fails to reach node-03, which is down;
// node-01 also serves a client without an agent at an address of no known
// host.
const hostSeries = `
load 1m
  shawk_host_connection_opened_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp"} 0+60x10
  shawk_host_connection_opened_total{job="slurmd", instance="node-01", shawk_role="server", service_peer_name="slurmctld", shawk_peer_agent="true", shawk_peer_host="ctl-01", server_port="6818", network_transport="tcp"} 0+60x10
  shawk_host_connection_opened_total{job="slurmd", instance="node-01", shawk_role="server", service_peer_name="~unresolved", shawk_peer_agent="false", shawk_peer_host="~unknown", server_port="6818", network_transport="tcp"} 0+120x10
  shawk_host_connection_failed_by_reason_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="false", shawk_peer_host="node-03", server_port="6818", network_transport="tcp", error_type="timeout"} 0+30x10
  shawk_host_tcp_handshake_seconds_sum{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp"} 0+0.6x10
  shawk_host_tcp_handshake_seconds_count{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp"} 0+60x10
  shawk_host_tcp_syn_retransmits_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="false", shawk_peer_host="node-03", server_port="6818", network_transport="tcp"} 0+90x10
  shawk_host_network_io_bytes_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp", network_io_direction="transmit"} 0+600x10
  shawk_host_network_io_bytes_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp", network_io_direction="receive"} 0+6000x10
  shawk_host_network_io_bytes_total{job="slurmd", instance="node-01", shawk_role="server", service_peer_name="slurmctld", shawk_peer_agent="true", shawk_peer_host="ctl-01", server_port="6818", network_transport="tcp", network_io_direction="receive"} 0+600x10
  shawk_host_network_io_bytes_total{job="slurmd", instance="node-01", shawk_role="server", service_peer_name="~unresolved", shawk_peer_agent="false", shawk_peer_host="~unknown", server_port="6818", network_transport="tcp", network_io_direction="receive"} 0+300x10
  shawk_host_network_io_bytes_total{job="slurmd", instance="node-01", shawk_role="server", service_peer_name="~unresolved", shawk_peer_agent="false", shawk_peer_host="~unknown", server_port="6818", network_transport="tcp", network_io_direction="transmit"} 0+3000x10
  shawk_host_tcp_retransmits_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp"} 0+60x10
  shawk_host_tcp_retransmits_total{job="slurmd", instance="node-01", shawk_role="server", service_peer_name="slurmctld", shawk_peer_agent="true", shawk_peer_host="ctl-01", server_port="6818", network_transport="tcp"} 0+180x10
`

func TestHostRecordingRules(t *testing.T) {
	records, _ := loadRules(t)
	r := func(name string) string {
		e, ok := records[name]
		if !ok {
			t.Fatalf("no recording rule %s", name)
		}
		return inline(e, nil)
	}
	node1 := `src_host="ctl-01", src="slurmctld", dst_host="node-01", dst="slurmd", server_port="6818", network_transport="tcp"`
	node3 := `src_host="ctl-01", src="slurmctld", dst_host="node-03", dst="slurmd", server_port="6818", network_transport="tcp"`
	unknown := `src_host="~unknown", src="~unresolved", dst_host="node-01", dst="slurmd", server_port="6818", network_transport="tcp"`
	script := hostSeries + `
# The server side of slurmctld's connections (shawk_peer_agent="true") is
# not counted twice; that of the client without an agent is.
eval instant at 10m ` + r("shawk:host_dependency_connections:rate5m") + `
  {` + node1 + `} 1
  {` + unknown + `} 2

eval instant at 10m ` + r("shawk:host_dependency_connection_failures_by_reason:rate5m") + `
  {` + node3 + `, error_type="timeout"} 0.5

eval instant at 10m ` + r("shawk:host_dependency_handshake_seconds_sum:rate5m") + " / " + r("shawk:host_dependency_handshake_seconds_count:rate5m") + `
  {` + node1 + `} 0.01

eval instant at 10m ` + r("shawk:host_dependency_syn_retransmits:rate5m") + `
  {` + node3 + `} 1.5

eval instant at 10m ` + r("shawk:host_dependency_request_bytes:rate5m") + `
  {` + node1 + `} 10
  {` + unknown + `} 5

eval instant at 10m ` + r("shawk:host_dependency_response_bytes:rate5m") + `
  {` + node1 + `} 100
  {` + unknown + `} 50

# Each side's own retransmissions; the server names the client host.
eval instant at 10m ` + r("shawk:host_dependency_retransmits:rate5m") + `
  {` + node1 + `, shawk_role="client"} 1
  {` + node1 + `, shawk_role="server"} 3
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}

func TestAlerts(t *testing.T) {
	records, alerts := loadRules(t)
	a := func(name string) string {
		e, ok := alerts[name]
		if !ok {
			t.Fatalf("no alert %s", name)
		}
		return inline(e, records)
	}
	script := series + `
# app-02 stopped sending at 10m; the alert fires once its series are stale.
eval instant at 12m ` + a("ShawkAgentDown") + `

eval instant at 20m ` + a("ShawkAgentDown") + `
  {host_name="app-02"} 1

eval instant at 10m ` + a("ShawkFlowsDropped") + `
  {job="shawk-agent", host_name="app-01"} 5

# 0.5 failures/s against 2 connections/s.
eval instant at 10m ` + a("ShawkConnectionFailureRate") + `
  {src="shop/app", dst="postgres", server_port="5432", network_transport="tcp"} 0.2

load 1m
  shawk_agent_udp_traced{job="shawk-agent", host_name="app-01"} 1x30
  shawk_agent_udp_traced{job="shawk-agent", host_name="app-03"} 0x30
  shawk_agent_unix_traced{job="shawk-agent", host_name="app-01"} 1x30
  shawk_agent_unix_traced{job="shawk-agent", host_name="app-03"} 0x30
  shawk_agent_export_failures_total{job="shawk-agent", host_name="app-01"} 0x30
  shawk_agent_export_failures_total{job="shawk-agent", host_name="app-03"} 0+1x30
  shawk_agent_cgroup_events_dropped_total{job="shawk-agent", host_name="app-01"} 0x30
  shawk_agent_cgroup_events_dropped_total{job="shawk-agent", host_name="app-03"} 0x10 2504x20
  shawk_agent_container_reads_dropped_total{job="shawk-agent", host_name="app-01"} 0x30
  shawk_agent_container_reads_dropped_total{job="shawk-agent", host_name="app-03"} 0x15 7x15

eval instant at 20m ` + a("ShawkUDPNotTraced") + `
  shawk_agent_udp_traced{job="shawk-agent", host_name="app-03"} 0

eval instant at 20m ` + a("ShawkUnixNotTraced") + `
  shawk_agent_unix_traced{job="shawk-agent", host_name="app-03"} 0

# One failure a minute.
eval instant at 20m ` + a("ShawkExportFailures") + `
  {job="shawk-agent", host_name="app-03"} 15

eval instant at 15m ` + a("ShawkCgroupEventsDropped") + `
  {job="shawk-agent", host_name="app-03"} 2504

# Resolved 10 minutes after the burst.
eval instant at 25m ` + a("ShawkCgroupEventsDropped") + `

eval instant at 20m ` + a("ShawkContainerReadsDropped") + `
  {job="shawk-agent", host_name="app-03"} 7

# The agents of Slurm nodes stop at 10m. Those powered down, powering down
# or powering up by power saving, or in a maintenance reservation, are not
# alerted. DOWN, DRAIN and a node that does not respond (cn09) are, and so
# is a node whose state the exporter stopped reporting at 12m (cn07). cn08
# powers up for a job from 16m and is up at 21m, without its agent. The
# series of states end with staleness markers, as when a scrape no longer
# has them.
load 1m
  shawk_agent_up{job="shawk-agent", host_name="cn01"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn02"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn03"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn04"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn05"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn06"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn07"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn08"} 1x10
  shawk_agent_up{job="shawk-agent", host_name="cn09"} 1x10
  slurm_node_state{node="cn01", state="IDLE+POWERED_DOWN"} 1x30
  slurm_node_state{node="cn02", state="idle+powering_down"} 1x30
  slurm_node_state{node="cn03", state="DOWN+POWERED_DOWN"} 1x30
  slurm_node_state{node="cn04", state="IDLE+DRAIN+POWERED_DOWN"} 1x30
  slurm_node_state{node="cn05", state="DOWN+MAINT"} 1x30
  slurm_node_state{node="cn06", state="IDLE"} 1x30
  slurm_node_state{node="cn07", state="IDLE+POWERED_DOWN"} 1x12 stale
  slurm_node_state{node="cn08", state="IDLE+POWERED_DOWN"} 1x15 stale
  slurm_node_state{node="cn08", state="ALLOCATED+POWERING_UP"} _x16 1x4 stale
  slurm_node_state{node="cn08", state="ALLOCATED"} _x21 1x9
  slurm_node_state{node="cn09", state="IDLE*+POWERED_DOWN"} 1x30

# The series of the agents last 5 minutes.
eval instant at 15m ` + a("ShawkAgentDown") + `
  {host_name="app-02"} 1
  {host_name="cn03"} 1
  {host_name="cn04"} 1
  {host_name="cn06"} 1
  {host_name="cn07"} 1
  {host_name="cn09"} 1

eval instant at 18m ` + a("ShawkAgentDown") + `
  {host_name="app-02"} 1
  {host_name="cn03"} 1
  {host_name="cn04"} 1
  {host_name="cn06"} 1
  {host_name="cn07"} 1
  {host_name="cn09"} 1

# cn08 is up and its agent has not sent for 2 minutes.
eval instant at 23m ` + a("ShawkAgentDown") + `
  {host_name="app-02"} 1
  {host_name="cn03"} 1
  {host_name="cn04"} 1
  {host_name="cn06"} 1
  {host_name="cn07"} 1
  {host_name="cn08"} 1
  {host_name="cn09"} 1
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
	for name, e := range alerts {
		if _, err := parser.NewParser(parser.Options{}).ParseExpr(e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSYNRetransmitRatio evaluates the panel of SYN retransmissions per
// attempt of the dependency details dashboard. Its denominator is the union
// of the handshakes and the failures by reason, which the agents that send
// the retransmissions send too: app-03 sends failures without handshakes,
// and the dependency on redis-server has no failures.
func TestSYNRetransmitRatio(t *testing.T) {
	records, _ := loadRules(t)
	d := loadJSON(t, grafana+"/dashboards/shawk-dependency.json")
	var expr string
	for _, p := range d["panels"].([]any) {
		p := p.(map[string]any)
		if p["title"] == "SYN retransmissions per attempt" {
			expr = p["targets"].([]any)[0].(map[string]any)["expr"].(string)
		}
	}
	if expr == "" {
		t.Fatal("no panel of SYN retransmissions per attempt")
	}
	// All clients and servers: the recording rules are inlined, which takes
	// no matchers.
	expr = strings.ReplaceAll(expr, `{src=~"$src", dst=~"$dst"}`, "")
	pg := `job="shop/app", shawk_role="client", service_peer_name="postgres", shawk_peer_agent="true", server_port="5432", network_transport="tcp"`
	redis := `job="shop/app", instance="app-01", shawk_role="client", service_peer_name="redis-server", shawk_peer_agent="true", server_port="6379", network_transport="tcp"`
	script := `
load 1m
  shawk_tcp_handshake_seconds_count{instance="app-01", ` + pg + `} 0+120x10
  shawk_tcp_syn_retransmits_total{instance="app-01", ` + pg + `} 0+30x10
  shawk_connection_failed_by_reason_total{instance="app-01", ` + pg + `, error_type="timeout"} 0+30x10
  shawk_connection_failed_total{instance="app-01", ` + pg + `} 0+30x10
  shawk_connection_failed_total{instance="app-03", ` + pg + `} 0+60x10
  shawk_tcp_handshake_seconds_count{` + redis + `} 0+60x10
  shawk_tcp_syn_retransmits_total{` + redis + `} 0+6x10

# 0.5 SYNs/s over 2 handshakes/s and 0.5 failures/s of app-01; 0.1 SYNs/s
# over 1 handshake/s.
eval instant at 10m ` + inline(expr, records) + `
  {src="shop/app", dst="postgres", server_port="5432"} 0.2
  {src="shop/app", dst="redis-server", server_port="6379"} 0.1
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}

// TestHostFailureRatio evaluates the panel of the failure ratio by peer host
// of the peer hosts dashboard: node-03 accepts no connection at all, so its
// pair has failures without connections, and shows 100%.
func TestHostFailureRatio(t *testing.T) {
	records, _ := loadRules(t)
	d := loadJSON(t, grafana+"/dashboards/shawk-hosts.json")
	var expr string
	for _, p := range d["panels"].([]any) {
		p := p.(map[string]any)
		if p["title"] == "Connection failure ratio by peer host" {
			expr = p["targets"].([]any)[0].(map[string]any)["expr"].(string)
		}
	}
	if expr == "" {
		t.Fatal("no panel of the failure ratio by peer host")
	}
	expr = strings.ReplaceAll(expr, `{dst=~"$dst", src=~"$src", dst_host=~"$dst_host"}`, "")
	script := hostSeries + `
load 1m
  shawk_host_connection_failed_by_reason_total{job="slurmctld", instance="ctl-01", shawk_role="client", service_peer_name="slurmd", shawk_peer_agent="true", shawk_peer_host="node-01", server_port="6818", network_transport="tcp", error_type="refused"} 0+20x10

# node-01: 1/3 failures/s over 1 connection/s; node-03: failures only.
eval instant at 10m ` + inline(expr, records) + `
  {src_host="ctl-01", src="slurmctld", dst_host="node-01", dst="slurmd", server_port="6818"} 0.25
  {src_host="ctl-01", src="slurmctld", dst_host="node-03", dst="slurmd", server_port="6818"} 1
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}
