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
  shawk_agent_export_failures_total{job="shawk-agent", host_name="app-01"} 0x30
  shawk_agent_export_failures_total{job="shawk-agent", host_name="app-03"} 0+1x30

eval instant at 20m ` + a("ShawkUDPNotTraced") + `
  shawk_agent_udp_traced{job="shawk-agent", host_name="app-03"} 0

# One failure a minute.
eval instant at 20m ` + a("ShawkExportFailures") + `
  {job="shawk-agent", host_name="app-03"} 15
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
	for name, e := range alerts {
		if _, err := parser.NewParser(parser.Options{}).ParseExpr(e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
