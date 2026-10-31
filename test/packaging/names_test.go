package packaging

import (
	"testing"

	"github.com/prometheus/otlptranslator"
)

// TestPrometheusNames checks the names Prometheus gives to the metrics the
// shawk connector sends (the contract of §4.3 of the design), with the
// default translation of its OTLP receiver.
func TestPrometheusNames(t *testing.T) {
	namer := otlptranslator.MetricNamer{WithMetricSuffixes: true}
	for _, tc := range []struct {
		name, unit string
		typ        otlptranslator.MetricType
		want       string
	}{
		{"shawk.connection.opened", "{connection}", otlptranslator.MetricTypeMonotonicCounter, "shawk_connection_opened_total"},
		{"shawk.connection.failed", "{connection}", otlptranslator.MetricTypeMonotonicCounter, "shawk_connection_failed_total"},
		{"shawk.connection.count", "{connection}", otlptranslator.MetricTypeNonMonotonicCounter, "shawk_connection_count"},
		{"shawk.network.io", "By", otlptranslator.MetricTypeMonotonicCounter, "shawk_network_io_bytes_total"},
		{"shawk.udp.datagrams", "{datagram}", otlptranslator.MetricTypeMonotonicCounter, "shawk_udp_datagrams_total"},
		{"shawk.tcp.retransmits", "{segment}", otlptranslator.MetricTypeMonotonicCounter, "shawk_tcp_retransmits_total"},
		{"shawk.tcp.rtt", "s", otlptranslator.MetricTypeHistogram, "shawk_tcp_rtt_seconds"},
		{"shawk.agent.up", "", otlptranslator.MetricTypeGauge, "shawk_agent_up"},
		{"shawk.agent.udp.traced", "", otlptranslator.MetricTypeGauge, "shawk_agent_udp_traced"},
		{"shawk.agent.flows.dropped", "{update}", otlptranslator.MetricTypeMonotonicCounter, "shawk_agent_flows_dropped_total"},
		{"shawk.agent.export.failures", "{request}", otlptranslator.MetricTypeMonotonicCounter, "shawk_agent_export_failures_total"},
	} {
		got, err := namer.Build(otlptranslator.Metric{Name: tc.name, Unit: tc.unit, Type: tc.typ})
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}
