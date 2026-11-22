package otlp

import (
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// TestWireProtocols checks that an edge keeps when each wire protocol was
// first and last seen, and sends two gauges per protocol seen.
func TestWireProtocols(t *testing.T) {
	s := NewState(15 * time.Minute)
	k := clientEdge()
	end := t0.Add(15 * time.Second)
	bit := func(name string) uint32 {
		for i, p := range WireProtocols {
			if p == name {
				return 1 << i
			}
		}
		t.Fatalf("no wire protocol %s", name)
		return 0
	}
	s.AddEdge(k, EdgeStats{Conns: 1, Protocols: bit("tls_1_2")}, t0, end)
	s.AddEdge(k, EdgeStats{Conns: 2, Protocols: bit("tls_1_2") | bit("tls_1_3")}, end, end.Add(15*time.Second))
	// The connections of an interval without new ones change nothing.
	s.AddEdge(k, EdgeStats{BytesSent: 10}, end.Add(15*time.Second), end.Add(30*time.Second))
	other := k
	other.Port = 6379
	s.AddEdge(other, EdgeStats{Conns: 1}, t0, end)

	e := s.Edges()[k]
	if got := e.Protocols[4]; got.First != end || got.Last != end.Add(15*time.Second) {
		t.Errorf("tls_1_2 seen %+v", got)
	}
	if got := e.Protocols[5]; got.First != end.Add(15*time.Second) || got.Last != got.First {
		t.Errorf("tls_1_3 seen %+v", got)
	}
	req := s.Request(Resource{Hostname: "h"}, AgentStatus{}, end.Add(30*time.Second))
	seen := map[string][2]int64{}
	for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		if m.Name != MetricEdgeWireFirst && m.Name != MetricEdgeWireLast {
			continue
		}
		if m.Unit != "s" {
			t.Errorf("%s has unit %q", m.Name, m.Unit)
		}
		for _, p := range m.GetGauge().GetDataPoints() {
			a := attrMap(p.Attributes)
			if a[AttrServerPort] != int64(5432) {
				t.Errorf("%s of the edge of port %v, which saw no protocol", m.Name, a[AttrServerPort])
			}
			name, _ := a[AttrWireProtocol].(string)
			v := seen[name]
			if m.Name == MetricEdgeWireFirst {
				v[0] = p.GetAsInt()
			} else {
				v[1] = p.GetAsInt()
			}
			seen[name] = v
		}
	}
	want := map[string][2]int64{
		"tls_1_2": {end.Unix(), end.Add(15 * time.Second).Unix()},
		"tls_1_3": {end.Add(15 * time.Second).Unix(), end.Add(15 * time.Second).Unix()},
	}
	if len(seen) != len(want) {
		t.Errorf("protocols sent: %v, want %v", seen, want)
	}
	for name, v := range want {
		if seen[name] != v {
			t.Errorf("%s: first and last seen %v, want %v", name, seen[name], v)
		}
	}
}

// TestWireProtocolSize checks that wireProtocolSize bounds every value of
// shawk.wire_protocol.
func TestWireProtocolSize(t *testing.T) {
	for _, p := range WireProtocols {
		if n := attrsSize([]*commonpb.KeyValue{str(AttrWireProtocol, p)}); n > wireProtocolSize {
			t.Errorf("%s takes %d bytes, more than %d", p, n, wireProtocolSize)
		}
	}
}
