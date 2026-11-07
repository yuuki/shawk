package shawkconnector

import (
	"math"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// TestInvalidMetricTypes: a metric of edges of another type than the agents
// send, and a point whose attributes identify no edge, are invalid and left
// out; a metric of another name is ignored, and one of the agent that it
// does not send is dropped.
func TestInvalidMetricTypes(t *testing.T) {
	md := tAgent{host: "app-01", time: t0, edges: []tEdge{{role: roleClient, proto: "tcp", local: "10.0.0.11",
		peer: "10.0.0.10", port: 5432, svc: "app", comm: "app", opened: 3}}}.metrics()
	ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	add := func(name string, kind pmetric.MetricType) pmetric.NumberDataPoint {
		m := ms.AppendEmpty()
		m.SetName(name)
		var dp pmetric.NumberDataPoint
		switch kind {
		case pmetric.MetricTypeGauge:
			dp = m.SetEmptyGauge().DataPoints().AppendEmpty()
		case pmetric.MetricTypeSum:
			dp = m.SetEmptySum().DataPoints().AppendEmpty()
		}
		dp.SetTimestamp(pcommon.NewTimestampFromTime(t0))
		dp.SetIntValue(1)
		return dp
	}
	add(metricConnOpened, pmetric.MetricTypeGauge)
	add(metricRTT, pmetric.MetricTypeSum)
	add(metricEdgeFirst, pmetric.MetricTypeSum)
	add(metricNetworkIO, pmetric.MetricTypeSum).Attributes().PutStr(attrIODirection, "transmit")
	add("other.metric", pmetric.MetricTypeSum)
	add("shawk.agent.unknown", pmetric.MetricTypeGauge)
	// The flows dropped since a start the agent does not send.
	add(metricAgentFlowsDropped, pmetric.MetricTypeSum).SetIntValue(4)

	b, err := parseResource(md.ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if b.invalid != 4 {
		t.Errorf("%d invalid data points, want 4", b.invalid)
	}
	if b.agentDropped != 1 || b.agentDroppedName != "shawk.agent.unknown" {
		t.Errorf("agent metrics dropped: %d, %q", b.agentDropped, b.agentDroppedName)
	}
	if b.dropped != 4 || !b.droppedSince.IsZero() {
		t.Errorf("flows dropped: %d since %v", b.dropped, b.droppedSince)
	}
	if len(b.edges) != 1 {
		t.Fatalf("%d edges, want 1", len(b.edges))
	}
	for _, e := range b.edges {
		if p := e.values[valueKey{metric: metricConnOpened}]; p.value != 3 {
			t.Errorf("connections opened = %v, want 3", p.value)
		}
		if !e.first.Equal(t0) {
			t.Errorf("edge first seen %v, want %v", e.first, t0)
		}
	}
	if !b.time.Equal(t0) {
		t.Errorf("time = %v, want %v", b.time, t0)
	}
	var names []string
	for i := range b.agent.Len() {
		names = append(names, b.agent.At(i).Name())
	}
	if len(names) != 3 || names[2] != metricAgentFlowsDropped {
		t.Errorf("forwarded agent metrics = %v", names)
	}
}

// TestValuesNotNumbers: a value of an edge that is not a number, or beyond
// the int64 counts of agents, is an invalid point. It would otherwise stay
// in the outputs it is added to, e.g. a NaN sum of RTTs in every later
// point of the series of its dependency.
func TestValuesNotNumbers(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	request := func(opened float64, rttSum float64) pmetric.Metrics {
		md := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now.Add(-time.Second), edges: []tEdge{{
			role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", comm: "puma",
			opened: 1, rttSum: rttSum, rttCount: 2}}}.metrics()
		ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
		for i := range ms.Len() {
			if m := ms.At(i); m.Name() == metricConnOpened {
				m.Sum().DataPoints().At(0).SetDoubleValue(opened)
			}
		}
		return md
	}
	b, err := parseResource(request(math.NaN(), math.Inf(1)).ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if b.invalid != 2 {
		t.Errorf("%d invalid data points, want 2", b.invalid)
	}
	*now = now.Add(15 * time.Second)
	consumeRequest(t, c, sink, request(1, 0.1))
	for _, v := range []float64{math.NaN(), math.Inf(-1), 1 << 63, -1 << 63} {
		*now = now.Add(15 * time.Second)
		consumeRequest(t, c, sink, request(v, v))
	}
	*now = now.Add(15 * time.Second)
	out := consumeRequest(t, c, sink, request(5, 0.25))
	opened := find(out, metricConnOpened, "app", "*", roleClient, "")
	rtt := find(out, metricRTT, "app", "*", roleClient, "")
	if len(opened) != 1 || opened[0].value != 5 || len(rtt) != 1 || rtt[0].value != 0.25 {
		t.Errorf("opened %+v, rtt %+v; want 5 and 0.25", opened, rtt)
	}
}

// BenchmarkParseResource decodes the request written by the agent's tests,
// as the connector decodes every request.
func BenchmarkParseResource(b *testing.B) {
	data, err := os.ReadFile("testdata/agent-request.json")
	if err != nil {
		b.Fatal(err)
	}
	md, err := (&pmetric.JSONUnmarshaler{}).UnmarshalMetrics(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseResource(md.ResourceMetrics().At(0)); err != nil {
			b.Fatal(err)
		}
	}
}
