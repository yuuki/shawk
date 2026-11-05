package shawkconnector

import (
	"testing"

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
