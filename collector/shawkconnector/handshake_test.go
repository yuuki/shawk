package shawkconnector

import (
	"math"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// hsBuckets returns buckets of shawk.tcp.handshake with the counts given by
// index.
func hsBuckets(counts map[int]uint64) []uint64 {
	b := make([]uint64, len(handshakeBounds)+1)
	for i, n := range counts {
		b[i] = n
	}
	return b
}

// findReason returns the output failures of a reason of the client app.
func findReason(ss []series, errType string) []series {
	var out []series
	for _, s := range find(ss, metricConnFailedByReason, "app", "~external", roleClient, "") {
		if s.errType == errType {
			out = append(out, s)
		}
	}
	return out
}

// TestHandshakeOutputs checks the outputs of the metrics of active opens per
// dependency: the histogram of handshakes without buckets, the SYN
// retransmissions, and the failures by reason, whose series emit 0 at
// first.
func TestHandshakeOutputs(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	agent := func(e tEdge) tAgent {
		*now = now.Add(15 * time.Second)
		e.role, e.proto, e.local, e.peer, e.port, e.svc, e.comm = roleClient, "tcp", "10.0.0.11", "1.1.1.1", 443, "app", "app"
		if e.start.IsZero() {
			e.start = t0
		}
		return tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{e}}
	}
	value := func(out []series, metric string) series {
		t.Helper()
		s := find(out, metric, "app", "~external", roleClient, "")
		if len(s) != 1 {
			t.Fatalf("%s = %v", metric, s)
		}
		return s[0]
	}
	reason := func(out []series, errType string) float64 {
		t.Helper()
		s := findReason(out, errType)
		if len(s) != 1 {
			t.Fatalf("failures %s = %v", errType, s)
		}
		return s[0].value
	}

	// The edge and a reason start in the first interval: they count whole.
	out := consume(t, c, sink, agent(tEdge{opened: 2, failed: 1, handshakes: hsBuckets(map[int]uint64{0: 2}), hsSum: 0.0002,
		reasons: map[string]tReason{"timeout": {value: 1}}}))
	if h := value(out, metricHandshake); h.count != 2 || math.Abs(h.value-0.0002) > 1e-12 || h.buckets != nil {
		t.Errorf("handshakes = %+v", h)
	}
	if s := value(out, metricSynRetransmits); s.value != 0 {
		t.Errorf("SYN retransmits = %+v", s)
	}
	if v := value(out, metricConnFailed); v.value != 1 {
		t.Errorf("failures = %+v", v)
	}
	// A new reason emits 0 first, so that rate() counts its increase.
	if v := reason(out, "timeout"); v != 0 {
		t.Errorf("timeouts at first = %v", v)
	}

	// A lost SYN, and a reason that first occurs in this interval: its
	// counter starts with the interval.
	prev := *now
	out = consume(t, c, sink, agent(tEdge{opened: 3, failed: 2, handshakes: hsBuckets(map[int]uint64{0: 2, 9: 1}), hsSum: 1.2002,
		synRetrans: 1, reasons: map[string]tReason{"timeout": {value: 1}, "refused": {value: 1, start: prev}}}))
	if h := value(out, metricHandshake); h.count != 3 || math.Abs(h.value-1.2002) > 1e-9 {
		t.Errorf("handshakes = %+v", h)
	}
	if s := value(out, metricSynRetransmits); s.value != 1 {
		t.Errorf("SYN retransmits = %+v", s)
	}
	if v := reason(out, "timeout"); v != 1 {
		t.Errorf("timeouts = %v", v)
	}
	if v := reason(out, "refused"); v != 0 {
		t.Errorf("refused at first = %v", v)
	}

	// A reason whose counter started before the latest interval closed here
	// was counted before: its value is a baseline, and its series starts
	// with its next increase.
	out = consume(t, c, sink, agent(tEdge{opened: 3, failed: 7, handshakes: hsBuckets(map[int]uint64{0: 2, 9: 1}), hsSum: 1.2002,
		synRetrans: 1, reasons: map[string]tReason{"timeout": {value: 1}, "refused": {value: 1, start: prev},
			errorTypeOther: {value: 5, start: t0.Add(-2 * time.Hour)}}}))
	if v := reason(out, "refused"); v != 1 {
		t.Errorf("refused = %v", v)
	}
	if s := findReason(out, errorTypeOther); len(s) != 0 {
		t.Errorf("a baseline created a series: %v", s)
	}
	out = consume(t, c, sink, agent(tEdge{opened: 3, failed: 8, handshakes: hsBuckets(map[int]uint64{0: 2, 9: 1}), hsSum: 1.2002,
		synRetrans: 1, reasons: map[string]tReason{"timeout": {value: 1}, "refused": {value: 1, start: prev},
			errorTypeOther: {value: 6, start: t0.Add(-2 * time.Hour)}}}))
	if v := reason(out, errorTypeOther); v != 0 {
		t.Errorf("other at first = %v", v)
	}
	out = consume(t, c, sink, agent(tEdge{opened: 3, failed: 8, handshakes: hsBuckets(map[int]uint64{0: 2, 9: 1}), hsSum: 1.2002,
		synRetrans: 1, reasons: map[string]tReason{"timeout": {value: 1}, "refused": {value: 1, start: prev},
			errorTypeOther: {value: 6, start: t0.Add(-2 * time.Hour)}}}))
	if v := reason(out, errorTypeOther); v != 1 {
		t.Errorf("other = %v", v)
	}
	if v := reason(out, "timeout"); v != 1 {
		t.Errorf("timeouts = %v", v)
	}
}

// TestHandshakeOutputsOfPartialRequests checks that a new reason emits 0 once
// when its increases arrive in several requests of an interval.
func TestHandshakeOutputsOfPartialRequests(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	edge := func(peer string, v int64) tEdge {
		return tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: peer, port: 443, svc: "app", comm: "app",
			failed: v, start: t0, handshakes: hsBuckets(nil), reasons: map[string]tReason{"unreachable": {value: v}}}
	}
	*now = now.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{edge("1.1.1.1", 2)}, partial: true})
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{edge("2.2.2.2", 3)}})
	if s := findReason(out, "unreachable"); len(s) != 1 || s[0].value != 0 {
		t.Fatalf("unreachable at first = %v", s)
	}
	*now = now.Add(15 * time.Second)
	out = consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
		edges: []tEdge{edge("1.1.1.1", 2), edge("2.2.2.2", 4)}})
	if s := findReason(out, "unreachable"); len(s) != 1 || s[0].value != 6 {
		t.Errorf("unreachable = %v, want 6", s)
	}
}

// TestHandshakeOutputsOfOldAgents checks that the edges of agents that
// predate the measurement of handshakes produce none of their outputs.
func TestHandshakeOutputsOfOldAgents(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	*now = now.Add(15 * time.Second)
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{{
		role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443, svc: "app", comm: "app",
		opened: 2, failed: 1, start: t0}}})
	if s := find(out, metricConnFailed, "app", "~external", roleClient, ""); len(s) != 1 || s[0].value != 1 {
		t.Errorf("failures = %v", s)
	}
	for _, m := range []string{metricHandshake, metricSynRetransmits, metricConnFailedByReason} {
		if s := find(out, m, "app", "*", "*", ""); len(s) != 0 {
			t.Errorf("%s = %v", m, s)
		}
	}
}

// TestHandshakeInvalidInputs checks that histograms of handshakes with other
// bounds, and failures by reason without a reason, are invalid and left out.
func TestHandshakeInvalidInputs(t *testing.T) {
	e := tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443, svc: "app", comm: "app",
		start: t0, handshakes: hsBuckets(nil), hsBounds: []float64{0.001, 0.01, 0.1, 1, 2, 3, 4, 5, 6, 7}}
	bad := e
	bad.handshakes = bad.handshakes[:len(bad.handshakes)-1]
	bad.hsBounds = handshakeBounds
	bad.peer = "2.2.2.2"
	md := tAgent{host: "app-01", time: t0, edges: []tEdge{e, bad}}.metrics()
	// A failure of a valid edge without error.type.
	ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	m := ms.AppendEmpty()
	m.SetName(metricConnFailedByReason)
	m.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	dp := m.Sum().DataPoints().AppendEmpty()
	for i := range ms.Len() {
		if ms.At(i).Name() == metricConnFailed {
			ms.At(i).Sum().DataPoints().At(0).Attributes().CopyTo(dp.Attributes())
		}
	}
	if _, ok := dp.Attributes().Get(attrRole); !ok {
		t.Fatal("no edge to copy the attributes of")
	}
	dp.SetStartTimestamp(pcommon.NewTimestampFromTime(t0))
	dp.SetTimestamp(pcommon.NewTimestampFromTime(t0))
	dp.SetIntValue(1)

	hb, err := parseResource(md.ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if hb.invalid != 3 {
		t.Errorf("%d invalid data points, want 3", hb.invalid)
	}
	for _, in := range hb.edges {
		if _, ok := in.values[valueKey{metric: metricHandshake}]; ok {
			t.Errorf("edge %v has handshakes", in.id.peer)
		}
		if _, ok := in.values[valueKey{metric: metricSynRetransmits}]; !ok {
			t.Errorf("edge %v has no SYN retransmits", in.id.peer)
		}
	}
}

// TestHistogramResetsAsAWhole checks that a histogram whose bucket decreased
// restarts, even when its count and sum did not.
func TestHistogramResetsAsAWhole(t *testing.T) {
	a := newAggregator(time.Hour, 100, false, t0.Add(-time.Hour))
	h := &hostOutputs{inputs: map[inputKey]*inputState{}, resources: map[svcKey]*outResource{}, emitted: t0}
	k := inputKey{value: valueKey{metric: metricHandshake}}
	start := pcommon.NewTimestampFromTime(t0)
	at := func(d time.Duration) pcommon.Timestamp { return pcommon.NewTimestampFromTime(t0.Add(d)) }
	pts := []point{
		{start: start, time: at(15 * time.Second), value: 1, count: 5, buckets: []uint64{5, 0}},
		{start: start, time: at(30 * time.Second), value: 1.5, count: 6, buckets: []uint64{5, 1}},
		{start: start, time: at(45 * time.Second), value: 2, count: 7, buckets: []uint64{4, 3}},
	}
	want := []struct {
		dv float64
		dc uint64
	}{{1, 5}, {0.5, 1}, {2, 7}}
	for i, p := range pts {
		dv, dc, fresh := a.delta(h, k, p, p.time.AsTime(), p.time.AsTime())
		if !fresh || dv != want[i].dv || dc != want[i].dc {
			t.Errorf("point %d: delta %v, %d, %v, want %v", i, dv, dc, fresh, want[i])
		}
	}
}
