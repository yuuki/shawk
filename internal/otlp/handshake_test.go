package otlp

import (
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// metricsOf returns the metrics of a request by name.
func metricsOf(t *testing.T, s *State, now time.Time) map[string]*metricspb.Metric {
	t.Helper()
	req := s.Request(Resource{Hostname: "h"}, AgentStatus{}, now)
	out := map[string]*metricspb.Metric{}
	for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		out[m.Name] = m
	}
	return out
}

// TestHandshakeMetrics checks the metrics of the active opens of TCP client
// edges: the histogram of handshakes, the SYN retransmissions, and the
// failures by reason, each sent from the interval of its first occurrence.
func TestHandshakeMetrics(t *testing.T) {
	s := NewState(15 * time.Minute)
	c := clientEdge()
	srv := clientEdge()
	srv.Role = RoleServer
	udp := clientEdge()
	udp.Proto = "udp"
	t1, t2 := t0.Add(15*time.Second), t0.Add(30*time.Second)
	var first EdgeStats
	first.Conns, first.ConnFails = 3, 3
	first.Handshakes[0], first.Handshakes[3], first.Handshakes[9] = 1, 1, 1
	first.HandshakeSumUs = 1_200_600
	first.SynRetrans = 2
	first.Fails[1], first.Fails[0] = 1, 1 // timeout, refused, and one other
	s.AddEdge(c, first, t0, t1)
	s.AddEdge(srv, EdgeStats{Conns: 1}, t0, t1)
	s.AddEdge(udp, EdgeStats{MsgsSent: 1}, t0, t1)
	var second EdgeStats
	second.ConnFails = 1
	second.Fails[4] = 1 // aborted
	s.AddEdge(c, second, t1, t2)

	ms := metricsOf(t, s, t2)
	hs := ms[MetricHandshake].GetHistogram()
	if hs == nil || hs.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE ||
		ms[MetricHandshake].Unit != "s" || len(hs.DataPoints) != 1 {
		t.Fatalf("%s = %v", MetricHandshake, ms[MetricHandshake])
	}
	p := hs.DataPoints[0]
	want := []uint64{1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0}
	if p.Count != 3 || math.Abs(p.GetSum()-1.2006) > 1e-9 || !slices.Equal(p.BucketCounts, want) ||
		!slices.Equal(p.ExplicitBounds, HandshakeBounds[:]) || p.StartTimeUnixNano != nanos(t0) ||
		attrMap(p.Attributes)["shawk.role"] != RoleClient {
		t.Errorf("handshakes = %v", p)
	}
	syn := ms[MetricSynRetransmits].GetSum()
	if syn == nil || !syn.IsMonotonic || len(syn.DataPoints) != 1 || syn.DataPoints[0].GetAsInt() != 2 {
		t.Errorf("%s = %v", MetricSynRetransmits, ms[MetricSynRetransmits])
	}
	if f := ms[MetricConnFailed].GetSum().GetDataPoints(); len(f) != 1 || f[0].GetAsInt() != 4 {
		t.Errorf("%s = %v", MetricConnFailed, f)
	}
	type reason struct {
		value int64
		start time.Time
	}
	got := map[string]reason{}
	byReason := ms[MetricConnFailedByReason].GetSum()
	if byReason == nil || !byReason.IsMonotonic || ms[MetricConnFailedByReason].Unit != "{connection}" {
		t.Fatalf("%s = %v", MetricConnFailedByReason, ms[MetricConnFailedByReason])
	}
	for _, p := range byReason.DataPoints {
		a := attrMap(p.Attributes)
		if a["shawk.role"] != RoleClient || a["network.transport"] != "tcp" {
			t.Errorf("reason on %v", a)
		}
		got[a[AttrErrorType].(string)] = reason{p.GetAsInt(), time.Unix(0, int64(p.StartTimeUnixNano))}
	}
	wantReasons := map[string]reason{
		"refused": {1, t0}, "timeout": {1, t0}, ErrorOther: {1, t0},
		// Its counter starts with the interval it first occurred in.
		"aborted": {1, t1},
	}
	if len(got) != len(wantReasons) {
		t.Errorf("reasons = %v, want %v", got, wantReasons)
	}
	for k, w := range wantReasons {
		if g := got[k]; g.value != w.value || !g.start.Equal(w.start) {
			t.Errorf("reason %s = %v, want %v", k, g, w)
		}
	}
}

// TestEdgeSizeBound checks that edgeSize bounds what an edge adds to a
// request, with every metric of a TCP client edge and the largest values.
func TestEdgeSizeBound(t *testing.T) {
	for _, role := range []string{RoleClient, RoleServer} {
		for _, transport := range []string{"tcp", "udp"} {
			s := NewState(15 * time.Minute)
			var st EdgeStats
			for _, v := range []*uint64{&st.Conns, &st.OpenConns, &st.BytesSent, &st.BytesRecv, &st.MsgsSent, &st.MsgsRecv,
				&st.Retrans, &st.RTTSumUs, &st.RTTSamples, &st.HandshakeSumUs, &st.SynRetrans} {
				*v = math.MaxInt64
			}
			for i := range st.Handshakes {
				st.Handshakes[i] = math.MaxUint64 / 16
			}
			for i := range st.Fails {
				st.Fails[i] = math.MaxInt64 / 8
			}
			st.ConnFails = math.MaxInt64
			k := clientEdge()
			k.Role, k.Proto = role, transport
			k.PeerAddr = netip.MustParseAddr("2001:db8::1")
			s.AddEdge(k, st, t0, t0)
			one := proto.Size(s.Request(Resource{Hostname: "h"}, AgentStatus{}, t0))
			k2 := k
			k2.PeerAddr = netip.MustParseAddr("2001:db8::2")
			s.AddEdge(k2, st, t0, t0)
			two := proto.Size(s.Request(Resource{Hostname: "h"}, AgentStatus{}, t0))
			if bound := edgeSize(&k2, s.edges[k2], edgeAttrs(&k2)); two-one > bound {
				t.Errorf("a %s %s edge adds %d bytes, more than the bound of %d", transport, role, two-one, bound)
			}
		}
	}
}

// TestErrorTypeSize checks that errorTypeSize bounds every value of error.type.
func TestErrorTypeSize(t *testing.T) {
	for _, r := range append(FailReasons[:], ErrorOther) {
		if n := attrsSize([]*commonpb.KeyValue{str(AttrErrorType, r)}); n > errorTypeSize {
			t.Errorf("error.type %s takes %d bytes, more than %d", r, n, errorTypeSize)
		}
	}
}

// TestFailStartAfterExpiry checks that an edge that expires and comes back
// starts its reasons of failure again, from the interval they occur in.
func TestFailStartAfterExpiry(t *testing.T) {
	s := NewState(time.Minute)
	c := clientEdge()
	var st EdgeStats
	st.ConnFails, st.Fails[0] = 1, 1
	s.AddEdge(c, st, t0, t0.Add(15*time.Second))
	s.Expire(t0.Add(2 * time.Minute))
	if len(s.edges) != 0 {
		t.Fatal("the edge did not expire")
	}
	back := t0.Add(3 * time.Minute)
	var again EdgeStats
	again.ConnFails, again.Fails[1] = 1, 1
	s.AddEdge(c, again, back, back.Add(15*time.Second))
	e := s.edges[c]
	if !e.FailStart[0].IsZero() || !e.FailStart[1].Equal(back) || e.Total.Fails[0] != 0 || e.Total.Fails[1] != 1 {
		t.Errorf("reasons after the edge came back: starts %v, totals %v", e.FailStart, e.Total.Fails)
	}
}
