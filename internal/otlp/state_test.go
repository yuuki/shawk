package otlp

import (
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func clientEdge() EdgeKey {
	return EdgeKey{
		Role: RoleClient, Proto: "tcp",
		LocalAddr: netip.MustParseAddr("10.0.0.11"), PeerAddr: netip.MustParseAddr("10.0.0.10"),
		Port: 5432, NetNS: 4026531840,
		Process: Process{Unit: "app.service", Comm: "puma", Exe: "/usr/bin/ruby", Service: "app"},
	}
}

func TestStateAccumulates(t *testing.T) {
	s := NewState(15 * time.Minute)
	k := clientEdge()
	s.BeginInterval()
	s.AddEdge(k, EdgeStats{Conns: 2, OpenConns: 1, BytesSent: 100, RTTSumUs: 300, RTTSamples: 2}, t0, t0.Add(15*time.Second))
	// The same edge reported twice in an interval, e.g. by two cgroups of
	// the same unit.
	s.AddEdge(k, EdgeStats{Conns: 1, OpenConns: 1}, t0, t0.Add(15*time.Second))
	e := s.Edges()[k]
	if e == nil {
		t.Fatal("edge not created")
	}
	if e.Start != t0 || e.FirstSeen != t0.Add(15*time.Second) || e.LastSeen != e.FirstSeen {
		t.Errorf("times = %+v", e)
	}
	want := EdgeStats{Conns: 3, OpenConns: 2, BytesSent: 100, RTTSumUs: 300, RTTSamples: 2}
	if e.Total != want {
		t.Errorf("total = %+v, want %+v", e.Total, want)
	}

	// The connections are closed in the next interval.
	s.BeginInterval()
	s.AddEdge(k, EdgeStats{BytesRecv: 10}, t0.Add(15*time.Second), t0.Add(30*time.Second))
	want = EdgeStats{Conns: 3, BytesSent: 100, BytesRecv: 10, RTTSumUs: 300, RTTSamples: 2}
	if e.Total != want {
		t.Errorf("total = %+v, want %+v", e.Total, want)
	}
	if e.LastSeen != t0.Add(30*time.Second) {
		t.Errorf("last seen = %v", e.LastSeen)
	}

	// An inactive interval does not advance the last seen time.
	s.BeginInterval()
	s.AddEdge(k, EdgeStats{}, t0.Add(30*time.Second), t0.Add(45*time.Second))
	if e.LastSeen != t0.Add(30*time.Second) {
		t.Errorf("last seen advanced without activity: %v", e.LastSeen)
	}

	// An edge without activity is not created.
	other := k
	other.Port = 6379
	s.AddEdge(other, EdgeStats{}, t0, t0.Add(15*time.Second))
	if _, ok := s.Edges()[other]; ok {
		t.Error("an inactive edge was created")
	}
}

func TestStateExpire(t *testing.T) {
	ttl := 15 * time.Minute
	s := NewState(ttl)
	k := clientEdge()
	lk := ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080, Process: k.Process}
	s.AddEdge(k, EdgeStats{Conns: 5}, t0, t0.Add(15*time.Second))
	s.AddListener(lk, t0.Add(15*time.Second))
	xk := TranslationKey{Proto: "tcp", Client: netip.MustParseAddr("10.0.0.1"), Virtual: netip.MustParseAddr("10.96.0.1"),
		VirtualPort: 80, Source: netip.MustParseAddr("10.0.0.1"), Backend: netip.MustParseAddr("10.0.0.9"), BackendPort: 8080}
	s.AddTranslation(xk, t0)
	s.AddTranslation(xk, t0.Add(15*time.Second))
	if x := s.Translations()[xk]; x.FirstSeen != t0 || x.LastSeen != t0.Add(15*time.Second) {
		t.Errorf("translation = %+v", x)
	}

	// An open connection keeps the edge alive.
	k2 := k
	k2.Port = 6379
	for i := range 80 {
		s.BeginInterval()
		end := t0.Add(time.Duration(i+1) * 15 * time.Second)
		s.AddEdge(k2, EdgeStats{OpenConns: 1}, end.Add(-15*time.Second), end)
	}

	if n := s.Expire(t0.Add(15*time.Second + ttl)); n != 0 {
		t.Errorf("expired %d series at the TTL", n)
	}
	if n := s.Expire(t0.Add(16*time.Second + ttl)); n != 3 {
		t.Errorf("expired %d series after the TTL, want 3", n)
	}
	if _, ok := s.Edges()[k2]; !ok {
		t.Error("an edge with an open connection expired")
	}

	// A reappearing edge starts again from zero.
	later := t0.Add(time.Hour)
	s.BeginInterval()
	s.AddEdge(k, EdgeStats{Conns: 1}, later, later.Add(15*time.Second))
	if e := s.Edges()[k]; e.Total.Conns != 1 || e.Start != later || e.FirstSeen != later.Add(15*time.Second) {
		t.Errorf("reappeared edge = %+v", e)
	}
}

func TestLocalAddrs(t *testing.T) {
	s := NewState(time.Minute)
	k := clientEdge()
	s.AddEdge(k, EdgeStats{Conns: 1}, t0, t0)
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 80}, t0)
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("172.17.0.2"), Port: 80}, t0)
	got := map[string]bool{}
	for _, a := range s.LocalAddrs(t0) {
		got[a.String()] = true
	}
	if len(got) != 2 || !got["10.0.0.11"] || !got["172.17.0.2"] {
		t.Errorf("LocalAddrs = %v", got)
	}
}

func TestSegment(t *testing.T) {
	ttl := 15 * time.Minute
	s := NewSegment(t0, ttl)
	if got := s.Start(t0.Add(time.Hour)); got != t0.Add(45*time.Minute) {
		// No request succeeded for an hour after the start.
		t.Errorf("start after an hour without success = %v", got)
	}
	now := t0.Add(10 * time.Minute)
	s.Succeeded(s.Start(now), now)
	if got := s.Start(now.Add(13 * time.Minute)); got != t0 {
		t.Errorf("start after short failures = %v, want the agent start", got)
	}
	// Failures for up to TTL - 1m keep the segment.
	ok := now.Add(14 * time.Minute)
	if got := s.Start(ok); got != t0 {
		t.Errorf("start at TTL - 1m = %v", got)
	}
	// Longer failures restart the segment at now - TTL once a request
	// succeeds; until then each attempt carries its own start.
	late := ok.Add(time.Second)
	if got := s.Start(late); got != late.Add(-ttl) {
		t.Errorf("start after long failures = %v, want %v", got, late.Add(-ttl))
	}
	later := late.Add(time.Minute)
	start := s.Start(later)
	s.Succeeded(start, later)
	if got := s.Start(later.Add(15 * time.Second)); got != later.Add(-ttl) {
		t.Errorf("start after recovery = %v, want %v", got, later.Add(-ttl))
	}

	// A segment never starts before the agent.
	s = NewSegment(t0, ttl)
	if got := s.Start(t0.Add(ttl)); got != t0 {
		t.Errorf("start = %v, want the agent start", got)
	}
}

// An address of a series kept only for its idle TTL is not reported: it
// may have moved to another host with its container.
func TestLocalAddrsRecent(t *testing.T) {
	s := NewState(15 * time.Minute)
	old, recent := clientEdge(), clientEdge()
	old.LocalAddr = netip.MustParseAddr("10.0.0.21")
	s.AddEdge(old, EdgeStats{Conns: 1}, t0, t0)
	later := t0.Add(10 * time.Minute)
	s.AddEdge(recent, EdgeStats{Conns: 1}, later, later)
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("10.0.0.22"), Port: 80}, t0)
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("10.0.0.23"), Port: 80}, later)
	got := map[string]bool{}
	for _, a := range s.LocalAddrs(later.Add(-time.Minute)) {
		got[a.String()] = true
	}
	if len(got) != 2 || !got["10.0.0.11"] || !got["10.0.0.23"] {
		t.Errorf("LocalAddrs = %v", got)
	}
}

// After the wall clock stepped, the start of the segment is sent by the new
// clock, so that the connector converts it with the current skew.
func TestSegmentClockStep(t *testing.T) {
	ttl := 15 * time.Minute
	step := -9 * time.Hour
	s := NewSegment(t0, ttl)
	now := t0.Add(time.Minute)
	s.Succeeded(s.Start(now), now)
	// The monotonic clock ignores the step; Sub of times without a
	// monotonic reading does not, so the test adds it back.
	elapsed = func(now, t time.Time) time.Duration { return now.Sub(t) - step }
	t.Cleanup(func() { elapsed = func(now, t time.Time) time.Duration { return now.Sub(t) } })
	stepped := t0.Add(2 * time.Minute).Add(step)
	if got := s.Start(stepped); !got.Equal(t0.Add(step)) {
		t.Errorf("start after the step = %v, want %v", got, t0.Add(step))
	}
}

// After the wall clock stepped back, a series seen again is last seen
// later by the monotonic clock but earlier by the wall clock, which the
// times are sent by: its first time moves back with it, so that it is never
// sent after the last (#261).
func TestStateClockStepBack(t *testing.T) {
	step := -5 * time.Minute
	t1 := t0.Add(15 * time.Second).Add(step)
	// The monotonic clock ignores the step; Sub of times without a
	// monotonic reading does not, so the test adds it back between t0 and
	// t1.
	elapsed = func(now, t time.Time) time.Duration {
		if now.Equal(t1) && t.Equal(t0) {
			return now.Sub(t) - step
		}
		return now.Sub(t)
	}
	t.Cleanup(func() { elapsed = func(now, t time.Time) time.Duration { return now.Sub(t) } })

	s := NewState(15 * time.Minute)
	k := clientEdge()
	l := ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("10.0.0.11"), Port: 80}
	x := TranslationKey{Proto: "tcp", Client: netip.MustParseAddr("10.0.0.11"), Virtual: netip.MustParseAddr("10.96.0.1"),
		VirtualPort: 443, Source: netip.MustParseAddr("10.0.0.11"), Backend: netip.MustParseAddr("10.0.1.5"), BackendPort: 8443}
	for _, at := range []struct{ start, end time.Time }{{t0.Add(-15 * time.Second), t0}, {t0, t1}} {
		s.BeginInterval()
		s.AddEdge(k, EdgeStats{Conns: 1, Protocols: 1}, at.start, at.end)
		s.AddListener(l, at.end)
		s.AddTranslation(x, at.end)
	}
	e := s.Edges()[k]
	for name, seen := range map[string]Seen{
		"edge":          {e.FirstSeen, e.LastSeen},
		"wire protocol": e.Protocols[0],
		"listener":      {s.Listeners()[l].FirstSeen, s.Listeners()[l].LastSeen},
		"translation":   {s.Translations()[x].FirstSeen, s.Translations()[x].LastSeen},
	} {
		if !seen.Last.Equal(t1) || seen.First.After(seen.Last) {
			t.Errorf("%s first seen %v, last seen %v; want both %v", name, seen.First, seen.Last, t1)
		}
	}
	m := metricsOf(t, s, t1)
	for _, names := range [][2]string{
		{MetricEdgeFirst, MetricEdgeLast}, {MetricEdgeWireFirst, MetricEdgeWireLast},
		{MetricListenerFirst, MetricListenerLast}, {MetricTranslationFirst, MetricTranslationLast},
	} {
		first, last := m[names[0]].GetGauge().GetDataPoints(), m[names[1]].GetGauge().GetDataPoints()
		if len(first) != 1 || len(last) != 1 {
			t.Errorf("%d %s and %d %s", len(first), names[0], len(last), names[1])
		} else if f, l := first[0].GetAsInt(), last[0].GetAsInt(); f > l {
			t.Errorf("%s %d after %s %d", names[0], f, names[1], l)
		}
	}
}
