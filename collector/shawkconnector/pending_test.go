package shawkconnector

import (
	"math"
	"testing"
	"time"
)

// TestChangesWithoutTimes: an edge, a listener or a translation that the
// agent sends without a last time is not written, and one without a first
// time was first seen when it was last seen.
func TestChangesWithoutTimes(t *testing.T) {
	seen := t0.Add(-time.Minute)
	b := testBatch(t, tAgent{host: "app-01", time: t0,
		edges: []tEdge{
			{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
				svc: "app", unit: "app.service", comm: "app", first: seen, last: seen},
			{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.20", port: 5432,
				svc: "batch", unit: "batch.service", comm: "batch", first: seen, last: seen},
		},
		listeners: []tListener{
			{proto: "tcp", addr: "10.0.0.11", port: 80, svc: "web", unit: "web.service", comm: "web", first: seen, last: seen},
			{proto: "tcp", addr: "10.0.0.11", port: 81, svc: "old", unit: "old.service", comm: "old", first: seen, last: seen},
		},
		translations: []tTranslation{
			{client: "10.0.0.11", virtual: "10.96.0.10", vport: 80, backend: "10.0.1.10", bport: 8080, first: seen, last: seen},
			{client: "10.0.0.11", virtual: "10.96.0.11", vport: 80, backend: "10.0.1.11", bport: 8080, first: seen, last: seen},
		}})
	for _, e := range b.edges {
		if e.id.peer == addrOf("10.0.0.10") {
			e.first = time.Time{}
		} else {
			e.last = time.Time{}
		}
	}
	for _, l := range b.listeners {
		if l.id.port == 80 {
			l.first = time.Time{}
		} else {
			l.last = time.Time{}
		}
	}
	for _, x := range b.translations {
		if x.id.virtual == addrOf("10.96.0.10") {
			x.first = time.Time{}
		} else {
			x.last = time.Time{}
		}
	}
	ch := newChanges(15*time.Minute, false)
	ch.add(b, t0)
	h := ch.pending[b.key]
	want := span{seen, seen}
	if len(h.edges) != 1 {
		t.Errorf("edges = %v, want one", h.edges)
	}
	for k, s := range h.edges {
		if k.peer != addrOf("10.0.0.10") || s != want {
			t.Errorf("edge %+v seen %v, want the one to 10.0.0.10 seen %v", k, s, want)
		}
	}
	if len(h.listeners) != 1 {
		t.Errorf("listeners = %v, want one", h.listeners)
	}
	for k, s := range h.listeners {
		if k.port != 80 || s != want {
			t.Errorf("listener %+v seen %v, want the one on port 80 seen %v", k, s, want)
		}
	}
	if len(h.translations) != 1 {
		t.Errorf("translations = %v, want one", h.translations)
	}
	for k, s := range h.translations {
		if k.virtual != addrOf("10.96.0.10") || s != want {
			t.Errorf("translation %+v seen %v, want the one to 10.96.0.10 seen %v", k, s, want)
		}
	}
	units := map[string]span{}
	for k, p := range h.processes {
		units[k.unit] = p.span
	}
	if len(units) != 2 || units["app.service"] != want || units["web.service"] != want {
		t.Errorf("processes = %v, want app.service and web.service seen %v", units, want)
	}
}

// TestAcceptedWhileReported: an edge, a listener or a translation that the
// agent goes on reporting unchanged stays accepted beyond the TTL, as of
// its last report, and is not written again.
func TestAcceptedWhileReported(t *testing.T) {
	seen := t0.Add(-time.Minute)
	b := testBatch(t, tAgent{host: "app-01", time: t0,
		edges: []tEdge{{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
			svc: "app", unit: "app.service", comm: "app", first: seen, last: seen}},
		listeners: []tListener{{proto: "tcp", addr: "10.0.0.11", port: 80, svc: "web", unit: "web.service", comm: "web",
			first: seen, last: seen}},
		translations: []tTranslation{{client: "10.0.0.11", virtual: "10.96.0.10", vport: 80, backend: "10.0.1.10",
			bport: 8080, first: seen, last: seen}}})
	ch := newChanges(15*time.Minute, false)
	ch.add(b, t0)
	ch.take()
	for _, at := range []time.Duration{10 * time.Minute, 20 * time.Minute} {
		ch.expire(t0.Add(at))
		ch.add(b, t0.Add(at))
		h := ch.take()[b.key]
		if len(h.edges) != 0 || len(h.listeners) != 0 || len(h.translations) != 0 || len(h.processes) != 0 {
			t.Errorf("after %v: written again: %v, %v, %v, %v", at, h.edges, h.listeners, h.translations, h.processes)
		}
	}
}

// TestSessionStartsNoLaterThanRequest: a segment start after the request
// that carries it, by the clock of the agent, is taken as the time of the
// request, whatever the clock skew: the session does not start after its
// heartbeat, and a time the agent makes up is not written.
func TestSessionStartsNoLaterThanRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ahead time.Duration // how far the clock of the agent is ahead
	}{
		{"synchronized", 0},
		{"agent ahead", time.Hour},
		{"agent behind", -time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := newChanges(15*time.Minute, false)
			at := t0.Add(tc.ahead)
			b := testBatch(t, tAgent{host: "app-01", time: at, segment: at.Add(24 * time.Hour)})
			ch.add(b, t0)
			sessions := ch.pending[b.key].sessions
			if len(sessions) != 1 {
				t.Fatalf("sessions = %v, want one", sessions)
			}
			for start, s := range sessions {
				if !start.Equal(at) || start.Add(s.clockSkew).After(s.lastHeartbeat) {
					t.Errorf("session starts at %v by the clock of the agent, %v by the connector's, heartbeat %v; "+
						"want the time of the request", start.Sub(t0), start.Add(s.clockSkew).Sub(t0), s.lastHeartbeat.Sub(t0))
				}
			}
		})
	}
}

// TestGaugeTimesOutOfRange: a time of a gauge of Unix seconds that is not a
// time an agent sends, before 1970 or after the year 9999, is invalid. One
// near 2^63 seconds would otherwise wrap around to a time far before 1970,
// which no cap catches and which PostgreSQL refuses.
func TestGaugeTimesOutOfRange(t *testing.T) {
	for _, v := range []float64{-1, math.NaN(), math.Inf(1), maxUnixTime + 1, maxValue - 1024} {
		md := tAgent{host: "app-01", time: t0, listeners: []tListener{{proto: "tcp", addr: "10.0.0.11", port: 80,
			svc: "web", comm: "web"}}}.metrics()
		ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
		for i := range ms.Len() {
			if m := ms.At(i); m.Name() == metricListenerLast {
				m.Gauge().DataPoints().At(0).SetDoubleValue(v)
			}
		}
		b, err := parseResource(md.ResourceMetrics().At(0))
		if err != nil {
			t.Fatal(err)
		}
		if b.invalid != 1 {
			t.Errorf("last seen %v: %d invalid points, want 1", v, b.invalid)
		}
		ch := newChanges(15*time.Minute, false)
		ch.add(b, t0)
		if ls := ch.pending[b.key].listeners; len(ls) != 0 {
			t.Errorf("last seen %v: listeners written %v", v, ls)
		}
	}
}

// TestForgetKeepsLaterFloor: changes of a host dropped after its series
// were (max_series_per_host) do not move its session floor back, so that
// the next session does not cover the interval whose series were dropped.
func TestForgetKeepsLaterFloor(t *testing.T) {
	ch := newChanges(15*time.Minute, false)
	b := testBatch(t, tAgent{host: "app-01", time: t0, segment: t0.Add(-time.Hour)})
	ch.add(b, t0)
	// Series were dropped in the interval the request at 10s closes: the
	// next session starts no earlier than that request.
	limited := t0.Add(10 * time.Second)
	b.time, b.limited = limited, true
	ch.add(b, limited)
	if got := ch.floors[b.key].start; !got.Equal(limited) {
		t.Fatalf("floor %v after the series were dropped, want %v", got.Sub(t0), limited.Sub(t0))
	}
	ch.take()
	// Changes of the host are dropped 30 seconds later.
	ch.forget(b.key, limited.Add(30*time.Second))
	if got := ch.floors[b.key].start; !got.Equal(limited) {
		t.Errorf("floor %v after changes were dropped, want it to stay at %v", got.Sub(t0), limited.Sub(t0))
	}
	next := t0.Add(time.Minute)
	b.time, b.limited = next, false
	ch.add(b, next)
	for start := range ch.pending[b.key].sessions {
		if start.Before(limited) {
			t.Errorf("session starts at %v, before the series dropped at %v", start.Sub(t0), limited.Sub(t0))
		}
	}
}
