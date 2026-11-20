package shawkconnector

import (
	"strings"
	"testing"
	"time"
)

// TestActivityOf: a time is in the month of UTC that holds it, at the hour
// of that month: the last hour of a month of 31 days is the last bit.
func TestActivityOf(t *testing.T) {
	jst := time.FixedZone("JST", 9*3600)
	for _, c := range []struct {
		at    time.Time
		month time.Time
		hour  int
	}{
		{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), 0},
		{time.Date(2026, 10, 31, 23, 59, 59, 999, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), activityHours - 1},
		{time.Date(2028, 2, 29, 23, 0, 0, 0, time.UTC), time.Date(2028, 2, 1, 0, 0, 0, 0, time.UTC), 29*24 - 1},
		// 08:30 on the first in Japan is still the month before in UTC.
		{time.Date(2026, 11, 1, 8, 30, 0, 0, jst), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), 30*24 + 23},
		{time.Date(2026, 11, 1, 9, 30, 0, 0, jst), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), 0},
	} {
		month, hour := activityOf(c.at)
		if month != c.month.Unix() || hour != c.hour {
			t.Errorf("activityOf(%v) = %v, hour %d; want %v, hour %d", c.at, time.Unix(month, 0).UTC(), hour, c.month, c.hour)
		}
	}
}

// TestActivityBits: the hours are written as PostgreSQL reads a bit string
// of the length of the column, the first hour on the left.
func TestActivityBits(t *testing.T) {
	var b activityBits
	for _, h := range []int{0, 9, activityHours - 1} {
		b.set(h)
	}
	s := b.String()
	if len(s) != activityHours || strings.Count(s, "1") != 3 || s[0] != '1' || s[9] != '1' || s[activityHours-1] != '1' {
		t.Errorf("bits = %s", s)
	}
	var o activityBits
	o.set(9)
	o.set(10)
	b.merge(&o)
	if s := b.String(); strings.Count(s, "1") != 4 || s[10] != '1' {
		t.Errorf("merged bits = %s", s)
	}
}

// hoursOf returns the hours pending of the edges of a host, as "month
// hour" of each, in the order of activityHours.
func hoursOf(h *hostChanges) map[string][]int {
	out := map[string][]int{}
	if h == nil {
		return out
	}
	for k, bits := range h.activity {
		month := time.Unix(k.month, 0).UTC().Format("2006-01")
		for i := range activityHours {
			if bits.has(i) {
				out[month] = append(out[month], i)
			}
		}
	}
	return out
}

// TestActivityRecorded: the hours in which an edge was first and last seen
// are written with it when it is new, and the hour it is last seen in when
// that moves into another hour: not at every write of an edge that stays
// active, and not for an edge written for a wire protocol alone.
func TestActivityRecorded(t *testing.T) {
	first := time.Date(2026, 10, 31, 9, 10, 0, 0, time.UTC)
	edge := tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app",
		unit: "app.service", comm: "app", first: first}
	ch := newChanges(15*time.Minute, false)
	// step reports the edge last seen at a time, in a request received 15
	// seconds later, and returns the changes to write.
	step := func(last time.Time) *hostChanges {
		t.Helper()
		edge.last = last
		at := last.Add(15 * time.Second)
		b := testBatch(t, tAgent{host: "app-01", time: at, edges: []tEdge{edge}})
		ch.add(b, at)
		return ch.take()[b.key]
	}
	// New here: the hours of its first and last times, 9 and 11 of the
	// 31st, with the edge.
	h := step(first.Add(2 * time.Hour))
	if got := hoursOf(h); len(got) != 1 || len(got["2026-10"]) != 2 || got["2026-10"][0] != 30*24+9 || got["2026-10"][1] != 30*24+11 {
		t.Errorf("hours of a new edge = %v, want 9 and 11 of the 31st", got)
	}
	if len(h.edges) != 1 {
		t.Errorf("edges = %v", h.edges)
	}
	// Reported again unchanged: nothing.
	if h := step(edge.last); len(h.edges) != 0 || len(h.activity) != 0 {
		t.Errorf("unchanged: edges %v, hours %v", h.edges, hoursOf(h))
	}
	// Active later in the same hour: the edge, not the hour again.
	if h := step(edge.last.Add(10 * time.Minute)); len(h.edges) != 1 || len(h.activity) != 0 {
		t.Errorf("same hour: edges %v, hours %v; want the edge alone", h.edges, hoursOf(h))
	}
	// Active in a later hour, which is in the next month.
	h = step(time.Date(2026, 11, 1, 0, 0, 15, 0, time.UTC))
	if got := hoursOf(h); len(got) != 1 || len(got["2026-11"]) != 1 || got["2026-11"][0] != 0 {
		t.Errorf("hours in the next month = %v, want the first of 2026-11", got)
	}
	// A wire protocol alone: the edge is written with it, without hours.
	edge.wire = map[string]span{"postgres": {edge.last, edge.last}}
	if h := step(edge.last); len(h.edges) != 1 || len(h.wire) != 1 || len(h.activity) != 0 {
		t.Errorf("a wire protocol alone: edges %v, wire %v, hours %v", h.edges, h.wire, hoursOf(h))
	}
}

// TestActivityPending: the months of activity of an edge count in the rows
// pending, are kept when failed writes are put back, with the hours added
// meanwhile, and the hours the agent still tells are written again once the
// connector forgets the edge: when the changes of its host are dropped, or
// when the agent has not reported it for the TTL.
func TestActivityPending(t *testing.T) {
	seen := time.Date(2026, 10, 31, 23, 30, 0, 0, time.UTC)
	edge := tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app",
		unit: "app.service", comm: "app", first: seen, last: seen.Add(time.Hour)}
	now := seen.Add(time.Hour + 15*time.Second)
	b := testBatch(t, tAgent{host: "app-01", time: now, edges: []tEdge{edge}})
	ch := newChanges(15*time.Minute, false)
	ch.add(b, now)
	// The host, its session, the process, the edge and its two months.
	if n := ch.pendingSize(); n != 6 {
		t.Errorf("%d rows pending, want 6", n)
	}
	h := ch.take()[b.key]
	if len(h.activity) != 2 {
		t.Fatalf("hours = %v, want those of two months", hoursOf(h))
	}
	// The write fails; meanwhile the edge is active two hours later.
	edge.last = seen.Add(3 * time.Hour)
	now = edge.last.Add(15 * time.Second)
	later := testBatch(t, tAgent{host: "app-01", time: now, edges: []tEdge{edge}})
	ch.add(later, now)
	ch.restore(h)
	h = ch.take()[b.key]
	if got := hoursOf(h); len(got["2026-10"]) != 1 || len(got["2026-11"]) != 2 || got["2026-11"][0] != 0 || got["2026-11"][1] != 2 {
		t.Errorf("hours put back = %v, want 23 of the 31st, and 0 and 2 of the 1st", got)
	}
	months := func(at time.Time) int {
		t.Helper()
		ch.add(later, at)
		return len(hoursOf(ch.take()[b.key]))
	}
	if n := months(now.Add(time.Minute)); n != 0 {
		t.Errorf("%d months written again", n)
	}
	ch.forget(b.key, now.Add(time.Minute))
	if n := months(now.Add(2 * time.Minute)); n != 2 {
		t.Errorf("%d months written after the changes of the host were dropped, want 2", n)
	}
	ch.expire(now.Add(30 * time.Minute))
	if n := months(now.Add(30 * time.Minute)); n != 2 {
		t.Errorf("%d months written after the TTL, want 2", n)
	}
}

// TestActivityOfUnixEdges: the client edges of Unix sockets have hours too.
func TestActivityOfUnixEdges(t *testing.T) {
	seen := t0.Add(-time.Minute)
	b := testBatch(t, tAgent{host: "app-01", time: t0, edges: []tEdge{{role: roleClient, proto: transportUnix,
		path: "/run/postgresql/.s.PGSQL.5432", svc: "app", unit: "app.service", comm: "app", first: seen, last: seen}}})
	ch := newChanges(15*time.Minute, false)
	ch.add(b, t0)
	h := ch.take()[b.key]
	if len(h.activity) != 1 {
		t.Fatalf("hours = %v", hoursOf(h))
	}
	for k := range h.activity {
		if k.edge.proto != transportUnix || k.edge.path != "/run/postgresql/.s.PGSQL.5432" {
			t.Errorf("hours of %+v", k.edge)
		}
	}
}
