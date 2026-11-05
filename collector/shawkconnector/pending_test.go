package shawkconnector

import (
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
