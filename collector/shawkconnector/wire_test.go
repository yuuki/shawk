package shawkconnector

import (
	"context"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// TestWireProtocolsOfTheAgent: the wire protocols of the request of the
// agent's tests are those of its edges.
func TestWireProtocolsOfTheAgent(t *testing.T) {
	data, err := os.ReadFile("testdata/agent-request.json")
	if err != nil {
		t.Fatal(err)
	}
	md, err := (&pmetric.JSONUnmarshaler{}).UnmarshalMetrics(data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseResource(md.ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if b.invalid != 0 {
		t.Errorf("%d invalid points", b.invalid)
	}
	if b.agentDropped != 0 {
		t.Errorf("%d points dropped, the first of %s", b.agentDropped, b.agentDroppedName)
	}
	// The agent sends every protocol on an edge of its tests, so that the
	// protocols of the agent and of the connector are the same.
	seen := t0.Add(15 * time.Second)
	all := map[string]bool{}
	for _, e := range b.edges {
		if e.id.proto != "tcp" && e.wire != nil {
			t.Errorf("%s edge with wire protocols %v", e.id.proto, e.wire)
		}
		for p, s := range e.wire {
			all[p] = true
			if !s.first.Equal(seen) || !s.last.Equal(seen) {
				t.Errorf("edge to port %d: %s seen %v to %v, want %v", e.id.port, p, s.first, s.last, seen)
			}
		}
	}
	if !maps.Equal(all, wireProtocols) {
		t.Errorf("the agent sends the wire protocols %v, the connector knows %v", slices.Sorted(maps.Keys(all)),
			slices.Sorted(maps.Keys(wireProtocols)))
	}
}

// TestWireProtocolsInvalid: a wire protocol of a value the agents do not
// send, or of an edge that is not of TCP, is an invalid point and left out,
// so that an agent cannot make a row per value.
func TestWireProtocolsInvalid(t *testing.T) {
	w := map[string]span{"tls_1_3": {t0, t0}, "gopher": {t0, t0}}
	md := tAgent{host: "app-01", time: t0, edges: []tEdge{
		{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 443, svc: "app", comm: "app", opened: 1, wire: w},
		{role: roleClient, proto: "udp", local: "10.0.0.11", peer: "10.0.0.10", port: 53, svc: "app", comm: "app",
			wire: map[string]span{"unknown": {t0, t0}}},
	}}.metrics()
	b, err := parseResource(md.ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	// Two points, first and last seen: those of the UDP edge are invalid,
	// those of the protocol it does not know, as of a newer agent, are
	// dropped like the metrics of the agent it does not know, which are
	// logged at most once a minute.
	if b.invalid != 2 {
		t.Errorf("%d invalid points, want 2", b.invalid)
	}
	if b.agentDropped != 2 || b.agentDroppedName != "shawk.wire_protocol=gopher" {
		t.Errorf("%d points dropped, the first of %q; want 2 of shawk.wire_protocol=gopher", b.agentDropped, b.agentDroppedName)
	}
	for _, e := range b.edges {
		switch e.id.proto {
		case "tcp":
			if _, ok := e.wire["tls_1_3"]; !ok || len(e.wire) != 1 {
				t.Errorf("wire protocols of the TCP edge = %v", e.wire)
			}
		default:
			if e.wire != nil {
				t.Errorf("wire protocols of the %s edge = %v", e.id.proto, e.wire)
			}
		}
	}
}

// TestWireProtocolsWritten: the wire protocols of an edge are written to
// PostgreSQL with their edge, once per change like edges, and forwarded to
// Prometheus neither as series nor as labels.
func TestWireProtocolsWritten(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	edge := tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app",
		unit: "app.service", comm: "puma", exe: "/usr/bin/ruby", opened: 1, first: t0.Add(15 * time.Second),
		wire: map[string]span{"postgres": {t0.Add(15 * time.Second), t0.Add(15 * time.Second)}}}
	ta := tAgent{host: "app-01", machineID: "m1", addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second),
		segment: t0.Add(-time.Hour), edges: []tEdge{edge}}
	consume(t, c, sink, ta)
	if len(sink.AllMetrics()) == 0 {
		t.Fatal("nothing forwarded")
	}
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			if _, ok := rms.At(i).Resource().Attributes().Get(attrWireProtocol); ok {
				t.Errorf("forwarded a resource with %s", attrWireProtocol)
			}
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					m := ms.At(k)
					if strings.Contains(m.Name(), "wire_protocol") {
						t.Errorf("forwarded the metric %s", m.Name())
					}
					for _, a := range pointAttributes(m) {
						if _, ok := a.Get(attrWireProtocol); ok {
							t.Errorf("forwarded %s with %s", m.Name(), attrWireProtocol)
						}
					}
				}
			}
		}
	}
	c.flush(context.Background())
	if len(st.writes) != 1 {
		t.Fatalf("%d writes", len(st.writes))
	}
	h := st.writes[0]
	if len(h.edges) != 1 || len(h.wire) != 1 {
		t.Fatalf("edges %v, wire protocols %v", h.edges, h.wire)
	}
	for k, s := range h.wire {
		if k.protocol != "postgres" || k.edge.port != 5432 || k.edge.role != roleClient || !s.first.Equal(edge.first) {
			t.Errorf("wire protocol %+v %+v", k, s)
		}
		if _, ok := h.edges[k.edge]; !ok {
			t.Errorf("the edge of %+v is not written with it", k)
		}
	}

	// The same edge and protocol again: nothing to write.
	advance := func() {
		*now = now.Add(15 * time.Second)
		ta.time = ta.time.Add(15 * time.Second)
	}
	advance()
	ta.edges[0].last = edge.first
	consume(t, c, sink, ta)
	c.flush(context.Background())
	if h := st.writes[1]; len(h.edges) != 0 || len(h.wire) != 0 {
		t.Errorf("an unchanged edge written again: edges %v, wire protocols %v", h.edges, h.wire)
	}

	// A connection with TLS: the edge, whose last seen did not advance, is
	// written with the new protocol.
	advance()
	ta.edges[0].wire = map[string]span{"postgres": edge.wire["postgres"], "tls_1_3": {edge.first, edge.first}}
	consume(t, c, sink, ta)
	c.flush(context.Background())
	h = st.writes[2]
	if len(h.edges) != 1 || len(h.wire) != 1 {
		t.Fatalf("edges %v, wire protocols %v; want the edge and tls_1_3", h.edges, h.wire)
	}
	for k := range h.wire {
		if k.protocol != "tls_1_3" {
			t.Errorf("wire protocol %+v written, want tls_1_3", k)
		}
	}
}

// TestPGEdgeProtocols: the wire protocols are written with their edges and
// read in shawk_v1.edge_protocols with the addresses of the client and of
// the server, whichever side saw them; they are pruned with the edges, and
// on their own once older than the retention.
func TestPGEdgeProtocols(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-48 * time.Hour)
	h := newHostChanges(hostKey("m", "db-01"))
	h.setHost("m", "db-01", "6.8", "test", now)
	pg := procKey{"postgresql.service", "postgres", "postgres", ""}
	app := procKey{"app.service", "puma", "app", ""}
	h.addProcess(pg, "/usr/bin/postgres", span{old, now})
	h.addProcess(app, "/usr/bin/ruby", span{old, now})
	server := edgeRowKey{role: roleServer, proto: "tcp", local: addrOf("10.0.0.5"), peer: addrOf("10.0.0.11"), port: 5432,
		netns: 1, procKey: pg}
	client := edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.5"), peer: addrOf("10.0.0.9"), port: 443,
		netns: 1, procKey: app}
	// The clients outside the internal ranges, folded.
	folded := edgeRowKey{role: roleServer, proto: "tcp", local: addrOf("10.0.0.5"), peer: addrOf("0.0.0.0"), folded: true,
		port: 8443, netns: 1, procKey: app}
	for _, k := range []edgeRowKey{server, client, folded} {
		h.addEdge(k, span{old, now})
	}
	h.addWire(wireRowKey{server, "postgres"}, span{now.Add(-time.Hour), now})
	h.addWire(wireRowKey{client, "tls_1_2"}, span{old, old})
	h.addWire(wireRowKey{client, "tls_1_3"}, span{now.Add(-time.Hour), now.Add(-time.Minute)})
	h.addWire(wireRowKey{folded, "tls_1_3"}, span{now, now})
	if err := st.write(ctx, h); err != nil {
		t.Fatal(err)
	}
	// Written again with other times: the span widens.
	h2 := newHostChanges(h.key)
	h2.setHost("m", "db-01", "6.8", "test", now)
	h2.addProcess(app, "/usr/bin/ruby", span{old, now})
	h2.addEdge(client, span{old, now})
	h2.addWire(wireRowKey{client, "tls_1_3"}, span{now.Add(-2 * time.Hour), now.Add(-30 * time.Minute)})
	if err := st.write(ctx, h2); err != nil {
		t.Fatal(err)
	}

	type row struct {
		host, service, role, client, server, protocol string
		port                                          int
		first, last                                   time.Time
	}
	read := func() map[string]row {
		t.Helper()
		rows, err := conn.Query(ctx, `SELECT host, service, role, client_addr::text, server_addr::text, port, protocol,
  first_seen, last_seen FROM shawk_v1.edge_protocols`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]row{}
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.host, &r.service, &r.role, &r.client, &r.server, &r.port, &r.protocol, &r.first, &r.last); err != nil {
				t.Fatal(err)
			}
			out[r.service+"/"+r.role+"/"+r.protocol+"/"+r.client] = r
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	got := read()
	want := map[string]row{
		"postgres/server/postgres/10.0.0.11/32": {"db-01", "postgres", "server", "10.0.0.11/32", "10.0.0.5/32", "postgres", 5432,
			now.Add(-time.Hour), now},
		"app/client/tls_1_2/10.0.0.5/32": {"db-01", "app", "client", "10.0.0.5/32", "10.0.0.9/32", "tls_1_2", 443, old, old},
		"app/client/tls_1_3/10.0.0.5/32": {"db-01", "app", "client", "10.0.0.5/32", "10.0.0.9/32", "tls_1_3", 443,
			now.Add(-2 * time.Hour), now.Add(-time.Minute)},
		"app/server/tls_1_3/0.0.0.0/0": {"db-01", "app", "server", "0.0.0.0/0", "10.0.0.5/32", "tls_1_3", 8443, now, now},
	}
	if len(got) != len(want) {
		t.Errorf("rows = %v", got)
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("no row %s in %v", k, got)
			continue
		}
		if g.first.Equal(w.first) && g.last.Equal(w.last) {
			g.first, g.last = w.first, w.last
		}
		if g != w {
			t.Errorf("row %s = %+v, want %+v", k, g, w)
		}
	}

	// A protocol older than the retention goes, its edge stays.
	if _, err := st.prune(ctx, 24*time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	if _, ok := read()["app/client/tls_1_2/10.0.0.5/32"]; ok {
		t.Error("tls_1_2, last seen before the retention, was not pruned")
	}
	if n := len(read()); n != 3 {
		t.Errorf("%d rows after the prune, want 3", n)
	}
	// The rows go with their edge.
	execAll(t, conn, `DELETE FROM shawk.edges WHERE port = 443`)
	if n := len(read()); n != 2 {
		t.Errorf("%d rows after the edge was deleted, want 2", n)
	}
	// A value the agents do not send is refused, and every value of the
	// connector is accepted: one refused would fail the writes of its host.
	if _, err := conn.Exec(ctx, `INSERT INTO shawk.edge_protocols SELECT id, 'gopher', now(), now() FROM shawk.edges LIMIT 1`); err == nil {
		t.Error("a protocol of another value was written")
	}
	h3 := newHostChanges(h.key)
	h3.setHost("m", "db-01", "6.8", "test", now)
	h3.addProcess(pg, "/usr/bin/postgres", span{old, now})
	h3.addEdge(server, span{old, now})
	for p := range wireProtocols {
		h3.addWire(wireRowKey{server, p}, span{now, now})
	}
	if err := st.write(ctx, h3); err != nil {
		t.Fatalf("writing every wire protocol: %v", err)
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM shawk_v1.edge_protocols WHERE port = 5432`).Scan(&n); err != nil || n != len(wireProtocols) {
		t.Errorf("%d protocols of the edge, want %d (%v)", n, len(wireProtocols), err)
	}
	// The protocols of an edge that the retention prunes go with it.
	execAll(t, conn, `UPDATE shawk.edges SET first_seen = now() - interval '9 days', last_seen = now() - interval '9 days' WHERE port = 5432`)
	if _, err := st.prune(ctx, 24*time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM shawk.edge_protocols`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d protocols after the edge was pruned, want the one of port 8443 (%v)", n, err)
	}
}

// pointAttributes returns the attributes of the data points of a metric.
func pointAttributes(m pmetric.Metric) []pcommon.Map {
	var out []pcommon.Map
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		for i := range m.Gauge().DataPoints().Len() {
			out = append(out, m.Gauge().DataPoints().At(i).Attributes())
		}
	case pmetric.MetricTypeSum:
		for i := range m.Sum().DataPoints().Len() {
			out = append(out, m.Sum().DataPoints().At(i).Attributes())
		}
	case pmetric.MetricTypeHistogram:
		for i := range m.Histogram().DataPoints().Len() {
			out = append(out, m.Histogram().DataPoints().At(i).Attributes())
		}
	}
	return out
}
