package shawkconnector

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

func boolPtr(b bool) *bool { return &b }

// TestUnixPeerNames: the peer of the client edge of a Unix socket is the
// service listening on its name on the same host, in the namespace of the
// client, else, for a path, in the only namespace that has one; else
// ~unresolved. Its
// outputs have the connections only, with port 0.
func TestUnixPeerNames(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	const host, container, other = "4026531840", "4026532001", "4026532002"
	// A listener of the same name on another host names nothing here.
	consume(t, c, sink, tAgent{host: "db-02", addrs: []string{"10.0.0.12"}, time: ts,
		listeners: []tListener{{proto: transportUnix, path: "/run/app.sock", svc: "elsewhere", unit: "elsewhere.service", comm: "elsewhere"}}})
	unix := func(path, netns string, opened int64) tEdge {
		return tEdge{role: roleClient, proto: transportUnix, path: path, netns: netns, svc: "app", unit: "app.service",
			comm: "puma", opened: opened, failed: 1, count: 2, reasons: map[string]tReason{"refused": {value: 1}}}
	}
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts, unixTraced: boolPtr(true),
		listeners: []tListener{
			{proto: transportUnix, path: "/run/postgresql/.s.PGSQL.5432", svc: "postgres", unit: "postgresql.service", comm: "postgres"},
			// dockerd in the namespace of the host, reached from a container.
			{proto: transportUnix, path: "/run/docker.sock", svc: "dockerd", unit: "docker.service", comm: "dockerd"},
			// A name served in the namespace of the container and in another.
			{proto: transportUnix, path: "/tmp/app.sock", netns: container, svc: "sidecar", unit: "docker-0123456789ab", comm: "sidecar"},
			{proto: transportUnix, path: "/tmp/app.sock", netns: other, svc: "other", unit: "docker-ba9876543210", comm: "other"},
			// A name served in two namespaces, neither the client's.
			{proto: transportUnix, path: "/run/twice.sock", netns: container, svc: "one", unit: "one.service", comm: "one"},
			{proto: transportUnix, path: "/run/twice.sock", netns: other, svc: "two", unit: "two.service", comm: "two"},
			// An owner the agent could not resolve names nothing.
			{proto: transportUnix, path: "@unknown", svc: unknownService, comm: "x"},
			// An abstract name served in another namespace only, which the
			// client cannot reach.
			{proto: transportUnix, path: "@ctl", netns: other, svc: "ctl", unit: "ctl.service", comm: "ctl"},
		},
		edges: []tEdge{
			unix("/run/postgresql/.s.PGSQL.5432", host, 3),
			unix("/run/docker.sock", container, 4),
			unix("/tmp/app.sock", container, 5),
			unix("/run/twice.sock", host, 6),
			unix("/run/app.sock", host, 7),
			unix("@unknown", host, 8),
			unix("@ctl", host, 9),
		}})
	got := map[string]float64{}
	for _, s := range find(out, metricConnOpened, "app", "*", roleClient, "") {
		if s.transport != transportUnix || s.port != 0 || !s.agent {
			t.Errorf("output %+v", s)
		}
		got[s.peer] = s.value
	}
	// The sockets without a known service add up in ~unresolved.
	want := map[string]float64{"postgres": 3, "dockerd": 4, "sidecar": 5, peerUnresolved: 6 + 7 + 8 + 9}
	if !maps.Equal(got, want) {
		t.Errorf("connections by peer = %v, want %v", got, want)
	}
	for metric, v := range map[string]float64{metricConnFailed: 1, metricConnCount: 2} {
		if s := find(out, metric, "app", "postgres", roleClient, ""); len(s) != 1 || s[0].value != v {
			t.Errorf("%s = %v", metric, s)
		}
	}
	if s := find(out, metricConnFailedByReason, "app", "postgres", roleClient, ""); len(s) != 1 || s[0].errType != "refused" {
		t.Errorf("failures by reason = %v", s)
	}
	for _, s := range out {
		if s.job == "app" && s.metric != metricConnOpened && s.metric != metricConnFailed && s.metric != metricConnCount &&
			s.metric != metricConnFailedByReason {
			t.Errorf("output %s of a Unix socket", s.metric)
		}
	}
}

// TestUnixPeerReplaced: a listener that is gone from the namespace of the
// client, replaced in another namespace, no longer names the peer: the
// agent sends it with its last time seen until its idle TTL.
func TestUnixPeerReplaced(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Minute)
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts,
		listeners: []tListener{
			{proto: transportUnix, path: "/run/app.sock", svc: "old", unit: "old.service", comm: "old",
				first: t0, last: t0.Add(5 * time.Minute)},
			{proto: transportUnix, path: "/run/app.sock", netns: "4026532001", svc: "new", unit: "new.service", comm: "new",
				first: t0.Add(5 * time.Minute)},
		},
		edges: []tEdge{{role: roleClient, proto: transportUnix, path: "/run/app.sock", svc: "app", unit: "app.service",
			comm: "app", opened: 1, start: ts.Add(-time.Minute)}}})
	if s := find(out, metricConnOpened, "app", "*", roleClient, ""); len(s) != 1 || s[0].peer != "new" {
		t.Errorf("outputs = %v", s)
	}
}

// TestUnixPeerFromPostgres: the services listening on Unix sockets are also
// named from shawk_v1.unix_endpoints, as processes of Slurm jobs are named
// slurm-job.
func TestUnixPeerFromPostgres(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	app := hostKey("", "app-01")
	st.rows.unix = []unixEndpointRow{
		{key: unixKey{app, "/run/munge/munge.socket.2"}, unixEndpoint: unixEndpoint{4026531840, "munged"}, lastSeen: t0},
		{key: unixKey{app, "@job"}, unixEndpoint: unixEndpoint{4026531840, slurmJobService}, lastSeen: t0},
	}
	c.prepare(context.Background())
	*now = ts
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{
			{role: roleClient, proto: transportUnix, path: "/run/munge/munge.socket.2", svc: "slurmd", unit: "slurmd.service", comm: "slurmd", opened: 1},
			{role: roleClient, proto: transportUnix, path: "@job", svc: "slurmd", unit: "slurmd.service", comm: "slurmd", opened: 2},
		}})
	got := map[string]float64{}
	for _, s := range find(out, metricConnOpened, "slurmd", "*", roleClient, "") {
		got[s.peer] = s.value
	}
	if !maps.Equal(got, map[string]float64{"munged": 1, slurmJobService: 2}) {
		t.Errorf("peers = %v", got)
	}
}

// TestUnixPeerHost: with peer_hosts, the peer of a Unix socket is the host
// itself, in the outputs per peer host.
func TestUnixPeerHost(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) { cfg.PeerHosts = true })
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second),
		listeners: []tListener{{proto: transportUnix, path: "/run/pg.sock", svc: "postgres", unit: "postgresql.service", comm: "postgres"}},
		edges: []tEdge{{role: roleClient, proto: transportUnix, path: "/run/pg.sock", svc: "app", unit: "app.service", comm: "app",
			opened: 2, failed: 1, reasons: map[string]tReason{"timeout": {value: 1}}}}})
	for _, metric := range []string{metricHostConnOpened, metricHostConnFailedByReason} {
		s := find(out, metric, "app", "postgres", roleClient, "")
		if len(s) != 1 || s[0].peerHost != "app-01" || s[0].transport != transportUnix {
			t.Errorf("%s = %v", metric, s)
		}
	}
	for _, s := range out {
		if s.peerHost != "" && s.metric != metricHostConnOpened && s.metric != metricHostConnFailedByReason {
			t.Errorf("output per peer host %s of a Unix socket", s.metric)
		}
	}
}

// TestUnixInvalid: an agent traces the clients of Unix sockets only; a
// server edge, or an edge or a listener without a name or a namespace, is
// invalid.
func TestUnixInvalid(t *testing.T) {
	for name, ta := range map[string]tAgent{
		"server edge":         {edges: []tEdge{{role: roleServer, proto: transportUnix, path: "/run/a.sock", svc: "a", comm: "a"}}},
		"edge without a name": {edges: []tEdge{{role: roleClient, proto: transportUnix, svc: "a", comm: "a"}}},
		"edge without a namespace": {edges: []tEdge{{role: roleClient, proto: transportUnix, path: "/run/a.sock", netns: "x",
			svc: "a", comm: "a"}}},
		"listener without a name": {listeners: []tListener{{proto: transportUnix, svc: "a", comm: "a"}}},
	} {
		ta.host, ta.time = "h1", t0
		b, err := parseResource(ta.metrics().ResourceMetrics().At(0))
		if err != nil {
			t.Fatal(err)
		}
		if b.invalid == 0 || len(b.edges)+len(b.listeners) != 0 {
			t.Errorf("%s: %d invalid points, %d edges, %d listeners", name, b.invalid, len(b.edges), len(b.listeners))
		}
	}
}

// TestUnixChanges: the edges and listeners of Unix sockets are written with
// their names, and whether the agent traces Unix sockets with the session;
// an agent that does not tell leaves it unknown.
func TestUnixChanges(t *testing.T) {
	c, st, sink, _ := testConnector(t, func(cfg *Config) { cfg.KeepPeerAddress = true })
	ts := t0.Add(15 * time.Second)
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts, unixTraced: boolPtr(false),
		listeners: []tListener{{proto: transportUnix, path: "@app/control", svc: "app", unit: "app.service", comm: "app"}},
		edges: []tEdge{{role: roleClient, proto: transportUnix, path: "/run/pg.sock", netns: "4026532001", svc: "app",
			unit: "app.service", comm: "app", opened: 1}}})
	// keep_peer_address keeps no address of a Unix socket.
	sink.Reset()
	if err := c.ConsumeMetrics(context.Background(), tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts.Add(15 * time.Second),
		unixTraced: boolPtr(false), edges: []tEdge{{role: roleClient, proto: transportUnix, path: "/run/pg.sock", netns: "4026532001", svc: "app",
			unit: "app.service", comm: "app", opened: 2}}}.metrics()); err != nil {
		t.Fatal(err)
	}
	for _, md := range sink.AllMetrics() {
		forEachPoint(md, func(name string, a map[string]any) {
			if _, ok := a[attrPeerAddr]; ok && a[attrTransport] == transportUnix {
				t.Errorf("%s keeps the address %v of a Unix socket", name, a[attrPeerAddr])
			}
		})
	}
	if len(find(out, metricConnOpened, "app", peerUnresolved, roleClient, "")) != 1 {
		t.Errorf("outputs = %v", out)
	}
	c.flush(context.Background())
	if len(st.writes) != 1 {
		t.Fatalf("%d writes", len(st.writes))
	}
	h := st.writes[0]
	pk := procKey{unit: "app.service", comm: "app", service: "app"}
	if _, ok := h.edges[edgeRowKey{role: roleClient, proto: transportUnix, path: "/run/pg.sock", netns: 4026532001, procKey: pk}]; !ok {
		t.Errorf("edges = %v", slices.Collect(maps.Keys(h.edges)))
	}
	if _, ok := h.listeners[listenerRowKey{proto: transportUnix, path: "@app/control", netns: 4026531840, procKey: pk}]; !ok {
		t.Errorf("listeners = %v", slices.Collect(maps.Keys(h.listeners)))
	}
	var sessions []*sessionRow
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	if len(sessions) != 1 || sessions[0].unixTraced == nil || *sessions[0].unixTraced {
		t.Errorf("sessions = %+v", sessions)
	}
	// An agent before shawk.agent.unix.traced.
	consume(t, c, sink, tAgent{host: "old-01", addrs: []string{"10.0.0.12"}, time: ts})
	c.flush(context.Background())
	for _, h := range st.writes[1:] {
		for _, s := range h.sessions {
			if s.unixTraced != nil {
				t.Errorf("unix traced of an agent that does not tell = %v", *s.unixTraced)
			}
		}
	}
	if len(st.writes) != 2 {
		t.Errorf("%d writes", len(st.writes))
	}
}

// forEachPoint calls f with the name and attributes of every point of md.
func forEachPoint(md pmetric.Metrics, f func(string, map[string]any)) {
	rms := md.ResourceMetrics()
	for i := range rms.Len() {
		sms := rms.At(i).ScopeMetrics()
		for j := range sms.Len() {
			ms := sms.At(j).Metrics()
			for k := range ms.Len() {
				m := ms.At(k)
				switch m.Type() {
				case pmetric.MetricTypeSum:
					for l := range m.Sum().DataPoints().Len() {
						f(m.Name(), m.Sum().DataPoints().At(l).Attributes().AsRaw())
					}
				case pmetric.MetricTypeGauge:
					for l := range m.Gauge().DataPoints().Len() {
						f(m.Name(), m.Gauge().DataPoints().At(l).Attributes().AsRaw())
					}
				case pmetric.MetricTypeHistogram:
					for l := range m.Histogram().DataPoints().Len() {
						f(m.Name(), m.Histogram().DataPoints().At(l).Attributes().AsRaw())
					}
				}
			}
		}
	}
}

// TestUnixTracedForwarded: shawk.agent.unix.traced is forwarded like
// shawk.agent.udp.traced.
func TestUnixTracedForwarded(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second), unixTraced: boolPtr(true)})
	n := 0
	for _, md := range sink.AllMetrics() {
		forEachPoint(md, func(name string, _ map[string]any) {
			if name == metricAgentUnixTraced {
				n++
			}
		})
	}
	if n != 1 {
		t.Errorf("%d points of %s forwarded", n, metricAgentUnixTraced)
	}
}
