package query

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/shawk/internal/api"
)

// fakeSource simulates the ledgers of several agents.
type fakeSource struct {
	infos     map[string]*api.Info
	edges     map[string][]api.Edge
	listeners map[string][]api.Listener
	// coverage overrides the full coverage reported by default.
	coverage map[string]*api.Coverage
}

func (f *fakeSource) Coverage(_ context.Context, host string, since, until time.Time) (*api.Coverage, error) {
	if _, ok := f.infos[host]; !ok {
		return nil, errors.New("connection refused")
	}
	if c, ok := f.coverage[host]; ok {
		return c, nil
	}
	return &api.Coverage{Since: since, Until: until, Covered: until.Sub(since), UDP: true}, nil
}

func (f *fakeSource) Info(_ context.Context, host string) (*api.Info, error) {
	if i, ok := f.infos[host]; ok {
		return i, nil
	}
	if host == "8.8.8.8" {
		return nil, api.ErrPeerNotAllowed
	}
	return nil, errors.New("connection refused")
}

func (f *fakeSource) Edges(_ context.Context, host string, q api.EdgeQuery) ([]api.Edge, error) {
	if _, ok := f.infos[host]; !ok {
		return nil, errors.New("connection refused")
	}
	var out []api.Edge
	for _, e := range f.edges[host] {
		if (q.Direction != "" && e.Direction != q.Direction) || (q.Proto != "" && e.Proto != q.Proto) ||
			(q.LocalAddr != "" && e.LocalAddr != q.LocalAddr) || (q.RemoteAddr != "" && e.RemoteAddr != q.RemoteAddr) ||
			(q.Port != 0 && e.Port != q.Port) || (q.Unit != "" && e.Unit != q.Unit) || (q.Comm != "" && e.Comm != q.Comm) ||
			(q.NetNS != 0 && e.NetNS != q.NetNS) ||
			(!q.Since.IsZero() && e.LastSeen.Before(q.Since)) || (!q.Until.IsZero() && e.FirstSeen.After(q.Until)) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeSource) Listeners(_ context.Context, host string, _ time.Time) ([]api.Listener, error) {
	if _, ok := f.infos[host]; !ok {
		return nil, errors.New("connection refused")
	}
	return f.listeners[host], nil
}

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func edge(dir, laddr, raddr string, port uint16, unit, comm string, conns uint64) api.Edge {
	return api.Edge{
		Direction: dir, Proto: "tcp", LocalAddr: laddr, RemoteAddr: raddr, Port: port, Unit: unit, Comm: comm,
		FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-time.Minute), Stats: api.Stats{Conns: conns},
	}
}

// Topology:
//
//	192.168.1.50 (no agent) -> lb:80 haproxy -> app:8080 puma -> db:5432 postgres
//	                                            app puma -> 127.0.0.1:6379 redis on app
//	10.0.0.99 (no agent) -> db:5432
func topology() *fakeSource {
	f := &fakeSource{
		infos: map[string]*api.Info{
			"10.0.0.5":  {ID: "id-lb", Hostname: "lb-01", Addrs: []string{"10.0.0.5", "127.0.0.1"}, NetNS: "all"},
			"10.0.0.11": {ID: "id-app", Hostname: "app-01", Addrs: []string{"10.0.0.11", "127.0.0.1"}, NetNS: "all"},
			"10.0.0.10": {ID: "id-db", Hostname: "db-01", Addrs: []string{"10.0.0.10", "127.0.0.1"}, NetNS: "all"},
		},
		edges: map[string][]api.Edge{
			"10.0.0.5": {
				edge("in", "10.0.0.5", "192.168.1.50", 80, "haproxy.service", "haproxy", 100),
				edge("out", "10.0.0.5", "10.0.0.11", 8080, "haproxy.service", "haproxy", 90),
			},
			"10.0.0.11": {
				edge("in", "10.0.0.11", "10.0.0.5", 8080, "app.service", "puma", 90),
				edge("out", "10.0.0.11", "10.0.0.10", 5432, "app.service", "puma", 5),
				edge("out", "127.0.0.1", "127.0.0.1", 6379, "app.service", "puma", 7),
				edge("in", "127.0.0.1", "127.0.0.1", 6379, "redis.service", "redis-server", 7),
			},
			"10.0.0.10": {
				edge("in", "10.0.0.10", "10.0.0.11", 5432, "postgresql.service", "postgres", 5),
				edge("in", "10.0.0.10", "10.0.0.99", 5432, "postgresql.service", "postgres", 3),
			},
		},
		listeners: map[string][]api.Listener{
			"10.0.0.11": {
				{Proto: "tcp", Addr: "127.0.0.1", Port: 6379, Unit: "redis.service", Comm: "redis-server"},
				{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Unit: "app.service", Comm: "puma"},
			},
			"10.0.0.10": {
				{Proto: "tcp", Addr: "0.0.0.0", Port: 5432, Unit: "postgresql.service", Comm: "postgres"},
				{Proto: "tcp", Addr: "0.0.0.0", Port: 9187, Unit: "postgres_exporter.service", Comm: "postgres_export"},
			},
		},
	}
	return f
}

func newTestQuerier() *Querier {
	return New(topology(), now.Add(-30*24*time.Hour), now)
}

func TestWhoUses(t *testing.T) {
	q := newTestQuerier()
	roots, err := q.WhoUses(context.Background(), "10.0.0.10", 5432, "", "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 {
		t.Fatalf("roots = %d", len(roots))
	}
	db := roots[0]
	if db.Host != "db-01" || db.Comm != "postgres" || db.Port != 5432 || db.Stats.Conns != 8 {
		t.Errorf("root = %+v", db)
	}
	if len(db.Children) != 2 {
		t.Fatalf("clients of db = %+v", db.Children)
	}
	app, unknown := db.Children[0], db.Children[1]
	if app.Host != "app-01" || app.Comm != "puma" || app.Unit != "app.service" || !app.Agent {
		t.Errorf("app client = %+v", app)
	}
	if unknown.Agent || unknown.Host != "10.0.0.99" {
		t.Errorf("unknown client = %+v", unknown)
	}
	// app's service 8080 is used by haproxy on lb-01, which is used by an
	// external client.
	if len(app.Children) != 1 || app.Children[0].Port != 8080 {
		t.Fatalf("services of app = %+v", app.Children)
	}
	lb := app.Children[0].Children
	if len(lb) != 1 || lb[0].Host != "lb-01" || lb[0].Comm != "haproxy" {
		t.Fatalf("clients of app:8080 = %+v", lb)
	}
	if len(lb[0].Children) != 1 || lb[0].Children[0].Children[0].Host != "192.168.1.50" {
		t.Errorf("clients of lb = %+v", lb[0].Children)
	}
}

func TestWhoUsesLoopback(t *testing.T) {
	q := newTestQuerier()
	roots, err := q.WhoUses(context.Background(), "10.0.0.11", 6379, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || len(roots[0].Children) != 1 {
		t.Fatalf("roots = %+v", roots)
	}
	c := roots[0].Children[0]
	if c.Host != "app-01" || c.Comm != "puma" || c.Stats.Conns != 7 {
		t.Errorf("client = %+v", c)
	}
}

func TestDeps(t *testing.T) {
	q := newTestQuerier()
	roots, err := q.Deps(context.Background(), "10.0.0.5", "", "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0].Comm != "haproxy" || len(roots[0].Children) != 1 {
		t.Fatalf("roots = %+v", roots)
	}
	app := roots[0].Children[0]
	if app.Host != "app-01" || app.Port != 8080 || app.Comm != "puma" {
		t.Errorf("app = %+v", app)
	}
	var got []string
	for _, c := range app.Children {
		got = append(got, c.Host+":"+c.Comm)
	}
	if strings.Join(got, ",") != "db-01:postgres,app-01:redis-server" {
		t.Errorf("deps of app = %v", got)
	}
}

func TestCanIRemove(t *testing.T) {
	ctx := context.Background()
	q := newTestQuerier()
	r, err := q.CanIRemove(ctx, "10.0.0.10", 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict() != VerdictInUse || len(r.Clients) != 1 || len(r.Clients[0].Children) != 2 {
		t.Errorf("removal = %+v", r)
	}
	// Only local clients use redis on app-01.
	r, err = q.CanIRemove(ctx, "10.0.0.11", 6379)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict() != VerdictSafe {
		t.Errorf("verdict for redis = %s: %+v %v", r.Verdict(), r.Clients, r.Reasons)
	}
}

// TestCanIRemoveIncomplete checks that the absence of clients is not
// reported as safe when the record may miss them.
func TestCanIRemoveIncomplete(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		modify func(*fakeSource)
		port   uint16
		reason string
	}{
		{"empty ledger", func(f *fakeSource) {
			f.coverage["10.0.0.11"] = &api.Coverage{Gaps: []api.Gap{{From: now.Add(-30 * 24 * time.Hour), To: now}}}
		}, 6379, "did not record"},
		{"gap in the window", func(f *fakeSource) {
			f.coverage["10.0.0.11"] = &api.Coverage{Covered: time.Hour, UDP: true,
				Gaps: []api.Gap{{From: now.Add(-2 * time.Hour), To: now.Add(-time.Hour)}}}
		}, 6379, "did not record 1h0m0s"},
		{"dropped flows", func(f *fakeSource) {
			f.coverage["10.0.0.11"] = &api.Coverage{Covered: 30 * 24 * time.Hour, UDP: true, Drops: 3}
		}, 6379, "3 flow updates were dropped"},
		{"UDP not traced", func(f *fakeSource) {
			f.coverage["10.0.0.11"] = &api.Coverage{Covered: 30 * 24 * time.Hour}
		}, 0, "UDP was not traced"},
		{"restricted namespace", func(f *fakeSource) {
			f.infos["10.0.0.11"].NetNS = "4026531840"
		}, 6379, "only network namespace"},
		{"no such service", func(*fakeSource) {}, 5433, "no service listened on port 5433"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := topology()
			src.coverage = map[string]*api.Coverage{}
			// Remove the remote clients of app-01 so that it would be safe.
			src.edges["10.0.0.11"] = slices.DeleteFunc(src.edges["10.0.0.11"], func(e api.Edge) bool { return e.Port == 8080 })
			tc.modify(src)
			r, err := New(src, now.Add(-30*24*time.Hour), now).CanIRemove(ctx, "10.0.0.11", tc.port)
			if err != nil {
				t.Fatal(err)
			}
			if r.Verdict() != VerdictUnknown || !strings.Contains(strings.Join(r.Reasons, "; "), tc.reason) {
				t.Errorf("verdict = %s, reasons = %q; want unknown with %q", r.Verdict(), r.Reasons, tc.reason)
			}
		})
	}

	// A TCP-only service is not affected by UDP not being traced.
	src := topology()
	src.coverage = map[string]*api.Coverage{"10.0.0.11": {Covered: 30 * 24 * time.Hour}}
	r, err := New(src, now.Add(-30*24*time.Hour), now).CanIRemove(ctx, "10.0.0.11", 6379)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict() != VerdictSafe {
		t.Errorf("verdict for a TCP service without UDP tracing = %s %v", r.Verdict(), r.Reasons)
	}
}

func TestUnused(t *testing.T) {
	q := newTestQuerier()
	ls, reasons, err := q.Unused(context.Background(), "10.0.0.10")
	if err != nil || len(reasons) != 0 {
		t.Fatal(err, reasons)
	}
	if len(ls) != 1 || ls[0].Port != 9187 {
		t.Errorf("unused = %+v", ls)
	}
}

func TestDiff(t *testing.T) {
	src := topology()
	added := edge("out", "10.0.0.11", "10.0.0.20", 6379, "app.service", "puma", 1)
	added.FirstSeen = now.Add(-time.Hour)
	removed := edge("out", "10.0.0.11", "10.0.0.21", 11211, "app.service", "puma", 1)
	removed.LastSeen = now.Add(-3 * 24 * time.Hour)
	src.edges["10.0.0.11"] = append(src.edges["10.0.0.11"], added, removed)
	q := New(src, now.Add(-24*time.Hour), now)
	changes, reasons, err := q.Diff(context.Background(), "10.0.0.11", now.Add(-7*24*time.Hour))
	if err != nil || len(reasons) != 0 {
		t.Fatal(err, reasons)
	}
	if len(changes) != 2 || !changes[0].Added || changes[0].Edge.Port != 6379 || changes[1].Added || changes[1].Edge.Port != 11211 {
		t.Errorf("changes = %+v", changes)
	}
}

func TestGraph(t *testing.T) {
	q := newTestQuerier()
	g, err := q.Graph(context.Background(), []string{"10.0.0.11"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	var edges []string
	labels := map[string]string{}
	for _, n := range g.Nodes {
		labels[n.ID] = n.Label()
	}
	for _, e := range g.Edges {
		edges = append(edges, labels[e.From]+" -> "+labels[e.To])
	}
	want := []string{
		"10.0.0.99 -> db-01: postgres (postgresql.service)",
		"192.168.1.50 -> lb-01: haproxy (haproxy.service)",
		"app-01: puma (app.service) -> app-01: redis-server (redis.service)",
		"app-01: puma (app.service) -> db-01: postgres (postgresql.service)",
		"lb-01: haproxy (haproxy.service) -> app-01: puma (app.service)",
	}
	got := map[string]bool{}
	for _, e := range edges {
		got[e] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing edge %q in %v", w, edges)
		}
	}
	if len(edges) != len(want) {
		t.Errorf("edges = %v", edges)
	}
	var buf bytes.Buffer
	if err := g.WriteMermaid(&buf); err != nil || !strings.Contains(buf.String(), "-->|tcp/5432|") {
		t.Errorf("mermaid = %s, %v", buf.String(), err)
	}
	buf.Reset()
	if err := g.WriteDOT(&buf); err != nil || !strings.Contains(buf.String(), "digraph") {
		t.Errorf("dot = %s, %v", buf.String(), err)
	}
}

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Target
	}{
		{"db-01", Target{Host: "db-01"}},
		{"db-01:5432", Target{Host: "db-01", Port: 5432}},
		{"10.0.0.1:80", Target{Host: "10.0.0.1", Port: 80}},
		{"[2001:db8::1]:80", Target{Host: "2001:db8::1", Port: 80}},
		{"2001:db8::1", Target{Host: "2001:db8::1"}},
		{"web-01/nginx.service", Target{Host: "web-01", Unit: "nginx.service"}},
		{"web-01:443/@nginx", Target{Host: "web-01", Port: 443, Comm: "nginx"}},
	} {
		got, err := ParseTarget(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{":80", "host:x", "host:70000"} {
		if _, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) succeeded", in)
		}
	}
}

func TestUnqueriedPeer(t *testing.T) {
	src := topology()
	// A client on the internet, which the client must not contact.
	src.edges["10.0.0.5"] = append(src.edges["10.0.0.5"], edge("in", "10.0.0.5", "8.8.8.8", 80, "haproxy.service", "haproxy", 1))
	roots, err := New(src, now.Add(-30*24*time.Hour), now).WhoUses(context.Background(), "10.0.0.5", 80, "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range roots[0].Children {
		got = append(got, c.Host+" "+c.Process())
	}
	if strings.Join(got, ", ") != "192.168.1.50 (no agent), 8.8.8.8 (not queried)" {
		t.Errorf("clients = %v", got)
	}
}

// flatten returns the hosts and processes of a tree in depth-first order.
func flatten(nodes []*Node) []string {
	var out []string
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		out = append(out, fmt.Sprintf("%d:%s:%s", depth, n.Host, n.Process()))
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	for _, n := range nodes {
		walk(n, 0)
	}
	return out
}

func TestWhoUsesUnknownClientIsNotExpanded(t *testing.T) {
	src := topology()
	// app-01 runs an agent but did not see its side of the connection to db.
	src.edges["10.0.0.11"] = slices.DeleteFunc(src.edges["10.0.0.11"], func(e api.Edge) bool { return e.Port == 5432 })
	roots, err := New(src, now.Add(-30*24*time.Hour), now).WhoUses(context.Background(), "10.0.0.10", 5432, "", "", 3)
	if err != nil {
		t.Fatal(err)
	}
	app := roots[0].Children[0]
	if app.Host != "app-01" || app.Process() != "?" || len(app.Children) != 0 {
		t.Errorf("unknown client = %+v, children %v", app, flatten(app.Children))
	}
}

func TestMultiAddressClient(t *testing.T) {
	src := topology()
	src.infos["10.0.0.11"].Addrs = append(src.infos["10.0.0.11"].Addrs, "10.0.1.11")
	src.infos["10.0.1.11"] = src.infos["10.0.0.11"]
	ruby := edge("out", "10.0.1.11", "10.0.0.10", 5432, "batch.service", "ruby", 2)
	src.edges["10.0.0.11"] = append(src.edges["10.0.0.11"], ruby)
	src.edges["10.0.1.11"] = src.edges["10.0.0.11"]
	src.edges["10.0.0.10"] = append(src.edges["10.0.0.10"], edge("in", "10.0.0.10", "10.0.1.11", 5432, "postgresql.service", "postgres", 2))

	roots, err := New(src, now.Add(-30*24*time.Hour), now).WhoUses(context.Background(), "10.0.0.10", 5432, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	got := flatten(roots)
	want := []string{
		"0:db-01:postgres (postgresql.service)",
		"1:app-01:puma (app.service)",
		"1:10.0.0.99:(no agent)",
		"1:app-01:ruby (batch.service)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("tree =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestServerOnSamePortDifferentAddresses(t *testing.T) {
	src := topology()
	src.infos["10.0.0.10"].Addrs = append(src.infos["10.0.0.10"].Addrs, "10.0.0.20")
	src.infos["10.0.0.20"] = src.infos["10.0.0.10"]
	src.edges["10.0.0.10"] = append(src.edges["10.0.0.10"],
		edge("in", "10.0.0.10", "10.0.0.11", 80, "nginx.service", "nginx", 1),
		edge("in", "10.0.0.20", "10.0.0.11", 80, "httpd.service", "httpd", 1))
	src.edges["10.0.0.20"] = src.edges["10.0.0.10"]
	src.edges["10.0.0.11"] = append(src.edges["10.0.0.11"],
		edge("out", "10.0.0.11", "10.0.0.10", 80, "app.service", "puma", 1),
		edge("out", "10.0.0.11", "10.0.0.20", 80, "app.service", "puma", 1))

	roots, err := New(src, now.Add(-30*24*time.Hour), now).Deps(context.Background(), "10.0.0.11", "app.service", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	var comms []string
	for _, c := range roots[0].Children {
		if c.Port == 80 {
			comms = append(comms, c.Comm)
		}
	}
	slices.Sort(comms)
	if strings.Join(comms, ",") != "httpd,nginx" {
		t.Errorf("servers on port 80 = %v", comms)
	}
}

func TestLoopbackAcrossNamespaces(t *testing.T) {
	src := topology()
	// Two containers on app-01, each with its own redis on 127.0.0.1:6379.
	a := edge("out", "127.0.0.1", "127.0.0.1", 6379, "docker-aaa", "worker-a", 1)
	a.NetNS = 1
	b := edge("out", "127.0.0.1", "127.0.0.1", 6379, "docker-bbb", "worker-b", 1)
	b.NetNS = 2
	ra := edge("in", "127.0.0.1", "127.0.0.1", 6379, "docker-aaa", "redis-server", 1)
	ra.NetNS = 1
	rb := edge("in", "127.0.0.1", "127.0.0.1", 6379, "docker-bbb", "redis-server", 1)
	rb.NetNS = 2
	src.edges["10.0.0.11"] = []api.Edge{a, b, ra, rb}

	roots, err := New(src, now.Add(-30*24*time.Hour), now).WhoUses(context.Background(), "10.0.0.11", 6379, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range roots {
		if len(svc.Children) != 1 || svc.Children[0].Unit != svc.Unit {
			t.Errorf("clients of redis in %s = %v", svc.Unit, flatten(svc.Children))
		}
	}
}

func TestWhoUsesWithRenamedWorkers(t *testing.T) {
	src := topology()
	// The master accepts (listener owner) but workers connect out.
	for i, e := range src.edges["10.0.0.11"] {
		if e.Direction == "in" && e.Port == 8080 {
			src.edges["10.0.0.11"][i].Comm = "gunicorn: maste"
		}
		if e.Direction == "out" && e.Port == 5432 {
			src.edges["10.0.0.11"][i].Comm = "gunicorn: worke"
		}
	}
	roots, err := New(src, now.Add(-30*24*time.Hour), now).WhoUses(context.Background(), "10.0.0.10", 5432, "", "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(flatten(roots), "3:lb-01:haproxy (haproxy.service)") {
		t.Errorf("the chain stopped at the worker:\n%s", strings.Join(flatten(roots), "\n"))
	}
}

func TestGraphByHostName(t *testing.T) {
	src := topology()
	src.infos["app-01"] = src.infos["10.0.0.11"]
	src.edges["app-01"] = src.edges["10.0.0.11"]
	src.listeners["app-01"] = src.listeners["10.0.0.11"]
	g, err := New(src, now.Add(-30*24*time.Hour), now).Graph(context.Background(), []string{"app-01"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]int{}
	for _, n := range g.Nodes {
		labels[n.Label()]++
	}
	for l, n := range labels {
		if n > 1 {
			t.Errorf("node %q appears %d times", l, n)
		}
	}
}

func TestGraphKeepsClientsAtTheFrontier(t *testing.T) {
	g, err := newTestQuerier().Graph(context.Background(), []string{"10.0.0.10"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, n := range g.Nodes {
		labels[n.ID] = n.Label()
	}
	var edges []string
	for _, e := range g.Edges {
		edges = append(edges, labels[e.From]+" -> "+labels[e.To])
	}
	if !slices.Contains(edges, "app-01: puma (app.service) -> db-01: postgres (postgresql.service)") {
		t.Errorf("edges = %v", edges)
	}
}
