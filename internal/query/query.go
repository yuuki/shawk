// Package query answers dependency questions by walking edges across the
// ledgers of agents. There is no central database: each agent knows the
// edges of its own host, and a dependency between two hosts is followed by
// asking the agent on the other end.
package query

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yuuki/shawk/internal/api"
)

// Source provides the ledgers of agents. *client.Client implements it.
type Source interface {
	Info(ctx context.Context, host string) (*api.Info, error)
	Edges(ctx context.Context, host string, q api.EdgeQuery) ([]api.Edge, error)
	Listeners(ctx context.Context, host string, since time.Time) ([]api.Listener, error)
}

// Querier walks dependencies over agents.
type Querier struct {
	src   Source
	Since time.Time
	Until time.Time

	mu        sync.Mutex
	listeners map[string][]api.Listener
}

// New returns a Querier for the time window [since, until].
func New(src Source, since, until time.Time) *Querier {
	return &Querier{src: src, Since: since, Until: until, listeners: map[string][]api.Listener{}}
}

// Node is a process in a dependency tree. A node with a Port is a server
// process serving on that port.
type Node struct {
	Host      string    `json:"host"`            // host name reported by the agent, or the address
	Addr      string    `json:"addr"`            // address or name used to reach the host
	Agent     bool      `json:"agent"`           // whether an agent answered for the host
	Unit      string    `json:"unit,omitempty"`  // systemd unit or container of the process
	Comm      string    `json:"comm,omitempty"`  // command name of the process
	Proto     string    `json:"proto,omitempty"` // protocol of the service
	Port      uint16    `json:"port,omitempty"`  // service port of a server node
	Stats     api.Stats `json:"stats"`           // traffic of the dependency to the parent
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Children  []*Node   `json:"children,omitempty"`
	// Cycle is set when the node already appears in its ancestors.
	Cycle bool `json:"cycle,omitempty"`
}

// Process returns the display name of the process of the node.
func (n *Node) Process() string {
	switch {
	case !n.Agent:
		return "(no agent)"
	case n.Comm == "" && n.Unit == "":
		return "?"
	case n.Unit == "":
		return n.Comm
	case n.Comm == "":
		return "(" + n.Unit + ")"
	}
	return n.Comm + " (" + n.Unit + ")"
}

func (n *Node) key() string { return n.Addr + "|" + n.Unit + "|" + n.Comm }

func (q *Querier) window(e *api.EdgeQuery) {
	e.Since, e.Until = q.Since, q.Until
}

func (q *Querier) displayHost(ctx context.Context, host string) (string, bool) {
	info, err := q.src.Info(ctx, host)
	if err != nil {
		return host, false
	}
	return info.Hostname, true
}

// peerHost returns the host to ask about addr as seen from host. Loopback
// addresses and addresses of the host itself refer to the host.
func (q *Querier) peerHost(ctx context.Context, host, addr string) string {
	a, err := netip.ParseAddr(addr)
	if err == nil && (a.IsLoopback() || a.IsUnspecified()) {
		return host
	}
	if info, err := q.src.Info(ctx, host); err == nil && slices.Contains(info.Addrs, addr) {
		return host
	}
	return addr
}

func isLocal(info *api.Info, addr string) bool {
	if a, err := netip.ParseAddr(addr); err == nil && a.IsLoopback() {
		return true
	}
	return info != nil && slices.Contains(info.Addrs, addr)
}

type serviceKey struct {
	proto      string
	port       uint16
	unit, comm string
}

// WhoUses returns the services on host (filtered by port and process) with
// the processes that used them as children, recursively up to depth levels.
// It answers which processes are affected when the services fail.
func (q *Querier) WhoUses(ctx context.Context, host string, port uint16, unit, comm string, depth int) ([]*Node, error) {
	return q.whoUses(ctx, host, port, unit, comm, depth, map[string]bool{})
}

func (q *Querier) whoUses(ctx context.Context, host string, port uint16, unit, comm string, depth int, path map[string]bool) ([]*Node, error) {
	name, ok := q.displayHost(ctx, host)
	if !ok {
		_, err := q.src.Info(ctx, host)
		return nil, err
	}
	eq := api.EdgeQuery{Direction: "in", Port: port, Unit: unit, Comm: comm}
	q.window(&eq)
	edges, err := q.src.Edges(ctx, host, eq)
	if err != nil {
		return nil, err
	}

	var (
		order    []serviceKey
		services = map[serviceKey]*Node{}
	)
	for i := range edges {
		e := &edges[i]
		k := serviceKey{e.Proto, e.Port, e.Unit, e.Comm}
		svc, ok := services[k]
		if !ok {
			svc = &Node{Host: name, Addr: host, Agent: true, Unit: e.Unit, Comm: e.Comm, Proto: e.Proto, Port: e.Port}
			services[k] = svc
			order = append(order, k)
		}
		addStats(svc, e)
		for _, c := range q.clientsOf(ctx, host, e) {
			if depth > 1 && c.Agent {
				ck := c.key()
				if path[ck] {
					c.Cycle = true
				} else {
					next := maps2(path, svc.key(), ck)
					c.Children, _ = q.whoUses(ctx, c.Addr, 0, c.Unit, c.Comm, depth-1, next)
				}
			}
			svc.Children = append(svc.Children, c)
		}
	}
	out := make([]*Node, 0, len(order))
	for _, k := range order {
		n := services[k]
		mergeSiblings(n)
		out = append(out, n)
	}
	return out, nil
}

// clientsOf resolves the client processes of an incoming edge by asking the
// agent on the client host.
func (q *Querier) clientsOf(ctx context.Context, host string, in *api.Edge) []*Node {
	clientHost := q.peerHost(ctx, host, in.RemoteAddr)
	name, ok := q.displayHost(ctx, clientHost)
	if !ok {
		return []*Node{{Host: in.RemoteAddr, Addr: in.RemoteAddr, Stats: in.Stats, FirstSeen: in.FirstSeen, LastSeen: in.LastSeen}}
	}
	eq := api.EdgeQuery{Direction: "out", Proto: in.Proto, Port: in.Port, RemoteAddr: in.LocalAddr}
	q.window(&eq)
	outs, err := q.src.Edges(ctx, clientHost, eq)
	if err == nil && clientHost == host {
		// Both ends are on this host; keep the edges from the client address.
		outs = slices.DeleteFunc(outs, func(e api.Edge) bool { return e.LocalAddr != in.RemoteAddr })
	}
	if err != nil || len(outs) == 0 {
		// The agent did not see the client side (e.g. behind NAT or before
		// its ledger started).
		return []*Node{{Host: name, Addr: clientHost, Agent: true, Stats: in.Stats, FirstSeen: in.FirstSeen, LastSeen: in.LastSeen}}
	}
	nodes := make([]*Node, 0, len(outs))
	for i := range outs {
		o := &outs[i]
		nodes = append(nodes, &Node{
			Host: name, Addr: clientHost, Agent: true, Unit: o.Unit, Comm: o.Comm,
			Stats: o.Stats, FirstSeen: o.FirstSeen, LastSeen: o.LastSeen,
		})
	}
	return nodes
}

// Deps returns the processes on host (filtered by process) with the
// services they depend on as children, recursively up to depth levels.
func (q *Querier) Deps(ctx context.Context, host, unit, comm string, depth int) ([]*Node, error) {
	return q.deps(ctx, host, unit, comm, depth, map[string]bool{})
}

func (q *Querier) deps(ctx context.Context, host, unit, comm string, depth int, path map[string]bool) ([]*Node, error) {
	name, ok := q.displayHost(ctx, host)
	if !ok {
		_, err := q.src.Info(ctx, host)
		return nil, err
	}
	eq := api.EdgeQuery{Direction: "out", Unit: unit, Comm: comm}
	q.window(&eq)
	edges, err := q.src.Edges(ctx, host, eq)
	if err != nil {
		return nil, err
	}
	type procKey struct{ unit, comm string }
	var (
		order []procKey
		procs = map[procKey]*Node{}
	)
	for i := range edges {
		e := &edges[i]
		k := procKey{e.Unit, e.Comm}
		p, ok := procs[k]
		if !ok {
			p = &Node{Host: name, Addr: host, Agent: true, Unit: e.Unit, Comm: e.Comm}
			procs[k] = p
			order = append(order, k)
		}
		srv := q.serverOf(ctx, host, e)
		if depth > 1 && srv.Agent && (srv.Unit != "" || srv.Comm != "") {
			sk := srv.key()
			if path[sk] || sk == p.key() {
				srv.Cycle = true
			} else if sub, err := q.deps(ctx, srv.Addr, srv.Unit, srv.Comm, depth-1, maps2(path, p.key(), sk)); err == nil {
				for _, s := range sub {
					srv.Children = append(srv.Children, s.Children...)
				}
			}
		}
		p.Children = append(p.Children, srv)
	}
	out := make([]*Node, 0, len(order))
	for _, k := range order {
		out = append(out, procs[k])
	}
	return out, nil
}

// serverOf resolves the server process of an outgoing edge by asking the
// agent on the server host.
func (q *Querier) serverOf(ctx context.Context, host string, out *api.Edge) *Node {
	serverHost := q.peerHost(ctx, host, out.RemoteAddr)
	n := &Node{
		Host: out.RemoteAddr, Addr: serverHost, Proto: out.Proto, Port: out.Port,
		Stats: out.Stats, FirstSeen: out.FirstSeen, LastSeen: out.LastSeen,
	}
	name, ok := q.displayHost(ctx, serverHost)
	if !ok {
		return n
	}
	n.Host, n.Agent = name, true
	eq := api.EdgeQuery{Direction: "in", Proto: out.Proto, Port: out.Port, RemoteAddr: out.LocalAddr}
	q.window(&eq)
	if ins, err := q.src.Edges(ctx, serverHost, eq); err == nil && len(ins) > 0 {
		n.Unit, n.Comm = ins[0].Unit, ins[0].Comm
		return n
	}
	if l := q.listenerOn(ctx, serverHost, out.Proto, out.RemoteAddr, out.Port); l != nil {
		n.Unit, n.Comm = l.Unit, l.Comm
	}
	return n
}

func (q *Querier) listenersOf(ctx context.Context, host string) []api.Listener {
	q.mu.Lock()
	ls, ok := q.listeners[host]
	q.mu.Unlock()
	if ok {
		return ls
	}
	ls, _ = q.src.Listeners(ctx, host, q.Since)
	q.mu.Lock()
	q.listeners[host] = ls
	q.mu.Unlock()
	return ls
}

func (q *Querier) listenerOn(ctx context.Context, host, proto, addr string, port uint16) *api.Listener {
	ls := q.listenersOf(ctx, host)
	var wildcard *api.Listener
	for i := range ls {
		l := &ls[i]
		if l.Proto != proto || l.Port != port {
			continue
		}
		if l.Addr == addr {
			return l
		}
		if a, err := netip.ParseAddr(l.Addr); err == nil && a.IsUnspecified() {
			wildcard = l
		}
	}
	return wildcard
}

// Removal is the result of CanIRemove.
type Removal struct {
	Host string `json:"host"`
	// Clients are the services on the host with their remote clients.
	Clients []*Node `json:"clients"`
	// Coverage is when the ledger of the host started. Dependencies before it
	// are unknown.
	Coverage time.Time `json:"coverage"`
}

// Safe reports whether no remote process used the host in the window.
func (r *Removal) Safe() bool { return len(r.Clients) == 0 }

// CanIRemove finds the remote processes that used services on host (on port
// if not zero).
func (q *Querier) CanIRemove(ctx context.Context, host string, port uint16) (*Removal, error) {
	info, err := q.src.Info(ctx, host)
	if err != nil {
		return nil, err
	}
	services, err := q.WhoUses(ctx, host, port, "", "", 1)
	if err != nil {
		return nil, err
	}
	r := &Removal{Host: info.Hostname, Coverage: info.LedgerSince}
	for _, svc := range services {
		svc.Children = slices.DeleteFunc(svc.Children, func(c *Node) bool { return c.Addr == host })
		if len(svc.Children) > 0 {
			r.Clients = append(r.Clients, svc)
		}
	}
	return r, nil
}

// Unused returns the listeners on host that no process used in the window,
// excluding the agent itself.
func (q *Querier) Unused(ctx context.Context, host string) ([]api.Listener, error) {
	ls, err := q.src.Listeners(ctx, host, q.Since)
	if err != nil {
		return nil, err
	}
	eq := api.EdgeQuery{Direction: "in"}
	q.window(&eq)
	edges, err := q.src.Edges(ctx, host, eq)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, e := range edges {
		used[fmt.Sprintf("%s/%d/%d", e.Proto, e.NetNS, e.Port)] = true
	}
	var out []api.Listener
	for _, l := range ls {
		if !used[fmt.Sprintf("%s/%d/%d", l.Proto, l.NetNS, l.Port)] {
			out = append(out, l)
		}
	}
	return out, nil
}

// Change is a dependency that appeared or disappeared.
type Change struct {
	Added bool     `json:"added"`
	Edge  api.Edge `json:"edge"`
}

// Diff compares the dependencies of host in [Since, Until] with those in
// [baseline, Since): edges first seen in the window are added and edges
// last seen before the window are removed.
func (q *Querier) Diff(ctx context.Context, host string, baseline time.Time) ([]Change, error) {
	eq := api.EdgeQuery{Since: baseline, Until: q.Until}
	edges, err := q.src.Edges(ctx, host, eq)
	if err != nil {
		return nil, err
	}
	var out []Change
	for _, e := range edges {
		switch {
		case !e.FirstSeen.Before(q.Since):
			out = append(out, Change{Added: true, Edge: e})
		case e.LastSeen.Before(q.Since):
			out = append(out, Change{Added: false, Edge: e})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Added && !out[j].Added })
	return out, nil
}

func addStats(n *Node, e *api.Edge) {
	n.Stats.Conns += e.Stats.Conns
	n.Stats.ConnFails += e.Stats.ConnFails
	n.Stats.MaxOpenConns += e.Stats.MaxOpenConns
	n.Stats.BytesSent += e.Stats.BytesSent
	n.Stats.BytesRecv += e.Stats.BytesRecv
	n.Stats.MsgsSent += e.Stats.MsgsSent
	n.Stats.MsgsRecv += e.Stats.MsgsRecv
	n.Stats.Retrans += e.Stats.Retrans
	if n.FirstSeen.IsZero() || e.FirstSeen.Before(n.FirstSeen) {
		n.FirstSeen = e.FirstSeen
	}
	if e.LastSeen.After(n.LastSeen) {
		n.LastSeen = e.LastSeen
	}
}

// mergeSiblings merges children that refer to the same process, which
// happens when a client reaches a service through several addresses.
func mergeSiblings(n *Node) {
	var (
		out  []*Node
		seen = map[string]*Node{}
	)
	for _, c := range n.Children {
		k := c.key() + "|" + c.Host
		if prev, ok := seen[k]; ok {
			prev.Stats.Conns += c.Stats.Conns
			prev.Stats.ConnFails += c.Stats.ConnFails
			prev.Stats.BytesSent += c.Stats.BytesSent
			prev.Stats.BytesRecv += c.Stats.BytesRecv
			prev.Stats.MsgsSent += c.Stats.MsgsSent
			prev.Stats.MsgsRecv += c.Stats.MsgsRecv
			if c.LastSeen.After(prev.LastSeen) {
				prev.LastSeen = c.LastSeen
			}
			continue
		}
		seen[k] = c
		out = append(out, c)
	}
	n.Children = out
}

func maps2(m map[string]bool, keys ...string) map[string]bool {
	out := make(map[string]bool, len(m)+len(keys))
	for k, v := range m {
		out[k] = v
	}
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// Target is a host, optionally narrowed to a service port and a process.
//
//	db-01            the host
//	db-01:5432       the service on port 5432
//	[2001:db8::1]:80 an IPv6 address with a port
//	web-01/nginx.service, web-01/@nginx
//	                 a process by unit or by command name
type Target struct {
	Host string
	Port uint16
	Unit string
	Comm string
}

// ParseTarget parses a target.
func ParseTarget(s string) (Target, error) {
	var t Target
	hostPort, proc, _ := strings.Cut(s, "/")
	if strings.HasPrefix(proc, "@") {
		t.Comm = proc[1:]
	} else {
		t.Unit = proc
	}
	if ap, err := netip.ParseAddrPort(hostPort); err == nil {
		t.Host, t.Port = ap.Addr().String(), ap.Port()
		return t, nil
	}
	if a, err := netip.ParseAddr(strings.Trim(hostPort, "[]")); err == nil {
		t.Host = a.String()
		return t, nil
	}
	host, port, found := strings.Cut(hostPort, ":")
	if found {
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err != nil || p <= 0 || p > 65535 {
			return t, fmt.Errorf("invalid port in %q", s)
		}
		t.Port = uint16(p)
	}
	if host == "" {
		return t, fmt.Errorf("missing host in %q", s)
	}
	t.Host = host
	return t, nil
}
