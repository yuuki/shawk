package query

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/yuuki/shawk/internal/api"
)

// Graph is a dependency graph between processes across hosts.
type Graph struct {
	Nodes []*GraphNode `json:"nodes"`
	Edges []*GraphEdge `json:"edges"`
}

// GraphNode is a process, or a remote address without an agent.
type GraphNode struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Addr  string `json:"addr"`
	Agent bool   `json:"agent"`
	Unit  string `json:"unit,omitempty"`
	Comm  string `json:"comm,omitempty"`
}

// Label returns a display label of the node.
func (n *GraphNode) Label() string {
	if !n.Agent {
		return n.Host
	}
	p := (&Node{Agent: true, Unit: n.Unit, Comm: n.Comm}).Process()
	return n.Host + ": " + p
}

// GraphEdge is a dependency from a client process to a server process.
type GraphEdge struct {
	From  string    `json:"from"`
	To    string    `json:"to"`
	Proto string    `json:"proto"`
	Port  uint16    `json:"port"`
	Stats api.Stats `json:"stats"`
}

type graphBuilder struct {
	q     *Querier
	nodes map[string]*GraphNode
	edges map[string]*GraphEdge
}

// Graph builds the dependency graph reachable from the hosts within depth
// hops, following dependencies in both directions.
func (q *Querier) Graph(ctx context.Context, hosts []string, depth int) (*Graph, error) {
	b := &graphBuilder{q: q, nodes: map[string]*GraphNode{}, edges: map[string]*GraphEdge{}}
	// Hosts are visited once whatever name or address they are reached by.
	visited := map[string]bool{}
	frontier := hosts
	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []string
		for _, h := range frontier {
			id := q.identity(ctx, h)
			if visited[id] {
				continue
			}
			visited[id] = true
			peers, err := b.visit(ctx, h)
			if err != nil {
				if level == 0 {
					return nil, err
				}
				continue
			}
			next = append(next, peers...)
		}
		frontier = next
	}

	g := &Graph{}
	for _, n := range b.nodes {
		g.Nodes = append(g.Nodes, n)
	}
	for _, e := range b.edges {
		g.Edges = append(g.Edges, e)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool {
		a, c := g.Edges[i], g.Edges[j]
		return a.From+a.To+fmt.Sprint(a.Port) < c.From+c.To+fmt.Sprint(c.Port)
	})
	return g, nil
}

// node returns the graph node of a process. hostID identifies its host
// across addresses; nodes without an agent are identified by the address.
func (b *graphBuilder) node(hostID, host, addr string, agent bool, unit, comm string) *GraphNode {
	id := addr
	if agent {
		id = hostID + "/" + unit + "/" + comm
	}
	n, ok := b.nodes[id]
	if !ok {
		n = &GraphNode{ID: id, Host: host, Addr: addr, Agent: agent, Unit: unit, Comm: comm}
		b.nodes[id] = n
	}
	return n
}

func (b *graphBuilder) nodeOf(n *Node) *GraphNode {
	return b.node(n.ID, n.Host, n.Addr, n.Agent, n.Unit, n.Comm)
}

func (b *graphBuilder) edge(from, to *GraphNode, e *api.Edge) {
	k := from.ID + "->" + to.ID + "/" + e.Proto + fmt.Sprint(e.Port)
	ge, ok := b.edges[k]
	if !ok {
		ge = &GraphEdge{From: from.ID, To: to.ID, Proto: e.Proto, Port: e.Port}
		b.edges[k] = ge
	}
	// Each edge is observed from both ends; keep the larger observation.
	if e.Stats.Conns+e.Stats.MsgsSent+e.Stats.MsgsRecv > ge.Stats.Conns+ge.Stats.MsgsSent+ge.Stats.MsgsRecv {
		ge.Stats = e.Stats
	}
}

// visit adds the edges recorded on host and returns the peer hosts.
func (b *graphBuilder) visit(ctx context.Context, host string) ([]string, error) {
	q := b.q
	name, ok := q.displayHost(ctx, host)
	if !ok {
		_, err := q.src.Info(ctx, host)
		return nil, err
	}
	eq := api.EdgeQuery{}
	q.window(&eq)
	edges, err := q.src.Edges(ctx, host, eq)
	if err != nil {
		return nil, err
	}
	id := q.identity(ctx, host)
	var peers []string
	for i := range edges {
		e := &edges[i]
		local := b.node(id, name, host, true, e.Unit, e.Comm)
		peer := q.peerHost(ctx, host, e.RemoteAddr)
		if peer != host {
			peers = append(peers, peer)
		}
		if e.Direction == "out" {
			b.edge(local, b.nodeOf(q.serverOf(ctx, host, e)), e)
			continue
		}
		// The client side resolves the client process. The same edge is also
		// added when visiting the client, unless it is beyond the depth.
		for _, c := range q.clientsOf(ctx, host, e) {
			b.edge(b.nodeOf(c), local, e)
		}
	}
	return peers, nil
}

// WriteDOT renders the graph in Graphviz DOT.
func (g *Graph) WriteDOT(w io.Writer) error {
	var sb strings.Builder
	sb.WriteString("digraph shawk {\n  rankdir=LR;\n  node [shape=box, fontname=\"Helvetica\"];\n")
	hosts := map[string][]*GraphNode{}
	var order []string
	for _, n := range g.Nodes {
		if _, ok := hosts[n.Host]; !ok {
			order = append(order, n.Host)
		}
		hosts[n.Host] = append(hosts[n.Host], n)
	}
	for i, h := range order {
		ns := hosts[h]
		if len(ns) == 1 && !ns[0].Agent {
			fmt.Fprintf(&sb, "  %q [label=%q, style=dashed];\n", ns[0].ID, ns[0].Host)
			continue
		}
		fmt.Fprintf(&sb, "  subgraph cluster_%d {\n    label=%q;\n", i, h)
		for _, n := range ns {
			fmt.Fprintf(&sb, "    %q [label=%q];\n", n.ID, (&Node{Agent: n.Agent, Unit: n.Unit, Comm: n.Comm}).Process())
		}
		sb.WriteString("  }\n")
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&sb, "  %q -> %q [label=\"%s/%d\"];\n", e.From, e.To, e.Proto, e.Port)
	}
	sb.WriteString("}\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// WriteMermaid renders the graph as a Mermaid flowchart.
func (g *Graph) WriteMermaid(w io.Writer) error {
	var sb strings.Builder
	sb.WriteString("flowchart LR\n")
	ids := map[string]string{}
	for i, n := range g.Nodes {
		ids[n.ID] = fmt.Sprintf("n%d", i)
		label := strings.ReplaceAll(n.Label(), `"`, "'")
		if n.Agent {
			fmt.Fprintf(&sb, "  %s[\"%s\"]\n", ids[n.ID], label)
		} else {
			fmt.Fprintf(&sb, "  %s([\"%s\"])\n", ids[n.ID], label)
		}
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&sb, "  %s -->|%s/%d| %s\n", ids[e.From], e.Proto, e.Port, ids[e.To])
	}
	_, err := io.WriteString(w, sb.String())
	return err
}
