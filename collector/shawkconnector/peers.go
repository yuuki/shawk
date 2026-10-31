package shawkconnector

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// endpointKey is a service endpoint: an address and port a server accepts
// connections on.
type endpointKey struct {
	addr  netip.Addr
	port  uint16
	proto string
}

// clientKey identifies the client side of connections as their server
// sees it: the client address, the server address and the service port.
type clientKey struct {
	client, server netip.Addr
	port           uint16
	proto          string
}

// endpoint is a service seen on an endpoint, or a client service seen on
// the client side of connections.
type endpoint struct {
	host     string // hosts.id
	service  string
	lastSeen time.Time
}

// peer is the name of the peer of an edge.
type peer struct {
	name string // service.peer.name
	// agent tells whether the peer runs on a host with an agent, which then
	// records the other side of the edge (shawk.peer.agent).
	agent bool
}

// resolver names the peers of edges. It combines the endpoints, clients and
// agent addresses read from PostgreSQL with those the connector has seen
// itself since, which may not be written yet.
type resolver struct {
	cidrs []namedPrefix

	mu sync.RWMutex
	// From shawk_v1.service_endpoints, shawk_v1.client_endpoints and
	// shawk_v1.agent_addrs.
	dbEndpoints map[endpointKey][]endpoint
	dbClients   map[clientKey][]endpoint
	dbAgents    map[netip.Addr][]string
	// Seen by this connector, with the time they were last seen.
	localEndpoints map[endpointKey]map[endpoint]time.Time
	localClients   map[clientKey]map[endpoint]time.Time
	localAgents    map[netip.Addr]map[string]time.Time
}

func newResolver(cidrs []namedPrefix) *resolver {
	return &resolver{
		cidrs:          cidrs,
		dbEndpoints:    map[endpointKey][]endpoint{},
		dbClients:      map[clientKey][]endpoint{},
		dbAgents:       map[netip.Addr][]string{},
		localEndpoints: map[endpointKey]map[endpoint]time.Time{},
		localClients:   map[clientKey]map[endpoint]time.Time{},
		localAgents:    map[netip.Addr]map[string]time.Time{},
	}
}

// endpointRow is a row of shawk_v1.service_endpoints.
type endpointRow struct {
	key endpointKey
	endpoint
}

// clientRow is a row of shawk_v1.client_endpoints.
type clientRow struct {
	key clientKey
	endpoint
}

// agentAddrRow is a row of shawk_v1.agent_addrs.
type agentAddrRow struct {
	addr netip.Addr
	host string
}

// peerRows are the rows the resolver loads from PostgreSQL.
type peerRows struct {
	endpoints []endpointRow
	clients   []clientRow
	agents    []agentAddrRow
}

// load replaces what was read from PostgreSQL.
func (r *resolver) load(rows peerRows) {
	eps := make(map[endpointKey][]endpoint, len(rows.endpoints))
	for _, e := range rows.endpoints {
		eps[e.key] = append(eps[e.key], e.endpoint)
	}
	cls := make(map[clientKey][]endpoint, len(rows.clients))
	for _, c := range rows.clients {
		cls[c.key] = append(cls[c.key], c.endpoint)
	}
	ags := make(map[netip.Addr][]string, len(rows.agents))
	for _, a := range rows.agents {
		ags[a.addr] = append(ags[a.addr], a.host)
	}
	r.mu.Lock()
	r.dbEndpoints, r.dbClients, r.dbAgents = eps, cls, ags
	r.mu.Unlock()
}

func learnInto[K comparable](m map[K]map[endpoint]time.Time, k K, host, service string, now time.Time) {
	if service == "" {
		return
	}
	es := m[k]
	if es == nil {
		es = map[endpoint]time.Time{}
		m[k] = es
	}
	es[endpoint{host: host, service: service}] = now
}

// learn records the endpoints, clients and addresses of a host seen in a
// request at now. Listeners on an unspecified address listen on every
// address of the host.
func (r *resolver) learn(b *hostBatch, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range b.listeners {
		svc := l.id.job()
		if !l.id.addr.IsUnspecified() {
			learnInto(r.localEndpoints, endpointKey{l.id.addr, l.id.port, l.id.proto}, b.key, svc, now)
			continue
		}
		for _, a := range b.addrs {
			if l.id.addr.Is4() && !a.Is4() {
				continue
			}
			learnInto(r.localEndpoints, endpointKey{a, l.id.port, l.id.proto}, b.key, svc, now)
		}
	}
	for _, e := range b.edges {
		switch e.id.role {
		case roleServer:
			learnInto(r.localEndpoints, endpointKey{e.id.local, e.id.port, e.id.proto}, b.key, e.id.job(), now)
		case roleClient:
			learnInto(r.localClients, clientKey{e.id.local, e.id.peer, e.id.port, e.id.proto}, b.key, e.id.job(), now)
		}
	}
	for _, a := range b.addrs {
		m := r.localAgents[a]
		if m == nil {
			m = map[string]time.Time{}
			r.localAgents[a] = m
		}
		m[b.key] = now
	}
}

func expireLearned[K comparable, V comparable](m map[K]map[V]time.Time, t time.Time) {
	for k, es := range m {
		for e, at := range es {
			if at.Before(t) {
				delete(es, e)
			}
		}
		if len(es) == 0 {
			delete(m, k)
		}
	}
}

// expire forgets what was learned before t.
func (r *resolver) expire(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	expireLearned(r.localEndpoints, t)
	expireLearned(r.localClients, t)
	expireLearned(r.localAgents, t)
}

// peer names the peer of an edge of host.
//
// The peer of a client edge is the service listening on the peer address
// and port. The peer of a server edge is the client service whose client
// edge has the same addresses and port. A peer without a known service is
// named after its address range.
//
// A loopback peer is on the host itself. So is a peer whose address several
// live hosts hold at once, such as the address of a container bridge, when
// the host holds it too; such an address is never resolved to another host.
func (r *resolver) peer(host string, id *edgeID) peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hosts := r.hostsOf(id.peer)
	shared := len(hosts) > 1
	local := id.peer.IsLoopback() || (shared && hosts[host])
	sameHostOnly := id.peer.IsLoopback() || shared
	p := peer{agent: local || (!shared && len(hosts) > 0)}
	if id.role == roleClient {
		k := endpointKey{id.peer, id.port, id.proto}
		p.name = best(host, r.localEndpoints[k], r.dbEndpoints[k], sameHostOnly)
	} else {
		k := clientKey{id.peer, id.local, id.port, id.proto}
		p.name = best(host, r.localClients[k], r.dbClients[k], sameHostOnly)
	}
	if p.name == "" {
		p.name = r.classify(id.peer)
	}
	return p
}

// best returns the service of the best candidate: one on the host itself,
// then the most recently seen one.
func best(host string, local map[endpoint]time.Time, db []endpoint, sameHostOnly bool) string {
	var b endpoint
	consider := func(e endpoint) {
		if sameHostOnly && e.host != host {
			return
		}
		switch {
		case b.service == "":
			b = e
		case (e.host == host) != (b.host == host):
			if e.host == host {
				b = e
			}
		case e.lastSeen.After(b.lastSeen):
			b = e
		}
	}
	for e, at := range local {
		e.lastSeen = at
		consider(e)
	}
	for _, e := range db {
		consider(e)
	}
	return b.service
}

// hostsOf returns the live hosts with agents that hold an address.
func (r *resolver) hostsOf(a netip.Addr) map[string]bool {
	var hosts map[string]bool
	add := func(h string) {
		if hosts == nil {
			hosts = map[string]bool{}
		}
		hosts[h] = true
	}
	for h := range r.localAgents[a] {
		add(h)
	}
	for _, h := range r.dbAgents[a] {
		add(h)
	}
	return hosts
}

// classify names a peer without a known service from its address.
func (r *resolver) classify(a netip.Addr) string {
	for _, p := range r.cidrs {
		if p.prefix.Contains(a) {
			return p.name
		}
	}
	if isPrivate(a) {
		return peerUnresolved
	}
	return peerExternal
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPrivate tells whether an address is not routed on the Internet:
// loopback, link-local, RFC 1918, CGNAT and IPv6 ULA.
func isPrivate(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a) || a.IsUnspecified()
}

// sortPrefixes orders prefixes from the narrowest.
func sortPrefixes(ps []namedPrefix) {
	slices.SortStableFunc(ps, func(a, b namedPrefix) int {
		if a.prefix.Bits() != b.prefix.Bits() {
			return b.prefix.Bits() - a.prefix.Bits()
		}
		return a.prefix.Addr().Compare(b.prefix.Addr())
	})
}
