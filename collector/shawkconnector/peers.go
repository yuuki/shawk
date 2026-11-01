package shawkconnector

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// aliveWindow is how long an agent may be silent and still count as alive;
// it matches shawk.alive_window() in PostgreSQL.
const aliveWindow = 5 * time.Minute

// shareWindow is how close in time two hosts must have reported an address
// for the address to count as held by both at once. An address whose
// former holder stopped reporting it earlier has moved, e.g. to a renamed
// or rebuilt host.
const shareWindow = 3 * time.Minute

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
	host    string // hosts.id
	service string
	// exact is true when the address was observed on a socket, and false
	// when it is an address of the host that a listener on an unspecified
	// address may serve.
	exact    bool
	lastSeen time.Time
}

// agentHost is what is known of the agent of a host.
type agentHost struct {
	seen      time.Time // by the clock of the connector
	udpTraced bool      // UDP edges are recorded only if UDP is traced
}

// covers tells whether the agent records the edges of a protocol. An agent
// that traces one network namespace reports the addresses of that
// namespace only, so the peers at its addresses are traced.
func (h agentHost) covers(proto string) bool {
	return proto != "udp" || h.udpTraced
}

// peer is the name of the peer of an edge.
type peer struct {
	name string // service.peer.name
	// agent tells whether the peer runs on a host whose agent records the
	// other side of the edge (shawk.peer.agent).
	agent bool
}

// resolver names the peers of edges. It combines the endpoints, clients and
// agents read from PostgreSQL with those the connector has seen itself
// since, which may not be written yet.
type resolver struct {
	cidrs []namedPrefix

	mu sync.RWMutex
	// From shawk_v1.service_endpoints, shawk_v1.client_endpoints and
	// shawk_v1.agent_addrs, read at loaded. Their times are judged as of
	// loaded: while the database cannot be read, the agents and addresses
	// it knew keep the age they had then, rather than all expiring.
	loaded      time.Time
	dbEndpoints map[endpointKey][]endpoint
	dbClients   map[clientKey][]endpoint
	dbAddrs     map[netip.Addr]map[string]time.Time // address -> host -> last seen
	dbAgents    map[string]agentHost
	// Seen by this connector, with the time they were last seen.
	localEndpoints map[endpointKey]map[endpoint]time.Time
	localClients   map[clientKey]map[endpoint]time.Time
	localAddrs     map[netip.Addr]map[string]time.Time
	localAgents    map[string]agentHost
}

func newResolver(cidrs []namedPrefix) *resolver {
	return &resolver{
		cidrs:          cidrs,
		dbEndpoints:    map[endpointKey][]endpoint{},
		dbClients:      map[clientKey][]endpoint{},
		dbAddrs:        map[netip.Addr]map[string]time.Time{},
		dbAgents:       map[string]agentHost{},
		localEndpoints: map[endpointKey]map[endpoint]time.Time{},
		localClients:   map[clientKey]map[endpoint]time.Time{},
		localAddrs:     map[netip.Addr]map[string]time.Time{},
		localAgents:    map[string]agentHost{},
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

// agentAddrRow is a row of shawk_v1.agent_addrs: an address of a host
// last seen at seen, and its agent.
type agentAddrRow struct {
	addr netip.Addr
	host string
	seen time.Time
	// agent.seen is the last heartbeat of the agent.
	agent agentHost
}

// peerRows are the rows the resolver loads from PostgreSQL.
type peerRows struct {
	endpoints []endpointRow
	clients   []clientRow
	agents    []agentAddrRow
}

// load replaces what was read from PostgreSQL at now.
func (r *resolver) load(rows peerRows, now time.Time) {
	eps := make(map[endpointKey][]endpoint, len(rows.endpoints))
	for _, e := range rows.endpoints {
		eps[e.key] = append(eps[e.key], e.endpoint)
	}
	cls := make(map[clientKey][]endpoint, len(rows.clients))
	for _, c := range rows.clients {
		cls[c.key] = append(cls[c.key], c.endpoint)
	}
	addrs := make(map[netip.Addr]map[string]time.Time, len(rows.agents))
	agents := map[string]agentHost{}
	for _, a := range rows.agents {
		m := addrs[a.addr]
		if m == nil {
			m = map[string]time.Time{}
			addrs[a.addr] = m
		}
		m[a.host] = a.seen
		if cur, ok := agents[a.host]; !ok || a.agent.seen.After(cur.seen) {
			agents[a.host] = a.agent
		}
	}
	r.mu.Lock()
	r.loaded = now
	r.dbEndpoints, r.dbClients, r.dbAddrs, r.dbAgents = eps, cls, addrs, agents
	r.mu.Unlock()
}

// dbAge is how long ago what was read from PostgreSQL was read, which is
// added to its times.
func (r *resolver) dbAge(now time.Time) time.Duration {
	if r.loaded.IsZero() || now.Before(r.loaded) {
		return 0
	}
	return now.Sub(r.loaded)
}

func learnInto[K comparable](m map[K]map[endpoint]time.Time, k K, e endpoint, now time.Time) {
	// A socket without a known owner names no service; PostgreSQL does not
	// keep it as an endpoint either.
	if e.service == "" || e.service == unknownService {
		return
	}
	es := m[k]
	if es == nil {
		es = map[endpoint]time.Time{}
		m[k] = es
	}
	es[e] = now
}

// learn records the endpoints, clients and addresses of a host seen in a
// request at now. Listeners on an unspecified address listen on every
// address of the host. The host holds its addresses, and its agent is
// alive, only as of a request that closes an interval: an agent whose
// last requests do not arrive emits nothing for its host.
func (r *resolver) learn(b *hostBatch, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range b.listeners {
		svc := l.id.job()
		if !l.id.addr.IsUnspecified() {
			learnInto(r.localEndpoints, endpointKey{l.id.addr, l.id.port, l.id.proto},
				endpoint{host: b.key, service: svc, exact: true}, now)
			continue
		}
		for _, a := range b.addrs {
			if l.id.addr.Is4() && !a.Is4() {
				continue
			}
			learnInto(r.localEndpoints, endpointKey{a, l.id.port, l.id.proto}, endpoint{host: b.key, service: svc}, now)
		}
	}
	for _, e := range b.edges {
		switch e.id.role {
		case roleServer:
			learnInto(r.localEndpoints, endpointKey{e.id.local, e.id.port, e.id.proto},
				endpoint{host: b.key, service: e.id.job(), exact: true}, now)
		case roleClient:
			learnInto(r.localClients, clientKey{e.id.local, e.id.peer, e.id.port, e.id.proto},
				endpoint{host: b.key, service: e.id.job(), exact: true}, now)
		}
	}
	if !b.final {
		return
	}
	for _, a := range b.addrs {
		m := r.localAddrs[a]
		if m == nil {
			m = map[string]time.Time{}
			r.localAddrs[a] = m
		}
		m[b.key] = now
	}
	r.localAgents[b.key] = agentHost{seen: now, udpTraced: b.udpTraced}
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

// expire forgets endpoints and clients learned before t, and addresses and
// agents not seen within the alive window before now.
func (r *resolver) expire(t, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	expireLearned(r.localEndpoints, t)
	expireLearned(r.localClients, t)
	expireLearned(r.localAddrs, now.Add(-aliveWindow))
	for h, a := range r.localAgents {
		if a.seen.Before(now.Add(-aliveWindow)) {
			delete(r.localAgents, h)
		}
	}
}

// peer names the peer of an edge of host at now.
//
// The peer of a client edge is the service listening on the peer address
// and port. The peer of a server edge is the client service whose client
// edge has the same addresses and port. A peer without a known service is
// named after its address range.
//
// A loopback peer is on the host itself. So is a peer whose address several
// live hosts hold at once, such as the address of a container bridge, when
// the host holds it too; such an address is never resolved to another host.
func (r *resolver) peer(host string, id *edgeID, now time.Time) peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	holders := r.holders(id.peer, now)
	shared := len(holders) > 1
	loopback := id.peer.IsLoopback()
	local := loopback || (shared && holders[host])
	sameHostOnly := loopback || shared

	var p peer
	switch {
	case local:
		// The host itself runs an agent; before its first complete interval
		// what it traces is not known yet.
		p.agent = true
		if a, ok := r.agent(host, now); ok {
			p.agent = a.covers(id.proto)
		}
	case len(holders) == 1:
		for h := range holders {
			if a, ok := r.agent(h, now); ok {
				p.agent = a.covers(id.proto)
			}
		}
	}
	if id.role == roleClient {
		k := endpointKey{id.peer, id.port, id.proto}
		p.name = best(host, r.localEndpoints[k], r.dbEndpoints[k], r.dbAge(now), sameHostOnly)
	} else {
		k := clientKey{id.peer, id.local, id.port, id.proto}
		p.name = best(host, r.localClients[k], r.dbClients[k], r.dbAge(now), sameHostOnly)
	}
	if p.name == "" {
		p.name = r.classify(id.peer)
	}
	return p
}

// holders returns the hosts with live agents that hold an address now. A
// host that last reported the address well before another one did no
// longer holds it.
func (r *resolver) holders(a netip.Addr, now time.Time) map[string]bool {
	seen := map[string]time.Time{}
	var newest time.Time
	add := func(h string, t time.Time) {
		if t.Before(now.Add(-aliveWindow)) {
			return
		}
		if t.After(seen[h]) {
			seen[h] = t
		}
		if t.After(newest) {
			newest = t
		}
	}
	for h, t := range r.localAddrs[a] {
		add(h, t)
	}
	age := r.dbAge(now)
	for h, t := range r.dbAddrs[a] {
		add(h, t.Add(age))
	}
	var out map[string]bool
	for h, t := range seen {
		if t.Before(newest.Add(-shareWindow)) {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[h] = true
	}
	return out
}

// agent returns the latest known agent of a host, if it is alive.
func (r *resolver) agent(host string, now time.Time) (agentHost, bool) {
	a, ok := r.localAgents[host]
	if d, dok := r.dbAgents[host]; dok {
		d.seen = d.seen.Add(r.dbAge(now))
		if !ok || d.seen.After(a.seen) {
			a, ok = d, true
		}
	}
	if !ok || a.seen.Before(now.Add(-aliveWindow)) {
		return agentHost{}, false
	}
	return a, true
}

// best returns the service of the best candidate: one on the host itself,
// then one observed on a socket rather than inferred from a listener on an
// unspecified address, then the most recently seen one, then the first by
// name, so that the choice does not depend on the order of maps.
func best(host string, local map[endpoint]time.Time, db []endpoint, dbAge time.Duration, sameHostOnly bool) string {
	var b endpoint
	better := func(e endpoint) bool {
		switch {
		case b.service == "":
			return true
		case (e.host == host) != (b.host == host):
			return e.host == host
		case e.exact != b.exact:
			return e.exact
		case !e.lastSeen.Equal(b.lastSeen):
			return e.lastSeen.After(b.lastSeen)
		}
		return strings.Compare(e.service, b.service) < 0
	}
	consider := func(e endpoint) {
		if sameHostOnly && e.host != host {
			return
		}
		if better(e) {
			b = e
		}
	}
	for e, at := range local {
		e.lastSeen = at
		consider(e)
	}
	for _, e := range db {
		e.lastSeen = e.lastSeen.Add(dbAge)
		consider(e)
	}
	return b.service
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
