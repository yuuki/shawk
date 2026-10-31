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

// endpoint is a service that listened on an endpoint.
type endpoint struct {
	host     string // hosts.id
	service  string
	lastSeen time.Time
}

// resolver names the peers of edges (service.peer.name). It combines the
// endpoints and agent addresses read from PostgreSQL with those the
// connector has seen itself since, which may not be written yet.
type resolver struct {
	cidrs []namedPrefix

	mu sync.RWMutex
	// From shawk_v1.service_endpoints and shawk_v1.agent_addrs.
	dbEndpoints map[endpointKey][]endpoint
	dbAgents    map[netip.Addr][]string
	// Seen by this connector, with the time they were last seen.
	localEndpoints map[endpointKey]map[endpoint]time.Time
	localAgents    map[netip.Addr]map[string]time.Time
}

func newResolver(cidrs []namedPrefix) *resolver {
	return &resolver{
		cidrs:          cidrs,
		dbEndpoints:    map[endpointKey][]endpoint{},
		dbAgents:       map[netip.Addr][]string{},
		localEndpoints: map[endpointKey]map[endpoint]time.Time{},
		localAgents:    map[netip.Addr]map[string]time.Time{},
	}
}

// endpointRow is a row of shawk_v1.service_endpoints.
type endpointRow struct {
	key endpointKey
	endpoint
}

// agentAddrRow is a row of shawk_v1.agent_addrs.
type agentAddrRow struct {
	addr netip.Addr
	host string
}

// load replaces the endpoints and agent addresses read from PostgreSQL.
func (r *resolver) load(endpoints []endpointRow, agents []agentAddrRow) {
	eps := make(map[endpointKey][]endpoint, len(endpoints))
	for _, e := range endpoints {
		eps[e.key] = append(eps[e.key], e.endpoint)
	}
	ags := make(map[netip.Addr][]string, len(agents))
	for _, a := range agents {
		ags[a.addr] = append(ags[a.addr], a.host)
	}
	r.mu.Lock()
	r.dbEndpoints, r.dbAgents = eps, ags
	r.mu.Unlock()
}

// learn records the endpoints and addresses of a host seen in a request at
// now. Listeners on an unspecified address listen on every address of the
// host.
func (r *resolver) learn(b *hostBatch, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addEndpoint := func(k endpointKey, service string, t time.Time) {
		if service == "" {
			return
		}
		m := r.localEndpoints[k]
		if m == nil {
			m = map[endpoint]time.Time{}
			r.localEndpoints[k] = m
		}
		m[endpoint{host: b.key, service: service}] = t
	}
	for _, l := range b.listeners {
		svc := l.id.job()
		if !l.id.addr.IsUnspecified() {
			addEndpoint(endpointKey{l.id.addr, l.id.port, l.id.proto}, svc, now)
			continue
		}
		for _, a := range b.addrs {
			if l.id.addr.Is4() && !a.Is4() {
				continue
			}
			addEndpoint(endpointKey{a, l.id.port, l.id.proto}, svc, now)
		}
	}
	for _, e := range b.edges {
		if e.id.role == roleServer {
			addEndpoint(endpointKey{e.id.local, e.id.port, e.id.proto}, e.id.job(), now)
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

// expire forgets what was learned before t.
func (r *resolver) expire(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, m := range r.localEndpoints {
		for e, at := range m {
			if at.Before(t) {
				delete(m, e)
			}
		}
		if len(m) == 0 {
			delete(r.localEndpoints, k)
		}
	}
	for a, m := range r.localAgents {
		for h, at := range m {
			if at.Before(t) {
				delete(m, h)
			}
		}
		if len(m) == 0 {
			delete(r.localAgents, a)
		}
	}
}

// peerName names the peer of an edge of host.
func (r *resolver) peerName(host string, id *edgeID) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// A loopback peer is on the same host.
	sameHost := id.peer.IsLoopback()
	if id.role == roleClient {
		if svc := r.service(host, endpointKey{id.peer, id.port, id.proto}, sameHost); svc != "" {
			return svc
		}
	} else if sameHost || r.isAgent(id.peer) {
		// The client side of the edge is recorded by its own agent.
		return peerAgent
	}
	return r.classify(id.peer)
}

// service returns the service listening on an endpoint. An endpoint of the
// host itself is preferred, then the most recently seen one.
func (r *resolver) service(host string, k endpointKey, sameHostOnly bool) string {
	var best endpoint
	consider := func(e endpoint) {
		if sameHostOnly && e.host != host {
			return
		}
		switch {
		case best.service == "":
			best = e
		case (e.host == host) != (best.host == host):
			if e.host == host {
				best = e
			}
		case e.lastSeen.After(best.lastSeen):
			best = e
		}
	}
	for e, at := range r.localEndpoints[k] {
		e.lastSeen = at
		consider(e)
	}
	for _, e := range r.dbEndpoints[k] {
		consider(e)
	}
	return best.service
}

func (r *resolver) isAgent(a netip.Addr) bool {
	return len(r.localAgents[a]) > 0 || len(r.dbAgents[a]) > 0
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
