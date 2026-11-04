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
	name      string    // of the host
	// fold is what the agent folds (foldNone, foldIn, foldAll; empty if not
	// known), and internal the ranges of peers it keeps exact.
	fold     string
	internal []netip.Prefix
}

// covers tells whether the agent records the edges of a protocol. An agent
// that traces one network namespace reports the addresses of that
// namespace only, so the peers at its addresses are traced.
func (h agentHost) covers(proto string) bool {
	return proto != "udp" || h.udpTraced
}

// foldsClient tells whether the agent folds a client at an address into
// its external peers: whether it folds the peers of its servers and the
// address is outside the ranges it keeps exact.
func (h agentHost) foldsClient(a netip.Addr) bool {
	return (h.fold == foldIn || h.fold == foldAll) && !h.keeps(a)
}

// foldsServer tells whether the agent folds a server at an address into
// its external peers: whether it folds the peers of its clients too and
// the address is outside the ranges it keeps exact.
func (h agentHost) foldsServer(a netip.Addr) bool {
	return h.fold == foldAll && !h.keeps(a)
}

// keepsRange tells whether every address of a range is in a range the agent
// keeps exact.
func (h agentHost) keepsRange(r netip.Prefix) bool {
	for _, p := range h.internal {
		if p.Bits() <= r.Bits() && p.Contains(r.Addr()) {
			return true
		}
	}
	return false
}

// keeps tells whether an address is in a range the agent keeps exact.
func (h agentHost) keeps(a netip.Addr) bool {
	for _, p := range h.internal {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peer is the name of the peer of an edge.
type peer struct {
	name string // service.peer.name
	// agent tells whether the peer runs on a host whose agent records the
	// other side of the edge (shawk.peer.agent).
	agent bool
	// foldedBy is set on an edge whose peer runs an agent that folds this
	// side into its external peers although it runs an agent too: the edges
	// of the two sides do not match. It is the host of the peer and its
	// name. On a client edge, the server folds its client: both sides count
	// the connections (§7). On a server edge (foldsServer), the client folds
	// its server, so its client edge names no service: agent is false, so
	// that this side counts them.
	foldedBy, foldedByName string
	foldsServer            bool
	// foldedVirtual is set when the agent of the client folds the virtual
	// address of a translation through which it reaches this server, rather
	// than the address of the server.
	foldedVirtual netip.Addr
	// port is the port of the server, when the peer of a client edge is
	// named through a translation whose backend has another port than the
	// one the client connected to; 0 otherwise.
	port uint16
	// server is the address of the server, when the peer of a client edge
	// is named through a translation; invalid otherwise.
	server netip.Addr
}

// resolver names the peers of edges. It combines the endpoints, clients and
// agents read from PostgreSQL with those the connector has seen itself
// since, which may not be written yet.
type resolver struct {
	cidrs []namedPrefix
	// translations are those of the configuration, and virtuals their
	// virtual addresses, with port 0 for every port.
	translations []translation
	virtuals     map[endpointKey]*translation

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
	// The learned translations, by their client side and, for those that
	// keep the address of the client, by their server side, with when they
	// were last seen: read from PostgreSQL (by the clock of the agents, as
	// of loaded) and seen by this connector.
	dbLearned           map[learnedClientKey]map[learnedBackend]time.Time
	dbLearnedServers    map[learnedServerKey]map[learnedClient]time.Time
	localLearned        map[learnedClientKey]map[learnedBackend]time.Time
	localLearnedServers map[learnedServerKey]map[learnedClient]time.Time
	// localServed are the services of the server edges this connector saw,
	// by their client address, server address and port: whether a client
	// reached a relay with an agent at a virtual address, as direct tells
	// in PostgreSQL.
	localServed map[clientKey]map[endpoint]time.Time
	// inferred counts the endpoints of localEndpoints inferred from the
	// listeners of each host on unspecified addresses, one per address of
	// the host and port. maxInferred bounds them per host, and those a
	// request infers (0: unbounded); the others are named from PostgreSQL
	// after its next load.
	inferred    map[string]int
	maxInferred int

	// rangeCache holds the best service on the endpoints within a range of
	// backends, found by a scan of the endpoints, until the next load or
	// expiry.
	rangeMu    sync.Mutex
	rangeCache map[rangeKey][]candidate
}

// rangeKey is a range of addresses of backends, on a port.
type rangeKey struct {
	prefix netip.Prefix
	port   uint16
	proto  string
}

func newResolver(cidrs []namedPrefix, translations []translation) *resolver {
	virtuals := map[endpointKey]*translation{}
	for i := range translations {
		t := &translations[i]
		for _, v := range t.virtual {
			for _, proto := range t.protos {
				virtuals[endpointKey{v.Addr(), v.Port(), proto}] = t
			}
		}
	}
	return &resolver{
		cidrs:          cidrs,
		translations:   translations,
		virtuals:       virtuals,
		rangeCache:     map[rangeKey][]candidate{},
		dbEndpoints:    map[endpointKey][]endpoint{},
		dbClients:      map[clientKey][]endpoint{},
		dbAddrs:        map[netip.Addr]map[string]time.Time{},
		dbAgents:       map[string]agentHost{},
		localEndpoints: map[endpointKey]map[endpoint]time.Time{},
		localClients:   map[clientKey]map[endpoint]time.Time{},
		localAddrs:     map[netip.Addr]map[string]time.Time{},
		localAgents:    map[string]agentHost{},

		dbLearned:           map[learnedClientKey]map[learnedBackend]time.Time{},
		dbLearnedServers:    map[learnedServerKey]map[learnedClient]time.Time{},
		localLearned:        map[learnedClientKey]map[learnedBackend]time.Time{},
		localLearnedServers: map[learnedServerKey]map[learnedClient]time.Time{},
		localServed:         map[clientKey]map[endpoint]time.Time{},
		inferred:            map[string]int{},
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
	learned   []learnedRow
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
	learned, learnedServers := loadLearned(rows.learned)
	r.mu.Lock()
	r.loaded = now
	r.dbEndpoints, r.dbClients, r.dbAddrs, r.dbAgents = eps, cls, addrs, agents
	r.dbLearned, r.dbLearnedServers = learned, learnedServers
	r.clearRanges()
	r.mu.Unlock()
}

// clearRanges forgets the services found within ranges of backends.
func (r *resolver) clearRanges() {
	r.rangeMu.Lock()
	clear(r.rangeCache)
	r.rangeMu.Unlock()
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
	budget := r.maxInferred
	for _, l := range b.listeners {
		svc := l.id.job()
		if !l.id.addr.IsUnspecified() {
			learnInto(r.localEndpoints, endpointKey{l.id.addr, l.id.port, l.id.proto},
				endpoint{host: b.key, service: svc, exact: true}, now)
			continue
		}
		for _, a := range b.addrs {
			if r.maxInferred > 0 {
				if budget == 0 {
					break
				}
				budget--
			}
			if l.id.addr.Is4() && !a.Is4() {
				continue
			}
			r.infer(endpointKey{a, l.id.port, l.id.proto}, endpoint{host: b.key, service: svc}, now)
		}
	}
	for _, e := range b.edges {
		switch e.id.role {
		case roleServer:
			learnInto(r.localEndpoints, endpointKey{e.id.local, e.id.port, e.id.proto},
				endpoint{host: b.key, service: e.id.job(), exact: true}, now)
			if !e.id.folded {
				learnInto(r.localServed, clientKey{e.id.peer, e.id.local, e.id.port, e.id.proto},
					endpoint{host: b.key, service: e.id.job(), exact: true}, now)
			}
		case roleClient:
			if e.id.folded {
				// Not a server address: no server edge has it as its local
				// address.
				continue
			}
			learnInto(r.localClients, clientKey{e.id.local, e.id.peer, e.id.port, e.id.proto},
				endpoint{host: b.key, service: e.id.job(), exact: true}, now)
		}
	}
	for _, x := range b.translations {
		// The agent sends a translation for its idle TTL after its last use:
		// it was last seen as long before now as before the request, by the
		// clock of the agent.
		at := now
		if !x.last.IsZero() && !b.time.IsZero() && x.last.Before(b.time) {
			at = now.Add(x.last.Sub(b.time))
		}
		learnTranslation(b.key, x.id, at, r.localLearned, r.localLearnedServers)
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
	r.localAgents[b.key] = agentHost{seen: now, udpTraced: b.udpTraced, name: b.hostname,
		fold: b.peerFold, internal: b.peerInternal}
}

// infer learns an endpoint inferred from a listener on an unspecified
// address, unless its host holds maxInferred of them already. r.mu is held.
func (r *resolver) infer(k endpointKey, e endpoint, now time.Time) {
	if e.service == "" || e.service == unknownService {
		return
	}
	if _, ok := r.localEndpoints[k][e]; !ok {
		if r.maxInferred > 0 && r.inferred[e.host] >= r.maxInferred {
			return
		}
		r.inferred[e.host]++
	}
	learnInto(r.localEndpoints, k, e, now)
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
	for k, es := range r.localEndpoints {
		for e, at := range es {
			if !at.Before(t) {
				continue
			}
			delete(es, e)
			if !e.exact {
				if r.inferred[e.host]--; r.inferred[e.host] <= 0 {
					delete(r.inferred, e.host)
				}
			}
		}
		if len(es) == 0 {
			delete(r.localEndpoints, k)
		}
	}
	expireLearned(r.localClients, t)
	expireLearned(r.localLearned, t)
	expireLearned(r.localLearnedServers, t)
	expireLearned(r.localServed, t)
	expireLearned(r.localAddrs, now.Add(-aliveWindow))
	for h, a := range r.localAgents {
		if a.seen.Before(now.Add(-aliveWindow)) {
			delete(r.localAgents, h)
		}
	}
	r.clearRanges()
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
// A peer whose address one live host holds alone is resolved to that host
// only (see holderOf).
//
// A folded peer, every peer outside the internal ranges of the agent, is
// named after its network and has no agent.
//
// A peer without a known service may be reached through a translation: the
// peer of a client edge to a virtual address is the service at a backend,
// on the port of the backend, and its agent records the other side; the
// peer of a server edge at a backend of a translation that keeps the
// address of the client is the client service whose client edge to a
// virtual address has the address of the client. Behind a translation with
// sources, the server sees the relay, which is named after its address.
func (r *resolver) peer(host string, id *edgeID, now time.Time) peer {
	if id.folded {
		return peer{name: r.classifyFolded(id.peer)}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	holders := r.holders(id.peer, now)
	shared := len(holders) > 1
	loopback := id.peer.IsLoopback()
	local := loopback || (shared && holders[host])
	sameHostOnly := loopback || shared
	// rules choose among the services and clients seen at the address of
	// the peer.
	rules := chooser{host: host, sameHostOnly: sameHostOnly}

	var p peer
	// covers tells whether the agent of the peer records the other side,
	// unless it folds this one.
	var covers bool
	switch {
	case local:
		// The host itself runs an agent; before its first complete interval
		// what it traces is not known yet.
		p.agent = true
		if a, ok := r.agent(host, now); ok {
			p.agent = a.covers(id.proto)
		}
		covers = p.agent
	case len(holders) == 1:
		for h := range holders {
			rules.holder = h
			if a, ok := r.agent(h, now); ok {
				p.agent = a.covers(id.proto)
				covers = p.agent
				switch {
				case !p.agent || h == host:
				case id.role == roleClient && r.foldsPeer(a, h, id.local, false, now):
					p.foldedBy, p.foldedByName = h, a.name
				case id.role == roleServer:
					// Through a translation, the client connects to a virtual
					// address, which its agent may fold.
					v, through := r.foldedVirtual(a, h, id, now)
					if !through && !r.foldsPeer(a, h, id.local, true, now) {
						break
					}
					p.agent = false
					p.foldedBy, p.foldedByName, p.foldsServer, p.foldedVirtual = h, a.name, true, v
				}
			}
		}
	}
	if id.role == roleClient {
		k := endpointKey{id.peer, id.port, id.proto}
		c := rules
		learned := r.virtualOf(id) == nil && len(r.learnedOf(host, id, now)) > 0
		if r.virtualOf(id) != nil || learned {
			// At a virtual address, only a service observed on a socket at it
			// recently, such as a relay that runs an agent, comes before the
			// backends: a listener on an unspecified address of a host that
			// holds the address may be bypassed (DNAT), and a server edge of
			// days ago replaced by a relay without an agent.
			c.exactSince = now.Add(-aliveWindow)
		}
		if learned {
			// Through a learned translation, only a service whose server edge
			// from this client this connector saw recently comes first, as a
			// match by address does in PostgreSQL: a container that reaches a
			// published port of its host goes through docker-proxy, which
			// serves the address, while the clients of other hosts go to the
			// container.
			c.add(r.localServed[clientKey{id.local, id.peer, id.port, id.proto}], nil, 0, 0)
		} else {
			c.add(r.localEndpoints[k], r.dbEndpoints[k], r.dbAge(now), 0)
		}
		p.name = c.best.service
		if p.name == "" {
			if c, t, ok := r.translatedServer(id, now); ok {
				// The holder of the virtual address, if any, is not the server.
				p = peer{name: c.service, agent: c.agent, server: c.addr}
				if c.port != id.port {
					p.port = c.port
				}
				// Through a translation without sources the backend sees the
				// address of the client, which its agent may fold.
				if a, ok := r.agent(c.host, now); ok && c.agent && c.host != host && len(t.sources) == 0 &&
					r.foldsPeer(a, c.host, id.local, false, now) {
					p.foldedBy, p.foldedByName = c.host, a.name
				}
			} else if !learned {
			} else if c, ok := r.learnedServer(host, id, now); ok {
				p = peer{name: c.service, agent: c.agent, server: c.addr}
				if c.port != id.port {
					p.port = c.port
				}
				if a, ok := r.agent(c.host, now); ok && c.agent && c.host != host && c.dnat &&
					r.foldsPeer(a, c.host, id.local, false, now) {
					p.foldedBy, p.foldedByName = c.host, a.name
				}
			}
		}
	} else {
		k := clientKey{id.peer, id.local, id.port, id.proto}
		c := rules
		c.add(r.localClients[k], r.dbClients[k], r.dbAge(now), 0)
		p.name = c.best.service
		if p.name == "" {
			if p.name = r.translatedClient(rules, id, now); p.name != "" {
				// The client connected to the virtual address, which its agent
				// keeps exact, whatever it does with the address of this host.
				p.agent = covers
				p.foldedBy, p.foldedByName, p.foldsServer, p.foldedVirtual = "", "", false, netip.Addr{}
			} else if r.behindRelay(id) {
				// The server sees a relay that replaces the addresses of its
				// clients: an agent at the address of the relay records none of
				// them, so this side counts the connections.
				p.agent = false
				p.foldedBy, p.foldedByName, p.foldsServer, p.foldedVirtual = "", "", false, netip.Addr{}
			} else if p.name = r.learnedClientName(host, id, rules.holder, now); p.name != "" {
				// As through a static translation without sources. A learned
				// SNAT keeps its name: the source forwards several clients.
				p.agent = covers
				p.foldedBy, p.foldedByName, p.foldsServer, p.foldedVirtual = "", "", false, netip.Addr{}
			}
		}
	}
	if p.name == "" {
		p.name = r.classify(id.peer)
	}
	return p
}

// foldsPeer tells whether the agent a of the host peer folds this side, at
// the address local, into its external peers: a client if a is the agent of
// its server, a server if it is that of its client (server). A loopback
// address, and one that several hosts or peer itself hold, never reaches it
// from outside. r.mu is held.
func (r *resolver) foldsPeer(a agentHost, peer string, local netip.Addr, server bool, now time.Time) bool {
	if !local.IsValid() || local.IsLoopback() || local.IsUnspecified() {
		return false
	}
	if server && !a.foldsServer(local) || !server && !a.foldsClient(local) {
		return false
	}
	hs := r.holders(local, now)
	return len(hs) <= 1 && !hs[peer]
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

// holderOf returns the live host that alone holds a non-loopback address
// now, or "" if no live host or several hosts hold it. The services and
// clients that other hosts report at such an address do not name peers.
// The connector cannot check that a host holds the addresses its agent
// reports, but an agent reports in host.ip the addresses of its listeners
// and of its recent edges, so two hosts that both have sockets at an address
// both hold it, and the address is shared. What another host reports at
// the address is then a socket it no longer has, such as an idle server
// edge at a virtual address that moved to another host, or a socket its
// agent made up. r.mu is held.
func (r *resolver) holderOf(a netip.Addr, now time.Time) string {
	if a.IsLoopback() {
		return ""
	}
	hs := r.holders(a, now)
	if len(hs) != 1 {
		return ""
	}
	for h := range hs {
		return h
	}
	return ""
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

// chooser picks the best of the services seen on endpoints: one on the
// host itself, then one observed on a socket rather than inferred from a
// listener on an unspecified address, then the most recently seen one, then
// the first by name, port and host, so that the choice does not depend on
// the order of maps.
type chooser struct {
	host string
	// sameHostOnly leaves out the endpoints of other hosts.
	sameHostOnly bool
	// holder, if set, is the live host that alone holds the address of the
	// endpoints (holderOf): the endpoints of every other host are left
	// out, even those of host.
	holder string
	// exactSince, if set, leaves out the endpoints inferred from listeners
	// on unspecified addresses and those last seen before it.
	exactSince time.Time
	best       endpoint
	port       uint16 // of the best endpoint
}

func (c *chooser) better(e endpoint, port uint16) bool {
	b := c.best
	switch {
	case b.service == "":
		return true
	case (e.host == c.host) != (b.host == c.host):
		return e.host == c.host
	case e.exact != b.exact:
		return e.exact
	case !e.lastSeen.Equal(b.lastSeen):
		return e.lastSeen.After(b.lastSeen)
	case e.service != b.service:
		return strings.Compare(e.service, b.service) < 0
	case port != c.port:
		return port < c.port
	}
	return e.host < b.host
}

// consider takes e, seen on port, if it is better.
func (c *chooser) consider(e endpoint, port uint16) {
	if c.sameHostOnly && e.host != c.host || c.holder != "" && e.host != c.holder {
		return
	}
	if !c.exactSince.IsZero() && (!e.exact || e.lastSeen.Before(c.exactSince)) {
		return
	}
	if c.better(e, port) {
		c.best, c.port = e, port
	}
}

// add considers the endpoints the connector has seen, with the time it saw
// them, and those read from PostgreSQL, whose times are dbAge older.
func (c *chooser) add(local map[endpoint]time.Time, db []endpoint, dbAge time.Duration, port uint16) {
	for e, at := range local {
		e.lastSeen = at
		c.consider(e, port)
	}
	for _, e := range db {
		e.lastSeen = e.lastSeen.Add(dbAge)
		c.consider(e, port)
	}
}

// candidate is a service on an endpoint at a backend of a translation, on
// the port of the backend. agent tells whether the agent of its host
// records the server side.
type candidate struct {
	endpoint
	// addr and port are where the service is reached.
	addr  netip.Addr
	port  uint16
	agent bool
	// dnat tells, of a backend of a learned translation, that it sees the
	// address of the client.
	dnat bool
}

// backendWindow is how long before the most recently seen backend another
// one may have been seen and still be current. Backends report at
// different times; the choice among the current ones does not depend on
// which reported last, so that it does not change with every report.
const backendWindow = aliveWindow

// appendCandidates appends the endpoints the connector has seen, with the
// time it saw them, and those read from PostgreSQL, whose times are dbAge
// older. If holder is set, the live host that alone holds the address of the
// endpoints (holderOf), the endpoints of other hosts are left out.
func appendCandidates(cs []candidate, local map[endpoint]time.Time, db []endpoint, dbAge time.Duration, addr netip.Addr,
	port uint16, holder string) []candidate {
	for e, at := range local {
		if holder == "" || e.host == holder {
			e.lastSeen = at
			cs = append(cs, candidate{endpoint: e, addr: addr, port: port})
		}
	}
	for _, e := range db {
		if holder == "" || e.host == holder {
			e.lastSeen = e.lastSeen.Add(dbAge)
			cs = append(cs, candidate{endpoint: e, addr: addr, port: port})
		}
	}
	return cs
}

// pickBackend returns the best of the current candidates: one observed on a
// socket rather than inferred from a listener on an unspecified address,
// then one whose agent records the server side, then the first by service,
// port and host.
func pickBackend(cs []candidate) (candidate, bool) {
	var newest time.Time
	for _, c := range cs {
		if c.lastSeen.After(newest) {
			newest = c.lastSeen
		}
	}
	var b candidate
	found := false
	for _, c := range cs {
		if c.lastSeen.Before(newest.Add(-backendWindow)) {
			continue
		}
		if !found || betterBackend(c, b) {
			b, found = c, true
		}
	}
	return b, found
}

func betterBackend(c, b candidate) bool {
	switch {
	case c.exact != b.exact:
		return c.exact
	case c.agent != b.agent:
		return c.agent
	case c.service != b.service:
		return c.service < b.service
	case c.port != b.port:
		return c.port < b.port
	}
	return c.host < b.host
}

// translatedServer finds the service at a backend of the translation whose
// virtual address a client edge connects to, on the port of the backend or
// the port of the edge. r.mu is held.
func (r *resolver) translatedServer(id *edgeID, now time.Time) (candidate, *translation, bool) {
	t := r.virtualOf(id)
	if t == nil {
		return candidate{}, nil, false
	}
	age := r.dbAge(now)
	var cs []candidate
	for _, b := range t.backends {
		port := b.port
		if port == 0 {
			port = id.port
		}
		if b.prefix.IsSingleIP() {
			k := endpointKey{b.prefix.Addr(), port, id.proto}
			cs = appendCandidates(cs, r.localEndpoints[k], r.dbEndpoints[k], age, k.addr, port, r.holderOf(k.addr, now))
			continue
		}
		cs = append(cs, r.inRange(b.prefix, port, id.proto, age, now)...)
	}
	for i := range cs {
		if a, ok := r.agent(cs[i].host, now); ok {
			cs[i].agent = a.covers(id.proto)
		}
	}
	c, ok := pickBackend(cs)
	return c, t, ok
}

// inRange returns the services on the endpoints within a range on a port,
// without those of hosts at an address that another host alone holds
// (holderOf). It scans the endpoints, so the result is kept until the next
// load or expiry. r.mu is held.
func (r *resolver) inRange(p netip.Prefix, port uint16, proto string, dbAge time.Duration, now time.Time) []candidate {
	k := rangeKey{p, port, proto}
	r.rangeMu.Lock()
	defer r.rangeMu.Unlock()
	if cs, ok := r.rangeCache[k]; ok {
		return cs
	}
	var cs []candidate
	for ek, es := range r.localEndpoints {
		if ek.port == port && ek.proto == proto && p.Contains(ek.addr) {
			cs = appendCandidates(cs, es, nil, 0, ek.addr, port, r.holderOf(ek.addr, now))
		}
	}
	for ek, es := range r.dbEndpoints {
		if ek.port == port && ek.proto == proto && p.Contains(ek.addr) {
			cs = appendCandidates(cs, nil, es, dbAge, ek.addr, port, r.holderOf(ek.addr, now))
		}
	}
	// The slice is shared: callers append to a copy.
	r.rangeCache[k] = cs[:len(cs):len(cs)]
	return r.rangeCache[k]
}

// virtualOf returns the translation whose virtual address a client edge
// connects to, if any.
func (r *resolver) virtualOf(id *edgeID) *translation {
	if t := r.virtuals[endpointKey{id.peer, id.port, id.proto}]; t != nil {
		return t
	}
	return r.virtuals[endpointKey{id.peer, 0, id.proto}]
}

// behindRelay tells whether a server edge is at a backend of a translation
// with sources and from one of them.
func (r *resolver) behindRelay(id *edgeID) bool {
	for i := range r.translations {
		t := &r.translations[i]
		if len(t.sources) == 0 || !t.has(id.proto) || len(t.clientEnds(id.local, id.port)) == 0 {
			continue
		}
		for _, s := range t.sources {
			if s.Contains(id.peer) {
				return true
			}
		}
	}
	return false
}

// foldedVirtual returns a virtual address of a translation without sources,
// static or learned (DNAT),
// through which the client of a server edge reaches it, and that the agent a
// of the client, on the host client, folds. r.mu is held.
func (r *resolver) foldedVirtual(a agentHost, client string, id *edgeID, now time.Time) (netip.Addr, bool) {
	for i := range r.translations {
		t := &r.translations[i]
		if len(t.sources) > 0 || !t.has(id.proto) {
			continue
		}
		for _, v := range t.clientEnds(id.local, id.port) {
			if r.foldsPeer(a, client, v.Addr(), true, now) {
				return v.Addr(), true
			}
		}
	}
	// Through a learned DNAT the client connects to its virtual address.
	k := learnedServerKey{id.proto, id.local, id.port, id.peer}
	for _, m := range []map[learnedClient]time.Time{r.localLearnedServers[k], r.dbLearnedServers[k]} {
		for lc := range m {
			if r.foldsPeer(a, client, lc.virtual, true, now) {
				return lc.virtual, true
			}
		}
	}
	return netip.Addr{}, false
}

// translatedClient finds the client service of a server edge at a backend
// of a translation that keeps the address of the client: the service whose
// client edge to a virtual address of the translation has the address of
// the client, on a port that reaches the port of the server edge, chosen by
// the rules of the address of the client. r.mu is held.
func (r *resolver) translatedClient(rules chooser, id *edgeID, now time.Time) string {
	c := rules
	age := r.dbAge(now)
	for i := range r.translations {
		t := &r.translations[i]
		if len(t.sources) > 0 || !t.has(id.proto) {
			continue
		}
		for _, v := range t.clientEnds(id.local, id.port) {
			k := clientKey{id.peer, v.Addr(), v.Port(), id.proto}
			c.add(r.localClients[k], r.dbClients[k], age, 0)
		}
	}
	return c.best.service
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

// classifyFolded names a folded peer, the network of every address of the
// family of a (0.0.0.0/0 or ::/0): a range of peer_cidrs that holds the
// whole network, ~external otherwise, as peer_class() names the network in
// PostgreSQL.
func (r *resolver) classifyFolded(a netip.Addr) string {
	for _, p := range r.cidrs {
		if p.prefix.Bits() == 0 && p.prefix.Addr().BitLen() == a.BitLen() {
			return p.name
		}
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
