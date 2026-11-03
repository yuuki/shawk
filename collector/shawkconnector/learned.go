package shawkconnector

import (
	"net/netip"
	"time"
)

// Translations of addresses learned by the agents of the hosts that make
// them (shawk.learned_translations). The resolver names peers through them
// like through static translations, which come first.

// learnedName is the translation of the rows that PostgreSQL matches
// through learned translations; names of the configuration may not start
// with ~.
const learnedName = "~learned"

// learnedClientKey is the client side of a learned translation: the
// client connected to the virtual address and port.
type learnedClientKey struct {
	proto   string
	client  netip.Addr
	virtual netip.Addr
	vport   uint16
}

// learnedBackend is where a learned translation sent the connections: the
// backend saw them from source. host and netns are those of the host that
// translated them.
type learnedBackend struct {
	host    string
	netns   uint64
	source  netip.Addr
	backend netip.Addr
	bport   uint16
}

// learnedServerKey is the server side of a learned translation that keeps
// the address of the client (DNAT): the backend on its port, and the
// client it saw.
type learnedServerKey struct {
	proto   string
	backend netip.Addr
	bport   uint16
	client  netip.Addr
}

// learnedClient is the client end of a learned DNAT, translated by host in
// netns.
type learnedClient struct {
	host    string
	netns   uint64
	virtual netip.Addr
	vport   uint16
}

// learnedRow is a row of shawk.learned_translations.
type learnedRow struct {
	host     string
	id       translationID
	lastSeen time.Time
}

// sameHostAddr tells whether an address identifies its host only: loopback, or an
// address that several hosts hold, such as that of a container bridge.
// r.mu is held.
func (r *resolver) sameHostAddr(a netip.Addr, now time.Time) bool {
	return a.IsLoopback() || len(r.holders(a, now)) > 1
}

// learnTranslation records in client and server a translation that host
// made, seen at t.
func learnTranslation(host string, id translationID, t time.Time, client map[learnedClientKey]map[learnedBackend]time.Time,
	server map[learnedServerKey]map[learnedClient]time.Time) {
	learnTimed(client, learnedClientKey{id.proto, id.client, id.virtual, id.vport},
		learnedBackend{host, id.netns, id.source, id.backend, id.bport}, t)
	if id.dnat() {
		learnTimed(server, learnedServerKey{id.proto, id.backend, id.bport, id.client},
			learnedClient{host, id.netns, id.virtual, id.vport}, t)
	}
}

func learnTimed[K comparable, V comparable](m map[K]map[V]time.Time, k K, v V, t time.Time) {
	vs := m[k]
	if vs == nil {
		vs = map[V]time.Time{}
		m[k] = vs
	}
	if t.After(vs[v]) {
		vs[v] = t
	}
}

// learnedOf returns the backends of the learned translations of a client
// edge of host, in its scope: a loopback client address in the host and
// network namespace of the translation, a shared one on its host. r.mu is
// held.
func (r *resolver) learnedOf(host string, id *edgeID, now time.Time) []learnedBackend {
	k := learnedClientKey{id.proto, id.local, id.peer, id.port}
	sameHost := r.sameHostAddr(id.local, now)
	var out []learnedBackend
	add := func(b learnedBackend) {
		switch {
		case id.local.IsLoopback() && (b.host != host || b.netns != id.netns):
		case sameHost && b.host != host:
		default:
			out = append(out, b)
		}
	}
	for b := range r.localLearned[k] {
		add(b)
	}
	for b := range r.dbLearned[k] {
		add(b)
	}
	return out
}

// learnedServer finds the service at a backend of the learned translations
// of a client edge of host. A backend at a loopback or shared address is
// looked up on the host that translated the connections only. The dnat of
// the candidate tells that its backend sees the address of the client.
// r.mu is held.
func (r *resolver) learnedServer(host string, id *edgeID, now time.Time) (candidate, bool) {
	age := r.dbAge(now)
	var cs []candidate
	for _, b := range r.learnedOf(host, id, now) {
		k := endpointKey{b.backend, b.bport, id.proto}
		found := appendCandidates(nil, r.localEndpoints[k], r.dbEndpoints[k], age, b.bport)
		onHost := r.sameHostAddr(b.backend, now)
		for _, f := range found {
			if onHost && f.host != b.host {
				continue
			}
			f.dnat = b.source == id.local
			cs = append(cs, f)
		}
	}
	for i := range cs {
		if a, ok := r.agent(cs[i].host, now); ok {
			cs[i].agent = a.covers(id.proto)
		}
	}
	return pickBackend(cs)
}

// learnedClientName finds the client service of a server edge of host
// through the learned translations that keep the address of the client:
// the service whose client edge to the virtual address and port has the
// address of the client. A backend or a client at a loopback or shared
// address is matched on the host that translated the connections only.
// r.mu is held.
func (r *resolver) learnedClientName(host string, id *edgeID, now time.Time) string {
	k := learnedServerKey{id.proto, id.local, id.port, id.peer}
	serverHost := r.sameHostAddr(id.local, now) || r.sameHostAddr(id.peer, now)
	clientHost := r.sameHostAddr(id.peer, now)
	age := r.dbAge(now)
	var best chooser
	consider := func(lc learnedClient) {
		switch {
		case (id.local.IsLoopback() || id.peer.IsLoopback()) && (lc.host != host || lc.netns != id.netns):
			return
		case serverHost && lc.host != host:
			return
		}
		c := chooser{host: lc.host, sameHostOnly: clientHost}
		ck := clientKey{id.peer, lc.virtual, lc.vport, id.proto}
		c.add(r.localClients[ck], r.dbClients[ck], age, 0)
		if c.best.service == "" {
			return
		}
		best.host = host
		if best.better(c.best, 0) {
			best.best = c.best
		}
	}
	for lc := range r.localLearnedServers[k] {
		consider(lc)
	}
	for lc := range r.dbLearnedServers[k] {
		consider(lc)
	}
	return best.best.service
}

// loadLearned builds the maps of the learned translations read from
// PostgreSQL, with their times.
func loadLearned(rows []learnedRow) (map[learnedClientKey]map[learnedBackend]time.Time, map[learnedServerKey]map[learnedClient]time.Time) {
	client := map[learnedClientKey]map[learnedBackend]time.Time{}
	server := map[learnedServerKey]map[learnedClient]time.Time{}
	for _, row := range rows {
		learnTranslation(row.host, row.id, row.lastSeen, client, server)
	}
	return client, server
}
