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
// edge of host, in its scope (a loopback client address in the host and
// network namespace of the translation, a shared one on its host), among
// those seen within backendWindow of the most recently seen one: a
// published port re-pointed to another container leaves the former one,
// whose address may now be another service's. r.mu is held.
func (r *resolver) learnedOf(host string, id *edgeID, now time.Time) []learnedBackend {
	k := learnedClientKey{id.proto, id.local, id.peer, id.port}
	local, db := r.localLearned[k], r.dbLearned[k]
	if len(local) == 0 && len(db) == 0 {
		return nil
	}
	sameHost := r.sameHostAddr(id.local, now)
	seen := map[learnedBackend]time.Time{}
	var newest time.Time
	add := func(b learnedBackend, at time.Time) {
		switch {
		case id.local.IsLoopback() && (b.host != host || b.netns != id.netns):
		case sameHost && b.host != host:
		default:
			if at.After(seen[b]) {
				seen[b] = at
			}
			if at.After(newest) {
				newest = at
			}
		}
	}
	for b, at := range local {
		add(b, at)
	}
	age := r.dbAge(now)
	for b, at := range db {
		add(b, at.Add(age))
	}
	var out []learnedBackend
	for b, at := range seen {
		if !at.Before(newest.Add(-backendWindow)) {
			out = append(out, b)
		}
	}
	return out
}

// learnedServer finds the service at a backend of the learned translations
// of a client edge of host. A backend at a loopback or shared address is
// looked up on the host that translated the connections only, and one at an
// address that a live host holds alone on that host only (holderOf). The
// dnat of the candidate tells that its backend sees the address of the
// client. r.mu is held.
func (r *resolver) learnedServer(host string, id *edgeID, now time.Time) (candidate, bool) {
	age := r.dbAge(now)
	var cs []candidate
	for _, b := range r.learnedOf(host, id, now) {
		k := endpointKey{b.backend, b.bport, id.proto}
		found := appendCandidates(nil, r.localEndpoints[k], r.dbEndpoints[k], age, b.backend, b.bport, r.holderOf(b.backend, now))
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
// address of the client, among the translations seen within backendWindow
// of the most recently seen one. A backend or a client at a loopback or
// shared address is matched on the host that translated the connections
// only, and a client at an address that holder, a live host, holds alone
// on that host only (holderOf). r.mu is held.
func (r *resolver) learnedClientName(host string, id *edgeID, holder string, now time.Time) string {
	var best chooser
	best.host = host
	age := r.dbAge(now)
	clientHost := r.sameHostAddr(id.peer, now)
	for _, lc := range r.learnedClientsOf(host, id, now) {
		c := chooser{host: lc.host, sameHostOnly: clientHost, holder: holder}
		ck := clientKey{id.peer, lc.virtual, lc.vport, id.proto}
		c.add(r.localClients[ck], r.dbClients[ck], age, 0)
		if c.best.service != "" && best.better(c.best, 0) {
			best.best = c.best
		}
	}
	return best.best.service
}

// learnedClientsOf returns the client ends of the learned DNAT whose
// backend is the local address and port of a server edge of host, from its
// peer, in its scope, among those seen within backendWindow of the most
// recently seen one. r.mu is held.
func (r *resolver) learnedClientsOf(host string, id *edgeID, now time.Time) []learnedClient {
	k := learnedServerKey{id.proto, id.local, id.port, id.peer}
	local, db := r.localLearnedServers[k], r.dbLearnedServers[k]
	if len(local) == 0 && len(db) == 0 {
		return nil
	}
	loopback := id.local.IsLoopback() || id.peer.IsLoopback()
	serverHost := loopback || r.sameHostAddr(id.local, now) || r.sameHostAddr(id.peer, now)
	seen := map[learnedClient]time.Time{}
	var newest time.Time
	add := func(lc learnedClient, at time.Time) {
		if (loopback && (lc.host != host || lc.netns != id.netns)) || (serverHost && lc.host != host) {
			return
		}
		if at.After(seen[lc]) {
			seen[lc] = at
		}
		if at.After(newest) {
			newest = at
		}
	}
	for lc, at := range local {
		add(lc, at)
	}
	age := r.dbAge(now)
	for lc, at := range db {
		add(lc, at.Add(age))
	}
	var out []learnedClient
	for lc, at := range seen {
		if !at.Before(newest.Add(-backendWindow)) {
			out = append(out, lc)
		}
	}
	return out
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
