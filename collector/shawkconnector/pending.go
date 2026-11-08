package shawkconnector

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// span is when something was first and last seen.
type span struct {
	first, last time.Time
}

// notAfter returns s with its times no later than t.
func (s span) notAfter(t time.Time) span {
	if s.first.After(t) {
		s.first = t
	}
	if s.last.After(t) {
		s.last = t
	}
	return s
}

// merge widens s to cover o. Zero times are ignored.
func (s *span) merge(o span) {
	if !o.first.IsZero() && (s.first.IsZero() || o.first.Before(s.first)) {
		s.first = o.first
	}
	if o.last.After(s.last) {
		s.last = o.last
	}
}

// procKey identifies a process in PostgreSQL. The service name is part of
// it, so that processes of one unit with the same comm but different
// OTEL_SERVICE_NAME stay apart. With job_users, so is the user of a process
// of a Slurm job (its uid in decimal, "" if unknown), so that the jobs of
// different users stay apart; it is "" for other processes.
type procKey struct{ unit, comm, service, user string }

type procRow struct {
	exe string
	span
}

// edgeRowKey identifies an edge in PostgreSQL: a row of shawk.edges, or of
// shawk.unix_edges for transportUnix, which has a path and no addresses.
type edgeRowKey struct {
	role, proto string
	path        string // of transportUnix
	local, peer netip.Addr
	folded      bool // the peer is the network of peer, as in edgeID
	port        uint16
	netns       uint64
	procKey
}

// listenerRowKey identifies a listener and its owner: a listener that
// changes hands has a row per owner, which keeps its history. A listener
// of transportUnix has a path and no address. kernelChosen tells that the
// kernel chose the port; the row of the owner keeps when it last did, of
// the keys that differ only by it.
type listenerRowKey struct {
	proto        string
	path         string
	addr         netip.Addr
	port         uint16
	netns        uint64
	kernelChosen bool
	procKey      // zero if the owner is unknown
}

type sessionRow struct {
	lastHeartbeat time.Time
	// clockSkew is how far the clock of the connector is ahead of the clock
	// of the agent, from the latest request.
	clockSkew time.Duration
	udpTraced bool
	// unixTraced tells whether the agent traces Unix sockets, nil if it
	// does not tell.
	unixTraced *bool
	netnsScope string
	dropped    int64
	// countersStarted is when the counters of the agent started, by the
	// clock of the agent as it sends it: the same for every session of one
	// run of the agent, whatever connector writes them and however its clock
	// steps, so that the drops of a run are compared with those of the same
	// run; zero if unknown.
	countersStarted time.Time
	// peerFold and peerInternal are what the agent folds (foldNone, foldIn
	// or foldAll) and the ranges it keeps exact, nil if it does not tell.
	peerFold     string
	peerInternal []netip.Prefix
}

// hostChanges are the changes of a host to write in one transaction.
type hostChanges struct {
	key                 string
	machineID, hostname string
	kernel, version     string
	span

	sessions     map[time.Time]*sessionRow
	addrs        map[netip.Addr]span
	processes    map[procKey]*procRow
	edges        map[edgeRowKey]span
	listeners    map[listenerRowKey]span
	translations map[translationID]span
}

func newHostChanges(key string) *hostChanges {
	return &hostChanges{
		key:          key,
		sessions:     map[time.Time]*sessionRow{},
		addrs:        map[netip.Addr]span{},
		processes:    map[procKey]*procRow{},
		edges:        map[edgeRowKey]span{},
		listeners:    map[listenerRowKey]span{},
		translations: map[translationID]span{},
	}
}

// size is the number of rows to write: the host, and its sessions,
// addresses, processes, edges, listeners and translations.
func (h *hostChanges) size() int {
	return 1 + len(h.sessions) + len(h.addrs) + len(h.processes) + len(h.edges) + len(h.listeners) + len(h.translations)
}

func (h *hostChanges) setHost(machineID, hostname, kernel, version string, t time.Time) {
	if t.After(h.last) || h.hostname == "" {
		h.machineID, h.hostname, h.kernel, h.version = machineID, hostname, kernel, version
	}
	h.span.merge(span{t, t})
}

func (h *hostChanges) addSession(start time.Time, s sessionRow) {
	cur := h.sessions[start]
	if cur == nil || !s.lastHeartbeat.Before(cur.lastHeartbeat) {
		h.sessions[start] = &s
	}
}

// floorSessions makes the sessions start no earlier than floor, by the
// clock of the agent: a session whose last heartbeat is before the floor
// is not written, and the others start at the floor if they started
// before.
func (h *hostChanges) floorSessions(floor time.Time) {
	for start, s := range h.sessions {
		if !start.Before(floor) {
			continue
		}
		delete(h.sessions, start)
		if !s.lastHeartbeat.Add(-s.clockSkew).Before(floor) {
			h.addSession(floor, *s)
		}
	}
}

func (h *hostChanges) addAddr(a netip.Addr, s span) {
	cur := h.addrs[a]
	cur.merge(s)
	h.addrs[a] = cur
}

func (h *hostChanges) addProcess(k procKey, exe string, s span) {
	p := h.processes[k]
	if p == nil {
		p = &procRow{}
		h.processes[k] = p
	}
	if !s.last.Before(p.last) {
		p.exe = exe
	}
	p.span.merge(s)
}

func (h *hostChanges) addEdge(k edgeRowKey, s span) {
	cur := h.edges[k]
	cur.merge(s)
	h.edges[k] = cur
}

func (h *hostChanges) addListener(k listenerRowKey, s span) {
	cur := h.listeners[k]
	cur.merge(s)
	h.listeners[k] = cur
}

func (h *hostChanges) addTranslation(k translationID, s span) {
	cur := h.translations[k]
	cur.merge(s)
	h.translations[k] = cur
}

// merge adds the changes of o, which are older, back into h after o failed
// to be written.
func (h *hostChanges) merge(o *hostChanges) {
	if o.hostname != "" {
		if h.hostname == "" {
			h.machineID, h.hostname, h.kernel, h.version = o.machineID, o.hostname, o.kernel, o.version
		}
		h.span.merge(o.span)
	}
	for t, s := range o.sessions {
		h.addSession(t, *s)
	}
	for a, s := range o.addrs {
		h.addAddr(a, s)
	}
	for k, p := range o.processes {
		h.addProcess(k, p.exe, p.span)
	}
	for k, s := range o.edges {
		h.addEdge(k, s)
	}
	for k, s := range o.listeners {
		h.addListener(k, s)
	}
	for k, s := range o.translations {
		h.addTranslation(k, s)
	}
}

// changes accumulates the changes of every host until they are written. To
// write an edge whose last_seen alone advances only once per interval, it
// remembers what it last accepted and skips data that changes nothing.
type changes struct {
	ttl time.Duration
	// jobUsers keeps the users of the processes of Slurm jobs (job_users).
	jobUsers bool
	pending  map[string]*hostChanges
	// accepted are the spans last accepted for writing, with when they were
	// last reported.
	acceptedEdges        map[string]map[edgeRowKey]acceptedSpan
	acceptedListeners    map[string]map[listenerRowKey]acceptedSpan
	acceptedTranslations map[string]map[translationID]acceptedSpan
	// floors bound the start of the sessions of hosts.
	floors map[string]sessionFloor
}

// minAgentIdleTTL is the shortest idle TTL of an agent: an edge active that
// long before a request is still sent in it.
const minAgentIdleTTL = 2 * time.Minute

// maxClockAhead is how far ahead of the clock of the connector the times
// of observations may be written. Edges, listeners and translations keep
// the times of the agent, and a later time is written as now plus this:
// otherwise a time far in the future, which an agent may send, would stay
// the last_seen of its row (greatest()), be taken for the most recently
// seen endpoint by every connector, and never reach the retention. Clocks
// are alerted on beyond a minute of skew; PostgreSQL matches the two sides
// of a connection within 2 minutes.
const maxClockAhead = 2 * time.Minute

// sessionFloor is the earliest start of a session of a host the connector
// can vouch for, by the clock of the agent. An agent sends the edges active
// within its idle TTL; older ones reached an earlier instance of the
// connector, or were in changes it dropped, and may never have been
// written. When the connector first sees a host, or drops changes of the
// host, a session therefore starts no earlier than the idle TTL before;
// the session written before then ends at its last heartbeat, and the time
// in between shows as not observed.
type sessionFloor struct {
	start time.Time
	skew  time.Duration // the latest clock skew of the agent
	seen  time.Time
}

type acceptedSpan struct {
	span
	seen time.Time
}

func newChanges(ttl time.Duration, jobUsers bool) *changes {
	return &changes{
		ttl:                  ttl,
		jobUsers:             jobUsers,
		pending:              map[string]*hostChanges{},
		acceptedEdges:        map[string]map[edgeRowKey]acceptedSpan{},
		acceptedListeners:    map[string]map[listenerRowKey]acceptedSpan{},
		acceptedTranslations: map[string]map[translationID]acceptedSpan{},
		floors:               map[string]sessionFloor{},
	}
}

// procKey returns the row of a process in PostgreSQL.
func (c *changes) procKey(p *process) procKey {
	k := procKey{unit: p.unit, comm: p.comm, service: p.job()}
	if c.jobUsers && strings.HasPrefix(p.unit, slurmJobUnit) {
		k.user = p.user
	}
	return k
}

func (c *changes) host(key string) *hostChanges {
	h := c.pending[key]
	if h == nil {
		h = newHostChanges(key)
		c.pending[key] = h
	}
	return h
}

// add records the changes of a request received at now.
//
// Whether a host is alive is judged by the clock of the connector: the
// heartbeat and the last seen times of the host and its addresses are the
// time of receipt, and the difference to the time of the request is kept
// as the clock skew of the agent. Edges, listeners, translations and
// processes keep the times of the agent, which observed them, up to
// maxClockAhead after now.
func (c *changes) add(b *hostBatch, now time.Time) {
	latest := now.Add(maxClockAhead)
	var skew time.Duration
	if !b.time.IsZero() {
		skew = now.Sub(b.time)
	}
	h := c.host(b.key)
	h.setHost(b.machineID, b.hostname, b.kernel, b.agentVersion, now)
	f := c.advanceFloor(b, skew, now)
	if !b.segmentStart.IsZero() && !b.limited {
		start := b.segmentStart
		if start.Before(f.start) {
			start = f.start
		}
		s := sessionRow{lastHeartbeat: now, clockSkew: skew, udpTraced: b.udpTraced, unixTraced: b.unixTraced,
			netnsScope: b.netnsScope, dropped: b.dropped, peerFold: b.peerFold, peerInternal: b.peerInternal}
		s.countersStarted = b.droppedSince
		h.addSession(start, s)
	}
	// The host holds its addresses as of the requests that close intervals,
	// like its heartbeat.
	if b.final {
		for _, a := range b.addrs {
			h.addAddr(a, span{now, now})
		}
	}
	c.addEdges(b, h, latest, now)
	c.addListeners(b, h, latest, now)
	c.addTranslations(b, h, latest, now)
}

// advanceFloor updates the session floor of the host of a request received
// at now, skew being how far the clock of the connector is ahead of the
// clock of the agent, and returns it.
func (c *changes) advanceFloor(b *hostBatch, skew time.Duration, now time.Time) sessionFloor {
	f, ok := c.floors[b.key]
	switch {
	case !ok:
		f.start = now.Add(-skew).Add(-minAgentIdleTTL).Truncate(time.Second)
	case skew-f.skew > clockStepBack || f.skew-skew > clockStepBack:
		// The clock of the agent stepped: keep the floor at the same time.
		f.start = f.start.Add(f.skew - skew)
	}
	if b.limited {
		// Series of the host were dropped in the interval this request
		// closes (max_series_per_host), and may never be written: the
		// session ends at its last heartbeat, and the next one starts no
		// earlier than this request. A series dropped then and not sent
		// again was last active before it.
		if t := now.Add(-skew).Truncate(time.Second); t.After(f.start) {
			f.start = t
		}
	}
	f.skew, f.seen = skew, now
	c.floors[b.key] = f
	return f
}

// addEdges records the edges of a request received at now, and their
// processes, if they changed since they were last accepted for writing.
// Their times are no later than latest.
func (c *changes) addEdges(b *hostBatch, h *hostChanges, latest, now time.Time) {
	edges := acceptedOf(c.acceptedEdges, b.key)
	for _, e := range b.edges {
		if e.last.IsZero() {
			continue
		}
		s := observedSpan(e.first, e.last, latest)
		pk := c.procKey(&e.id.process)
		k := edgeRowKey{role: e.id.role, proto: e.id.proto, path: e.id.path, local: e.id.local, peer: e.id.peer, folded: e.id.folded,
			port: e.id.port, netns: e.id.netns, procKey: pk}
		if !accept(edges, k, s, now) {
			continue
		}
		h.addProcess(pk, e.id.exe, s)
		h.addEdge(k, s)
	}
}

// addListeners records the listeners of a request received at now, and
// their processes, if they changed since they were last accepted for
// writing. Their times are no later than latest.
func (c *changes) addListeners(b *hostBatch, h *hostChanges, latest, now time.Time) {
	listeners := acceptedOf(c.acceptedListeners, b.key)
	for _, l := range b.listeners {
		if l.last.IsZero() {
			continue
		}
		s := observedSpan(l.first, l.last, latest)
		k := listenerRowKey{proto: l.id.proto, path: l.id.path, addr: l.id.addr, port: l.id.port, netns: l.id.netns,
			kernelChosen: l.id.kernelChosen}
		if l.id.unit != "" || l.id.comm != "" {
			k.procKey = c.procKey(&l.id.process)
		}
		// A listener's last_seen advances at every request; write it once
		// per interval like the edges.
		if !accept(listeners, k, s, now) {
			continue
		}
		if k.procKey != (procKey{}) {
			h.addProcess(k.procKey, l.id.exe, s)
		}
		h.addListener(k, s)
	}
}

// addTranslations records the translations of a request received at now if
// they changed since they were last accepted for writing. Their times are
// no later than latest.
func (c *changes) addTranslations(b *hostBatch, h *hostChanges, latest, now time.Time) {
	xlats := acceptedOf(c.acceptedTranslations, b.key)
	for _, x := range b.translations {
		if x.last.IsZero() {
			continue
		}
		s := observedSpan(x.first, x.last, latest)
		if accept(xlats, x.id, s, now) {
			h.addTranslation(x.id, s)
		}
	}
}

// acceptedOf returns the spans last accepted for writing of a host.
func acceptedOf[K comparable](m map[string]map[K]acceptedSpan, host string) map[K]acceptedSpan {
	acc := m[host]
	if acc == nil {
		acc = map[K]acceptedSpan{}
		m[host] = acc
	}
	return acc
}

// observedSpan is the span of an observation first and last seen at those
// times, first being zero if not known, and no later than latest.
func observedSpan(first, last, latest time.Time) span {
	s := span{first, last}
	if s.first.IsZero() {
		s.first = s.last
	}
	return s.notAfter(latest)
}

// accept records that the span s of k was reported at now, and tells
// whether it changes what was last accepted for writing.
func accept[K comparable](accepted map[K]acceptedSpan, k K, s span, now time.Time) bool {
	acc, ok := accepted[k]
	changed := !ok || s.first.Before(acc.first) || s.last.After(acc.last)
	acc.span.merge(s)
	acc.seen = now
	accepted[k] = acc
	return changed
}

// take returns the pending changes and starts new ones.
func (c *changes) take() map[string]*hostChanges {
	p := c.pending
	c.pending = map[string]*hostChanges{}
	return p
}

// restore puts back changes that failed to be written.
func (c *changes) restore(h *hostChanges) {
	c.host(h.key).merge(h)
}

// forget is called when changes of a host were dropped at now. The spans
// accepted for writing are forgotten, so that the edges and listeners the
// agent still sends are written again, and the next session of the host
// starts no earlier than the idle TTL of an agent before now. So do the
// sessions already pending, of requests received while the dropped changes
// were being written: those requests skipped the edges the changes held.
func (c *changes) forget(key string, now time.Time) {
	delete(c.acceptedEdges, key)
	delete(c.acceptedListeners, key)
	delete(c.acceptedTranslations, key)
	f, ok := c.floors[key]
	if !ok {
		return
	}
	f.start = now.Add(-f.skew).Add(-minAgentIdleTTL).Truncate(time.Second)
	c.floors[key] = f
	if h := c.pending[key]; h != nil {
		h.floorSessions(f.start)
	}
}

// bound drops the pending changes of whole hosts, those pending the longest
// first, until at most max rows are pending, and forgets them as dropped at
// now. It returns the hosts and rows dropped.
func (c *changes) bound(max int, now time.Time) (hosts, rows int) {
	size := c.pendingSize()
	if size <= max {
		return 0, 0
	}
	pending := slices.SortedFunc(maps.Values(c.pending), func(a, b *hostChanges) int {
		return cmp.Or(a.first.Compare(b.first), strings.Compare(a.key, b.key))
	})
	for _, h := range pending {
		if size <= max {
			break
		}
		n := h.size()
		size -= n
		hosts++
		rows += n
		delete(c.pending, h.key)
		c.forget(h.key, now)
	}
	return hosts, rows
}

// expire forgets accepted spans not reported for the TTL.
func (c *changes) expire(now time.Time) {
	for host, m := range c.acceptedEdges {
		for k, a := range m {
			if now.Sub(a.seen) > c.ttl {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(c.acceptedEdges, host)
		}
	}
	for host, m := range c.acceptedListeners {
		for k, a := range m {
			if now.Sub(a.seen) > c.ttl {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(c.acceptedListeners, host)
		}
	}
	for host, m := range c.acceptedTranslations {
		for k, a := range m {
			if now.Sub(a.seen) > c.ttl {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(c.acceptedTranslations, host)
		}
	}
	for host, f := range c.floors {
		if now.Sub(f.seen) > c.ttl {
			delete(c.floors, host)
		}
	}
}

// pendingSize is the number of rows waiting to be written.
func (c *changes) pendingSize() int {
	n := 0
	for _, h := range c.pending {
		n += h.size()
	}
	return n
}
