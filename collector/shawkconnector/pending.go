package shawkconnector

import (
	"net/netip"
	"time"
)

// span is when something was first and last seen.
type span struct {
	first, last time.Time
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
// OTEL_SERVICE_NAME stay apart.
type procKey struct{ unit, comm, service string }

type procRow struct {
	exe string
	span
}

type edgeRowKey struct {
	role, proto string
	local, peer netip.Addr
	port        uint16
	netns       uint64
	procKey
}

// listenerRowKey identifies a listener and its owner: a listener that
// changes hands has a row per owner, which keeps its history.
type listenerRowKey struct {
	proto   string
	addr    netip.Addr
	port    uint16
	netns   uint64
	procKey // zero if the owner is unknown
}

type sessionRow struct {
	lastHeartbeat time.Time
	// clockSkew is how far the clock of the connector is ahead of the clock
	// of the agent, from the latest request.
	clockSkew  time.Duration
	udpTraced  bool
	netnsScope string
	dropped    int64
}

// hostChanges are the changes of a host to write in one transaction.
type hostChanges struct {
	key                 string
	machineID, hostname string
	kernel, version     string
	span

	sessions  map[time.Time]*sessionRow
	addrs     map[netip.Addr]span
	processes map[procKey]*procRow
	edges     map[edgeRowKey]span
	listeners map[listenerRowKey]span
}

func newHostChanges(key string) *hostChanges {
	return &hostChanges{
		key:       key,
		sessions:  map[time.Time]*sessionRow{},
		addrs:     map[netip.Addr]span{},
		processes: map[procKey]*procRow{},
		edges:     map[edgeRowKey]span{},
		listeners: map[listenerRowKey]span{},
	}
}

func (h *hostChanges) size() int {
	return len(h.sessions) + len(h.addrs) + len(h.processes) + len(h.edges) + len(h.listeners)
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
}

// changes accumulates the changes of every host until they are written. To
// write an edge whose last_seen alone advances only once per interval, it
// remembers what it last accepted and skips data that changes nothing.
type changes struct {
	ttl     time.Duration
	pending map[string]*hostChanges
	// accepted are the spans last accepted for writing, with when they were
	// last reported.
	acceptedEdges     map[string]map[edgeRowKey]acceptedSpan
	acceptedListeners map[string]map[listenerRowKey]acceptedSpan
	// floors bound the start of the sessions of hosts.
	floors map[string]sessionFloor
}

// minAgentIdleTTL is the shortest idle TTL of an agent: an edge active that
// long before a request is still sent in it.
const minAgentIdleTTL = 2 * time.Minute

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

func newChanges(ttl time.Duration) *changes {
	return &changes{
		ttl:               ttl,
		pending:           map[string]*hostChanges{},
		acceptedEdges:     map[string]map[edgeRowKey]acceptedSpan{},
		acceptedListeners: map[string]map[listenerRowKey]acceptedSpan{},
		floors:            map[string]sessionFloor{},
	}
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
// as the clock skew of the agent. Edges, listeners and processes keep the
// times of the agent, which observed them.
func (c *changes) add(b *hostBatch, now time.Time) {
	var skew time.Duration
	if !b.time.IsZero() {
		skew = now.Sub(b.time)
	}
	h := c.host(b.key)
	h.setHost(b.machineID, b.hostname, b.kernel, b.agentVersion, now)
	f, ok := c.floors[b.key]
	switch {
	case !ok:
		f.start = now.Add(-skew).Add(-minAgentIdleTTL).Truncate(time.Second)
	case skew-f.skew > clockStepBack || f.skew-skew > clockStepBack:
		// The clock of the agent stepped: keep the floor at the same time.
		f.start = f.start.Add(f.skew - skew)
	}
	f.skew, f.seen = skew, now
	c.floors[b.key] = f
	if !b.segmentStart.IsZero() {
		start := b.segmentStart
		if start.Before(f.start) {
			start = f.start
		}
		h.addSession(start, sessionRow{lastHeartbeat: now, clockSkew: skew, udpTraced: b.udpTraced,
			netnsScope: b.netnsScope, dropped: b.dropped})
	}
	// The host holds its addresses as of the requests that close intervals,
	// like its heartbeat.
	if b.final {
		for _, a := range b.addrs {
			h.addAddr(a, span{now, now})
		}
	}

	edges := c.acceptedEdges[b.key]
	if edges == nil {
		edges = map[edgeRowKey]acceptedSpan{}
		c.acceptedEdges[b.key] = edges
	}
	for _, e := range b.edges {
		if e.last.IsZero() {
			continue
		}
		s := span{e.first, e.last}
		if s.first.IsZero() {
			s.first = s.last
		}
		pk := procKey{e.id.unit, e.id.comm, e.id.job()}
		k := edgeRowKey{role: e.id.role, proto: e.id.proto, local: e.id.local, peer: e.id.peer,
			port: e.id.port, netns: e.id.netns, procKey: pk}
		acc, ok := edges[k]
		changed := !ok || s.first.Before(acc.first) || s.last.After(acc.last)
		acc.span.merge(s)
		acc.seen = now
		edges[k] = acc
		if !changed {
			continue
		}
		h.addProcess(pk, e.id.exe, s)
		h.addEdge(k, s)
	}

	listeners := c.acceptedListeners[b.key]
	if listeners == nil {
		listeners = map[listenerRowKey]acceptedSpan{}
		c.acceptedListeners[b.key] = listeners
	}
	for _, l := range b.listeners {
		if l.last.IsZero() {
			continue
		}
		s := span{l.first, l.last}
		if s.first.IsZero() {
			s.first = s.last
		}
		k := listenerRowKey{proto: l.id.proto, addr: l.id.addr, port: l.id.port, netns: l.id.netns}
		if l.id.unit != "" || l.id.comm != "" {
			k.procKey = procKey{l.id.unit, l.id.comm, l.id.job()}
		}
		acc, ok := listeners[k]
		// A listener's last_seen advances at every request; write it once
		// per interval like the edges.
		changed := !ok || s.first.Before(acc.first) || s.last.After(acc.last)
		acc.span.merge(s)
		acc.seen = now
		listeners[k] = acc
		if !changed {
			continue
		}
		if k.procKey != (procKey{}) {
			h.addProcess(k.procKey, l.id.exe, s)
		}
		h.addListener(k, s)
	}
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
// starts no earlier than the idle TTL of an agent before now.
func (c *changes) forget(key string, now time.Time) {
	delete(c.acceptedEdges, key)
	delete(c.acceptedListeners, key)
	if f, ok := c.floors[key]; ok {
		f.start = now.Add(-f.skew).Add(-minAgentIdleTTL).Truncate(time.Second)
		c.floors[key] = f
	}
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
