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

// wireRowKey identifies a row of shawk.edge_protocols: a wire protocol of
// a TCP edge.
type wireRowKey struct {
	edge     edgeRowKey
	protocol string
}

// activityHours is how many hours a month of the activity of an edge
// holds: those of a month of 31 days.
const activityHours = 31 * 24

// activityRowKey identifies a row of shawk.edge_activity, or of
// shawk.unix_edge_activity for an edge of transportUnix: a month of the
// activity of an edge. month is the start of the month in UTC, in Unix
// seconds.
type activityRowKey struct {
	edge  edgeRowKey
	month int64
}

// activityBits are the hours of a month in which an edge was active: bit i,
// from the left, is the hour that starts i hours after the month.
type activityBits [activityHours / 8]byte

// activityOf returns the month of a time and its hour in the month.
func activityOf(t time.Time) (month int64, hour int) {
	t = t.UTC()
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start.Unix(), int(t.Sub(start) / time.Hour)
}

func (b *activityBits) set(hour int) { b[hour/8] |= 0x80 >> (hour % 8) }

func (b *activityBits) has(hour int) bool { return b[hour/8]&(0x80>>(hour%8)) != 0 }

// merge adds the hours of o.
func (b *activityBits) merge(o *activityBits) {
	for i := range b {
		b[i] |= o[i]
	}
}

// String returns the hours as PostgreSQL reads a bit string: a character 0
// or 1 per hour.
func (b *activityBits) String() string {
	out := make([]byte, activityHours)
	for i := range out {
		out[i] = '0'
		if b.has(i) {
			out[i] = '1'
		}
	}
	return string(out)
}

// established tells whether a connection of an edge was established since
// the agent counts them: one it opened, or one that is open (an adopted
// connection is counted open only).
func established(e *edgeInput) bool {
	return e.values[valueKey{metric: metricConnOpened}].value > 0 || e.values[valueKey{metric: metricConnCount}].value > 0
}

// sameHour tells whether two times are in the same hour, in UTC.
func sameHour(a, b time.Time) bool {
	return a.Truncate(time.Hour).Equal(b.Truncate(time.Hour))
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
	// unixTraced tells whether the agent traces Unix sockets, and
	// protocolsClassified whether it classifies wire protocols, nil if it
	// does not tell.
	unixTraced          *bool
	protocolsClassified *bool
	netnsScope          string
	dropped             int64
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

	sessions  map[time.Time]*sessionRow
	addrs     map[netip.Addr]span
	processes map[procKey]*procRow
	edges     map[edgeRowKey]span
	wire      map[wireRowKey]span              // the wire protocols of edges, whose edges are in edges
	activity  map[activityRowKey]*activityBits // the hours edges were active in, whose edges are in edges
	// established are the edges of Unix sockets, among edges, of which a
	// connection was established: the others are failed attempts only.
	established  map[edgeRowKey]struct{}
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
		wire:         map[wireRowKey]span{},
		activity:     map[activityRowKey]*activityBits{},
		established:  map[edgeRowKey]struct{}{},
		listeners:    map[listenerRowKey]span{},
		translations: map[translationID]span{},
	}
}

// size is the number of rows to write: the host, and its sessions,
// addresses, processes, edges with their wire protocols and the months of
// their activity, listeners and translations.
func (h *hostChanges) size() int {
	return 1 + len(h.sessions) + len(h.addrs) + len(h.processes) + len(h.edges) + len(h.wire) + len(h.activity) +
		len(h.listeners) + len(h.translations)
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

func (h *hostChanges) addWire(k wireRowKey, s span) {
	cur := h.wire[k]
	cur.merge(s)
	h.wire[k] = cur
}

// addActivity records that an edge was active at t: the hour of t in its
// month.
func (h *hostChanges) addActivity(k edgeRowKey, t time.Time) {
	month, hour := activityOf(t)
	h.activityOf(activityRowKey{edge: k, month: month}).set(hour)
}

// activityOf returns the hours pending of a month of an edge.
func (h *hostChanges) activityOf(k activityRowKey) *activityBits {
	bits := h.activity[k]
	if bits == nil {
		bits = new(activityBits)
		h.activity[k] = bits
	}
	return bits
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
	for k, s := range o.wire {
		h.addWire(k, s)
	}
	for k, bits := range o.activity {
		h.activityOf(k).merge(bits)
	}
	for k := range o.established {
		h.established[k] = struct{}{}
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
	acceptedEdges map[string]map[edgeRowKey]acceptedSpan
	// acceptedWire are those of the wire protocols of edges, by edge and
	// protocol, so that an edge is held once whatever its protocols.
	acceptedWire         map[string]map[edgeRowKey]map[string]acceptedSpan
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
		acceptedWire:         map[string]map[edgeRowKey]map[string]acceptedSpan{},
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
			protocolsClassified: b.protocolsClassified,
			netnsScope:          b.netnsScope, dropped: b.dropped, peerFold: b.peerFold, peerInternal: b.peerInternal}
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

// addEdges records the edges of a request received at now, their wire
// protocols and their processes, if they changed since they were last
// accepted for writing. Their times are no later than latest. An edge is
// written with a wire protocol that changed, so that the row of the
// protocol finds the row of its edge.
//
// An edge is last seen at the end of the latest interval in which its
// agent saw it active, and first seen at the end of the first: the hours of
// those times are the hours of its activity (shawk.edge_activity). They are
// recorded when the edge is new here and when a time moves into another
// hour, so that an edge active all along is written with its activity once
// an hour, and an edge whose changes were dropped again with the hours the
// agent still tells.
func (c *changes) addEdges(b *hostBatch, h *hostChanges, latest, now time.Time) {
	edges := acceptedOf(c.acceptedEdges, b.key)
	wire := c.acceptedWire[b.key]
	if wire == nil {
		wire = map[edgeRowKey]map[string]acceptedSpan{}
		c.acceptedWire[b.key] = wire
	}
	for _, e := range b.edges {
		if e.last.IsZero() {
			continue
		}
		s := observedSpan(e.first, e.last, latest)
		pk := c.procKey(&e.id.process)
		k := edgeRowKey{role: e.id.role, proto: e.id.proto, path: e.id.path, local: e.id.local, peer: e.id.peer, folded: e.id.folded,
			port: e.id.port, netns: e.id.netns, procKey: pk}
		prev, known := edges[k]
		changed := accept(edges, k, s, now)
		for p, ws := range e.wire {
			if ws.last.IsZero() {
				continue
			}
			acc := wire[k]
			if acc == nil {
				acc = map[string]acceptedSpan{}
				wire[k] = acc
			}
			if ws := observedSpan(ws.first, ws.last, latest); accept(acc, p, ws, now) {
				h.addWire(wireRowKey{edge: k, protocol: p}, ws)
				changed = true
			}
		}
		if !changed {
			continue
		}
		h.addProcess(pk, e.id.exe, s)
		h.addEdge(k, s)
		if k.proto == transportUnix && established(e) {
			h.established[k] = struct{}{}
		}
		if !known || s.first.Before(prev.first) && !sameHour(s.first, prev.first) {
			h.addActivity(k, s.first)
		}
		if !known || s.last.After(prev.last) && !sameHour(s.last, prev.last) {
			h.addActivity(k, s.last)
		}
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
	delete(c.acceptedWire, key)
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
	expireAccepted(c.acceptedEdges, now, c.ttl)
	for host, edges := range c.acceptedWire {
		for k, acc := range edges {
			for p, a := range acc {
				if now.Sub(a.seen) > c.ttl {
					delete(acc, p)
				}
			}
			if len(acc) == 0 {
				delete(edges, k)
			}
		}
		if len(edges) == 0 {
			delete(c.acceptedWire, host)
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

// expireAccepted forgets the spans of m not reported for ttl, and the hosts
// left without any.
func expireAccepted[K comparable](m map[string]map[K]acceptedSpan, now time.Time, ttl time.Duration) {
	for host, acc := range m {
		for k, a := range acc {
			if now.Sub(a.seen) > ttl {
				delete(acc, k)
			}
		}
		if len(acc) == 0 {
			delete(m, host)
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
