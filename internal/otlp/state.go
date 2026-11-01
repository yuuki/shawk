package otlp

import (
	"net/netip"
	"time"
)

// Process identifies the local process of an edge or a listener. The PID is
// deliberately absent: a restarted process continues the same series.
type Process struct {
	Unit             string
	Comm             string
	Exe              string // path of the executable
	Service          string // service.name
	ServiceNamespace string // service.namespace
}

// EdgeKey identifies an edge series.
type EdgeKey struct {
	Role      string // RoleClient or RoleServer
	Proto     string // "tcp" or "udp"
	LocalAddr netip.Addr
	PeerAddr  netip.Addr
	// Port is the service port: the peer port of a client edge and the local
	// port of a server edge.
	Port  uint16
	NetNS uint32
	Process
}

// EdgeStats are the statistics of an edge. As input to AddEdge they cover
// one interval; in a series they are totals, except OpenConns, which is the
// number of connections open at the end of the latest interval.
type EdgeStats struct {
	Conns      uint64
	ConnFails  uint64
	OpenConns  uint64
	BytesSent  uint64
	BytesRecv  uint64
	MsgsSent   uint64
	MsgsRecv   uint64
	Retrans    uint64
	RTTSumUs   uint64
	RTTSamples uint64
}

// active tells whether the statistics of an interval show activity.
func (s *EdgeStats) active() bool {
	return s.Conns|s.ConnFails|s.OpenConns|s.BytesSent|s.BytesRecv|s.MsgsSent|s.MsgsRecv|s.Retrans|s.RTTSamples != 0
}

func (s *EdgeStats) add(o *EdgeStats) {
	s.Conns += o.Conns
	s.ConnFails += o.ConnFails
	s.OpenConns += o.OpenConns
	s.BytesSent += o.BytesSent
	s.BytesRecv += o.BytesRecv
	s.MsgsSent += o.MsgsSent
	s.MsgsRecv += o.MsgsRecv
	s.Retrans += o.Retrans
	s.RTTSumUs += o.RTTSumUs
	s.RTTSamples += o.RTTSamples
}

// ListenerKey identifies a listener series.
type ListenerKey struct {
	Proto string
	Addr  netip.Addr
	Port  uint16
	NetNS uint32
	Process
}

// Edge is the state of an edge series.
type Edge struct {
	// Start is when the cumulative counters started.
	Start     time.Time
	FirstSeen time.Time
	LastSeen  time.Time
	Total     EdgeStats
}

// Listener is the state of a listener series.
type Listener struct {
	FirstSeen time.Time
	LastSeen  time.Time
}

// State holds the live series of an agent.
type State struct {
	idleTTL   time.Duration
	edges     map[EdgeKey]*Edge
	listeners map[ListenerKey]*Listener
}

// NewState returns an empty state that drops series idle for idleTTL.
func NewState(idleTTL time.Duration) *State {
	return &State{idleTTL: idleTTL, edges: map[EdgeKey]*Edge{}, listeners: map[ListenerKey]*Listener{}}
}

// AddEdge accounts the statistics of the interval (start, end] to an edge.
// A new series starts at the start of the interval. FirstSeen and LastSeen
// advance only when the interval shows activity.
func (s *State) AddEdge(k EdgeKey, st EdgeStats, start, end time.Time) {
	e, ok := s.edges[k]
	if !ok {
		if !st.active() {
			return
		}
		e = &Edge{Start: start, FirstSeen: end}
		s.edges[k] = e
	}
	e.Total.add(&st)
	if st.active() && end.After(e.LastSeen) {
		e.LastSeen = end
	}
}

// AddListener records that a listener was seen at t.
func (s *State) AddListener(k ListenerKey, t time.Time) {
	l, ok := s.listeners[k]
	if !ok {
		l = &Listener{FirstSeen: t}
		s.listeners[k] = l
	}
	if t.After(l.LastSeen) {
		l.LastSeen = t
	}
}

// BeginInterval prepares the series for the statistics of a new interval:
// the connections of an edge are open only if the interval reports them.
func (s *State) BeginInterval() {
	for _, e := range s.edges {
		e.Total.OpenConns = 0
	}
}

// Expire drops the series whose last activity is older than the idle TTL
// and returns how many were dropped.
func (s *State) Expire(now time.Time) int {
	n := 0
	for k, e := range s.edges {
		if now.Sub(e.LastSeen) > s.idleTTL {
			delete(s.edges, k)
			n++
		}
	}
	for k, l := range s.listeners {
		if now.Sub(l.LastSeen) > s.idleTTL {
			delete(s.listeners, k)
			n++
		}
	}
	return n
}

// Edges returns the live edge series. The map must not be modified.
func (s *State) Edges() map[EdgeKey]*Edge { return s.edges }

// Listeners returns the live listener series. The map must not be modified.
func (s *State) Listeners() map[ListenerKey]*Listener { return s.listeners }

// LocalAddrs returns the specified local addresses of the series active
// since a time, such as the addresses of containers in other network
// namespaces, and those of the listeners still open then. An address of a
// series that has only been kept for its idle TTL may have moved to
// another host with its container.
func (s *State) LocalAddrs(since time.Time) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for k, e := range s.edges {
		if !e.LastSeen.Before(since) {
			add(k.LocalAddr)
		}
	}
	for k, l := range s.listeners {
		if !l.LastSeen.Before(since) {
			add(k.Addr)
		}
	}
	return out
}

// Segment tracks the start of the observation segment of an agent: the
// time from which every edge active on the host has reached the connector.
type Segment struct {
	idleTTL     time.Duration
	start       time.Time
	lastSuccess time.Time
}

// NewSegment starts a segment when the agent starts.
func NewSegment(start time.Time, idleTTL time.Duration) *Segment {
	return &Segment{idleTTL: idleTTL, start: start, lastSuccess: start}
}

// Start returns the start of the segment to send in a request made at now.
// While requests succeed it is the start of the agent. If they have failed
// for longer than the idle TTL minus a minute, edges that ended in the
// meantime may have been dropped before reaching the connector; the
// segment then restarts at now minus the idle TTL, since the edges active
// after that are still being sent.
//
// The start is expressed by the current wall clock, which differs from the
// time it was taken at if the clock stepped since, e.g. when NTP corrected
// it after the agent started: the connector converts it with the current
// clock skew of the agent.
func (s *Segment) Start(now time.Time) time.Time {
	start := wall(s.start, now)
	if elapsed(now, s.lastSuccess) <= s.idleTTL-time.Minute {
		return start
	}
	if t := now.Add(-s.idleTTL); t.After(start) {
		return t
	}
	return start
}

// Succeeded records that a request made at now with the segment start
// start was delivered.
func (s *Segment) Succeeded(start, now time.Time) {
	s.start = start
	s.lastSuccess = now
}

// elapsed is the time that passed from t to now: by the monotonic clock
// when both times have a reading of it, which a step of the wall clock does
// not change; replaced in tests.
var elapsed = func(now, t time.Time) time.Duration { return now.Sub(t) }

// wall returns t by the wall clock of now. It keeps the monotonic reading
// of t, and equals t unless the wall clock stepped in between.
func wall(t, now time.Time) time.Time { return now.Add(-elapsed(now, t)) }
