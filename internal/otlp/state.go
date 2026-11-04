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
	// ContainerID is the full id of the container of the process
	// (container.id), which changes when the container is recreated; the
	// unit names the container by what stays.
	ContainerID string
	// UserID is the effective user id of the process (process.user.id) if
	// HasUserID. The agent sends it for the processes of Slurm jobs only,
	// with -job-users.
	UserID    uint32
	HasUserID bool
}

// EdgeKey identifies an edge series.
type EdgeKey struct {
	Role      string // RoleClient or RoleServer
	Proto     string // "tcp" or "udp"
	LocalAddr netip.Addr
	PeerAddr  netip.Addr
	// PeerFolded tells that the edge bundles the peers outside the internal
	// ranges of the agent; PeerAddr is then 0.0.0.0 or ::.
	PeerFolded bool
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
	// Of the active opens of a TCP client edge: the handshakes established
	// by duration, in the buckets of HandshakeBounds, and the sum of their
	// durations; the SYNs retransmitted; and the failures by reason, in the
	// order of FailReasons. ConnFails minus the sum of Fails failed for
	// another reason (ErrorOther).
	Handshakes     [len(HandshakeBounds) + 1]uint64
	HandshakeSumUs uint64
	SynRetrans     uint64
	Fails          [len(FailReasons)]uint64
}

// fails returns the failures for reason i of FailReasons, or for ErrorOther
// when i is len(FailReasons).
func (s *EdgeStats) fails(i int) uint64 {
	if i < len(s.Fails) {
		return s.Fails[i]
	}
	n := s.ConnFails
	for _, c := range s.Fails {
		n -= min(c, n)
	}
	return n
}

// handshakes returns the number of handshakes with a duration.
func (s *EdgeStats) handshakes() uint64 {
	var n uint64
	for _, c := range s.Handshakes {
		n += c
	}
	return n
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
	for i := range s.Handshakes {
		s.Handshakes[i] += o.Handshakes[i]
	}
	s.HandshakeSumUs += o.HandshakeSumUs
	s.SynRetrans += o.SynRetrans
	for i := range s.Fails {
		s.Fails[i] += o.Fails[i]
	}
}

// ListenerKey identifies a listener series.
type ListenerKey struct {
	Proto string
	Addr  netip.Addr
	Port  uint16
	NetNS uint32
	Process
}

// TranslationKey identifies a translation of addresses the host made, as
// conntrack holds it: the client connected to Virtual on VirtualPort, and
// the backend at Backend on BackendPort saw the connection from Source,
// which is Client unless the host replaced the address of the client.
type TranslationKey struct {
	Proto       string // "tcp" or "udp"
	NetNS       uint32
	Client      netip.Addr
	Virtual     netip.Addr
	VirtualPort uint16
	Source      netip.Addr
	Backend     netip.Addr
	BackendPort uint16
}

// Translation is the state of a translation series.
type Translation struct {
	FirstSeen time.Time
	LastSeen  time.Time
}

// Edge is the state of an edge series.
type Edge struct {
	// Start is when the cumulative counters started.
	Start     time.Time
	FirstSeen time.Time
	LastSeen  time.Time
	Total     EdgeStats
	// FailStart is when the counter of each reason of failure started, in
	// the order of FailReasons and then ErrorOther: the start of the
	// interval in which the reason first occurred on the edge, zero before.
	// A reason is sent from then on only, so that an edge does not carry
	// a data point for every reason, and the connector takes its first
	// value as new rather than as a baseline.
	FailStart [len(FailReasons) + 1]time.Time
}

// Listener is the state of a listener series.
type Listener struct {
	FirstSeen time.Time
	LastSeen  time.Time
}

// State holds the live series of an agent.
type State struct {
	idleTTL      time.Duration
	edges        map[EdgeKey]*Edge
	listeners    map[ListenerKey]*Listener
	translations map[TranslationKey]*Translation
	// oversized counts the series left out of requests because alone they
	// exceed the size of a request (see Requests).
	oversized uint64
}

// Oversized returns how many series were left out of requests because
// alone they exceed the size of a request (cumulative).
func (s *State) Oversized() uint64 { return s.oversized }

// NewState returns an empty state that drops series idle for idleTTL.
func NewState(idleTTL time.Duration) *State {
	return &State{idleTTL: idleTTL, edges: map[EdgeKey]*Edge{}, listeners: map[ListenerKey]*Listener{},
		translations: map[TranslationKey]*Translation{}}
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
	for i := range e.FailStart {
		if e.FailStart[i].IsZero() && st.fails(i) > 0 {
			e.FailStart[i] = start
		}
	}
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

// AddTranslation records that a translation was in use at t: a new
// connection went through it, or one was open.
func (s *State) AddTranslation(k TranslationKey, t time.Time) {
	x, ok := s.translations[k]
	if !ok {
		x = &Translation{FirstSeen: t}
		s.translations[k] = x
	}
	if t.After(x.LastSeen) {
		x.LastSeen = t
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
	for k, x := range s.translations {
		if now.Sub(x.LastSeen) > s.idleTTL {
			delete(s.translations, k)
			n++
		}
	}
	return n
}

// Edges returns the live edge series. The map must not be modified.
func (s *State) Edges() map[EdgeKey]*Edge { return s.edges }

// Listeners returns the live listener series. The map must not be modified.
func (s *State) Listeners() map[ListenerKey]*Listener { return s.listeners }

// Translations returns the live translation series. The map must not be
// modified.
func (s *State) Translations() map[TranslationKey]*Translation { return s.translations }

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
