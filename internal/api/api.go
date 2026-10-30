// Package api defines the types exchanged between shawk agents and clients.
package api

import (
	"net/url"
	"strconv"
	"time"
)

// DefaultPort is the default TCP port of the agent API.
const DefaultPort = 7464

// Info describes an agent.
type Info struct {
	Hostname string   `json:"hostname"`
	Version  string   `json:"version"`
	Kernel   string   `json:"kernel"`
	Addrs    []string `json:"addrs"` // addresses of the host
	// StartedAt is when the agent process started.
	StartedAt time.Time `json:"started_at"`
	// LedgerSince is when the ledger started recording. Dependencies before
	// it are unknown.
	LedgerSince time.Time `json:"ledger_since"`
	Interval    string    `json:"interval"`
	UDP         bool      `json:"udp"`   // whether UDP is traced
	Drops       uint64    `json:"drops"` // flow updates dropped in the kernel
}

// Stats are the statistics of an edge aggregated over a time window.
type Stats struct {
	Conns        uint64  `json:"conns"`
	ConnFails    uint64  `json:"conn_fails"`
	MaxOpenConns uint64  `json:"max_open_conns"`
	BytesSent    uint64  `json:"bytes_sent"`
	BytesRecv    uint64  `json:"bytes_recv"`
	MsgsSent     uint64  `json:"msgs_sent"`
	MsgsRecv     uint64  `json:"msgs_recv"`
	Retrans      uint64  `json:"retrans"`
	RTTAvgUs     float64 `json:"rtt_avg_us"`
}

// Edge is a dependency observed on a host: a bundled flow between a local
// process and a remote address. For an outgoing edge the local process is
// the client of RemoteAddr:Port; for an incoming edge it is the server
// listening on LocalAddr:Port.
type Edge struct {
	Direction  string    `json:"direction"` // "out" or "in"
	Proto      string    `json:"proto"`     // "tcp" or "udp"
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	Port       uint16    `json:"port"`
	NetNS      uint32    `json:"netns"`
	Unit       string    `json:"unit"`
	Comm       string    `json:"comm"`
	Exe        string    `json:"exe,omitempty"`
	Cgroup     string    `json:"cgroup,omitempty"`
	PID        uint32    `json:"pid,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Stats      Stats     `json:"stats"`
}

// Process returns a display name of the local process.
func (e *Edge) Process() string { return processName(e.Unit, e.Comm) }

// Listener is a listening TCP socket or a bound UDP server socket.
type Listener struct {
	Proto     string    `json:"proto"`
	Addr      string    `json:"addr"`
	Port      uint16    `json:"port"`
	NetNS     uint32    `json:"netns"`
	Unit      string    `json:"unit"`
	Comm      string    `json:"comm"`
	Exe       string    `json:"exe,omitempty"`
	PID       uint32    `json:"pid,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Process returns a display name of the owner process.
func (l *Listener) Process() string { return processName(l.Unit, l.Comm) }

func processName(unit, comm string) string {
	switch {
	case comm == "" && unit == "":
		return "?"
	case unit == "":
		return comm
	case comm == "":
		return "(" + unit + ")"
	}
	return comm + " (" + unit + ")"
}

// EdgeQuery selects edges active in [Since, Until]. Empty fields match
// everything.
type EdgeQuery struct {
	Direction  string
	Proto      string
	LocalAddr  string
	RemoteAddr string
	Port       uint16
	Unit       string
	Comm       string
	Since      time.Time
	Until      time.Time
}

// Values encodes the query as URL parameters.
func (q EdgeQuery) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("direction", q.Direction)
	set("proto", q.Proto)
	set("local", q.LocalAddr)
	set("remote", q.RemoteAddr)
	set("unit", q.Unit)
	set("comm", q.Comm)
	if q.Port != 0 {
		v.Set("port", strconv.Itoa(int(q.Port)))
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339))
	}
	if !q.Until.IsZero() {
		v.Set("until", q.Until.UTC().Format(time.RFC3339))
	}
	return v
}

// ParseEdgeQuery decodes URL parameters encoded by EdgeQuery.Values.
func ParseEdgeQuery(v url.Values) (EdgeQuery, error) {
	q := EdgeQuery{
		Direction:  v.Get("direction"),
		Proto:      v.Get("proto"),
		LocalAddr:  v.Get("local"),
		RemoteAddr: v.Get("remote"),
		Unit:       v.Get("unit"),
		Comm:       v.Get("comm"),
	}
	if s := v.Get("port"); s != "" {
		p, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return q, err
		}
		q.Port = uint16(p)
	}
	var err error
	if q.Since, err = parseTime(v.Get("since")); err != nil {
		return q, err
	}
	if q.Until, err = parseTime(v.Get("until")); err != nil {
		return q, err
	}
	return q, nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

// EdgesResponse is the response of GET /api/v1/edges.
type EdgesResponse struct {
	Edges []Edge `json:"edges"`
}

// ListenersResponse is the response of GET /api/v1/listeners.
type ListenersResponse struct {
	Listeners []Listener `json:"listeners"`
}
