package tracer

import (
	"fmt"
	"net/netip"
)

// Direction is the direction of a flow seen from the local host.
type Direction uint8

const (
	// DirOut means the local process opened the connection (client side).
	DirOut Direction = 1
	// DirIn means the local process accepted the connection (server side).
	DirIn Direction = 2
)

func (d Direction) String() string {
	switch d {
	case DirOut:
		return "out"
	case DirIn:
		return "in"
	}
	return fmt.Sprintf("dir(%d)", uint8(d))
}

// ParseDirection parses the string form of a Direction.
func ParseDirection(s string) (Direction, error) {
	switch s {
	case "out":
		return DirOut, nil
	case "in":
		return DirIn, nil
	}
	return 0, fmt.Errorf("invalid direction %q", s)
}

// Proto is an IP protocol number.
type Proto uint8

const (
	ProtoTCP Proto = 6
	ProtoUDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return fmt.Sprintf("proto(%d)", uint8(p))
}

// ParseProto parses the string form of a Proto.
func ParseProto(s string) (Proto, error) {
	switch s {
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	}
	return 0, fmt.Errorf("invalid protocol %q", s)
}

// FlowKey identifies a bundled flow. All connections or datagrams between
// LocalAddr and RemoteAddr to the same service Port by the same process
// identity are bundled into one flow.
type FlowKey struct {
	Direction  Direction
	Proto      Proto
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	// Port is the service port: the remote port for outgoing flows and the
	// local port for incoming flows.
	Port     uint16
	NetNS    uint32
	CgroupID uint64
	Comm     string
}

// FlowStats holds the statistics of a bundled flow in an interval.
type FlowStats struct {
	Conns      uint64 // TCP connections established
	ConnFails  uint64 // TCP active opens that failed
	OpenConns  uint64 // TCP connections open at the end of the interval
	BytesSent  uint64
	BytesRecv  uint64
	MsgsSent   uint64 // UDP datagrams sent
	MsgsRecv   uint64 // UDP datagrams received
	Retrans    uint64 // TCP retransmitted segments
	RTTSumUs   uint64
	RTTSamples uint64
	PID        uint32 // last observed process id
}

// Add accumulates o into s.
func (s *FlowStats) Add(o FlowStats) {
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
	if o.PID != 0 {
		s.PID = o.PID
	}
}

// Flow is a bundled flow with its statistics.
type Flow struct {
	FlowKey
	FlowStats
}

// Listener is a listening TCP socket or a bound UDP server socket.
type Listener struct {
	Proto Proto
	Addr  netip.Addr
	Port  uint16
	NetNS uint32
	// Owner of the socket. PID is zero when the socket is owned by the
	// kernel or the owner could not be resolved.
	PID      uint32
	Comm     string
	CgroupID uint64
}

// Snapshot is the result of a collection interval.
type Snapshot struct {
	Flows     []Flow
	Listeners []Listener
	// Drops is the cumulative number of flow updates dropped because the
	// flow table was full, and of TCP connections lost because the kernel
	// could not allocate socket storage for them.
	Drops uint64
}

func addrFrom16(b [16]uint8) netip.Addr {
	return netip.AddrFrom16(b).Unmap()
}

func commString(c [16]int8) string { return cString(c[:]) }

func cString(c []int8) string {
	b := make([]byte, 0, len(c))
	for _, v := range c {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
