package tracer

import (
	"fmt"
	"net/netip"
	"time"
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
	// Folded tells that the flow bundles the peers outside the internal
	// ranges (see FoldMode): RemoteAddr is then 0.0.0.0 or ::, which stands
	// for the network 0.0.0.0/0 or ::/0.
	Folded bool
}

// FoldMode tells which flows fold their peers outside the internal ranges
// into one flow per local endpoint, so that an internet-facing host does
// not keep a flow per client address. It matches enum shawk_fold_mode of
// the BPF programs.
type FoldMode uint8

const (
	// FoldNone keeps the address of every peer.
	FoldNone FoldMode = 0
	// FoldIn folds the external peers of incoming flows (the clients of a
	// local server); outgoing flows keep the address of their server.
	FoldIn FoldMode = 1
	// FoldAll folds the external peers of all flows.
	FoldAll FoldMode = 2
)

func (m FoldMode) String() string {
	switch m {
	case FoldNone:
		return "none"
	case FoldIn:
		return "in"
	case FoldAll:
		return "all"
	}
	return fmt.Sprintf("fold(%d)", uint8(m))
}

// ParseFoldMode parses the string form of a FoldMode.
func ParseFoldMode(s string) (FoldMode, error) {
	for _, m := range []FoldMode{FoldNone, FoldIn, FoldAll} {
		if s == m.String() {
			return m, nil
		}
	}
	return 0, fmt.Errorf("invalid fold mode %q (none, in or all)", s)
}

// KernelComm is the Comm of flows and listeners whose socket belongs to the
// kernel rather than to a process: sockets the kernel opens itself (the
// clients of NFS, iSCSI, CIFS or Ceph, nfsd), and listeners that no process
// holds. Such flows and listeners have no PID and a CgroupID of zero, which
// no process has. It matches KERNEL_COMM of the BPF programs.
const KernelComm = "~kernel"

// KernelOwned reports whether the owner of a flow or a listener with comm
// and cgroupID is the kernel.
func KernelOwned(comm string, cgroupID uint64) bool {
	return comm == KernelComm && cgroupID == 0
}

// HandshakeBounds are the upper bounds, inclusive, of the buckets of the
// handshake durations of TCP active opens (FlowStats.Handshakes), as
// hs_bucket() of the BPF programs counts them; the last bucket has none.
var HandshakeBounds = [...]time.Duration{
	100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond, time.Millisecond,
	2500 * time.Microsecond, 10 * time.Millisecond, 50 * time.Millisecond, 250 * time.Millisecond,
	time.Second, 3 * time.Second,
}

// FailReason tells why a TCP active open failed. It matches enum
// shawk_fail_reason of the BPF programs.
type FailReason uint8

const (
	// FailRefused is a reset from the peer (no listener) or an ICMP port
	// unreachable, which firewalls also send to reject.
	FailRefused FailReason = iota
	// FailTimeout is no answer to any SYN.
	FailTimeout
	// FailUnreachable is an ICMP error from a router or a firewall, or no
	// answer to ARP or neighbor discovery.
	FailUnreachable
	// FailLocal is a connect that sent no SYN, e.g. without a free local
	// port.
	FailLocal
	// FailAborted is a connect that the application gave up first.
	FailAborted

	// NumFailReasons is the number of reasons, the length of
	// FlowStats.Fails.
	NumFailReasons = 5
)

func (r FailReason) String() string {
	switch r {
	case FailRefused:
		return "refused"
	case FailTimeout:
		return "timeout"
	case FailUnreachable:
		return "unreachable"
	case FailLocal:
		return "local"
	case FailAborted:
		return "aborted"
	}
	return fmt.Sprintf("reason(%d)", uint8(r))
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
	// Handshakes are the TCP active opens established, by the duration of
	// their handshake from connect(2) (buckets of HandshakeBounds), and
	// HandshakeSumUs the sum of their durations. Connections established
	// without a duration (TCP_REPAIR, TCP_FASTOPEN_CONNECT) and
	// simultaneous opens are counted in Conns only.
	Handshakes     [len(HandshakeBounds) + 1]uint64
	HandshakeSumUs uint64
	// SynRetrans are the SYNs that the TCP active opens counted in Conns
	// or ConnFails retransmitted.
	SynRetrans uint64
	// Fails are the TCP active opens that failed, by FailReason. ConnFails
	// minus their sum failed for another reason.
	Fails [NumFailReasons]uint64
	PID   uint32 // last observed process id
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
	for i := range s.Handshakes {
		s.Handshakes[i] += o.Handshakes[i]
	}
	s.HandshakeSumUs += o.HandshakeSumUs
	s.SynRetrans += o.SynRetrans
	for i := range s.Fails {
		s.Fails[i] += o.Fails[i]
	}
	if o.PID != 0 {
		s.PID = o.PID
	}
}

// HandshakeCount returns the number of handshakes with a duration.
func (s *FlowStats) HandshakeCount() uint64 {
	var n uint64
	for _, c := range s.Handshakes {
		n += c
	}
	return n
}

// OtherFails returns the failed active opens without a FailReason.
func (s *FlowStats) OtherFails() uint64 {
	n := s.ConnFails
	for _, c := range s.Fails {
		n -= min(c, n)
	}
	return n
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
	// kernel (Comm is then KernelComm) or the owner could not be resolved.
	PID      uint32
	Comm     string
	CgroupID uint64
}

// Snapshot is the result of a collection interval.
type Snapshot struct {
	Flows     []Flow
	Listeners []Listener
	// Drops is the cumulative number of flow updates dropped because the
	// flow table could not be updated, usually because it was full.
	Drops uint64
	// Contended is the part of Drops that the kernel refused because
	// another update on the same CPU held the lock of their bucket (#119).
	Contended uint64
	// CgroupEventDrops is the cumulative number of cgroups created whose
	// event the kernel dropped because the ring buffer was full: their
	// paths are not learned (#126).
	CgroupEventDrops uint64
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
