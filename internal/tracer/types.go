package tracer

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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

// Proto is an IP protocol number, or ProtoUnix.
type Proto uint8

const (
	ProtoTCP Proto = 6
	ProtoUDP Proto = 17
	// ProtoUnix stands for Unix stream and seqpacket sockets: not an IP
	// protocol number but IPPROTO_RAW, which shawk never traces, as
	// PROTO_UNIX of the BPF programs.
	ProtoUnix Proto = 255
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoUnix:
		return "unix"
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
	case "unix":
		return ProtoUnix, nil
	}
	return 0, fmt.Errorf("invalid protocol %q", s)
}

// FlowKey identifies a bundled flow. All connections or datagrams between
// LocalAddr and RemoteAddr to the same service Port by the same process
// identity are bundled into one flow. A flow of Unix sockets (ProtoUnix)
// bundles the connections of a client process to the socket named Path
// instead: it is outgoing, without addresses or port.
type FlowKey struct {
	Direction Direction
	Proto     Proto
	// Path is the name of the Unix socket a flow of ProtoUnix connected to
	// (see UnixName); empty otherwise.
	Path       string
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	// Port is the service port: the remote port for outgoing flows and the
	// local port for incoming flows.
	Port uint16
	// NetNS is the network namespace of the local socket: for a flow of
	// Unix sockets, of the client socket.
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

// WireProtocol is the protocol a TCP connection speaks, as the first
// payload that the local socket sent shows it: the request of a client, the
// answer or the greeting of a server. Of TLS, a client tells the highest
// version it offers, a server the version it chose. It matches enum
// shawk_wire_proto of the BPF programs.
type WireProtocol uint8

const (
	// WireUnknown is a first payload of none of the protocols below.
	WireUnknown WireProtocol = iota
	// WireTLS is TLS whose version the bytes read do not tell.
	WireTLS
	// WireTLS10 is TLS 1.0, or SSL 3.0 or 2.0.
	WireTLS10
	WireTLS11
	WireTLS12
	WireTLS13
	// WireHTTP1 is HTTP/1.x in clear text.
	WireHTTP1
	// WireHTTP2 is HTTP/2 in clear text (h2c), as gRPC without TLS.
	WireHTTP2
	WireSSH
	// WirePostgres is PostgreSQL in clear text: a client that starts
	// without TLS, or a server that refuses it. A request of GSSAPI or a
	// CancelRequest, and a server that accepts GSSAPI, add no protocol.
	WirePostgres
	// WireMySQL is MySQL without a request of TLS, or the greeting of its
	// server, which does not tell.
	WireMySQL
	// WireRedis is RESP, the protocol of Redis and Valkey.
	WireRedis
	// WireSlurm is the RPCs of Slurm.
	WireSlurm
	// WirePostgresTLS is PostgreSQL whose client asks for TLS, or whose
	// server accepts it; the version of TLS is not seen.
	WirePostgresTLS
	// WireMySQLTLS is MySQL whose client asks for TLS.
	WireMySQLTLS

	// NumWireProtocols is the number of wire protocols, at most 16.
	NumWireProtocols = 15
)

// wireNames are the names of the wire protocols, as the agent sends them.
var wireNames = [NumWireProtocols]string{
	"unknown", "tls", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3", "http1", "http2_grpc", "ssh", "postgres", "mysql",
	"redis", "slurm_rpc", "postgres_tls", "mysql_tls",
}

func (p WireProtocol) String() string {
	if p < NumWireProtocols {
		return wireNames[p]
	}
	return fmt.Sprintf("wire(%d)", uint8(p))
}

// WireProtocols is a set of wire protocols, a bit (1 << WireProtocol) each.
type WireProtocols uint32

// Has tells whether the set holds p.
func (s WireProtocols) Has(p WireProtocol) bool { return p < NumWireProtocols && s&(1<<p) != 0 }

// List returns the protocols of the set in order.
func (s WireProtocols) List() []WireProtocol {
	var out []WireProtocol
	for p := range WireProtocol(NumWireProtocols) {
		if s.Has(p) {
			out = append(out, p)
		}
	}
	return out
}

// String joins the names of the protocols of the set with commas.
func (s WireProtocols) String() string {
	names := make([]string, 0, NumWireProtocols)
	for _, p := range s.List() {
		names = append(names, p.String())
	}
	return strings.Join(names, ",")
}

// MarshalJSON encodes the set as the list of the names of its protocols.
func (s WireProtocols) MarshalJSON() ([]byte, error) {
	names := make([]string, 0, NumWireProtocols)
	for _, p := range s.List() {
		names = append(names, p.String())
	}
	return json.Marshal(names)
}

// FlowStats holds the statistics of a bundled flow in an interval.
type FlowStats struct {
	Conns      uint64 // TCP and Unix connections established
	ConnFails  uint64 // TCP active opens and Unix connects that failed
	OpenConns  uint64 // TCP and Unix connections open at the end of the interval
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
	// Fails are the TCP active opens and Unix connects that failed, by
	// FailReason. ConnFails minus their sum failed for another reason.
	Fails [NumFailReasons]uint64
	// Protocols are the wire protocols of the TCP connections whose first
	// payload the local socket sent (Options.ClassifyProtocols).
	Protocols WireProtocols `json:",omitempty"`
	PID       uint32        // last observed process id
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
	s.Protocols |= o.Protocols
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

// Listener is a listening TCP socket, a bound UDP server socket, or a
// listening Unix stream or seqpacket socket, which has a Path (see
// UnixName) rather than an address and a port.
type Listener struct {
	Proto Proto
	Path  string
	Addr  netip.Addr
	Port  uint16
	NetNS uint32
	// KernelChosen tells that the kernel chose the port: the socket was not
	// bound to a port (bind(2) to port 0, or listen(2) without bind), as
	// srun does without SrunPortRange. Of a SO_REUSEPORT group, true if it
	// is for any socket of the group.
	KernelChosen bool
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
	// Translations are the translations of addresses with a new or a live
	// conntrack entry in the interval (Options.LearnTranslations).
	Translations []Translation
	// TranslationDrops is the cumulative number of translations not
	// learned, or not kept while their connections are open, because the
	// in-kernel tables were full.
	TranslationDrops uint64
	// CgroupEventDrops is the cumulative number of cgroups created whose
	// event the kernel dropped because the ring buffer was full: their
	// paths are not learned (#126).
	CgroupEventDrops uint64
}

// UnixName returns the name of a Unix socket from the bytes of its sun_path
// (struct sockaddr_un), as ss(8) shows it: a path as it is, and an abstract
// name, which starts with a NUL, with @ for that NUL. Bytes that are not
// printable characters of valid UTF-8 are escaped as \xHH, a backslash as
// \\, and an @ that a path starts with as \x40, so that a name is valid
// UTF-8 and tells an abstract name from a path.
func UnixName(b []byte) string {
	var sb strings.Builder
	if len(b) > 0 && b[0] == 0 {
		sb.WriteByte('@')
		b = b[1:]
	} else if len(b) > 0 && b[0] == '@' {
		sb.WriteString(`\x40`)
		b = b[1:]
	}
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		switch {
		case r == '\\':
			sb.WriteString(`\\`)
		case r == utf8.RuneError && n <= 1, !unicode.IsPrint(r):
			for _, c := range b[:max(n, 1)] {
				fmt.Fprintf(&sb, `\x%02x`, c)
			}
		default:
			sb.Write(b[:n])
		}
		b = b[max(n, 1):]
	}
	return sb.String()
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
