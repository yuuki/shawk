package tracer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The tests of handshakes and failures of active opens run in a network
// namespace of their own, which the tracer alone traces, and whose sysctls
// they change. They use loopback only: a listener whose accept queue is full
// drops SYNs without an answer, and raw sockets read the SYNs and send the
// ICMP errors that routers and firewalls would. The virtual machines of
// test/vm hold the test binary alone, without ip, tc or nft.

// handshakeTracer returns a tracer of a network namespace of its own, and a
// function running f in that namespace.
func handshakeTracer(t *testing.T, maxFlows uint32) (*Tracer, func(func())) {
	t.Helper()
	skipIfNoNetwork(t, "tcp4")
	run, ns := newNetNS(t)
	return startTracer(t, Options{NetNS: ns, MaxFlows: maxFlows}), run
}

// loopback4 returns the address 127.0.0.n.
func loopback4(n byte) netip.Addr { return netip.AddrFrom4([4]byte{127, 0, 0, n}) }

// testSock is a TCP socket closed at the end of its test, unless closed
// before.
type testSock struct {
	fd     int
	closed bool
}

func (s *testSock) close() {
	if !s.closed {
		s.closed = true
		unix.Close(s.fd)
	}
}

// newSock returns a TCP socket in the network namespace of the thread,
// bound to src unless src is invalid, with setup applied to it before it
// connects.
func newSock(t *testing.T, src netip.Addr, nonblock bool, setup func(fd int) error) *testSock {
	t.Helper()
	typ := unix.SOCK_STREAM | unix.SOCK_CLOEXEC
	if nonblock {
		typ |= unix.SOCK_NONBLOCK
	}
	fd, err := unix.Socket(unix.AF_INET, typ, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &testSock{fd: fd}
	t.Cleanup(s.close)
	if src.IsValid() {
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: src.As4()}); err != nil {
			t.Fatalf("binding %s: %v", src, err)
		}
	}
	if setup != nil {
		if err := setup(fd); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s *testSock) connect(dst netip.AddrPort) error {
	return unix.Connect(s.fd, &unix.SockaddrInet4{Addr: dst.Addr().As4(), Port: int(dst.Port())})
}

// disconnect disconnects the socket with connect(AF_UNSPEC), which frees its
// local port unless it was bound, and sets its error to ECONNRESET.
func (s *testSock) disconnect(t *testing.T) {
	t.Helper()
	unspec := [16]byte{} // sa_family AF_UNSPEC
	if _, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(s.fd), uintptr(unsafe.Pointer(&unspec[0])), uintptr(len(unspec))); errno != 0 {
		t.Fatalf("connect(AF_UNSPEC): %v", errno)
	}
}

// wait waits for a non-blocking connect to complete and returns its error.
func (s *testSock) wait(t *testing.T, timeout time.Duration) error {
	t.Helper()
	fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLOUT}}
	for {
		n, err := unix.Poll(fds, int(timeout.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatalf("the connect did not complete within %v", timeout)
		}
		break
	}
	// Kernels without tcp_done_with_error() (5.14, RHEL 9, and others before
	// 6.11 or its backports) wake the socket up before tcp_done(), and reading
	// SO_ERROR before the tracepoint would take its error (fail_reason()).
	time.Sleep(20 * time.Millisecond)
	errno, err := unix.GetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		t.Fatal(err)
	}
	if errno != 0 {
		return unix.Errno(errno)
	}
	return nil
}

// totalRetrans returns the segments that the socket retransmitted, which
// TCP_INFO reports for closed sockets too.
func (s *testSock) totalRetrans(t *testing.T) uint64 {
	t.Helper()
	info, err := unix.GetsockoptTCPInfo(s.fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(info.Total_retrans)
}

// blackhole listens on 127.0.0.1 with an accept queue that two connections
// fill, so that it drops the SYNs it receives without an answer, as a host
// that is gone or a firewall that drops. accept makes room for one more
// connection.
func blackhole(t *testing.T) (addr netip.AddrPort, accept func()) {
	t.Helper()
	ln := newSock(t, loopback4(1), false, nil)
	// A backlog of 1 holds two connections: sk_acceptq_is_full() compares
	// with >.
	if err := unix.Listen(ln.fd, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(ln.fd)
	if err != nil {
		t.Fatal(err)
	}
	addr = netip.AddrPortFrom(loopback4(1), uint16(sa.(*unix.SockaddrInet4).Port))
	for range 2 {
		if err := newSock(t, loopback4(1), false, nil).connect(addr); err != nil {
			t.Fatal(err)
		}
	}
	// TCP_INFO of a listener reports the length of its accept queue.
	for deadline := time.Now().Add(5 * time.Second); ; {
		info, err := unix.GetsockoptTCPInfo(ln.fd, unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			t.Fatal(err)
		}
		if info.Unacked == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the accept queue holds %d connections", info.Unacked)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr, func() {
		fd, _, err := unix.Accept4(ln.fd, unix.SOCK_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
	}
}

// synReader reads the TCP segments that the network namespace of the thread
// receives, through a raw socket.
type synReader struct{ fd int }

func newSYNReader(t *testing.T) synReader {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		skipUnavailable(t, "raw socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	return synReader{fd}
}

// next returns the IP header and the first 8 bytes of the TCP header of the
// next SYN from src to the port dport, what an ICMP error quotes.
func (r synReader) next(t *testing.T, src netip.Addr, dport uint16) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("no SYN from %s: %v", src, err)
		}
		p := buf[:n]
		if n < 20 || p[0]>>4 != 4 {
			continue
		}
		ihl := int(p[0]&0xf) * 4
		if n < ihl+14 || p[9] != unix.IPPROTO_TCP || netip.AddrFrom4([4]byte(p[12:16])) != src {
			continue
		}
		tcp := p[ihl:]
		if binary.BigEndian.Uint16(tcp[2:]) == dport && tcp[13]&(tcpSYN|0x10) == tcpSYN {
			return append([]byte(nil), p[:ihl+8]...)
		}
	}
}

// sendICMPUnreachable sends an ICMP destination unreachable of code about a
// packet to its source, as a router or a firewall does; quoted is the IP
// header and the first 8 bytes of the payload of the packet.
func sendICMPUnreachable(t *testing.T, code uint8, quoted []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		skipUnavailable(t, "raw socket: %v", err)
	}
	defer unix.Close(fd)
	msg := make([]byte, 8+len(quoted))
	msg[0] = 3 // destination unreachable
	msg[1] = code
	copy(msg[8:], quoted)
	binary.BigEndian.PutUint16(msg[2:], inetChecksum(msg))
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrInet4{Addr: [4]byte(quoted[12:16])}); err != nil {
		t.Fatal(err)
	}
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		v := uint32(b[i]) << 8
		if i+1 < len(b) {
			v |= uint32(b[i+1])
		}
		sum += v
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// clientFlow returns the outgoing TCP flow from laddr to dst, summed over the
// snapshots, or nil.
func clientFlow(laddr netip.Addr, dst netip.AddrPort, snaps ...*Snapshot) *Flow {
	var found *Flow
	for _, snap := range snaps {
		for i := range snap.Flows {
			f := &snap.Flows[i]
			if f.Direction != DirOut || f.Proto != ProtoTCP || f.LocalAddr != laddr || f.RemoteAddr != dst.Addr() || f.Port != dst.Port() {
				continue
			}
			if found == nil {
				found = &Flow{FlowKey: f.FlowKey}
			}
			found.FlowStats.Add(f.FlowStats)
		}
	}
	return found
}

// bucketOf returns the bucket of HandshakeBounds that a duration falls in.
func bucketOf(d time.Duration) int {
	for i, b := range HandshakeBounds {
		if d <= b {
			return i
		}
	}
	return len(HandshakeBounds)
}

// TestHandshakeLoopback checks that every connection established on
// loopback counts one short handshake on the client side, and none on the
// server side.
func TestHandshakeLoopback(t *testing.T) {
	tr, run := handshakeTracer(t, 0)
	const conns = 5
	var srv netip.AddrPort
	run(func() {
		srv = echoServer(t, "tcp4", "127.0.0.1:0").Addr().(*net.TCPAddr).AddrPort()
		for range conns {
			c, err := net.Dial("tcp4", srv.String())
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, c, 100)
			c.Close()
		}
	})
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := findFlow(snap.Flows, DirOut, ProtoTCP, srv.Port(), srv.Addr())
	if out == nil || out.Conns != conns || out.HandshakeCount() != conns || out.SynRetrans != 0 || out.ConnFails != 0 {
		t.Fatalf("client flow = %+v", out)
	}
	// Loopback handshakes take 0.1 to 0.3 ms, more in emulated virtual
	// machines: the bound is loose.
	for i, n := range out.Handshakes {
		if n != 0 && i > bucketOf(50*time.Millisecond) {
			t.Errorf("%d handshakes in bucket %d, above 50 ms: %v", n, i, out.Handshakes)
		}
	}
	if out.HandshakeSumUs == 0 || out.HandshakeSumUs > conns*50000 {
		t.Errorf("handshakes took %d µs in all", out.HandshakeSumUs)
	}
	in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
	if in == nil || in.Conns != conns || in.HandshakeCount() != 0 || in.HandshakeSumUs != 0 || in.SynRetrans != 0 {
		t.Errorf("server flow = %+v", in)
	}
}

// TestHandshakeLostSYN checks a connection whose first SYN was lost: a full
// accept queue drops it, and the SYN retransmitted after 1 s gets through
// once a connection was accepted, with either schedule of retransmissions.
func TestHandshakeLostSYN(t *testing.T) {
	tr, run := handshakeTracer(t, 0)
	src := loopback4(5)
	var (
		hole      netip.AddrPort
		retrans   uint64
		overflows uint64
		took      time.Duration
	)
	run(func() {
		var accept func()
		hole, accept = blackhole(t)
		before := tcpExtCounter(t, "ListenOverflows")
		s := newSock(t, src, true, nil)
		start := time.Now()
		if err := s.connect(hole); !errors.Is(err, unix.EINPROGRESS) {
			t.Fatalf("connect: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		accept()
		if err := s.wait(t, 5*time.Second); err != nil {
			t.Fatalf("connect: %v", err)
		}
		took = time.Since(start)
		retrans = s.totalRetrans(t)
		overflows = tcpExtCounter(t, "ListenOverflows") - before
	})
	if retrans != 1 || overflows != 1 {
		t.Fatalf("%d SYNs retransmitted and %d listen overflows, want 1 and 1", retrans, overflows)
	}
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := clientFlow(src, hole, snap)
	if out == nil || out.Conns != 1 || out.ConnFails != 0 || out.SynRetrans != 1 || out.HandshakeCount() != 1 {
		t.Fatalf("client flow = %+v", out)
	}
	// The retransmission timer may expire up to a tick before 1 s.
	d := time.Duration(out.HandshakeSumUs) * time.Microsecond
	if d < 900*time.Millisecond || d > took || out.Handshakes[bucketOf(d)] != 1 {
		t.Errorf("handshake of %v (connect took %v) in the buckets %v", d, took, out.Handshakes)
	}
}

// TestConnectFailureReasons checks the reason of failed active opens that a
// reset, ICMP errors and the application end.
func TestConnectFailureReasons(t *testing.T) {
	tr, run := handshakeTracer(t, 0)
	type attempt struct {
		name   string
		src    netip.Addr
		dst    netip.AddrPort
		errno  error // what connect(2) returns
		reason FailReason
	}
	var attempts []attempt
	run(func() {
		hole, _ := blackhole(t)
		syns := newSYNReader(t)
		// A port of 127.0.0.1 without a listener, which resets.
		closed := newSock(t, loopback4(1), false, nil)
		sa, err := unix.Getsockname(closed.fd)
		if err != nil {
			t.Fatal(err)
		}
		closedAddr := netip.AddrPortFrom(loopback4(1), uint16(sa.(*unix.SockaddrInet4).Port))
		attempts = append(attempts, attempt{"reset", loopback4(2), closedAddr, unix.ECONNREFUSED, FailRefused})
		s := newSock(t, loopback4(2), false, nil)
		if err := s.connect(closedAddr); !errors.Is(err, unix.ECONNREFUSED) {
			t.Fatalf("connect to a closed port: %v", err)
		}

		// ICMP errors close a socket in SYN_SENT that no process holds,
		// e.g. while a non-blocking connect is in progress.
		for i, c := range []struct {
			name   string
			code   uint8
			errno  unix.Errno
			reason FailReason
		}{
			{"ICMP port unreachable", 3, unix.ECONNREFUSED, FailRefused},
			{"ICMP host unreachable", 1, unix.EHOSTUNREACH, FailUnreachable},
			{"ICMP network unreachable", 0, unix.ENETUNREACH, FailUnreachable},
			{"ICMP host unknown", 7, unix.EHOSTDOWN, FailUnreachable},
			{"ICMP administratively prohibited", 13, unix.EHOSTUNREACH, FailUnreachable},
		} {
			src := loopback4(byte(10 + i))
			attempts = append(attempts, attempt{c.name, src, hole, c.errno, c.reason})
			s := newSock(t, src, true, nil)
			if err := s.connect(hole); !errors.Is(err, unix.EINPROGRESS) {
				t.Fatalf("%s: connect: %v", c.name, err)
			}
			sendICMPUnreachable(t, c.code, syns.next(t, src, hole.Port()))
			if err := s.wait(t, 5*time.Second); !errors.Is(err, c.errno) {
				t.Fatalf("%s: connect: %v, want %v", c.name, err, c.errno)
			}
		}

		// The application gives up before an answer, also on a socket that
		// connect(AF_UNSPEC) left with the error ECONNRESET.
		srv := echoServer(t, "tcp4", "127.0.0.1:0").Addr().(*net.TCPAddr).AddrPort()
		for i, reused := range []bool{false, true} {
			name := "closed by the application"
			if reused {
				name += " after connect(AF_UNSPEC)"
			}
			src := loopback4(byte(3 + i))
			attempts = append(attempts, attempt{name, src, hole, nil, FailAborted})
			s := newSock(t, src, true, nil)
			if reused {
				if err := s.connect(srv); !errors.Is(err, unix.EINPROGRESS) {
					t.Fatalf("connect: %v", err)
				}
				if err := s.wait(t, 5*time.Second); err != nil {
					t.Fatal(err)
				}
				s.disconnect(t)
			}
			if err := s.connect(hole); !errors.Is(err, unix.EINPROGRESS) {
				t.Fatalf("connect: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			s.close()
		}
	})
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range attempts {
		out := clientFlow(a.src, a.dst, snap)
		if out == nil || out.Conns != 0 || out.ConnFails != 1 || out.Fails[a.reason] != 1 || out.OtherFails() != 0 ||
			out.SynRetrans != 0 || out.HandshakeCount() != 0 {
			t.Errorf("%s: flow = %+v, want a failure %v", a.name, out, a.reason)
		}
	}
}

// TestConnectFailureMPTCP checks the reason of an MPTCP connect that an
// ICMP error fails, which kernels without tcp_done_with_error() (5.14, RHEL
// 9) move from the first subflow
// to the MPTCP socket before the subflow closes.
func TestConnectFailureMPTCP(t *testing.T) {
	tr, run := handshakeTracer(t, 0)
	src := loopback4(20)
	var hole netip.AddrPort
	run(func() {
		enableMPTCP(t)
		hole, _ = blackhole(t)
		syns := newSYNReader(t)
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, ipprotoMPTCP)
		if err != nil {
			skipUnavailable(t, "MPTCP is unavailable: %v", err)
		}
		s := &testSock{fd: fd}
		t.Cleanup(s.close)
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: src.As4()}); err != nil {
			t.Fatal(err)
		}
		if err := s.connect(hole); !errors.Is(err, unix.EINPROGRESS) {
			t.Fatalf("connect: %v", err)
		}
		sendICMPUnreachable(t, 3, syns.next(t, src, hole.Port()))
		if err := s.wait(t, 5*time.Second); !errors.Is(err, unix.ECONNREFUSED) {
			t.Fatalf("connect: %v, want %v", err, unix.ECONNREFUSED)
		}
	})
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := clientFlow(src, hole, snap)
	if out == nil || out.ConnFails != 1 || out.Fails[FailRefused] != 1 || out.SynRetrans != 0 {
		t.Errorf("flow = %+v, want a refused connect", out)
	}
}

// TestConnectFailureTimeout checks connects that time out, under both
// schedules of SYN retransmissions where the kernel has linear timeouts.
func TestConnectFailureTimeout(t *testing.T) {
	const linear = "/proc/sys/net/ipv4/tcp_syn_linear_timeouts"
	for _, tc := range []struct {
		name   string
		linear string // tcp_syn_linear_timeouts, if the kernel has it
	}{
		{"exponential", "0"},
		{"linear", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, run := handshakeTracer(t, 0)
			src := loopback4(4)
			var (
				hole    netip.AddrPort
				retrans uint64
				skip    string
			)
			run(func() {
				if err := os.WriteFile(linear, []byte(tc.linear), 0o644); errors.Is(err, os.ErrNotExist) {
					if tc.linear != "0" {
						// Not an error in strict mode: the kernel predates
						// the linear timeouts.
						skip = "the kernel has no linear timeouts of SYNs"
						return
					}
				} else if err != nil {
					t.Fatal(err)
				}
				hole, _ = blackhole(t)
				// One retransmission besides the linear ones: about 3 s.
				// A blocking connect would disconnect the socket when it
				// fails, which clears the count of retransmissions.
				s := newSock(t, src, true, func(fd int) error {
					return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_SYNCNT, 1)
				})
				if err := s.connect(hole); !errors.Is(err, unix.EINPROGRESS) {
					t.Fatalf("connect: %v", err)
				}
				if err := s.wait(t, 10*time.Second); !errors.Is(err, unix.ETIMEDOUT) {
					t.Fatalf("connect: %v", err)
				}
				retrans = s.totalRetrans(t)
			})
			if skip != "" {
				t.Skip(skip)
			}
			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			out := clientFlow(src, hole, snap)
			if (tc.linear == "0" && retrans != 1) || retrans == 0 || out == nil || out.Conns != 0 || out.ConnFails != 1 ||
				out.Fails[FailTimeout] != 1 || out.SynRetrans != retrans {
				t.Errorf("flow = %+v, with %d SYNs retransmitted", out, retrans)
			}
		})
	}
}

// TestConnectFailureLocal checks connects that fail before sending a SYN, for
// want of a free local port, also on a socket that connect(AF_UNSPEC) left
// with the error ECONNRESET, and with TCP_FASTOPEN_CONNECT.
func TestConnectFailureLocal(t *testing.T) {
	tr, run := handshakeTracer(t, 0)
	var srv netip.AddrPort
	run(func() {
		srv = echoServer(t, "tcp4", "127.0.0.1:0").Addr().(*net.TCPAddr).AddrPort()
		// A range of one port, which one connection to the server holds.
		port := 40000
		if int(srv.Port()) == port {
			port++
		}
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", fmt.Appendf(nil, "%d %d", port, port), 0o644); err != nil {
			t.Fatal(err)
		}
		a := newSock(t, netip.Addr{}, false, nil)
		if err := a.connect(srv); err != nil {
			t.Fatal(err)
		}
		if err := newSock(t, netip.Addr{}, false, nil).connect(srv); !errors.Is(err, unix.EADDRNOTAVAIL) {
			t.Fatalf("connect without a free port: %v", err)
		}
		a.disconnect(t)
		if err := newSock(t, netip.Addr{}, false, nil).connect(srv); err != nil {
			t.Fatal(err)
		}
		if err := a.connect(srv); !errors.Is(err, unix.EADDRNOTAVAIL) {
			t.Fatalf("connect after connect(AF_UNSPEC) without a free port: %v", err)
		}
		// A connect with TCP_FASTOPEN_CONNECT fails before it can be
		// deferred.
		fo := newSock(t, netip.Addr{}, false, func(fd int) error {
			return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
		})
		if err := fo.connect(srv); !errors.Is(err, unix.EADDRNOTAVAIL) {
			t.Fatalf("connect with TCP_FASTOPEN_CONNECT without a free port: %v", err)
		}
	})
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := clientFlow(srv.Addr(), srv, snap)
	if out == nil || out.Conns != 2 || out.ConnFails != 3 || out.Fails[FailLocal] != 3 || out.SynRetrans != 0 {
		t.Errorf("flow = %+v, want 2 connections and 3 local failures", out)
	}
}

// TestHandshakeWithoutDuration checks the active opens whose handshake has no
// duration: a connect with TCP_FASTOPEN_CONNECT, deferred to the first
// write, which fails as aborted when the socket closes before writing, and
// a socket in TCP_REPAIR, established without a SYN.
func TestHandshakeWithoutDuration(t *testing.T) {
	tr, run := handshakeTracer(t, 0)
	fastOpen := func(fd int) error { return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1) }
	var (
		srv  netip.AddrPort
		skip string
	)
	run(func() {
		// Clients and servers, without cookies (0x1 | 0x2 | 0x4 | 0x200), so
		// that connects are deferred.
		if err := os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("519"), 0o644); err != nil {
			skip = err.Error()
			return
		}
		lc := net.ListenConfig{Control: setsockoptControl(unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 16)}
		lc.SetMultipathTCP(false)
		ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// A close with unread data resets the connection, which
				// the client may see before it reads.
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				io.ReadFull(c, make([]byte, len("hello")))
				c.Write([]byte("x"))
				c.Close()
			}
		}()
		srv = ln.Addr().(*net.TCPAddr).AddrPort()

		before := tcpExtCounter(t, "TCPFastOpenActive")
		s := newSock(t, loopback4(2), false, fastOpen)
		if err := s.connect(srv); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(s.fd, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Read(s.fd, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if tcpExtCounter(t, "TCPFastOpenActive") == before {
			skip = "the connect was not deferred"
			return
		}
		s.close()

		// Closed before its first write: no SYN was sent.
		s = newSock(t, loopback4(3), false, fastOpen)
		if err := s.connect(srv); err != nil {
			t.Fatal(err)
		}
		s.close()

		s = newSock(t, loopback4(4), false, func(fd int) error {
			return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 1)
		})
		if err := s.connect(srv); err != nil {
			t.Fatal(err)
		}
		s.close()
	})
	if skip != "" {
		skipUnavailable(t, "%s", skip)
	}
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name           string
		src            netip.Addr
		conns, aborted uint64
	}{
		{"deferred Fast Open", loopback4(2), 1, 0},
		{"deferred Fast Open closed before writing", loopback4(3), 0, 1},
		{"TCP_REPAIR", loopback4(4), 1, 0},
	} {
		out := clientFlow(c.src, srv, snap)
		if out == nil || out.Conns != c.conns || out.ConnFails != c.aborted || out.Fails[FailAborted] != c.aborted ||
			out.HandshakeCount() != 0 || out.HandshakeSumUs != 0 || out.SynRetrans != 0 {
			t.Errorf("%s: flow = %+v", c.name, out)
		}
	}
}

// TestHandshakeRecounted checks that a connection whose flow could not be
// updated when it was established is counted later with its handshake and
// its SYN retransmissions: here by its close, after the flow table was full
// at the establishment and at the next walk.
func TestHandshakeRecounted(t *testing.T) {
	tr, run := handshakeTracer(t, 2)
	src := loopback4(9)
	var (
		hole netip.AddrPort
		s    *testSock
	)
	run(func() {
		// The two connections that fill the accept queue fill the flow
		// table too, with their client and server flows.
		var accept func()
		hole, accept = blackhole(t)
		s = newSock(t, src, true, func(fd int) error {
			// Closing resets the connection, which goes to CLOSE at once.
			return unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0})
		})
		if err := s.connect(hole); !errors.Is(err, unix.EINPROGRESS) {
			t.Fatalf("connect: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		accept()
		if err := s.wait(t, 5*time.Second); err != nil {
			t.Fatalf("connect: %v", err)
		}
	})
	first, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if first.Drops == 0 || clientFlow(src, hole, first) != nil {
		t.Fatalf("the connection was counted at once: %d drops", first.Drops)
	}
	s.close()
	second, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := clientFlow(src, hole, first, second)
	if out == nil || out.Conns != 1 || out.SynRetrans != 1 || out.HandshakeCount() != 1 || out.HandshakeSumUs < 900000 {
		t.Errorf("client flow = %+v", out)
	}
}

func TestFailReasonString(t *testing.T) {
	seen := map[string]bool{}
	for r := range FailReason(NumFailReasons) {
		s := r.String()
		if seen[s] || s == "reason("+strconv.Itoa(int(r))+")" {
			t.Errorf("reason %d is %q", r, s)
		}
		seen[s] = true
	}
}
