package tracer

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests load the BPF programs into the running kernel and need root.

// acceptOne returns a listener on a port in the ephemeral range and a
// channel that receives the first connection it accepts.
func acceptOne(t *testing.T) (net.Listener, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c
	}()
	return ln, ch
}

func echo(c net.Conn) {
	defer c.Close()
	io.Copy(c, c)
}

// TestTCPAdoptedWithoutListener checks connections established before the
// tracer started whose listener was closed since, like those of a server
// draining connections after a graceful restart (#93). The server side must
// be recorded as incoming to the server port, not as outgoing to the port of
// the client.
func TestTCPAdoptedWithoutListener(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	ln, accepted := acceptOne(t)
	srv := ln.Addr().(*net.TCPAddr).AddrPort()
	cli, err := net.Dial("tcp4", srv.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	go echo(<-accepted)
	cliPort := cli.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	ln.Close()

	tr := newTestTracer(t)
	roundTrip(t, cli, 100)
	// The owner of the server side is the process holding the accepted socket.
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range snap.Flows {
		if f.Proto == ProtoTCP && f.Port == cliPort {
			t.Errorf("the client's port became a service port: %+v", f)
		}
	}
	out := findFlow(snap.Flows, DirOut, ProtoTCP, srv.Port(), srv.Addr())
	if out == nil || out.BytesSent != 100 || out.BytesRecv != 100 || out.OpenConns != 1 {
		t.Errorf("client flow = %+v", out)
	}
	in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
	if in == nil || in.BytesSent != 100 || in.BytesRecv != 100 || in.OpenConns != 1 {
		t.Fatalf("server flow = %+v in %+v", in, snap.Flows)
	}
	if in.Comm != testComm {
		t.Errorf("server flow owner = %q, want %q", in.Comm, testComm)
	}
}

// TestTCPAdoptedDirection checks the direction of connections established
// before the tracer started, whatever their ports (#93): clients that let
// connect(2) choose their port, bind port 0 or bind a privileged port, and
// servers whose listener was closed since, with clients on any port. It runs
// in the namespace of the test and in one whose ephemeral range is
// 1024-65535, where ports tell nothing.
func TestTCPAdoptedDirection(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	requireRoot(t)
	t.Run("default range", func(t *testing.T) {
		testAdoptedDirection(t, func(f func()) { f() }, currentNetNS(t))
	})
	t.Run("wide range", func(t *testing.T) {
		run, inode := newNetNS(t)
		run(func() {
			if err := os.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", []byte("1024 65535"), 0o644); err != nil {
				t.Fatal(err)
			}
		})
		testAdoptedDirection(t, run, inode)
	})
}

func testAdoptedDirection(t *testing.T, inNetNS func(func()), netns uint32) {
	type conn struct {
		name string
		srv  netip.AddrPort
		c    net.Conn
	}
	var conns []conn
	dial := func(name string, srv netip.AddrPort, laddr *net.TCPAddr) {
		t.Helper()
		d := net.Dialer{LocalAddr: laddr}
		c, err := d.Dial("tcp4", srv.String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Cleanup(func() { c.Close() })
		conns = append(conns, conn{name, srv, c})
	}
	// dialPrivileged binds a free port below 1024 before connecting.
	dialPrivileged := func(name string, srv netip.AddrPort) {
		t.Helper()
		for port := 900; port < 1024; port++ {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}}
			if c, err := d.Dial("tcp4", srv.String()); err == nil {
				t.Cleanup(func() { c.Close() })
				conns = append(conns, conn{name, srv, c})
				return
			}
		}
		t.Fatalf("%s: no free port below 1024", name)
	}
	inNetNS(func() {
		ln := echoServer(t, "tcp4", "127.0.0.1:0")
		srv := ln.Addr().(*net.TCPAddr).AddrPort()
		dial("client", srv, nil)
		dial("client bound to port 0", srv, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		dialPrivileged("client bound to a privileged port", srv)
		for _, bound := range []bool{false, true} {
			name := "server draining its connections"
			if bound {
				name += ", client on a privileged port"
			}
			ln := echoServer(t, "tcp4", "127.0.0.1:0")
			srv := ln.Addr().(*net.TCPAddr).AddrPort()
			if bound {
				dialPrivileged(name, srv)
			} else {
				dial(name, srv, nil)
			}
			roundTrip(t, conns[len(conns)-1].c, 1)
			ln.Close()
		}
	})

	tr := newTestTracer(t)
	for _, c := range conns {
		roundTrip(t, c.c, 100)
	}
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	var flows []Flow
	for _, f := range snap.Flows {
		if f.NetNS == netns && f.Proto == ProtoTCP {
			flows = append(flows, f)
		}
	}
	want := map[uint16]uint64{}
	for _, c := range conns {
		want[c.srv.Port()]++
		port := c.c.LocalAddr().(*net.TCPAddr).AddrPort().Port()
		for _, f := range flows {
			if f.Port == port {
				t.Errorf("%s: its port %d became a service port: %+v", c.name, port, f)
			}
		}
	}
	for port, n := range want {
		addr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		out := findFlow(flows, DirOut, ProtoTCP, port, addr)
		if out == nil || out.OpenConns != n || out.BytesSent != 100*n || out.BytesRecv != 100*n {
			t.Errorf("port %d: client flow = %+v, want %d connections", port, out, n)
		}
		in := findFlow(flows, DirIn, ProtoTCP, port, addr)
		if in == nil || in.OpenConns != n || in.BytesSent != 100*n || in.BytesRecv != 100*n || in.Comm != testComm {
			t.Errorf("port %d: server flow = %+v, want %d connections", port, in, n)
		}
	}
}

func currentNetNS(t *testing.T) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	return uint32(st.Ino)
}

// TestTCPSelfConnect checks a socket connected to itself, which goes through
// a simultaneous open (#97): it must stay an outgoing connection of its
// process.
func TestTCPSelfConnect(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	tr := newTestTracer(t)
	// Find a free port, then connect from it to itself.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := l.Addr().(*net.TCPAddr)
	l.Close()
	d := net.Dialer{LocalAddr: ap}
	c, err := d.Dial("tcp4", ap.String())
	if err != nil {
		skipUnavailable(t, "self-connect failed: %v", err)
	}
	roundTrip(t, c, 100)
	c.Close()
	time.Sleep(100 * time.Millisecond)

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	port := ap.AddrPort().Port()
	if in := findFlow(snap.Flows, DirIn, ProtoTCP, port, ap.AddrPort().Addr()); in != nil {
		t.Errorf("incoming flow recorded: %+v", in)
	}
	out := findFlow(snap.Flows, DirOut, ProtoTCP, port, ap.AddrPort().Addr())
	if out == nil {
		t.Fatalf("outgoing flow not found in %+v", snap.Flows)
	}
	if out.Conns != 1 || out.BytesSent != 100 || out.BytesRecv != 100 || out.Comm != testComm {
		t.Errorf("outgoing flow = %+v", out)
	}
}

// TestTCPCloseWithoutTraffic checks that closing a connection whose traffic
// was accounted by an earlier scan records nothing more: neither the FINs nor
// an empty flow (#97).
func TestTCPCloseWithoutTraffic(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	tr := newTestTracer(t)
	ln, accepted := acceptOne(t)
	srv := ln.Addr().(*net.TCPAddr).AddrPort()
	c, err := net.Dial("tcp4", srv.String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if _, err := c.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := tr.Collect(); err != nil {
		t.Fatal(err)
	}

	c.Close()
	s.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := s.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("read after the peer closed = %d, %v", n, err)
	}
	s.Close()
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range snap.Flows {
		if f.Proto == ProtoTCP && f.Port == srv.Port() {
			t.Errorf("flow recorded after the connection closed: %+v", f)
		}
	}
}

// TestTCPExactBytes checks that the FIN of either side is not counted as a
// byte of data (#97), whichever side closes first.
func TestTCPExactBytes(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	for _, serverCloses := range []bool{false, true} {
		name := "client closes"
		if serverCloses {
			name = "server closes"
		}
		t.Run(name, func(t *testing.T) {
			tr := newTestTracer(t)
			ln, accepted := acceptOne(t)
			srv := ln.Addr().(*net.TCPAddr).AddrPort()
			c, err := net.Dial("tcp4", srv.String())
			if err != nil {
				t.Fatal(err)
			}
			s := <-accepted
			if _, err := c.Write(make([]byte, 1000)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(s, make([]byte, 1000)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Write(make([]byte, 300)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, make([]byte, 300)); err != nil {
				t.Fatal(err)
			}
			first, second := c, s
			if serverCloses {
				first, second = s, c
			}
			first.Close()
			// Wait for the FIN before closing the other side.
			second.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := second.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("read after the peer closed = %d, %v", n, err)
			}
			second.Close()
			time.Sleep(100 * time.Millisecond)

			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			check := func(dir Direction, sent, recv uint64) {
				t.Helper()
				f := findFlow(snap.Flows, dir, ProtoTCP, srv.Port(), srv.Addr())
				if f == nil {
					t.Fatalf("flow %v not found in %+v", dir, snap.Flows)
				}
				if f.BytesSent != sent || f.BytesRecv != recv || f.Conns != 1 {
					t.Errorf("flow %v = %+v, want %d/%d bytes", dir, f.FlowStats, sent, recv)
				}
			}
			check(DirOut, 1000, 300)
			check(DirIn, 300, 1000)
		})
	}
}

// TestListenPortCapacity checks that the tables of listening ports are sized
// by MaxFlows and that their overflow is reported (#98).
func TestListenPortCapacity(t *testing.T) {
	requireRoot(t)
	for range 3 {
		echoServer(t, "tcp4", "127.0.0.1:0")
	}
	defer func(lo uint32) { minListenPorts = lo }(minListenPorts)
	minListenPorts = 2
	var logs strings.Builder
	tr, err := New(Options{
		TraceSelf:         true,
		MaxFlows:          2,
		OwnerScanInterval: time.Hour,
		Logger:            slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Listeners) < 3 {
		t.Fatalf("listeners = %+v", snap.Listeners)
	}
	if !strings.Contains(logs.String(), "more listening ports than the in-kernel tables hold") {
		t.Errorf("no warning about the overflow in %q", logs.String())
	}
}

// TestTCPFastOpen checks that data carried by the SYN of a TCP Fast Open
// connection is counted on both sides (#97). It runs in a network namespace
// of its own, whose sysctls it changes.
func TestTCPFastOpen(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	tr := newTestTracer(t)
	run, _ := newNetNS(t)
	setsockopt := func(opt, value int) func(string, string, syscall.RawConn) error {
		return func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, opt, value)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	const conns = 2
	var (
		srv       netip.AddrPort
		withData  uint64
		skipCause string
	)
	run(func() {
		// Clients and servers, without cookies (0x1 | 0x2 | 0x4 | 0x200), so
		// that every SYN carries data.
		if err := os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("519"), 0o644); err != nil {
			skipCause = err.Error()
			return
		}
		// The length of the queue of pending Fast Open requests.
		lc := net.ListenConfig{Control: setsockopt(unix.TCP_FASTOPEN, 16)}
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
				go func() {
					defer c.Close()
					if _, err := io.ReadFull(c, make([]byte, 1000)); err != nil {
						return
					}
					c.Write(make([]byte, 300))
					io.Copy(io.Discard, c)
				}()
			}
		}()
		srv = ln.Addr().(*net.TCPAddr).AddrPort()

		before := tcpExtCounter(t, "TCPFastOpenActive")
		d := net.Dialer{Control: setsockopt(unix.TCP_FASTOPEN_CONNECT, 1)}
		d.SetMultipathTCP(false)
		for range conns {
			c, err := d.Dial("tcp4", srv.String())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write(make([]byte, 1000)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, make([]byte, 300)); err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
		withData = tcpExtCounter(t, "TCPFastOpenActive") - before
	})
	if skipCause != "" {
		skipUnavailable(t, "%s", skipCause)
	}
	if withData != conns {
		skipUnavailable(t, "%d of %d connections carried data in their SYN", withData, conns)
	}
	time.Sleep(100 * time.Millisecond)

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := findFlow(snap.Flows, DirOut, ProtoTCP, srv.Port(), srv.Addr())
	if out == nil || out.Conns != conns || out.BytesSent != conns*1000 || out.BytesRecv != conns*300 {
		t.Errorf("client flow = %+v", out)
	}
	in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
	if in == nil || in.Conns != conns || in.BytesRecv != conns*1000 || in.BytesSent != conns*300 {
		t.Errorf("server flow = %+v", in)
	}
}

// tcpExtCounter returns a counter of the TcpExt section of netstat in the
// network namespace of the current thread.
func tcpExtCounter(t *testing.T, name string) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/thread-self/net/netstat")
	if err != nil {
		skipUnavailable(t, "%v", err)
	}
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i += 2 {
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(names) == 0 || names[0] != "TcpExt:" || len(names) != len(values) {
			continue
		}
		for j := range names {
			if names[j] == name {
				v, _ := strconv.ParseUint(values[j], 10, 64)
				return v
			}
		}
	}
	skipUnavailable(t, "no counter %s", name)
	return 0
}

// TestTCPFastOpenChildClosed checks a child of a listener created by a TCP
// Fast Open SYN that is reset before the handshake completes, so that it
// never becomes established (#97): its connection and the data of its SYN
// are counted. A raw socket sends the SYN; the kernel resets the connection
// when the SYN-ACK reaches a port without a socket.
//
// A SYN that also carries a FIN must create no child at all: listeners drop
// it (since Linux 3.5), so the FIN of the peer is always counted by
// bytes_received, which tcp_fastopen_add_skb() would not do. The test runs in
// a network namespace of its own, whose sysctls it changes.
func TestTCPFastOpenChildClosed(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	for _, tc := range []struct {
		name  string
		flags uint8
		child bool
	}{
		{"reset", tcpSYN, true},
		{"FIN in the SYN", tcpSYN | tcpFIN, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTestTracer(t)
			run, _ := newNetNS(t)
			var (
				srv       netip.AddrPort
				children  uint64
				skipCause string
			)
			run(func() {
				// Servers without cookies (0x2 | 0x200).
				if err := os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("514"), 0o644); err != nil {
					skipCause = err.Error()
					return
				}
				lc := net.ListenConfig{Control: setsockoptControl(unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 16)}
				lc.SetMultipathTCP(false)
				ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
				srv = ln.Addr().(*net.TCPAddr).AddrPort()
				before := tcpExtCounter(t, "TCPFastOpenPassive")
				sendRawSYN(t, srv, tc.flags, make([]byte, 100))
				time.Sleep(100 * time.Millisecond)
				children = tcpExtCounter(t, "TCPFastOpenPassive") - before
			})
			if skipCause != "" {
				skipUnavailable(t, "%s", skipCause)
			}
			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
			if !tc.child {
				if children != 0 || in != nil {
					t.Errorf("the listener accepted a SYN with a FIN: %d children, flow %+v", children, in)
				}
				return
			}
			if children != 1 {
				skipUnavailable(t, "the SYN created %d Fast Open children", children)
			}
			if in == nil || in.Conns != 1 || in.BytesRecv != 100 || in.BytesSent != 0 {
				t.Errorf("server flow = %+v", in)
			}
		})
	}
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
)

// sendRawSYN sends a SYN with data from 127.0.0.1 to dst through a raw socket,
// with the flags given.
func sendRawSYN(t *testing.T, dst netip.AddrPort, flags uint8, data []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		skipUnavailable(t, "raw socket: %v", err)
	}
	defer unix.Close(fd)
	src := [4]byte{127, 0, 0, 1}
	seg := make([]byte, 20+len(data))
	// A port without a socket, which the kernel resets.
	binary.BigEndian.PutUint16(seg[0:], uint16(61000+os.Getpid()%1000))
	binary.BigEndian.PutUint16(seg[2:], dst.Port())
	binary.BigEndian.PutUint32(seg[4:], 1000)
	seg[12] = 5 << 4 // header of 20 bytes
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:], 65535)
	copy(seg[20:], data)
	binary.BigEndian.PutUint16(seg[16:], tcpChecksum(src, dst.Addr().As4(), seg))
	if err := unix.Sendto(fd, seg, 0, &unix.SockaddrInet4{Addr: dst.Addr().As4()}); err != nil {
		t.Fatal(err)
	}
}

func tcpChecksum(src, dst [4]byte, seg []byte) uint16 {
	pseudo := append(append(append([]byte{}, src[:]...), dst[:]...), 0, unix.IPPROTO_TCP, byte(len(seg)>>8), byte(len(seg)))
	var sum uint32
	for _, b := range [][]byte{pseudo, seg} {
		for i := 0; i < len(b); i += 2 {
			v := uint32(b[i]) << 8
			if i+1 < len(b) {
				v |= uint32(b[i+1])
			}
			sum += v
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
