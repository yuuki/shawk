package tracer

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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

var netnsSeq atomic.Uint32

// newNetNS creates a named network namespace with its loopback up, whose
// sockets the tracer walks like those of a container. It returns a function
// running f on a thread that entered the namespace, and its inode. Sockets
// created by f belong to the namespace; /proc/sys/net and
// /proc/thread-self/net are those of the namespace while f runs.
func newNetNS(t *testing.T) (func(f func()), uint32) {
	t.Helper()
	ip, err := exec.LookPath("ip")
	if err != nil {
		skipUnavailable(t, "ip is not available")
	}
	name := fmt.Sprintf("shawkacc%d-%d", os.Getpid(), netnsSeq.Add(1))
	if out, err := exec.Command(ip, "netns", "add", name).CombinedOutput(); err != nil {
		skipUnavailable(t, "cannot create a network namespace: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(ip, "netns", "del", name).Run() })
	if out, err := exec.Command(ip, "-n", name, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var st unix.Stat_t
	if err := unix.Stat("/run/netns/"+name, &st); err != nil {
		t.Fatal(err)
	}
	run := func(f func()) {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			t.Fatal(err)
		}
		defer orig.Close()
		ns, err := os.Open("/run/netns/" + name)
		if err != nil {
			runtime.UnlockOSThread()
			t.Fatal(err)
		}
		defer ns.Close()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			t.Fatal(err)
		}
		// A thread that cannot return to its namespace ends with its
		// goroutine instead of being reused.
		defer func() {
			if unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET) == nil {
				runtime.UnlockOSThread()
			}
		}()
		f()
	}
	return run, uint32(st.Ino)
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
