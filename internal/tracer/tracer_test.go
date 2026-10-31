package tracer

import (
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests load the BPF programs into the running kernel and need root.

func newTestTracer(t *testing.T) *Tracer {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	tr, err := New(Options{TraceSelf: true, OwnerScanInterval: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

var testComm = func() string {
	c := filepath.Base(os.Args[0])
	if len(c) > 15 {
		c = c[:15]
	}
	return c
}()

// skipIfNoNetwork skips a test when the address family is unavailable,
// e.g. IPv6 disabled by the kernel command line.
func skipIfNoNetwork(t *testing.T, network string) {
	t.Helper()
	c, err := net.ListenPacket(map[string]string{"tcp4": "udp4", "tcp6": "udp6", "udp4": "udp4", "udp6": "udp6"}[network], map[string]string{"tcp4": "127.0.0.1:0", "tcp6": "[::1]:0", "udp4": "127.0.0.1:0", "udp6": "[::1]:0"}[network])
	if err != nil {
		t.Skipf("%s is unavailable: %v", network, err)
	}
	c.Close()
}

func findFlow(flows []Flow, dir Direction, proto Proto, port uint16, raddr netip.Addr) *Flow {
	var found *Flow
	for i := range flows {
		f := &flows[i]
		if f.Direction != dir || f.Proto != proto || f.Port != port || f.RemoteAddr != raddr {
			continue
		}
		if found == nil {
			found = &Flow{FlowKey: f.FlowKey}
		}
		found.FlowStats.Add(f.FlowStats)
	}
	return found
}

// echoServer accepts connections and echoes until the peer closes.
func echoServer(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
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
				io.Copy(c, c)
			}()
		}
	}()
	return ln
}

func roundTrip(t *testing.T, c net.Conn, n int) {
	t.Helper()
	buf := make([]byte, n)
	if _, err := c.Write(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
}

func TestTCPShortLived(t *testing.T) {
	for _, tc := range []struct{ network, addr string }{
		{"tcp4", "127.0.0.1:0"},
		{"tcp6", "[::1]:0"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			skipIfNoNetwork(t, tc.network)
			tr := newTestTracer(t)
			ln := echoServer(t, tc.network, tc.addr)
			srv := ln.Addr().(*net.TCPAddr).AddrPort()

			const conns = 5
			for range conns {
				c, err := net.Dial(tc.network, ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				roundTrip(t, c, 1000)
				c.Close()
			}
			time.Sleep(100 * time.Millisecond)

			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			addr := srv.Addr()
			out := findFlow(snap.Flows, DirOut, ProtoTCP, srv.Port(), addr)
			if out == nil {
				t.Fatalf("outgoing flow not found in %+v", snap.Flows)
			}
			if out.Conns != conns || out.BytesSent < conns*1000 || out.BytesRecv < conns*1000 {
				t.Errorf("outgoing stats = %+v", out.FlowStats)
			}
			if out.Comm != testComm || out.PID != uint32(os.Getpid()) {
				t.Errorf("outgoing owner = %q/%d, want %q/%d", out.Comm, out.PID, testComm, os.Getpid())
			}
			in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), addr)
			if in == nil {
				t.Fatalf("incoming flow not found in %+v", snap.Flows)
			}
			if in.Conns != conns || in.BytesRecv < conns*1000 || in.BytesSent < conns*1000 {
				t.Errorf("incoming stats = %+v", in.FlowStats)
			}
			if in.LocalAddr != addr {
				t.Errorf("incoming local addr = %v, want %v", in.LocalAddr, addr)
			}

			var listener *Listener
			for i := range snap.Listeners {
				l := &snap.Listeners[i]
				if l.Proto == ProtoTCP && l.Port == srv.Port() {
					listener = l
				}
			}
			if listener == nil {
				t.Fatalf("listener %d not found in %+v", srv.Port(), snap.Listeners)
			}
			if listener.PID != uint32(os.Getpid()) || listener.Comm != testComm {
				t.Errorf("listener owner = %d/%q", listener.PID, listener.Comm)
			}
		})
	}
}

func TestTCPLongLivedAndAdopted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	srv := ln.Addr().(*net.TCPAddr).AddrPort()

	// Established before the tracer starts.
	pre, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pre.Close()
	roundTrip(t, pre, 5000)

	tr := newTestTracer(t)
	// Established after the tracer starts and kept open.
	post, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer post.Close()

	for interval := range 2 {
		roundTrip(t, pre, 300)
		roundTrip(t, post, 700)
		time.Sleep(100 * time.Millisecond)
		snap, err := tr.Collect()
		if err != nil {
			t.Fatal(err)
		}
		out := findFlow(snap.Flows, DirOut, ProtoTCP, srv.Port(), srv.Addr())
		if out == nil {
			t.Fatalf("interval %d: outgoing flow not found in %+v", interval, snap.Flows)
		}
		// Traffic before the adoption must not be accounted.
		if out.BytesSent != 1000 || out.BytesRecv != 1000 {
			t.Errorf("interval %d: bytes = %d/%d, want 1000/1000", interval, out.BytesSent, out.BytesRecv)
		}
		if out.OpenConns != 2 {
			t.Errorf("interval %d: open conns = %d, want 2", interval, out.OpenConns)
		}
		wantConns := uint64(0)
		if interval == 0 {
			wantConns = 1
		}
		if out.Conns != wantConns {
			t.Errorf("interval %d: conns = %d, want %d", interval, out.Conns, wantConns)
		}
		if out.Comm != testComm {
			t.Errorf("interval %d: comm = %q", interval, out.Comm)
		}
		in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
		if in == nil || in.OpenConns != 2 || in.BytesRecv != 1000 {
			t.Errorf("interval %d: incoming flow = %+v", interval, in)
		}
	}
}

func TestTCPConnectFailure(t *testing.T) {
	tr := newTestTracer(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).AddrPort()
	ln.Close()
	if _, err := net.Dial("tcp4", port.String()); err == nil {
		t.Fatal("dial succeeded unexpectedly")
	}
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	out := findFlow(snap.Flows, DirOut, ProtoTCP, port.Port(), port.Addr())
	if out == nil || out.ConnFails != 1 || out.Conns != 0 {
		t.Fatalf("flow = %+v", out)
	}
}

func TestUDP(t *testing.T) {
	for _, tc := range []struct{ network, host string }{
		{"udp4", "127.0.0.1"},
		{"udp6", "::1"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			skipIfNoNetwork(t, tc.network)
			tr := newTestTracer(t)
			if !tr.UDPEnabled() {
				t.Skip("UDP tracing is unavailable on this kernel")
			}
			srv := listenUDPFixedPort(t, tc.network, tc.host)
			defer srv.Close()
			srvAddr := srv.LocalAddr().(*net.UDPAddr).AddrPort()
			go func() {
				buf := make([]byte, 2048)
				for {
					n, from, err := srv.ReadFrom(buf)
					if err != nil {
						return
					}
					srv.WriteTo(buf[:n], from)
				}
			}()

			// An unbound client socket.
			cli, err := net.DialUDP(tc.network, nil, net.UDPAddrFromAddrPort(srvAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			const msgs = 3
			buf := make([]byte, 100)
			for range msgs {
				if _, err := cli.Write(buf); err != nil {
					t.Fatal(err)
				}
				cli.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := cli.Read(buf); err != nil {
					t.Fatal(err)
				}
			}

			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			addr := srvAddr.Addr()
			out := findFlow(snap.Flows, DirOut, ProtoUDP, srvAddr.Port(), addr)
			if out == nil || out.MsgsSent != msgs || out.MsgsRecv != msgs || out.BytesSent != msgs*100 || out.BytesRecv != msgs*100 {
				t.Errorf("client flow = %+v", out)
			}
			in := findFlow(snap.Flows, DirIn, ProtoUDP, srvAddr.Port(), addr)
			if in == nil || in.MsgsSent != msgs || in.MsgsRecv != msgs {
				t.Errorf("server flow = %+v", in)
			}
			var found bool
			for _, l := range snap.Listeners {
				if l.Proto == ProtoUDP && l.Port == srvAddr.Port() {
					found = l.PID == uint32(os.Getpid())
				}
			}
			if !found {
				t.Errorf("UDP listener %d not found in %+v", srvAddr.Port(), snap.Listeners)
			}
		})
	}
}

// listenUDPFixedPort binds a UDP server socket to an explicit port outside
// the ephemeral range, as UDP servers do.
func listenUDPFixedPort(t *testing.T, network, host string) net.PacketConn {
	t.Helper()
	for port := 20000 + os.Getpid()%5000; port < 32000; port++ {
		c, err := net.ListenPacket(network, net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			return c
		}
	}
	t.Fatal("no free UDP port")
	return nil
}

func TestExcludeSelf(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	tr, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, 10)
	c.Close()
	// Another process connecting to the same server must be recorded.
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperDial$")
	helper.Env = append(os.Environ(), "SHAWK_TEST_DIAL="+ln.Addr().String())
	if out, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	time.Sleep(100 * time.Millisecond)

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).AddrPort().Port()
	var other int
	for _, f := range snap.Flows {
		if f.Port != port {
			continue
		}
		if f.PID == tr.SelfPID() || f.Direction == DirIn {
			t.Errorf("flow of the tracer itself was recorded: %+v", f)
			continue
		}
		other++
	}
	if other != 1 {
		t.Errorf("flows of the helper process = %d, want 1 in %+v", other, snap.Flows)
	}
}

// TestExcludeSelfInPIDNamespace runs TestExcludeSelf in a new PID namespace,
// where os.Getpid() differs from the process id the kernel reports.
func TestExcludeSelfInPIDNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("SHAWK_TEST_IN_PIDNS") != "" {
		t.Skip("already in a PID namespace")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare is not available")
	}
	cmd := exec.Command(unshare, "--pid", "--fork", "--mount-proc", os.Args[0], "-test.run=^TestExcludeSelf$", "-test.v")
	cmd.Env = append(os.Environ(), "SHAWK_TEST_IN_PIDNS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestExcludeSelf") {
		t.Fatalf("TestExcludeSelf did not pass in the PID namespace:\n%s", out)
	}
}

// TestHelperDial is run as a separate process by other tests.
func TestHelperDial(t *testing.T) {
	addr := os.Getenv("SHAWK_TEST_DIAL")
	if addr == "" {
		t.Skip("helper process for other tests")
	}
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, 10)
	c.Close()
}

// TestUDPDirection checks the direction of UDP sockets whose ports do not
// tell it.
func TestUDPDirection(t *testing.T) {
	skipIfNoNetwork(t, "udp4")
	findPort := func(flows []Flow, dir Direction, port uint16) *Flow {
		for i := range flows {
			if f := &flows[i]; f.Proto == ProtoUDP && f.Direction == dir && f.Port == port {
				return f
			}
		}
		return nil
	}
	echo := func(c net.PacketConn) {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			c.WriteTo(buf[:n], from)
		}
	}
	exchange := func(t *testing.T, cli net.PacketConn, to net.Addr) {
		t.Helper()
		buf := make([]byte, 64)
		if _, err := cli.WriteTo(buf, to); err != nil {
			t.Fatal(err)
		}
		cli.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := cli.ReadFrom(buf); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("client bound to a random port", func(t *testing.T) {
		tr := newTestTracer(t)
		if !tr.UDPEnabled() {
			t.Skip("UDP tracing is unavailable on this kernel")
		}
		srv := listenUDPFixedPort(t, "udp4", "127.0.0.1")
		defer srv.Close()
		go echo(srv)
		// Like a DNS resolver randomizing its source port below 32768.
		cli := listenUDPFixedPort(t, "udp4", "127.0.0.1")
		defer cli.Close()
		exchange(t, cli, srv.LocalAddr())

		snap, err := tr.Collect()
		if err != nil {
			t.Fatal(err)
		}
		srvPort := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
		cliPort := uint16(cli.LocalAddr().(*net.UDPAddr).Port)
		if f := findPort(snap.Flows, DirOut, srvPort); f == nil || f.MsgsSent != 1 || f.MsgsRecv != 1 {
			t.Errorf("client flow = %+v", f)
		}
		if f := findPort(snap.Flows, DirIn, srvPort); f == nil || f.MsgsSent != 1 || f.MsgsRecv != 1 {
			t.Errorf("server flow = %+v", f)
		}
		for _, f := range snap.Flows {
			if f.Proto == ProtoUDP && f.Port == cliPort {
				t.Errorf("the client's port became a service port: %+v", f)
			}
		}
	})

	t.Run("server in the ephemeral range", func(t *testing.T) {
		tr := newTestTracer(t)
		if !tr.UDPEnabled() {
			t.Skip("UDP tracing is unavailable on this kernel")
		}
		srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		go echo(srv)
		cli, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		exchange(t, cli, srv.LocalAddr())

		snap, err := tr.Collect()
		if err != nil {
			t.Fatal(err)
		}
		srvPort := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
		if f := findPort(snap.Flows, DirIn, srvPort); f == nil || f.MsgsRecv != 1 {
			t.Errorf("server flow = %+v", f)
		}
		if f := findPort(snap.Flows, DirOut, srvPort); f == nil || f.MsgsSent != 1 {
			t.Errorf("client flow = %+v", f)
		}
	})

	t.Run("server bound before the tracer replies first", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root")
		}
		srv := listenUDPFixedPort(t, "udp4", "127.0.0.1")
		defer srv.Close()
		peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		tr := newTestTracer(t)
		if !tr.UDPEnabled() {
			t.Skip("UDP tracing is unavailable on this kernel")
		}
		// A reply to a request received before the tracer started.
		if _, err := srv.WriteTo([]byte("reply"), peer.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		snap, err := tr.Collect()
		if err != nil {
			t.Fatal(err)
		}
		srvPort := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
		if f := findPort(snap.Flows, DirIn, srvPort); f == nil || f.MsgsSent != 1 {
			t.Errorf("server flow = %+v in %+v", f, snap.Flows)
		}
	})
}
