package tracer

import (
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

// TestTCPAdoptedBoundClient checks a connection established before the
// tracer started by a client that bound its port before connecting (#93): it
// must stay outgoing, although its port was not allocated by connect(2).
func TestTCPAdoptedBoundClient(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	ln := listenFixedPort(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go echo(c)
		}
	}()
	srv := ln.Addr().(*net.TCPAddr).AddrPort()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	cli, err := d.Dial("tcp4", srv.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cliPort := cli.LocalAddr().(*net.TCPAddr).AddrPort().Port()

	tr := newTestTracer(t)
	roundTrip(t, cli, 100)
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
	if out == nil || out.BytesSent != 100 || out.OpenConns != 1 || out.Comm != testComm {
		t.Errorf("client flow = %+v", out)
	}
	in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
	if in == nil || in.BytesRecv != 100 || in.OpenConns != 1 {
		t.Errorf("server flow = %+v", in)
	}
}

// listenFixedPort listens on a TCP port below the ephemeral range, as
// services do.
func listenFixedPort(t *testing.T) net.Listener {
	t.Helper()
	low, _ := ephemeralPortRange()
	for port := int(low) - 5000 + os.Getpid()%3000; port < int(low); port++ {
		ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			t.Cleanup(func() { ln.Close() })
			return ln
		}
	}
	t.Fatal("no free TCP port")
	return nil
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
		t.Skipf("self-connect failed: %v", err)
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
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	srv := ln.Addr().(*net.TCPAddr).AddrPort()
	c, err := net.Dial("tcp4", srv.String())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, 100)
	time.Sleep(50 * time.Millisecond)
	if _, err := tr.Collect(); err != nil {
		t.Fatal(err)
	}

	c.Close()
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
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	for range 3 {
		echoServer(t, "tcp4", "127.0.0.1:0")
	}
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
