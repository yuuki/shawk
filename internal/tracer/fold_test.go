package tracer

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The tests of folding run in a network namespace of their own, which the
// tracer alone traces. Its loopback holds an internal range, 10.9.0.0/24,
// and an external one, 198.18.0.0/24: 198.18.0.0/15 is reserved for
// benchmarks (RFC 2544) and is not private.

var internal10 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

// foldNetNS returns a network namespace for the tests of folding.
func foldNetNS(t *testing.T) (func(f func()), uint32) {
	t.Helper()
	run, ns := newNetNS(t)
	run(func() {
		addLoopbackAddr(t, netip.MustParsePrefix("10.9.0.1/24"))
		addLoopbackAddr(t, netip.MustParsePrefix("198.18.0.1/24"))
	})
	return run, ns
}

func newFoldTracer(t *testing.T, netns uint32, mode FoldMode, internal []netip.Prefix, maxFlows uint32) *Tracer {
	t.Helper()
	requireRoot(t)
	log := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	tr, err := New(Options{NetNS: netns, TraceSelf: true, OwnerScanInterval: time.Hour, Fold: mode,
		InternalPeers: internal, MaxFlows: maxFlows, Logger: log})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

// dialFrom dials addr from the local address src in the namespace of run.
func dialFrom(t *testing.T, run func(func()), network, src, addr string) net.Conn {
	t.Helper()
	var (
		c   net.Conn
		err error
	)
	run(func() {
		var local net.Addr = &net.TCPAddr{IP: net.ParseIP(src)}
		if network == "udp4" || network == "udp6" {
			local = &net.UDPAddr{IP: net.ParseIP(src)}
		}
		d := net.Dialer{LocalAddr: local}
		c, err = d.Dial(network, addr)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func collect(t *testing.T, tr *Tracer) *Snapshot {
	t.Helper()
	// The server side of closed connections closes after the client side.
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// checkFolded checks the flow of dir to port from peer: folded into the
// unspecified address, or exact.
func checkFolded(t *testing.T, flows []Flow, dir Direction, proto Proto, port uint16, peer netip.Addr, folded bool) *Flow {
	t.Helper()
	f := findFlow(flows, dir, proto, port, peer)
	switch {
	case f == nil:
		t.Errorf("no %s %s flow on port %d with %s", dir, proto, port, peer)
	case f.Folded != folded:
		t.Errorf("%s %s flow on port %d with %s: folded = %t, want %t", dir, proto, port, peer, f.Folded, folded)
	}
	return f
}

// TestFoldIncomingTCP checks that the external clients of a local server
// are folded into one flow, also a connection adopted at startup, while an
// internal client and the client side keep their addresses; and that
// nothing is folded with FoldNone.
func TestFoldIncomingTCP(t *testing.T) {
	for _, mode := range []FoldMode{FoldIn, FoldNone} {
		t.Run(mode.String(), func(t *testing.T) {
			run, ns := foldNetNS(t)
			var ln net.Listener
			run(func() { ln = echoServer(t, "tcp4", "10.9.0.100:0") })
			srv := ln.Addr().(*net.TCPAddr).AddrPort()
			adopted := dialFrom(t, run, "tcp4", "198.18.0.9", srv.String())
			roundTrip(t, adopted, 1)

			tr := newFoldTracer(t, ns, mode, internal10, 0)
			external := []string{"198.18.0.1", "198.18.0.2", "198.18.0.3"}
			for _, src := range append(external, "10.9.0.1") {
				c := dialFrom(t, run, "tcp4", src, srv.String())
				roundTrip(t, c, 100)
				c.Close()
			}
			roundTrip(t, adopted, 1000)
			snap := collect(t, tr)

			checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.MustParseAddr("10.9.0.1"), false)
			if out := checkFolded(t, snap.Flows, DirOut, ProtoTCP, srv.Port(), srv.Addr(), false); out != nil && out.Conns != 4 {
				t.Errorf("outgoing conns = %d, want 4", out.Conns)
			}
			if mode == FoldNone {
				for _, src := range append(external, "198.18.0.9") {
					checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.MustParseAddr(src), false)
				}
				return
			}
			in := checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.IPv4Unspecified(), true)
			if in != nil && (in.Conns != 3 || in.OpenConns != 1 || in.BytesRecv < 3*100+1000) {
				t.Errorf("folded conns/open/received = %d/%d/%d, want 3/1/at least %d", in.Conns, in.OpenConns, in.BytesRecv, 3*100+1000)
			}
			for _, f := range snap.Flows {
				if f.Direction == DirIn && f.RemoteAddr.As4()[0] == 198 {
					t.Errorf("external client kept its address: %+v", f.FlowKey)
				}
			}
		})
	}
}

// TestFoldOutgoingTCP checks that the external servers of local clients are
// folded with FoldAll only, also for failed connections.
func TestFoldOutgoingTCP(t *testing.T) {
	for _, mode := range []FoldMode{FoldAll, FoldIn} {
		t.Run(mode.String(), func(t *testing.T) {
			run, ns := foldNetNS(t)
			var ln, closed net.Listener
			run(func() {
				ln = echoServer(t, "tcp4", "198.18.0.100:0")
				closed = echoServer(t, "tcp4", "198.18.0.100:0")
			})
			srv := ln.Addr().(*net.TCPAddr).AddrPort()
			refused := closed.Addr().(*net.TCPAddr).AddrPort()
			closed.Close()

			tr := newFoldTracer(t, ns, mode, internal10, 0)
			c := dialFrom(t, run, "tcp4", "10.9.0.1", srv.String())
			roundTrip(t, c, 100)
			c.Close()
			run(func() {
				d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.9.0.1")}}
				if c, err := d.Dial("tcp4", refused.String()); err == nil {
					c.Close()
					t.Errorf("connected to the closed port %d", refused.Port())
				}
			})
			snap := collect(t, tr)

			checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.MustParseAddr("10.9.0.1"), false)
			peer := srv.Addr()
			if mode == FoldAll {
				peer = netip.IPv4Unspecified()
			}
			if out := checkFolded(t, snap.Flows, DirOut, ProtoTCP, srv.Port(), peer, mode == FoldAll); out != nil && out.Conns != 1 {
				t.Errorf("outgoing conns = %d, want 1", out.Conns)
			}
			if f := checkFolded(t, snap.Flows, DirOut, ProtoTCP, refused.Port(), peer, mode == FoldAll); f != nil && f.ConnFails != 1 {
				t.Errorf("failed connections = %d, want 1", f.ConnFails)
			}
		})
	}
}

// TestFoldUDP checks that the external clients of a local UDP server are
// folded, while the client side keeps the address of the server.
func TestFoldUDP(t *testing.T) {
	run, ns := foldNetNS(t)
	tr := newFoldTracer(t, ns, FoldIn, internal10, 0)
	requireUDP(t, tr)
	var (
		pc  net.PacketConn
		err error
	)
	run(func() { pc, err = net.ListenPacket("udp4", "10.9.0.100:0") })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	srv := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	for _, src := range []string{"198.18.0.1", "198.18.0.2", "198.18.0.3"} {
		c := dialFrom(t, run, "udp4", src, srv.String())
		c.SetDeadline(time.Now().Add(5 * time.Second))
		roundTrip(t, c, 10)
	}
	snap := collect(t, tr)

	if in := checkFolded(t, snap.Flows, DirIn, ProtoUDP, srv.Port(), netip.IPv4Unspecified(), true); in != nil &&
		(in.MsgsRecv != 3 || in.MsgsSent != 3) {
		t.Errorf("folded datagrams received/sent = %d/%d, want 3/3", in.MsgsRecv, in.MsgsSent)
	}
	if out := checkFolded(t, snap.Flows, DirOut, ProtoUDP, srv.Port(), srv.Addr(), false); out != nil && out.MsgsSent != 3 {
		t.Errorf("client datagrams sent = %d, want 3", out.MsgsSent)
	}
}

// TestFoldIPv6 checks that external IPv6 peers are folded into ::.
func TestFoldIPv6(t *testing.T) {
	skipIfNoNetwork(t, "tcp6")
	run, ns := newNetNS(t)
	run(func() {
		for _, a := range []string{"fd00::1/128", "fd00::100/128", "2001:db8::1/128", "2001:db8::2/128"} {
			addLoopbackAddr(t, netip.MustParsePrefix(a))
		}
	})
	var ln net.Listener
	run(func() { ln = echoServer(t, "tcp6", "[fd00::100]:0") })
	srv := ln.Addr().(*net.TCPAddr).AddrPort()
	tr := newFoldTracer(t, ns, FoldIn, []netip.Prefix{netip.MustParsePrefix("fc00::/7")}, 0)
	for _, src := range []string{"2001:db8::1", "2001:db8::2", "fd00::1"} {
		c := dialFrom(t, run, "tcp6", src, srv.String())
		roundTrip(t, c, 100)
		c.Close()
	}
	snap := collect(t, tr)

	if in := checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.IPv6Unspecified(), true); in != nil && in.Conns != 2 {
		t.Errorf("folded conns = %d, want 2", in.Conns)
	}
	checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.MustParseAddr("fd00::1"), false)
}

// TestFoldCapacity checks that a server with more external clients than
// the flow table holds loses no flow when they are folded, which it does
// without folding (#96).
func TestFoldCapacity(t *testing.T) {
	const clients, capacity = 100, 128
	for _, mode := range []FoldMode{FoldIn, FoldNone} {
		t.Run(mode.String(), func(t *testing.T) {
			run, ns := foldNetNS(t)
			var ln net.Listener
			run(func() { ln = echoServer(t, "tcp4", "10.9.0.100:0") })
			srv := ln.Addr().(*net.TCPAddr).AddrPort()
			tr := newFoldTracer(t, ns, mode, internal10, capacity)
			// Each client connection is also an outgoing flow of its own.
			for i := range clients {
				c := dialFrom(t, run, "tcp4", fmt.Sprintf("198.18.0.%d", 10+i), srv.String())
				roundTrip(t, c, 1)
				c.Close()
			}
			snap := collect(t, tr)
			if mode == FoldNone {
				if snap.Drops == 0 {
					t.Errorf("no flow dropped for %d incoming and %d outgoing flows in a table of %d", clients, clients, capacity)
				}
				return
			}
			if snap.Drops != 0 {
				t.Errorf("%d flow updates dropped", snap.Drops)
			}
			if in := checkFolded(t, snap.Flows, DirIn, ProtoTCP, srv.Port(), netip.IPv4Unspecified(), true); in != nil && in.Conns != clients {
				t.Errorf("folded conns = %d, want %d", in.Conns, clients)
			}
		})
	}
}

// TestFoldLocalAddrs checks that the peers at loopback and at the addresses
// given to SetLocalAddrs are kept, whatever the internal ranges.
func TestFoldLocalAddrs(t *testing.T) {
	run, ns := foldNetNS(t)
	var ln net.Listener
	run(func() { ln = echoServer(t, "tcp4", "0.0.0.0:0") })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	dst := func(a string) string { return netip.AddrPortFrom(netip.MustParseAddr(a), port).String() }
	tr := newFoldTracer(t, ns, FoldIn, nil, 0)
	if err := tr.SetLocalAddrs([]netip.Addr{netip.MustParseAddr("10.9.0.1")}); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"127.0.0.1", "10.9.0.1", "10.9.0.2"} {
		c := dialFrom(t, run, "tcp4", src, dst("10.9.0.100"))
		roundTrip(t, c, 1)
		c.Close()
	}
	snap := collect(t, tr)
	checkFolded(t, snap.Flows, DirIn, ProtoTCP, port, netip.MustParseAddr("127.0.0.1"), false)
	checkFolded(t, snap.Flows, DirIn, ProtoTCP, port, netip.MustParseAddr("10.9.0.1"), false)
	checkFolded(t, snap.Flows, DirIn, ProtoTCP, port, netip.IPv4Unspecified(), true)

	// Addresses that the host gave up are folded again.
	if err := tr.SetLocalAddrs(nil); err != nil {
		t.Fatal(err)
	}
	c := dialFrom(t, run, "tcp4", "10.9.0.1", dst("10.9.0.100"))
	roundTrip(t, c, 1)
	c.Close()
	snap = collect(t, tr)
	if f := findFlow(snap.Flows, DirIn, ProtoTCP, port, netip.MustParseAddr("10.9.0.1")); f != nil {
		t.Errorf("a former address of the host kept its address: %+v", f)
	}
	checkFolded(t, snap.Flows, DirIn, ProtoTCP, port, netip.IPv4Unspecified(), true)
}

func TestPeerPrefixKey(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		bits   uint32
		addr   string
	}{
		{"10.0.0.0/8", 104, "::ffff:10.0.0.0"},
		{"10.1.2.3/8", 104, "::ffff:10.0.0.0"},
		{"192.0.2.1/32", 128, "::ffff:192.0.2.1"},
		{"fc00::/7", 7, "fc00::"},
		{"::1/128", 128, "::1"},
	} {
		k := peerPrefixKey(netip.MustParsePrefix(tc.prefix))
		if k.Prefixlen != tc.bits || netip.AddrFrom16(k.Addr) != netip.MustParseAddr(tc.addr) {
			t.Errorf("%s: key = /%d %s, want /%d %s", tc.prefix, k.Prefixlen, netip.AddrFrom16(k.Addr), tc.bits, tc.addr)
		}
	}
}

// addLoopbackAddr adds an address with its prefix to the loopback of the
// network namespace of the thread (RTM_NEWADDR). On loopback, every address
// in the prefix of an IPv4 address is local, as in 127.0.0.0/8, so sockets
// can bind any of them.
func addLoopbackAddr(t *testing.T, p netip.Prefix) {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	family := byte(unix.AF_INET)
	if p.Addr().Is6() {
		family = unix.AF_INET6
	}
	// struct ifaddrmsg: family, prefixlen, flags, scope, index.
	body := []byte{family, byte(p.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE}
	body = binary.NativeEndian.AppendUint32(body, uint32(lo.Index))
	body = append(body, rtAttr(unix.IFA_LOCAL, p.Addr().AsSlice())...)
	body = append(body, rtAttr(unix.IFA_ADDRESS, p.Addr().AsSlice())...)
	if err := rtnetlink(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		t.Fatalf("adding %s to lo: %v", p, err)
	}
}

func rtAttr(typ uint16, data []byte) []byte {
	a := make([]byte, (4+len(data)+3)&^3)
	binary.NativeEndian.PutUint16(a, uint16(4+len(data)))
	binary.NativeEndian.PutUint16(a[2:], typ)
	copy(a[4:], data)
	return a
}

// rtnetlink sends a request to the routing netlink of the network namespace
// of the thread and returns the error it acknowledges.
func rtnetlink(msgType, flags uint16, body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg, uint32(unix.SizeofNlMsghdr+len(body)))
	binary.NativeEndian.PutUint16(msg[4:], msgType)
	binary.NativeEndian.PutUint16(msg[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.SizeofNlMsghdr+4 || binary.NativeEndian.Uint16(buf[4:]) != unix.NLMSG_ERROR {
		return fmt.Errorf("unexpected netlink reply of %d bytes", n)
	}
	if errno := int32(binary.NativeEndian.Uint32(buf[unix.SizeofNlMsghdr:])); errno != 0 {
		return unix.Errno(-errno)
	}
	return nil
}
