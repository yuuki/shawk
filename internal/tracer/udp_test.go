package tracer

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests load the BPF programs into the running kernel and need root.

// setsockoptControl returns a Control function that sets an integer socket
// option.
func setsockoptControl(level, opt, value int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), level, opt, value)
		}); err != nil {
			return err
		}
		return serr
	}
}

// TestUDPSegmentation checks that a UDP GSO send (UDP_SEGMENT) counts every
// datagram it carries, and so does a socket that receives them coalesced
// with UDP_GRO (#97).
func TestUDPSegmentation(t *testing.T) {
	for _, tc := range []struct {
		name, network, host string
		gro                 bool
	}{
		{"udp4", "udp4", "127.0.0.1", false},
		{"udp6", "udp6", "::1", false},
		{"udp4 to a GRO socket", "udp4", "127.0.0.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skipIfNoNetwork(t, tc.network)
			tr := newTestTracer(t)
			requireUDP(t, tr)
			srv := listenUDPFixedPort(t, tc.network, tc.host)
			defer srv.Close()
			if tc.gro {
				rc, err := srv.(*net.UDPConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				if err := setsockoptControl(unix.IPPROTO_UDP, unix.UDP_GRO, 1)("", "", rc); err != nil {
					skipUnavailable(t, "UDP_GRO: %v", err)
				}
			}
			srvAddr := srv.LocalAddr().(*net.UDPAddr).AddrPort()
			d := net.Dialer{Control: setsockoptControl(unix.IPPROTO_UDP, unix.UDP_SEGMENT, 100)}
			cli, err := d.Dial(tc.network, srvAddr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			// Three datagrams of 100 bytes in one send.
			if _, err := cli.Write(make([]byte, 300)); err != nil {
				skipUnavailable(t, "UDP GSO send: %v", err)
			}
			buf := make([]byte, 2048)
			var reads []int
			for got := 0; got < 300; {
				srv.SetReadDeadline(time.Now().Add(time.Second))
				n, _, err := srv.ReadFrom(buf)
				if err != nil {
					t.Fatalf("after %d bytes: %v", got, err)
				}
				got += n
				reads = append(reads, n)
			}
			// A GRO socket receives the datagrams in one read, without which
			// the test would not count the segments of a received skb.
			if tc.gro && len(reads) != 1 {
				skipUnavailable(t, "the datagrams were received in reads of %v bytes, not coalesced", reads)
			}

			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			addr := srvAddr.Addr()
			out := findFlow(snap.Flows, DirOut, ProtoUDP, srvAddr.Port(), addr)
			if out == nil || out.MsgsSent != 3 || out.BytesSent != 300 {
				t.Errorf("client flow = %+v", out)
			}
			in := findFlow(snap.Flows, DirIn, ProtoUDP, srvAddr.Port(), addr)
			if in == nil || in.MsgsRecv != 3 || in.BytesRecv != 300 {
				t.Errorf("server flow = %+v", in)
			}
		})
	}
}

// TestUDPPeek checks that a datagram peeked at with MSG_PEEK is counted once,
// when it is read, also when it is empty (#97).
func TestUDPPeek(t *testing.T) {
	skipIfNoNetwork(t, "udp4")
	tr := newTestTracer(t)
	requireUDP(t, tr)
	srv := listenUDPFixedPort(t, "udp4", "127.0.0.1")
	defer srv.Close()
	rc, err := srv.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	cli, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(cli)
	to := &unix.SockaddrInet4{Port: int(srvAddr.Port()), Addr: srvAddr.Addr().As4()}
	for _, size := range []int{0, 10} {
		if err := unix.Sendto(cli, make([]byte, size), 0, to); err != nil {
			t.Fatal(err)
		}
		// Peek twice, then read.
		for _, flags := range []int{unix.MSG_PEEK, unix.MSG_PEEK, 0} {
			var (
				n    int
				rerr error
			)
			// The deadline ends a wait for readability too.
			srv.SetReadDeadline(time.Now().Add(time.Second))
			err := rc.Read(func(fd uintptr) bool {
				n, _, rerr = unix.Recvfrom(int(fd), make([]byte, 100), flags|unix.MSG_DONTWAIT)
				return rerr != unix.EAGAIN
			})
			if err != nil || rerr != nil || n != size {
				t.Fatalf("recvfrom(%#x) of %d bytes = %d, %v, %v", flags, size, n, err, rerr)
			}
		}
	}

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	in := findFlow(snap.Flows, DirIn, ProtoUDP, srvAddr.Port(), srvAddr.Addr())
	if in == nil || in.MsgsRecv != 2 || in.BytesRecv != 10 {
		t.Errorf("server flow = %+v", in)
	}
}

// TestUDPIPv6ExtensionHeaders checks the datagrams of an IPv6 socket that
// sends a destination options header, which comes between the IPv6 and the
// UDP headers (#97).
func TestUDPIPv6ExtensionHeaders(t *testing.T) {
	skipIfNoNetwork(t, "udp6")
	tr := newTestTracer(t)
	requireUDP(t, tr)
	srv := listenUDPFixedPort(t, "udp6", "::1")
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
	// A destination options header with a PadN option of 4 bytes; the
	// kernel fills in the next header.
	dstopts := []byte{0, 0, 1, 4, 0, 0, 0, 0}
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, string(dstopts))
		}); err != nil {
			return err
		}
		return serr
	}}
	cli, err := d.Dial("udp6", srvAddr.String())
	if err != nil {
		skipUnavailable(t, "IPV6_DSTOPTS: %v", err)
	}
	defer cli.Close()
	buf := make([]byte, 100)
	if _, err := cli.Write(buf); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := cli.Read(buf); err != nil {
		t.Fatal(err)
	}

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.IPv6Loopback()
	out := findFlow(snap.Flows, DirOut, ProtoUDP, srvAddr.Port(), addr)
	if out == nil || out.MsgsSent != 1 || out.MsgsRecv != 1 || out.BytesSent != 100 || out.BytesRecv != 100 {
		t.Errorf("client flow = %+v", out)
	}
	in := findFlow(snap.Flows, DirIn, ProtoUDP, srvAddr.Port(), addr)
	if in == nil || in.MsgsRecv != 1 || in.MsgsSent != 1 || in.BytesSent != 100 || in.BytesRecv != 100 {
		t.Errorf("server flow = %+v", in)
	}
}

// TestUDPKprobes runs the tests of UDP with the kprobes that stand in for
// the fentry programs where BPF trampolines do not attach (#118), on any
// kernel with kprobes: the direction of a socket is then kept in a hash
// rather than in socket local storage.
func TestUDPKprobes(t *testing.T) {
	if noUDP, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_UDP")); noUDP {
		t.Skip("UDP tracing is unavailable on this kernel, as SHAWK_TEST_NO_UDP declares")
	}
	// The other tests of UDP run with the kprobes there already, which
	// requireUDP checks; running them twice in an emulated VM brings its
	// job close to the timeout of CI.
	if noTrampolines, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_TRAMPOLINES")); noTrampolines {
		t.Skip("the tests of UDP run with kprobes on this kernel, as SHAWK_TEST_NO_TRAMPOLINES declares")
	}
	forceUDPKprobes = true
	t.Cleanup(func() { forceUDPKprobes = false })
	tr := newTestTracer(t)
	if !tr.UDPEnabled() {
		skipUnavailable(t, "UDP is not traced with kprobes")
	}
	if !tr.udpKprobes {
		t.Fatal("UDP is traced, but not with kprobes")
	}
	for name, test := range map[string]func(*testing.T){
		"UDP":                     TestUDP,
		"UDPDirection":            TestUDPDirection,
		"UDPSegmentation":         TestUDPSegmentation,
		"UDPPeek":                 TestUDPPeek,
		"UDPIPv6ExtensionHeaders": TestUDPIPv6ExtensionHeaders,
		"FoldUDP":                 TestFoldUDP,
		"ListenerKernelChosen":    TestListenerKernelChosen,
	} {
		t.Run(name, test)
	}
}

// addVXLAN creates a VXLAN device on port in the network namespace of the
// thread and brings it up: it opens a UDP socket of the kernel bound to the
// port, which has no file. SHAWK_TEST_NO_VXLAN=1 declares a kernel without
// VXLAN, as those of the virtual machines of test/vm, whose initramfs has
// no module of it: the test is then skipped even in strict mode.
func addVXLAN(t *testing.T, name string, port uint16) {
	t.Helper()
	ifinfo := make([]byte, unix.SizeofIfInfomsg) // AF_UNSPEC, no flags
	data := slices.Concat(rtAttr(unix.IFLA_VXLAN_ID, binary.NativeEndian.AppendUint32(nil, 42)),
		rtAttr(unix.IFLA_VXLAN_PORT, binary.BigEndian.AppendUint16(nil, port)))
	linkInfo := slices.Concat(rtAttr(unix.IFLA_INFO_KIND, []byte("vxlan")),
		rtAttr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, data))
	body := slices.Concat(ifinfo, rtAttr(unix.IFLA_IFNAME, cstr(name)), rtAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, linkInfo))
	if err := rtnetlink(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		if no, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_VXLAN")); no {
			t.Skip("the kernel has no VXLAN, as SHAWK_TEST_NO_VXLAN declares")
		}
		skipUnavailable(t, "creating a VXLAN device: %v", err)
	}
	if err := linkUp(name); err != nil {
		t.Fatal(err)
	}
}

// delLink deletes an interface of the network namespace of the thread.
func delLink(t *testing.T, name string) {
	t.Helper()
	body := slices.Concat(make([]byte, unix.SizeofIfInfomsg), rtAttr(unix.IFLA_IFNAME, cstr(name)))
	if err := rtnetlink(unix.RTM_DELLINK, 0, body); err != nil {
		t.Fatalf("deleting %s: %v", name, err)
	}
}

// udpKstates returns the entries of udp_kstates of a tracer: the struct
// shawk_udp_kstate kept for each socket address.
func udpKstates(t *testing.T, tr *Tracer) map[uint64][16]byte {
	t.Helper()
	var (
		sk  uint64
		val [16]byte
	)
	out := map[uint64][16]byte{}
	it := tr.colls[0].Maps[bpfMapUdpKstates].Iterate()
	for it.Next(&sk, &val) {
		out[sk] = val
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestUDPKernelSocketReuse checks that a UDP socket of the kernel does not
// take the direction that udp_kstates keeps for a former socket at its
// address (#256). Sockets of the kernel have no file, and the inode of the
// file, 0 for both, matched: a socket that never received was listed as a
// server, and its first datagram with kprobes took the former direction.
// Rather than waiting for the allocator to reuse the memory of the former
// socket, the test moves its entry to the address of the new one. VXLAN
// devices hold such sockets.
func TestUDPKernelSocketReuse(t *testing.T) {
	requireRoot(t)
	run, ns := newNetNS(t)
	// A server that the tracer marks at its start, and a socket on a port of
	// the ephemeral range, which is not listed until it receives first.
	const serverPort = 4789
	low, high := ephemeralPortRange()
	clientPort := low + (high-low)/2
	run(func() { addVXLAN(t, "vxs", serverPort) })
	tr := startTracer(t, Options{NetNS: ns})
	former := udpKstates(t, tr)
	if len(former) != 1 {
		t.Fatalf("udp_kstates holds %d sockets of the namespace, want the VXLAN socket: %v", len(former), former)
	}
	run(func() {
		delLink(t, "vxs")
		addVXLAN(t, "vxc", clientPort)
	})
	// Another tracer marks the new socket at its start, which tells its
	// address, and checks that the walk sees it.
	other := startTracer(t, Options{NetNS: ns})
	listed := func(snap *Snapshot) bool {
		for _, l := range snap.Listeners {
			if l.Proto == ProtoUDP && l.NetNS == ns && l.Port == clientPort {
				return true
			}
		}
		return false
	}
	if !listed(collect(t, other)) {
		t.Fatal("the VXLAN socket that existed at the start is not listed")
	}
	current := udpKstates(t, other)
	if len(current) != 1 {
		t.Fatalf("udp_kstates holds %d sockets of the namespace, want the VXLAN socket: %v", len(current), current)
	}
	kstates := tr.colls[0].Maps[bpfMapUdpKstates]
	for sk := range former {
		if err := kstates.Delete(sk); err != nil {
			t.Fatal(err)
		}
	}
	for sk := range current {
		for _, val := range former {
			if err := kstates.Put(sk, val); err != nil {
				t.Fatal(err)
			}
		}
	}
	if listed(collect(t, tr)) {
		t.Error("the new socket of the kernel took the direction of the former one at its address: it is listed as a server")
	}
}
