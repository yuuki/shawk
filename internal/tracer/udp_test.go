package tracer

import (
	"net"
	"net/netip"
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
			var got int
			for got < 300 {
				srv.SetReadDeadline(time.Now().Add(time.Second))
				n, _, err := srv.ReadFrom(buf)
				if err != nil {
					t.Fatalf("after %d bytes: %v", got, err)
				}
				got += n
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
			deadline := time.Now().Add(time.Second)
			err := rc.Read(func(fd uintptr) bool {
				n, _, rerr = unix.Recvfrom(int(fd), make([]byte, 100), flags|unix.MSG_DONTWAIT)
				return rerr != unix.EAGAIN || time.Now().After(deadline)
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
