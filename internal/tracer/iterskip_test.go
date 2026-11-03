package tracer

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// TestTCPIteratorSkips checks the connections that the TCP iterator of Linux
// before 6.17 skips (see adopt_skipped() of the BPF programs): it skips the
// established sockets of the first bucket of the established hash that holds
// any of the namespace when its index is that of the last listening bucket
// holding a listener of the namespace plus one. The listening bucket of
// 127.0.0.1:port is a hash of the address XORed with the port, so 1024
// consecutive ports from a multiple of 1024 put the one listener of the
// namespace in every bucket of a listening hash of 1024 buckets, that of a
// host of 2 GB of memory such as the virtual machines of test/vm; with 100
// established sockets, the first bucket holding one is almost always among
// them. Every connection must be counted with every listener, and, where
// the kernel skips them, also while the listener stays.
func TestTCPIteratorSkips(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	run, ns := newNetNS(t)
	const pairs = 50
	var anchor netip.AddrPort
	run(func() {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		anchor = ln.Addr().(*net.TCPAddr).AddrPort()
		for range pairs {
			c, err := net.Dial("tcp4", anchor.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			s, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
		}
		// The connections stay, without their listener.
		ln.Close()
	})
	tr := startTracer(t, Options{NetNS: ns})
	check := func(what string) {
		t.Helper()
		snap, err := tr.Collect()
		if err != nil {
			t.Fatal(err)
		}
		var out, in uint64
		for _, f := range snap.Flows {
			if f.Proto == ProtoTCP && f.Port == anchor.Port() {
				if f.Direction == DirOut {
					out += f.OpenConns
				} else {
					in += f.OpenConns
				}
			}
		}
		if out != pairs || in != pairs {
			t.Errorf("%s: %d client and %d server connections counted as open, want %d", what, out, in, pairs)
		}
	}
	listen := func(port uint16) net.Listener {
		var ln net.Listener
		run(func() {
			ln, _ = net.Listen("tcp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
		})
		return ln
	}
	check("without a listener")
	var skipping uint16
	for p := uint16(40960); p < 40960+1024; p++ {
		ln := listen(p)
		if ln == nil {
			continue
		}
		before := tr.lastSkips
		check("with a listener on port " + strconv.Itoa(int(p)))
		if tr.lastSkips != before && skipping == 0 {
			skipping = p
		}
		ln.Close()
	}
	if skipping == 0 {
		t.Log("the TCP iterator of this kernel skipped no connection")
		return
	}
	t.Logf("the TCP iterator of this kernel skips connections with a listener on port %d", skipping)
	ln := listen(skipping)
	if ln == nil {
		t.Fatalf("cannot listen on port %d again", skipping)
	}
	defer ln.Close()
	for i := range 4 {
		check("interval " + strconv.Itoa(i) + " with the listener on the port that makes the iterator skip")
	}
	if !tr.skipping {
		t.Error("the processes are no longer walked at every interval while the iterator skips connections")
	}
}

// TestTCPWalkFullFlowTable checks that a connection whose flow does not fit
// in the flow table is not taken for one that the TCP iterator skipped: the
// walk visited it, and the walk of the processes leaves it. With one flow,
// the client or the server side of the connection does not fit at every
// walk. The namespace has no listener, so the iterator skips none (see
// TestTCPIteratorSkips).
func TestTCPWalkFullFlowTable(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	run, ns := newNetNS(t)
	tr := startTracer(t, Options{NetNS: ns, MaxFlows: 1})
	// The processes are walked at every interval.
	tr.opts.OwnerScanInterval = time.Nanosecond
	var conns []net.Conn
	run(func() {
		// Both sides are TCP sockets that the process holds.
		var lc net.ListenConfig
		lc.SetMultipathTCP(false)
		ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		s, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		conns = append(conns, c, s)
	})
	states := tr.colls[0].Maps[bpfMapSockStates]
	for i := range 3 {
		snap, err := tr.Collect()
		if err != nil {
			t.Fatal(err)
		}
		if snap.Drops == 0 {
			t.Errorf("walk %d: both flows fit", i)
		}
		for _, c := range conns {
			raw, err := c.(*net.TCPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var ss bpfShawkSockState
			raw.Control(func(fd uintptr) { err = states.Lookup(uint32(fd), &ss) })
			if err != nil {
				t.Fatalf("socket state of %v: %v", c.LocalAddr(), err)
			}
			if ss.Walked != tr.walks {
				t.Errorf("walk %d: %v was last visited by walk %d, want %d", i, c.LocalAddr(), ss.Walked, tr.walks)
			}
		}
		if tr.lastSkips != 0 || tr.skipping {
			t.Errorf("walk %d: %d connections taken for skipped ones", i, tr.lastSkips)
		}
	}
}
