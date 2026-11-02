package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

const ipprotoMPTCP = 262

// enableMPTCP turns MPTCP on in the network namespace of the thread for the
// test, as RHEL 9 turns it off by default (net.mptcp.enabled=0).
func enableMPTCP(t *testing.T) {
	t.Helper()
	const path = "/proc/sys/net/mptcp/enabled"
	old, err := os.ReadFile(path)
	if err != nil {
		skipUnavailable(t, "MPTCP is unavailable: %v", err)
	}
	if strings.TrimSpace(string(old)) == "1" {
		return
	}
	// The file of the namespace, which the cleanup may run outside of.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("1"); err != nil {
		f.Close()
		t.Fatalf("enabling MPTCP: %v", err)
	}
	t.Cleanup(func() {
		f.WriteString(string(old))
		f.Close()
	})
}

// dialMPTCP dials with MPTCP and skips the test when the connection is not
// MPTCP, e.g. on a kernel without it or with net.mptcp.enabled=0.
func dialMPTCP(t *testing.T, network, addr string) *net.TCPConn {
	t.Helper()
	var d net.Dialer
	d.SetMultipathTCP(true)
	c, err := d.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	tc := c.(*net.TCPConn)
	if ok, err := tc.MultipathTCP(); !ok {
		tc.Close()
		skipUnavailable(t, "MPTCP is unavailable: %v", err)
	}
	return tc
}

// listenMPTCP listens with MPTCP, as Go does by default since 1.24.
func listenMPTCP(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	lc.SetMultipathTCP(true)
	ln, err := lc.Listen(t.Context(), network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// TestMPTCPAdopted checks that the subflow of an outgoing MPTCP connection
// established before the tracer started is attributed to the process
// holding the MPTCP socket, like a TCP connection (TestTCPLongLivedAndAdopted).
func TestMPTCPAdopted(t *testing.T) {
	requireRoot(t)
	enableMPTCP(t)
	ln := listenMPTCP(t, "tcp4", "127.0.0.1:0")
	go acceptEcho(ln)
	srv := ln.Addr().(*net.TCPAddr).AddrPort()

	pre := dialMPTCP(t, "tcp4", srv.String())
	defer pre.Close()
	roundTrip(t, pre, 5000)

	tr := newTestTracer(t)
	post := dialMPTCP(t, "tcp4", srv.String())
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
		checkOwners(t, snap.Flows, srv.Port())
		in := findFlow(snap.Flows, DirIn, ProtoTCP, srv.Port(), srv.Addr())
		if in == nil || in.OpenConns != 2 || in.BytesRecv != 1000 {
			t.Errorf("interval %d: incoming flow = %+v", interval, in)
		}
	}
}

// TestMPTCPOwnersRemoved checks that the owners of MPTCP connections are
// forgotten when the connections close.
func TestMPTCPOwnersRemoved(t *testing.T) {
	requireRoot(t)
	enableMPTCP(t)
	ln := listenMPTCP(t, "tcp4", "127.0.0.1:0")
	go acceptEcho(ln)
	tr := newTestTracer(t)
	owners := func() int {
		var (
			k uint64
			v [32]byte // struct shawk_owner
			n int
		)
		it := tr.colls[0].Maps[bpfMapMptcpOwners].Iterate()
		for it.Next(&k, &v) {
			n++
		}
		if err := it.Err(); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := owners()
	var conns []*net.TCPConn
	for range 3 {
		c := dialMPTCP(t, "tcp4", ln.Addr().String())
		roundTrip(t, c, 10)
		conns = append(conns, c)
	}
	// Those of the client, by connect(2).
	if n := owners(); n < before+3 {
		t.Errorf("%d owners with 3 connections open, want at least %d", n, before+3)
	}
	for _, c := range conns {
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for owners() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d owners after the connections closed, want %d", owners(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// checkOwners checks that every TCP flow on port belongs to the test.
func checkOwners(t *testing.T, flows []Flow, port uint16) {
	t.Helper()
	for _, f := range flows {
		if f.Proto == ProtoTCP && f.Port == port && (f.Comm != testComm || f.PID != uint32(os.Getpid())) {
			t.Errorf("flow %v %v->%v:%d belongs to %q/%d, want %q/%d",
				f.Direction, f.LocalAddr, f.RemoteAddr, f.Port, f.Comm, f.PID, testComm, os.Getpid())
		}
	}
}

func acceptEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
	}
}

// TestMPTCPConnectFailure checks that a failed MPTCP connection attempt
// counts once. Go's dialer retries with TCP after any MPTCP error, which
// makes two attempts, so the socket is made directly.
func TestMPTCPConnectFailure(t *testing.T) {
	tr := newTestTracer(t)
	enableMPTCP(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).AddrPort()
	ln.Close()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, ipprotoMPTCP)
	if err != nil {
		skipUnavailable(t, "MPTCP is unavailable: %v", err)
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: int(port.Port()), Addr: port.Addr().As4()})
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("connect: %v, want %v", err, unix.ECONNREFUSED)
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

// TestMPTCPJoin checks that a subflow that the path manager adds to an
// MPTCP connection (MP_JOIN), which it opens in a kernel worker, belongs to
// the process holding the MPTCP socket, and that the connection counts
// once on both sides. The path manager is told to open a subflow from a
// second loopback address, in a network namespace of the test.
func TestMPTCPJoin(t *testing.T) {
	requireRoot(t)
	run, _ := newNetNS(t)
	var (
		ln  net.Listener
		err error
	)
	run(func() {
		enableMPTCP(t)
		if err = mptcpEndpoint(netip.MustParseAddr("127.0.0.2")); err != nil {
			return
		}
		var lc net.ListenConfig
		lc.SetMultipathTCP(true)
		ln, err = lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	})
	if err != nil {
		skipUnavailable(t, "configuring the MPTCP path manager: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go acceptEcho(ln)
	srv := ln.Addr().(*net.TCPAddr).AddrPort()

	tr := newTestTracer(t)
	var c *net.TCPConn
	run(func() { c = dialMPTCP(t, "tcp4", srv.String()) })
	defer c.Close()
	// The path manager opens subflows once the connection is fully
	// established, which takes data from the client.
	roundTrip(t, c, 1)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var joins uint64
		run(func() { joins, err = mptcpJoins() })
		if err != nil {
			skipUnavailable(t, "reading the MPTCP counters: %v", err)
		}
		if joins > 0 {
			break
		}
		if time.Now().After(deadline) {
			skipUnavailable(t, "the path manager opened no subflow")
		}
		time.Sleep(10 * time.Millisecond)
	}
	const n = 1 << 20
	roundTrip(t, c, n)
	time.Sleep(100 * time.Millisecond)

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	checkOwners(t, snap.Flows, srv.Port())
	var out, in FlowStats
	locals := map[netip.Addr]bool{}
	for _, f := range snap.Flows {
		if f.Proto != ProtoTCP || f.Port != srv.Port() {
			continue
		}
		if f.Direction == DirOut {
			out.Add(f.FlowStats)
			locals[f.LocalAddr] = true
		} else {
			in.Add(f.FlowStats)
		}
	}
	if len(locals) != 2 {
		t.Errorf("outgoing flows from %v, want both loopback addresses", locals)
	}
	if out.Conns != 1 || out.ConnFails != 0 || out.OpenConns != 1 {
		t.Errorf("outgoing conns/fails/open = %d/%d/%d, want 1/0/1", out.Conns, out.ConnFails, out.OpenConns)
	}
	if in.Conns != 1 || in.OpenConns != 1 {
		t.Errorf("incoming conns/open = %d/%d, want 1/1", in.Conns, in.OpenConns)
	}
	if out.BytesSent < n || out.BytesRecv < n {
		t.Errorf("outgoing bytes = %d/%d, want at least %d", out.BytesSent, out.BytesRecv, n)
	}
}

// mptcpJoins returns the number of additional subflows (MP_JOIN) completed
// in the network namespace of the thread: MPJoinAckRx of the MPTCP MIB,
// which the server side counts when the last ACK of a join arrives. The
// MIB exists since Linux 5.6, unlike MPTCP_INFO (5.16, and RHEL 9 by
// backport). /proc/thread-self is read, since /proc/self/net shows the
// namespace of the main thread.
func mptcpJoins() (uint64, error) {
	b, err := os.ReadFile("/proc/thread-self/net/netstat")
	if err != nil {
		return 0, err
	}
	// Each group of counters is a line of names and a line of values, both
	// starting with the name of the group.
	var names []string
	for line := range strings.Lines(string(b)) {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "MPTcpExt:" {
			continue
		}
		if names == nil {
			names = fields[1:]
			continue
		}
		for i, name := range names {
			if name == "MPJoinAckRx" && i+1 < len(fields) {
				return strconv.ParseUint(fields[i+1], 10, 64)
			}
		}
		break
	}
	return 0, errors.New("no MPJoinAckRx in /proc/thread-self/net/netstat")
}

// Generic netlink of the MPTCP path manager (include/uapi/linux/mptcp.h).
const (
	mptcpPMCmdAddAddr     = 1
	mptcpPMCmdSetLimits   = 5
	mptcpPMAttrAddr       = 1
	mptcpPMAttrRcvAddAddr = 2
	mptcpPMAttrSubflows   = 3
	mptcpPMAddrAttrFamily = 1
	mptcpPMAddrAttrAddr4  = 3
	mptcpPMAddrAttrFlags  = 6
	mptcpPMAddrFlagSubfl  = 2
)

// mptcpEndpoint makes the path manager of the network namespace of the
// thread open a subflow from addr on every MPTCP connection, as
// "ip mptcp limits set subflows 2 add_addr_accepted 2" and
// "ip mptcp endpoint add ADDR subflow" do.
func mptcpEndpoint(addr netip.Addr) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	family, err := genlFamily(fd, "mptcp_pm")
	if err != nil {
		return err
	}
	limits := append(nlAttr(mptcpPMAttrRcvAddAddr, u32(2)), nlAttr(mptcpPMAttrSubflows, u32(2))...)
	if err := genlRequest(fd, family, mptcpPMCmdSetLimits, 1, limits); err != nil {
		return fmt.Errorf("setting limits: %w", err)
	}
	a4 := addr.As4()
	var ep []byte
	ep = append(ep, nlAttr(mptcpPMAddrAttrFamily, u16(unix.AF_INET))...)
	ep = append(ep, nlAttr(mptcpPMAddrAttrAddr4, a4[:])...)
	ep = append(ep, nlAttr(mptcpPMAddrAttrFlags, u32(mptcpPMAddrFlagSubfl))...)
	if err := genlRequest(fd, family, mptcpPMCmdAddAddr, 1, nlAttr(mptcpPMAttrAddr|unix.NLA_F_NESTED, ep)); err != nil {
		return fmt.Errorf("adding endpoint: %w", err)
	}
	return nil
}

func u16(v uint16) []byte { return binary.NativeEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func nlAttr(typ uint16, data []byte) []byte {
	b := binary.NativeEndian.AppendUint16(nil, uint16(4+len(data)))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

var nlSeq uint32

// genlExchange sends a generic netlink request and returns the payloads
// (after the generic netlink header) of the replies.
func genlExchange(fd int, family uint16, cmd, version uint8, attrs []byte) ([][]byte, error) {
	nlSeq++
	msg := binary.NativeEndian.AppendUint32(nil, uint32(unix.NLMSG_HDRLEN+4+len(attrs)))
	msg = binary.NativeEndian.AppendUint16(msg, family)
	msg = binary.NativeEndian.AppendUint16(msg, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg = binary.NativeEndian.AppendUint32(msg, nlSeq)
	msg = binary.NativeEndian.AppendUint32(msg, 0)
	msg = append(msg, cmd, version, 0, 0)
	msg = append(msg, attrs...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var replies [][]byte
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != nlSeq {
				continue
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				if errno := int32(binary.NativeEndian.Uint32(m.Data)); errno != 0 {
					return nil, unix.Errno(-errno)
				}
				return replies, nil
			}
			if len(m.Data) >= 4 {
				replies = append(replies, bytes.Clone(m.Data[4:]))
			}
		}
	}
}

func genlRequest(fd int, family uint16, cmd, version uint8, attrs []byte) error {
	_, err := genlExchange(fd, family, cmd, version, attrs)
	return err
}

// genlFamily resolves the id of a generic netlink family.
func genlFamily(fd int, name string) (uint16, error) {
	replies, err := genlExchange(fd, unix.GENL_ID_CTRL, unix.CTRL_CMD_GETFAMILY, 1,
		nlAttr(unix.CTRL_ATTR_FAMILY_NAME, append([]byte(name), 0)))
	if err != nil {
		return 0, fmt.Errorf("resolving %s: %w", name, err)
	}
	for _, r := range replies {
		for len(r) >= 4 {
			l := int(binary.NativeEndian.Uint16(r))
			typ := binary.NativeEndian.Uint16(r[2:])
			if l < 4 || l > len(r) {
				break
			}
			if typ == unix.CTRL_ATTR_FAMILY_ID && l >= 6 {
				return binary.NativeEndian.Uint16(r[4:]), nil
			}
			r = r[min((l+3)&^3, len(r)):]
		}
	}
	return 0, fmt.Errorf("family %s not found", name)
}
