package tracer

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestChooseOwner(t *testing.T) {
	systemd := owner{pid: 1, comm: "systemd", cgroupID: 10}
	nginx := owner{pid: 100, comm: "nginx", cgroupID: 20}
	worker := owner{pid: 101, comm: "nginx", cgroupID: 20}
	envoy := owner{pid: 200, comm: "envoy", cgroupID: 30}
	for _, tc := range []struct {
		name   string
		cands  []owner
		cgroup uint64
		want   owner
		ok     bool
	}{
		{"no holder", nil, 20, owner{}, false},
		{"forked workers prefer the parent", []owner{worker, nginx}, 20, nginx, true},
		{"SO_REUSEPORT by cgroup", []owner{nginx, envoy}, 30, envoy, true},
		{"socket activation", []owner{systemd, nginx}, 10, nginx, true},
		{"only systemd", []owner{systemd}, 10, systemd, true},
		{"holder changed since the scan", []owner{nginx}, 30, owner{}, false},
		{"unknown cgroup", []owner{envoy, nginx}, 0, nginx, true},
	} {
		got, ok := chooseOwner(tc.cands, tc.cgroup)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: chooseOwner = %+v, %v; want %+v, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestAttributeKernel checks that incoming connections accepted by a
// listener of the kernel that no process holds, e.g. that of nfsd, belong to
// the kernel without requesting another owner scan, that those of another
// listener that no process the agent sees holds keep the cgroup of the
// socket, and that flows the BPF programs gave to the kernel keep it.
func TestAttributeKernel(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	peer := netip.MustParseAddr("10.0.0.2")
	key := func(a netip.Addr, port uint16) sockAddrKey {
		return sockAddrKey{proto: ProtoTCP, netns: 1, addr: a.As16(), port: port}
	}
	tr := &Tracer{
		self:      12345,
		owners:    map[sockAddrKey][]owner{key(addr, 80): {{pid: 100, comm: "nginx", cgroupID: 20}}},
		ownerless: map[sockAddrKey]bool{key(netip.IPv4Unspecified(), 2049): true, key(addr, 443): true},
		kernel:    map[sockAddrKey]bool{key(netip.IPv4Unspecified(), 2049): true},
	}
	in := func(port uint16, comm string, cgroup uint64) Flow {
		return Flow{FlowKey: FlowKey{Direction: DirIn, Proto: ProtoTCP, LocalAddr: addr, RemoteAddr: peer,
			Port: port, NetNS: 1, CgroupID: cgroup, Comm: comm}, FlowStats: FlowStats{Conns: 1}}
	}
	flows := tr.attribute([]Flow{
		in(2049, "", 30),       // accepted by nfsd on 0.0.0.0:2049
		in(80, "", 20),         // accepted by nginx
		in(111, KernelComm, 0), // adopted from a listener that is gone
		in(8080, "", 40),       // a listener closed since the last scan
		in(443, "", 50),        // held in another PID namespace
	})
	want := []struct {
		comm   string
		cgroup uint64
		pid    uint32
	}{{KernelComm, 0, 0}, {"nginx", 20, 100}, {KernelComm, 0, 0}, {"", 40, 0}, {"", 50, 0}}
	if len(flows) != len(want) {
		t.Fatalf("flows = %+v", flows)
	}
	for i, w := range want {
		if f := flows[i]; f.Comm != w.comm || f.CgroupID != w.cgroup || f.PID != w.pid {
			t.Errorf("flow to %d: owner %q/%d/%d, want %q/%d/%d", f.Port, f.Comm, f.CgroupID, f.PID, w.comm, w.cgroup, w.pid)
		}
	}
	if !tr.ownerMissing {
		t.Error("the closed listener requested no owner scan")
	}
	tr.ownerMissing = false
	tr.attribute([]Flow{in(2049, "", 30), in(111, KernelComm, 0)})
	if tr.ownerMissing {
		t.Error("connections of the kernel requested an owner scan")
	}
}

// TestReusePortOwners checks that connections accepted by two processes in
// different cgroups listening on the same port with SO_REUSEPORT are
// attributed to each of them.
func TestReusePortOwners(t *testing.T) {
	tr := newTestTracer(t)
	root := cgroup2Root()
	if root == "" {
		skipUnavailable(t, "cgroup v2 is not mounted")
	}
	cg := filepath.Join(root, fmt.Sprintf("shawktest-%d", os.Getpid()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		skipUnavailable(t, "cannot create a cgroup: %v", err)
	}
	t.Cleanup(func() { os.Remove(cg) })

	ln := listenReusePort(t, "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	go acceptAndClose(ln)

	helper := exec.Command(os.Args[0], "-test.run=^TestHelperReusePort$")
	helper.Env = append(os.Environ(), "SHAWK_TEST_REUSEPORT="+strconv.Itoa(port))
	stdin, _ := helper.StdinPipe()
	stdout, _ := helper.StdoutPipe()
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		helper.Wait()
	})
	// Move the helper to the new cgroup before it creates its listener.
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(helper.Process.Pid)), 0o644); err != nil {
		skipUnavailable(t, "cannot move a process to the cgroup: %v", err)
	}
	fmt.Fprintln(stdin, "listen")
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("helper did not listen: %q", line)
	}

	for range 40 {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Read(make([]byte, 1))
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	conns := map[uint32]uint64{}
	for _, f := range snap.Flows {
		if f.Direction == DirIn && f.Port == uint16(port) {
			conns[f.PID] += f.Conns
		}
	}
	self, other := conns[uint32(os.Getpid())], conns[uint32(helper.Process.Pid)]
	if self == 0 || other == 0 || self+other != 40 {
		t.Errorf("accepted connections by pid = %v (self %d, helper %d), want both > 0 and 40 in total",
			conns, os.Getpid(), helper.Process.Pid)
	}
	// The two sockets of the group are one listener.
	var listeners int
	for _, l := range snap.Listeners {
		if l.Proto == ProtoTCP && l.Port == uint16(port) {
			listeners++
		}
	}
	if listeners != 1 {
		t.Errorf("listeners on port %d = %d, want 1", port, listeners)
	}
}

// TestHelperReusePort is run by TestReusePortOwners.
func TestHelperReusePort(t *testing.T) {
	port := os.Getenv("SHAWK_TEST_REUSEPORT")
	if port == "" {
		t.Skip("helper process for other tests")
	}
	in := bufio.NewReader(os.Stdin)
	in.ReadString('\n')
	ln := listenReusePort(t, "127.0.0.1:"+port)
	go acceptAndClose(ln)
	fmt.Println("READY")
	in.ReadString('\n')
}

func listenReusePort(t *testing.T, addr string) net.Listener {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(t.Context(), "tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func acceptAndClose(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte{0})
		c.Close()
	}
}

func cgroup2Root() string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok || !strings.HasPrefix(right, "cgroup2 ") {
			continue
		}
		if fields := strings.Fields(left); len(fields) >= 5 {
			return fields[4]
		}
	}
	return ""
}

// TestCgroupEvents checks that a cgroup created while tracing is reported
// with its path, and that flows of a process in it carry its id after the
// cgroup is removed.
func TestCgroupEvents(t *testing.T) {
	requireRoot(t)
	root := cgroup2Root()
	if root == "" {
		skipUnavailable(t, "cgroup v2 is not mounted")
	}
	events := make(chan [2]any, 100)
	tr, err := New(Options{TraceSelf: true, OnCgroup: func(id uint64, path string) {
		events <- [2]any{id, path}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	name := fmt.Sprintf("shawktest-job-%d", os.Getpid())
	cg := filepath.Join(root, name)
	if err := os.Mkdir(cg, 0o755); err != nil {
		skipUnavailable(t, "cannot create a cgroup: %v", err)
	}
	defer os.Remove(cg)
	var st unix.Stat_t
	if err := unix.Stat(cg, &st); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for found := false; !found; {
		select {
		case e := <-events:
			found = e[0].(uint64) == st.Ino && e[1].(string) == "/"+name
		case <-deadline:
			t.Fatalf("no event for %s (id %d)", cg, st.Ino)
		}
	}

	// A short-lived job in the cgroup.
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperDial$")
	helper.Env = append(os.Environ(), "SHAWK_TEST_DIAL="+ln.Addr().String(), "SHAWK_TEST_WAIT=1")
	stdin, _ := helper.StdinPipe()
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(helper.Process.Pid)), 0o644); err != nil {
		skipUnavailable(t, "cannot move a process to the cgroup: %v", err)
	}
	stdin.Close()
	if err := helper.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cg); err != nil {
		t.Fatal(err)
	}
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	f := findFlow(snap.Flows, DirOut, ProtoTCP, port, ln.Addr().(*net.TCPAddr).AddrPort().Addr())
	if f == nil || f.CgroupID != st.Ino || f.PID != uint32(helper.Process.Pid) {
		t.Errorf("flow of the job = %+v, want cgroup %d", f, st.Ino)
	}
}

// TestListenerReplacedInCgroup checks that a listener replaced by one of
// another process in the same cgroup, like a restarted service, is
// attributed to the new process at once rather than after the next periodic
// owner scan (#98): the cgroup of the accepted connections cannot tell them
// apart, the sockets of the listeners can. The new process may listen after
// the former one stopped, or before, with SO_REUSEPORT.
func TestListenerReplacedInCgroup(t *testing.T) {
	requireRoot(t)
	for _, overlap := range []bool{false, true} {
		name := "stopped, then started"
		if overlap {
			name = "started before the former stops"
		}
		t.Run(name, func(t *testing.T) { testListenerReplaced(t, overlap) })
	}
}

func testListenerReplaced(t *testing.T, overlap bool) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// startHelper starts a process listening on the port with
	// SO_REUSEPORT, in the cgroup of the test, and returns it with a
	// function that stops it.
	startHelper := func() (*exec.Cmd, func()) {
		t.Helper()
		helper := exec.Command(os.Args[0], "-test.run=^TestHelperReusePort$")
		helper.Env = append(os.Environ(), "SHAWK_TEST_REUSEPORT="+strconv.Itoa(port))
		stdin, _ := helper.StdinPipe()
		stdout, _ := helper.StdoutPipe()
		if err := helper.Start(); err != nil {
			t.Fatal(err)
		}
		stop := func() {
			stdin.Close()
			helper.Wait()
		}
		t.Cleanup(stop)
		fmt.Fprintln(stdin, "listen")
		if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
			t.Fatalf("helper did not listen: %q", line)
		}
		return helper, stop
	}
	old, stopOld := startHelper()
	tr := newTestTracer(t)
	listenerPID := func(snap *Snapshot) uint32 {
		for _, l := range snap.Listeners {
			if l.Proto == ProtoTCP && l.Port == uint16(port) {
				return l.PID
			}
		}
		return 0
	}
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if pid := listenerPID(snap); pid != uint32(old.Process.Pid) {
		t.Fatalf("listener owner = %d, want %d", pid, old.Process.Pid)
	}

	var replacement *exec.Cmd
	if overlap {
		// Both hold the port at a scan, then the former stops.
		replacement, _ = startHelper()
		if _, err := tr.Collect(); err != nil {
			t.Fatal(err)
		}
		stopOld()
	} else {
		stopOld()
		replacement, _ = startHelper()
	}
	c, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.Read(make([]byte, 1))
	c.Close()
	time.Sleep(100 * time.Millisecond)
	if snap, err = tr.Collect(); err != nil {
		t.Fatal(err)
	}
	want := uint32(replacement.Process.Pid)
	if pid := listenerPID(snap); pid != want {
		t.Errorf("listener owner = %d, want %d", pid, want)
	}
	var in *Flow
	for i := range snap.Flows {
		if f := &snap.Flows[i]; f.Direction == DirIn && f.Port == uint16(port) {
			in = f
		}
	}
	if in == nil || in.Conns != 1 || in.PID != want {
		t.Errorf("incoming flow = %+v, want the connection of %d", in, want)
	}
}
