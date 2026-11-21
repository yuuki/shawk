package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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

// cgroupEventsCapacity returns how many events the ring buffer of cgroup
// events holds: each record has a header of 8 bytes, and records are
// aligned to 8 bytes.
func cgroupEventsCapacity(t *testing.T) int {
	t.Helper()
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	record := (binary.Size(bpfShawkCgroupEvent{}) + 8 + 7) &^ 7
	return int(spec.Maps["cgroup_events"].MaxEntries) / record
}

// TestCgroupBurst creates a burst of cgroups, as a node starting many pods
// does (#126). A reader that keeps up, as procinfo.Resolver.Learn, which
// only records the path, gets the events of all of them; one that stops
// reading, as Learn did while it read the state of containers, gets the
// kernel to drop some, which CgroupEventDrops counts.
//
// How far a reader falls behind a burst depends on the scheduler as much as
// on the reader: on a virtual machine, the 3000 cgroups can all be created
// before the reader runs, and fill the ring buffer even if the reader
// returns at once. A reader that keeps up therefore gets the cgroups in
// batches of three quarters of what the ring buffer holds, the rest being
// left to the cgroups that the host creates meanwhile, and the next batch
// starts once the reader has reported the previous one.
func TestCgroupBurst(t *testing.T) {
	requireRoot(t)
	root := cgroup2Root()
	if root == "" {
		skipUnavailable(t, "cgroup v2 is not mounted")
	}
	const n = 3000
	capacity := cgroupEventsCapacity(t)
	if capacity < 4 || capacity >= n {
		t.Fatalf("the ring buffer holds %d cgroup events", capacity)
	}
	for _, stalled := range []bool{false, true} {
		name := "a reader that keeps up"
		if stalled {
			name = "a reader that stalls"
		}
		batch := n
		if !stalled {
			batch = capacity * 3 / 4
		}
		t.Run(name, func(t *testing.T) {
			parent := filepath.Join(root, fmt.Sprintf("shawktest-burst-%d", os.Getpid()))
			prefix := "/" + filepath.Base(parent) + "/"
			var (
				mu   sync.Mutex
				seen = map[string]bool{}
			)
			resume := make(chan struct{})
			tr, err := New(Options{TraceSelf: true, OnCgroup: func(id uint64, path string) {
				if stalled {
					<-resume
				}
				if strings.HasPrefix(path, prefix) {
					mu.Lock()
					seen[path] = true
					mu.Unlock()
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer release()
			if err := os.Mkdir(parent, 0o755); err != nil {
				skipUnavailable(t, "cannot create a cgroup: %v", err)
			}
			var dirs []string
			defer func() {
				for _, d := range slices.Backward(dirs) {
					os.Remove(d)
				}
				os.Remove(parent)
			}()
			reported := func() int {
				mu.Lock()
				defer mu.Unlock()
				return len(seen)
			}
			start := time.Now()
			for i := range n {
				d := filepath.Join(parent, fmt.Sprintf("c%d", i))
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
				dirs = append(dirs, d)
				if (i+1)%batch != 0 || i+1 == n {
					continue
				}
				// A batch that the reader has not reported in 5 seconds
				// shows below as events neither reported nor dropped.
				for deadline := time.Now().Add(5 * time.Second); reported() < i+1 && time.Now().Before(deadline); {
					time.Sleep(time.Millisecond)
				}
			}
			elapsed := time.Since(start)
			release()
			deadline := time.Now().Add(5 * time.Second)
			var snap *Snapshot
			for {
				if snap, err = tr.Collect(); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				got := len(seen)
				mu.Unlock()
				if uint64(got)+snap.CgroupEventDrops >= n || time.Now().After(deadline) {
					t.Logf("%d cgroups in batches of %d in %v: %d reported, %d dropped", n, batch, elapsed, got, snap.CgroupEventDrops)
					if uint64(got)+snap.CgroupEventDrops < n {
						t.Errorf("%d cgroups neither reported nor counted as dropped", n-got-int(snap.CgroupEventDrops))
					}
					if stalled && snap.CgroupEventDrops == 0 {
						t.Errorf("a stalled reader dropped no events of %d cgroups", n)
					}
					if !stalled && snap.CgroupEventDrops != 0 {
						t.Errorf("a reader that keeps up dropped %d events", snap.CgroupEventDrops)
					}
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

type fakeListenMap struct {
	entries  map[bpfShawkListenKey]struct{}
	capacity int // 0 means unbounded
	puts     int
	keysErr  error
	delErr   func(bpfShawkListenKey) error
	putErr   func(bpfShawkListenKey) error
}

func newFakeListenMap(keys ...bpfShawkListenKey) *fakeListenMap {
	m := &fakeListenMap{entries: make(map[bpfShawkListenKey]struct{}, len(keys))}
	for _, k := range keys {
		m.entries[k] = struct{}{}
	}
	return m
}

func (f *fakeListenMap) keys() ([]bpfShawkListenKey, error) {
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	out := make([]bpfShawkListenKey, 0, len(f.entries))
	for k := range f.entries {
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeListenMap) delete(key bpfShawkListenKey) error {
	if f.delErr != nil {
		if err := f.delErr(key); err != nil {
			return err
		}
	}
	if _, ok := f.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, key)
	return nil
}

func (f *fakeListenMap) putNoExist(key bpfShawkListenKey) error {
	f.puts++
	if f.putErr != nil {
		if err := f.putErr(key); err != nil {
			return err
		}
	}
	if _, ok := f.entries[key]; ok {
		return ebpf.ErrKeyExist
	}
	if f.capacity > 0 && len(f.entries) >= f.capacity {
		return fmt.Errorf("key too big for map: %w", unix.E2BIG)
	}
	f.entries[key] = struct{}{}
	return nil
}

type callbackReadCloser struct {
	r      io.Reader
	onRead func()
	once   bool
	closed bool
}

func (c *callbackReadCloser) Read(p []byte) (int, error) {
	if !c.once && c.onRead != nil {
		c.once = true
		c.onRead()
	}
	return c.r.Read(p)
}

func (c *callbackReadCloser) Close() error {
	c.closed = true
	return nil
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func encodeIterRecs(t *testing.T, recs ...bpfShawkIterRec) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, recs); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func listenerRec(proto Proto, netns uint32, addr string, port uint16, ino uint64) bpfShawkIterRec {
	return bpfShawkIterRec{
		Type:  recListener,
		Proto: uint8(proto),
		Netns: netns,
		Addr:  netip.MustParseAddr(addr).As16(),
		Port:  port,
		Ino:   ino,
	}
}

// TestScanSocketsPrunesListenPorts checks that scanSocketsWith clears TCP
// listen_ports before walking namespaces while keeping pre-existing
// udp_listen_ports entries intact throughout the walk, preserving ports
// inserted concurrently by udp_direction(), pruning only stale UDP keys
// afterwards, and issuing no backfill puts in steady state.
func TestScanSocketsPrunesListenPorts(t *testing.T) {
	key := func(netns uint32, port uint16) bpfShawkListenKey {
		return bpfShawkListenKey{Netns: netns, Port: port}
	}
	initTCP := []bpfShawkListenKey{
		key(100, 80),
		key(100, 443),
		key(200, 80),
	}
	initUDP := []bpfShawkListenKey{
		key(100, 443),  // active UDP (TCP 443 closed)
		key(100, 53),   // stale UDP (also appears in a non-listener record)
		key(100, 5353), // IPv4 closed, IPv6 remains active
		key(200, 443),  // stale in netns 200 (netns 100 port 443 stays active)
		key(100, 9999), // removed before prune; ErrKeyNotExist must be ignored
	}
	tcpPorts := newFakeListenMap(initTCP...)
	udpPorts := newFakeListenMap(initUDP...)

	assertUDPPresent := func(phase string) {
		t.Helper()
		for _, k := range initUDP {
			if _, ok := udpPorts.entries[k]; !ok {
				t.Fatalf("%s: UDP key %+v was removed prematurely", phase, k)
			}
		}
	}

	concurrentUDP := key(100, 6000)
	var opened, drained bool
	open := func() ([]io.ReadCloser, error) {
		opened = true
		// TCP listen_ports must be cleared before iter/tcp opens so
		// adopted_direction() never sees stale closed TCP listeners.
		if len(tcpPorts.entries) != 0 {
			t.Fatalf("during open: tcpPorts = %v, want empty", tcpPorts.entries)
		}
		assertUDPPresent("during open")
		tcpRecs := encodeIterRecs(t,
			listenerRec(ProtoTCP, 100, "127.0.0.1", 80, 1),
			listenerRec(ProtoTCP, 100, "::1", 8080, 2),
		)
		udpRecs := encodeIterRecs(t,
			listenerRec(ProtoUDP, 100, "127.0.0.1", 443, 3),
			listenerRec(ProtoUDP, 100, "127.0.0.1", 443, 4), // SO_REUSEPORT peer
			listenerRec(ProtoUDP, 100, "::1", 5353, 5),
			listenerRec(ProtoUDP, 100, "127.0.0.1", 5000, 6),
			bpfShawkIterRec{Type: recOwner, Proto: uint8(ProtoUDP), Netns: 100, Port: 53, Pid: 42},
		)
		tcpRd := &callbackReadCloser{
			r: bytes.NewReader(tcpRecs),
			onRead: func() {
				if len(tcpPorts.entries) != 0 {
					t.Fatalf("before TCP read: tcpPorts = %v, want empty", tcpPorts.entries)
				}
				assertUDPPresent("during TCP read")
				// Simulate iter/tcp repopulating active TCP ports.
				tcpPorts.entries[key(100, 80)] = struct{}{}
				tcpPorts.entries[key(100, 8080)] = struct{}{}
			},
		}
		udpRd := &callbackReadCloser{
			r: bytes.NewReader(udpRecs),
			onRead: func() {
				drained = true
				assertUDPPresent("during UDP read")
				// Simulate iter/udp inserting the newly observed port,
				// udp_direction() concurrently inserting a brand-new server
				// port after the snapshot, and a stale entry disappearing.
				udpPorts.entries[key(100, 5000)] = struct{}{}
				udpPorts.entries[concurrentUDP] = struct{}{}
				delete(udpPorts.entries, key(100, 9999))
			},
		}
		return []io.ReadCloser{tcpRd, udpRd}, nil
	}

	listeners, inos, err := scanSocketsWith(tcpPorts, udpPorts, open)
	if err != nil {
		t.Fatal(err)
	}
	if !opened || !drained {
		t.Fatalf("opened=%v drained=%v, want both true", opened, drained)
	}
	if len(listeners) != 5 || len(inos) != 6 {
		t.Errorf("got %d listeners and %d inos, want 5 and 6", len(listeners), len(inos))
	}

	wantTCP := map[bpfShawkListenKey]struct{}{
		key(100, 80):   {},
		key(100, 8080): {},
	}
	if !maps.Equal(tcpPorts.entries, wantTCP) {
		t.Errorf("tcpPorts after walk = %v, want %v", tcpPorts.entries, wantTCP)
	}
	wantUDP := map[bpfShawkListenKey]struct{}{
		key(100, 443):  {},
		key(100, 5353): {},
		key(100, 5000): {},
		concurrentUDP:  {},
	}
	if !maps.Equal(udpPorts.entries, wantUDP) {
		t.Errorf("udpPorts after walk = %v, want %v", udpPorts.entries, wantUDP)
	}

	// Steady-state walk (activeUDP is a subset of prevUDP): no backfill puts,
	// and a closed port previously added by udp_direction() is now pruned.
	udpPorts.puts = 0
	_, _, err = scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
		recs := encodeIterRecs(t,
			listenerRec(ProtoTCP, 100, "127.0.0.1", 80, 1),
			listenerRec(ProtoUDP, 100, "127.0.0.1", 443, 3),
			listenerRec(ProtoUDP, 100, "::1", 5353, 5),
			listenerRec(ProtoUDP, 100, "127.0.0.1", 5000, 6),
		)
		return []io.ReadCloser{io.NopCloser(bytes.NewReader(recs))}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if udpPorts.puts != 0 {
		t.Errorf("steady-state walk performed %d backfill puts, want 0", udpPorts.puts)
	}
	if _, ok := udpPorts.entries[concurrentUDP]; ok {
		t.Errorf("closed UDP port %+v was not pruned on the next walk", concurrentUDP)
	}
	if _, ok := udpPorts.entries[key(100, 443)]; !ok {
		t.Errorf("active UDP port was pruned on the next walk")
	}
}

// TestScanSocketsBackfillsFullUDPListenPorts checks that newly observed UDP
// server ports dropped during the walk because stale entries filled
// udp_listen_ports are backfilled once stale entries are pruned, and that
// E2BIG is ignored when the map is genuinely full of active listeners.
func TestScanSocketsBackfillsFullUDPListenPorts(t *testing.T) {
	key := func(port uint16) bpfShawkListenKey {
		return bpfShawkListenKey{Netns: 100, Port: port}
	}

	t.Run("recovers after pruning stale entries", func(t *testing.T) {
		tcpPorts := newFakeListenMap()
		udpPorts := newFakeListenMap(key(443), key(53))
		udpPorts.capacity = 2

		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			// Map is full (443 active + 53 stale), so iter/udp fails to insert
			// newly opened port 5000 while still emitting its listener record.
			recs := encodeIterRecs(t,
				listenerRec(ProtoUDP, 100, "127.0.0.1", 443, 1),
				listenerRec(ProtoUDP, 100, "127.0.0.1", 5000, 2),
			)
			return []io.ReadCloser{io.NopCloser(bytes.NewReader(recs))}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := map[bpfShawkListenKey]struct{}{
			key(443):  {},
			key(5000): {},
		}
		if !maps.Equal(udpPorts.entries, want) {
			t.Errorf("udpPorts = %v, want %v", udpPorts.entries, want)
		}
	})

	t.Run("ignores E2BIG when still full of active listeners", func(t *testing.T) {
		tcpPorts := newFakeListenMap()
		udpPorts := newFakeListenMap(key(443), key(5353))
		udpPorts.capacity = 2

		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			recs := encodeIterRecs(t,
				listenerRec(ProtoUDP, 100, "127.0.0.1", 443, 1),
				listenerRec(ProtoUDP, 100, "127.0.0.1", 5353, 2),
				listenerRec(ProtoUDP, 100, "127.0.0.1", 5000, 3),
			)
			return []io.ReadCloser{io.NopCloser(bytes.NewReader(recs))}, nil
		})
		if err != nil {
			t.Fatalf("unexpected error when map is genuinely full: %v", err)
		}
		want := map[bpfShawkListenKey]struct{}{
			key(443):  {},
			key(5353): {},
		}
		if !maps.Equal(udpPorts.entries, want) {
			t.Errorf("udpPorts = %v, want %v", udpPorts.entries, want)
		}
	})
}

// TestScanSocketsErrorsPreserveListenPorts checks that errors during open or
// read leave existing udp_listen_ports entries intact, and that map errors
// propagate cleanly.
func TestScanSocketsErrorsPreserveListenPorts(t *testing.T) {
	k := bpfShawkListenKey{Netns: 100, Port: 443}
	boom := errors.New("boom")

	t.Run("open error", func(t *testing.T) {
		tcpPorts := newFakeListenMap(k)
		udpPorts := newFakeListenMap(k)
		partial := &callbackReadCloser{r: bytes.NewReader(nil)}
		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			return []io.ReadCloser{partial}, boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		if !partial.closed {
			t.Error("partial reader was not closed")
		}
		if _, ok := udpPorts.entries[k]; !ok {
			t.Error("udpPorts entry was removed on open error")
		}
	})

	t.Run("read error", func(t *testing.T) {
		tcpPorts := newFakeListenMap(k)
		udpPorts := newFakeListenMap(k)
		rd := &callbackReadCloser{r: errReader{err: boom}}
		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			return []io.ReadCloser{rd}, nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		if !rd.closed {
			t.Error("reader was not closed")
		}
		if _, ok := udpPorts.entries[k]; !ok {
			t.Error("udpPorts entry was removed on read error")
		}
	})

	t.Run("udp keys error", func(t *testing.T) {
		tcpPorts := newFakeListenMap(k)
		udpPorts := newFakeListenMap(k)
		udpPorts.keysErr = boom
		opened := false
		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			opened = true
			return nil, nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		if opened {
			t.Error("open was called after udp keys failed")
		}
		if _, ok := tcpPorts.entries[k]; !ok {
			t.Error("tcpPorts was cleared after udp keys failed")
		}
	})

	t.Run("tcp clear error", func(t *testing.T) {
		tcpPorts := newFakeListenMap(k)
		tcpPorts.delErr = func(bpfShawkListenKey) error { return boom }
		udpPorts := newFakeListenMap(k)
		opened := false
		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			opened = true
			return nil, nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		if opened {
			t.Error("open was called after tcp clear failed")
		}
		if _, ok := udpPorts.entries[k]; !ok {
			t.Error("udpPorts was modified after tcp clear failed")
		}
	})

	t.Run("udp delete error", func(t *testing.T) {
		tcpPorts := newFakeListenMap()
		udpPorts := newFakeListenMap(k)
		udpPorts.delErr = func(bpfShawkListenKey) error { return boom }
		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			return nil, nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
	})

	t.Run("udp backfill error", func(t *testing.T) {
		tcpPorts := newFakeListenMap()
		udpPorts := newFakeListenMap()
		udpPorts.putErr = func(bpfShawkListenKey) error { return boom }
		_, _, err := scanSocketsWith(tcpPorts, udpPorts, func() ([]io.ReadCloser, error) {
			recs := encodeIterRecs(t, listenerRec(ProtoUDP, 100, "127.0.0.1", 443, 1))
			return []io.ReadCloser{io.NopCloser(bytes.NewReader(recs))}, nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
	})
}

// TestScanSocketsPrunesEBPFMaps exercises ebpfListenMap and scanSocketsWith
// against real kernel BPF hash maps, including clearing TCP listen_ports
// before the walk, keeping UDP entries during the walk, preserving ports
// inserted concurrently, pruning stale entries, and backfilling new UDP
// ports after stale slots are freed.
func TestScanSocketsPrunesEBPFMaps(t *testing.T) {
	requireRoot(t)
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	newMap := func(name string, maxEntries uint32) *ebpf.Map {
		t.Helper()
		ms := spec.Maps[name].Copy()
		ms.MaxEntries = maxEntries
		m, err := ebpf.NewMap(ms)
		if err != nil {
			skipUnavailable(t, "creating %s: %v", name, err)
		}
		t.Cleanup(func() { m.Close() })
		return m
	}
	tcpMap := newMap(bpfMapListenPorts, 16)
	udpMap := newMap(bpfMapUdpListenPorts, 3)

	staleTCP := bpfShawkListenKey{Netns: 100, Port: 81}
	activeUDP := bpfShawkListenKey{Netns: 100, Port: 443}
	staleUDP := bpfShawkListenKey{Netns: 100, Port: 444}
	concurrentUDP := bpfShawkListenKey{Netns: 100, Port: 445}
	backfillUDP := bpfShawkListenKey{Netns: 100, Port: 446}
	overflowUDP := bpfShawkListenKey{Netns: 100, Port: 447}

	if err := tcpMap.Put(&staleTCP, uint8(1)); err != nil {
		t.Fatal(err)
	}
	for _, k := range []bpfShawkListenKey{activeUDP, staleUDP} {
		if err := udpMap.Put(&k, uint8(1)); err != nil {
			t.Fatal(err)
		}
	}

	open := func() ([]io.ReadCloser, error) {
		var v uint8
		if err := tcpMap.Lookup(&staleTCP, &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("stale TCP key still present during walk: %v", err)
		}
		if err := udpMap.Lookup(&activeUDP, &v); err != nil {
			t.Fatalf("active UDP key missing during walk: %v", err)
		}
		// Fill the 3rd slot concurrently as udp_direction() would, leaving no
		// room for backfillUDP until staleUDP is pruned after the walk.
		if err := udpMap.Put(&concurrentUDP, uint8(1)); err != nil {
			t.Fatal(err)
		}
		recs := encodeIterRecs(t,
			listenerRec(ProtoUDP, activeUDP.Netns, "127.0.0.1", activeUDP.Port, 1),
			listenerRec(ProtoUDP, backfillUDP.Netns, "127.0.0.1", backfillUDP.Port, 2),
		)
		return []io.ReadCloser{io.NopCloser(bytes.NewReader(recs))}, nil
	}

	if _, _, err := scanSocketsWith(ebpfListenMap{tcpMap}, ebpfListenMap{udpMap}, open); err != nil {
		t.Fatal(err)
	}

	var v uint8
	for _, tc := range []struct {
		name string
		key  bpfShawkListenKey
		want bool
	}{
		{"active UDP kept", activeUDP, true},
		{"concurrent UDP kept", concurrentUDP, true},
		{"backfilled UDP inserted after prune", backfillUDP, true},
		{"stale UDP pruned", staleUDP, false},
	} {
		err := udpMap.Lookup(&tc.key, &v)
		if tc.want && err != nil {
			t.Errorf("%s: Lookup = %v, want present", tc.name, err)
		}
		if !tc.want && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Errorf("%s: Lookup = %v, want ErrKeyNotExist", tc.name, err)
		}
	}

	// With all 3 slots occupied by active listeners, a 4th active UDP port
	// hits E2BIG during backfill and must be ignored without error.
	if _, _, err := scanSocketsWith(ebpfListenMap{tcpMap}, ebpfListenMap{udpMap}, func() ([]io.ReadCloser, error) {
		recs := encodeIterRecs(t,
			listenerRec(ProtoUDP, activeUDP.Netns, "127.0.0.1", activeUDP.Port, 1),
			listenerRec(ProtoUDP, concurrentUDP.Netns, "127.0.0.1", concurrentUDP.Port, 2),
			listenerRec(ProtoUDP, backfillUDP.Netns, "127.0.0.1", backfillUDP.Port, 3),
			listenerRec(ProtoUDP, overflowUDP.Netns, "127.0.0.1", overflowUDP.Port, 4),
		)
		return []io.ReadCloser{io.NopCloser(bytes.NewReader(recs))}, nil
	}); err != nil {
		t.Fatalf("full-map backfill returned error: %v", err)
	}
}

// TestUDPListenPortsKeptAcrossCollect checks that a walk of the sockets keeps
// the ports of the UDP servers while it runs (#238): a per-client connected
// socket of a server, like those of QUIC, that sends first during the walk is
// a server for good, not a client of the port of its client. A port whose
// server closed is deleted once the walk is over.
func TestUDPListenPortsKeptAcrossCollect(t *testing.T) {
	skipIfNoNetwork(t, "udp4")
	tr := newTestTracer(t)
	requireUDP(t, tr)

	reuse := setsockoptControl(unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	l := listenUDPFixedPort(t, "udp4", "127.0.0.1")
	srvAddr := l.LocalAddr().String()
	l.Close()
	srv, err := (&net.ListenConfig{Control: reuse}).ListenPacket(t.Context(), "udp4", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	closed := listenUDPFixedPort(t, "udp4", "127.0.0.1")
	defer closed.Close()
	srvKey := bpfShawkListenKey{Netns: tr.netns, Port: uint16(srv.LocalAddr().(*net.UDPAddr).Port)}
	closedKey := bpfShawkListenKey{Netns: tr.netns, Port: uint16(closed.LocalAddr().(*net.UDPAddr).Port)}
	if _, err := tr.Collect(); err != nil {
		t.Fatal(err)
	}
	var v uint8
	for _, k := range []bpfShawkListenKey{srvKey, closedKey} {
		if err := tr.udpListenPorts.Lookup(&k, &v); err != nil {
			t.Fatalf("port %d is not a UDP server port after the first walk: %v", k.Port, err)
		}
	}
	closed.Close()

	cli, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cliPort := uint16(cli.LocalAddr().(*net.UDPAddr).Port)
	var (
		conn    net.Conn
		hookErr error
	)
	buf := make([]byte, 32)
	t.Cleanup(func() { beforeSocketWalk = nil })
	beforeSocketWalk = func() {
		if err := tr.udpListenPorts.Lookup(&srvKey, &v); err != nil {
			hookErr = fmt.Errorf("the server port is missing during the walk: %w", err)
			return
		}
		conn, hookErr = (&net.Dialer{LocalAddr: srv.LocalAddr(), Control: reuse}).DialContext(t.Context(), "udp4", cli.LocalAddr().String())
		if hookErr != nil {
			return
		}
		if _, hookErr = conn.Write(buf); hookErr != nil {
			return
		}
		cli.SetReadDeadline(time.Now().Add(time.Second))
		_, _, hookErr = cli.ReadFrom(buf)
	}
	snap, err := tr.Collect()
	beforeSocketWalk = nil
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if err := tr.udpListenPorts.Lookup(&srvKey, &v); err != nil {
		t.Errorf("the server port is missing after the walk: %v", err)
	}
	if err := tr.udpListenPorts.Lookup(&closedKey, &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the port of the closed server after the walk: %v, want ErrKeyNotExist", err)
	}
	lo := netip.MustParseAddr("127.0.0.1")
	check := func(what string, snap *Snapshot) {
		t.Helper()
		if f := findFlow(snap.Flows, DirIn, ProtoUDP, srvKey.Port, lo); f == nil || f.MsgsSent != 1 {
			t.Errorf("%s: server flow = %+v in %+v", what, f, snap.Flows)
		}
		// The client socket receives first, which makes its own port that
		// of an incoming flow; the server socket must not be a client of it.
		if f := findFlow(snap.Flows, DirOut, ProtoUDP, cliPort, lo); f != nil {
			t.Errorf("%s: the server socket is a client of the port of its client: %+v", what, f)
		}
	}
	check("datagram sent during the walk", snap)

	// The socket keeps its direction.
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := cli.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	snap, err = tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	check("next datagram", snap)
}
