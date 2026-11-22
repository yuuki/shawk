package tracer

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var netnsSeq atomic.Uint32

// createNetNS creates a network namespace with its loopback up, kept by a
// bind mount in /run/netns as ip netns does, so that the tracer walks its
// sockets like those of a container. It returns the path of the mount. It
// needs no other program, so that the tests also run in the virtual
// machines of test/vm, whose initramfs holds the test binary alone.
func createNetNS(t *testing.T) string {
	t.Helper()
	requireRoot(t)
	dir := "/run/netns"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		skipUnavailable(t, "cannot create %s: %v", dir, err)
	}
	path := filepath.Join(dir, fmt.Sprintf("shawktest%d-%d", os.Getpid(), netnsSeq.Add(1)))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0o444)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() {
		unix.Unmount(path, unix.MNT_DETACH)
		os.Remove(path)
	})
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer orig.Close()
		// The thread returns to its namespace. One that cannot stays locked,
		// so that it ends with the goroutine; Go never ends the main thread,
		// which would then keep the namespace of the process.
		defer func() {
			if unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET) == nil {
				runtime.UnlockOSThread()
			}
		}()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("creating a network namespace: %w", err)
			return
		}
		if err := unix.Mount("/proc/thread-self/ns/net", path, "", unix.MS_BIND, ""); err != nil {
			errc <- fmt.Errorf("mounting the network namespace on %s: %w", path, err)
			return
		}
		errc <- loopbackUp()
	}()
	if err := <-errc; err != nil {
		skipUnavailable(t, "%v", err)
	}
	return path
}

// loopbackUp brings up the loopback of the network namespace of the thread.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("reading the flags of lo: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing up lo: %w", err)
	}
	return nil
}

// enterNetNS moves the thread of the calling goroutine to the network
// namespace at path and locks the goroutine to it. It returns a function
// that moves the thread back and unlocks it; a thread that cannot return
// ends with its goroutine.
func enterNetNS(t *testing.T, path string) (leave func()) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	ns, err := os.Open(path)
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer ns.Close()
	if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	return func() {
		defer orig.Close()
		if unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
	}
}

// newNetNS creates a network namespace (see createNetNS). It returns a
// function running f on a thread that entered the namespace, and its inode.
// Sockets created by f belong to the namespace; /proc/sys/net and
// /proc/thread-self/net are those of the namespace while f runs.
func newNetNS(t *testing.T) (func(f func()), uint32) {
	t.Helper()
	path := createNetNS(t)
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	run := func(f func()) {
		defer enterNetNS(t, path)()
		f()
	}
	return run, uint32(st.Ino)
}

// TestOtherNetNS checks that connections and listeners in another network
// namespace than the tracer's are accounted, including a connection that
// existed before the tracer started.
func TestOtherNetNS(t *testing.T) {
	path := createNetNS(t)
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperNetNSPair$")
	helper.Env = append(os.Environ(), "SHAWK_TEST_NETNS_PAIR="+path)
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		helper.Wait()
	})
	var port uint16
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if _, err := fmt.Sscanf(sc.Text(), "PORT %d", &port); err == nil {
			break
		}
	}
	if port == 0 {
		t.Fatal("helper did not report its port")
	}

	tr := newTestTracer(t)
	if _, err := tr.Collect(); err != nil {
		t.Fatal(err)
	}
	// One round trip of 100 bytes in the interval.
	fmt.Fprintln(stdin, "go")
	if !sc.Scan() || sc.Text() != "DONE" {
		t.Fatalf("helper did not exchange: %q", sc.Text())
	}
	time.Sleep(100 * time.Millisecond)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}

	pid := uint32(helper.Process.Pid)
	var out, in *Flow
	for i := range snap.Flows {
		f := &snap.Flows[i]
		if f.Port != port || f.NetNS == tr.netns {
			continue
		}
		switch f.Direction {
		case DirOut:
			out = f
		case DirIn:
			in = f
		}
	}
	if out == nil || out.OpenConns != 1 || out.BytesSent != 100 || out.BytesRecv != 100 || out.PID != pid {
		t.Errorf("outgoing flow in the other namespace = %+v", out)
	}
	if in == nil || in.OpenConns != 1 || in.BytesSent != 100 || in.BytesRecv != 100 || in.PID != pid {
		t.Errorf("incoming flow in the other namespace = %+v", in)
	}
	var listener *Listener
	for i := range snap.Listeners {
		if l := &snap.Listeners[i]; l.Port == port && l.NetNS != tr.netns {
			listener = l
		}
	}
	if listener == nil || listener.PID != pid {
		t.Errorf("listener in the other namespace = %+v", listener)
	}
}

// TestHelperNetNSPair is run by TestOtherNetNS. In the network namespace
// at SHAWK_TEST_NETNS_PAIR, it connects to its own listener, and makes a
// round trip of 100 bytes for every line of stdin until stdin is closed.
func TestHelperNetNSPair(t *testing.T) {
	path := os.Getenv("SHAWK_TEST_NETNS_PAIR")
	if path == "" {
		t.Skip("helper process for other tests")
	}
	// The thread that creates the sockets stays in the namespace.
	enterNetNS(t, path)
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c, 100)
	fmt.Printf("PORT %d\n", ln.Addr().(*net.TCPAddr).Port)
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		roundTrip(t, c, 100)
		fmt.Println("DONE")
	}
}

// TestCollectFromOtherNetNS checks that every network namespace is walked
// once when the thread that collects is in another namespace than the
// process, as the main thread of a process that entered a namespace stays
// (Go never ends it).
func TestCollectFromOtherNetNS(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	tr := newTestTracer(t)
	run, inode := newNetNS(t)
	dial := func(ln net.Listener) {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		roundTrip(t, c, 100)
	}
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	dial(ln)
	var other net.Listener
	run(func() {
		other = echoServer(t, "tcp4", "127.0.0.1:0")
		dial(other)
	})
	time.Sleep(100 * time.Millisecond)

	var (
		snap *Snapshot
		err  error
	)
	run(func() { snap, err = tr.Collect() })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ln    net.Listener
		netns uint32
	}{{ln, tr.netns}, {other, inode}} {
		srv := tc.ln.Addr().(*net.TCPAddr).AddrPort()
		for _, dir := range []Direction{DirOut, DirIn} {
			var f *Flow
			for i := range snap.Flows {
				if g := &snap.Flows[i]; g.NetNS == tc.netns && g.Direction == dir && g.Port == srv.Port() {
					f = g
				}
			}
			if f == nil || f.Conns != 1 || f.OpenConns != 1 || f.BytesSent != 100 || f.BytesRecv != 100 {
				t.Errorf("netns %d, port %d, %v: flow = %+v", tc.netns, srv.Port(), dir, f)
			}
		}
	}
}

// TestFindNetNS checks the paths kept for each network namespace (#257):
// those of bind mounts first, through one name of their directory, then
// those of the processes with the lowest PIDs, at most maxNetNSPaths of
// them; and that only keeps one namespace.
func TestFindNetNS(t *testing.T) {
	dir := t.TempDir()
	// Files stand in for the namespaces, and links to them for the paths
	// that open them.
	link := func(ns, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "ns", ns), path); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]fileID{}
	if err := os.Mkdir(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"a", "b", "c"} {
		path := filepath.Join(dir, "ns", ns)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		ids[ns] = fileIDOf(&st)
	}
	proc := filepath.Join(dir, "proc")
	pidPath := func(pid string) string { return filepath.Join(proc, pid, "ns", "net") }
	link("a", pidPath("1"))
	for _, pid := range []string{"10000", "2000", "300", "400", "500"} {
		link("b", pidPath(pid))
	}
	// A process whose namespace cannot be read.
	if err := os.MkdirAll(filepath.Join(proc, "600"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1", filepath.Join(proc, "self")); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(dir, "run")
	link("b", filepath.Join(run, "netns", "b"))
	link("c", filepath.Join(run, "docker", "netns", "c"))
	if err := os.MkdirAll(filepath.Join(dir, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(run, filepath.Join(dir, "var", "run")); err != nil {
		t.Fatal(err)
	}
	dirs := []string{
		filepath.Join(run, "netns"), filepath.Join(dir, "var", "run", "netns"),
		filepath.Join(run, "docker", "netns"), filepath.Join(dir, "missing"),
	}

	equal := func(a, b netnsRef) bool { return a.id == b.id && slices.Equal(a.paths, b.paths) }
	want := []netnsRef{
		{id: ids["b"], paths: []string{filepath.Join(run, "netns", "b"), pidPath("300"), pidPath("400"), pidPath("500")}},
		{id: ids["c"], paths: []string{filepath.Join(run, "docker", "netns", "c")}},
		{id: ids["a"], paths: []string{pidPath("self"), pidPath("1")}},
	}
	if got := findNetNS(proc, dirs, 0); !slices.EqualFunc(got, want, equal) {
		t.Errorf("findNetNS = %+v, want %+v", got, want)
	}
	if got := findNetNS(proc, dirs, uint32(ids["b"].ino)); !slices.EqualFunc(got, want[:1], equal) {
		t.Errorf("findNetNS of %d alone = %+v, want %+v", ids["b"].ino, got, want[:1])
	}
}

// TestOpenNetNS checks that a network namespace is opened by the first of
// its paths that still opens it (#257): a path that no longer exists, like
// that of a process that exited, or that opens another file, like that of a
// process whose PID was reused in another namespace, is passed over.
func TestOpenNetNS(t *testing.T) {
	dir := t.TempDir()
	other, target := filepath.Join(dir, "other"), filepath.Join(dir, "target")
	for _, path := range []string{other, target} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var st unix.Stat_t
	if err := unix.Stat(target, &st); err != nil {
		t.Fatal(err)
	}
	ns := netnsRef{id: fileIDOf(&st), paths: []string{filepath.Join(dir, "exited"), other, target}}
	f, err := openNetNS(&ns)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f.Name() != target {
		t.Errorf("opened %s, want %s", f.Name(), target)
	}
	ns.paths = ns.paths[:2]
	if f, err := openNetNS(&ns); err == nil {
		f.Close()
		t.Errorf("opened %s, which is another file", f.Name())
	}
}

// TestOpenInNetNSChecksPath checks that the iterators are opened in the
// network namespace that was listed when its first path opens another one
// (#257), like that of a process whose PID was reused in the namespace of
// the agent.
func TestOpenInNetNSChecksPath(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	tr := newTestTracer(t)
	path := createNetNS(t)
	leave := enterNetNS(t, path)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	leave()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	ns := netnsRef{id: fileIDOf(&st), paths: []string{"/proc/self/ns/net", path}}
	rcs, err := openInNetNS(&ns, tr.iterTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(rcs)
	recs, err := readRecords(rcs[0])
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	found := false
	for i := range recs {
		if r := &recs[i]; r.Type == recListener {
			if r.Netns != ns.inode() {
				t.Fatalf("walked network namespace %d, not %d", r.Netns, ns.inode())
			}
			found = found || r.Port == port
		}
	}
	if !found {
		t.Errorf("the listener on port %d in network namespace %d was not walked", port, ns.inode())
	}
}

// TestWalkNetNSWithFewFiles checks that a walk of the sockets holds the
// files of one network namespace at a time (#257): with room for the files
// of a few namespaces only, it still walks the listeners of every one.
func TestWalkNetNSWithFewFiles(t *testing.T) {
	skipIfNoNetwork(t, "tcp4")
	tr := newTestTracer(t)
	ports := map[uint32]uint16{}
	for range 8 {
		run, inode := newNetNS(t)
		run(func() {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			ports[inode] = uint16(ln.Addr().(*net.TCPAddr).Port)
		})
	}
	var (
		listeners []Listener
		err       error
	)
	withFreeFiles(t, 6, func() { listeners, _, err = tr.scanSockets() })
	if err != nil {
		t.Fatal(err)
	}
	for inode, port := range ports {
		if !slices.ContainsFunc(listeners, func(l Listener) bool {
			return l.Proto == ProtoTCP && l.NetNS == inode && l.Port == port
		}) {
			t.Errorf("the listener on port %d in network namespace %d was not walked", port, inode)
		}
	}
}

// withFreeFiles runs f with a limit of open files that leaves n of them to
// open.
func withFreeFiles(t *testing.T, n int, f func()) {
	t.Helper()
	var orig unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	open := map[int]bool{}
	for _, e := range entries {
		if fd, err := strconv.Atoi(e.Name()); err == nil {
			open[fd] = true
		}
	}
	// A file takes the lowest free descriptor, and fails above the limit.
	limit := 0
	for free := 0; free < n; limit++ {
		if !open[limit] {
			free++
		}
	}
	lim := unix.Rlimit{Cur: uint64(limit), Max: orig.Max}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &orig); err != nil {
			t.Fatal(err)
		}
	}()
	f()
}
