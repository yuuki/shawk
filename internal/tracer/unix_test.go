package tracer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUnixName(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want string
	}{
		{[]byte("/run/postgresql/.s.PGSQL.5432"), "/run/postgresql/.s.PGSQL.5432"},
		{[]byte("\x00/tmp/.X11-unix/X0"), "@/tmp/.X11-unix/X0"},
		// An abstract name may hold any byte, NULs included.
		{[]byte("\x00a\x00b"), `@a\x00b`},
		{[]byte{0}, "@"},
		// A path may start with @, which would read as an abstract name.
		{[]byte("@relative.sock"), `\x40relative.sock`},
		{[]byte(`C:\sock`), `C:\\sock`},
		{[]byte("/tmp/\xff\n"), `/tmp/\xff\x0a`},
		{[]byte("/tmp/ソケット"), "/tmp/ソケット"},
		{[]byte("/tmp/\u0085"), `/tmp/\xc2\x85`},
		{nil, ""},
	} {
		if got := UnixName(tc.in); got != tc.want {
			t.Errorf("UnixName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// requireUnix skips a test of the tracing of Unix sockets when the kernel
// cannot trace them: their programs need BPF trampolines, which
// SHAWK_TEST_NO_TRAMPOLINES=1 declares the kernel has not, as
// SHAWK_TEST_NO_UDP=1 does.
func requireUnix(t *testing.T, tr *Tracer) {
	t.Helper()
	noTrampolines, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_TRAMPOLINES"))
	noUDP, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_UDP"))
	noTrampolines = noTrampolines || noUDP
	switch {
	case noTrampolines && tr.UnixEnabled():
		t.Fatal("Unix sockets are traced, but the kernel is declared without BPF trampolines")
	case noTrampolines:
		t.Skip("Unix sockets are not traced on this kernel, which is declared without BPF trampolines")
	case !tr.UnixEnabled():
		skipUnavailable(t, "Unix sockets are not traced on this kernel")
	}
}

// findUnixFlow returns the statistics of the flows of Unix sockets to the
// name path, summed, or nil.
func findUnixFlow(flows []Flow, path string) *Flow {
	var found *Flow
	for i := range flows {
		f := &flows[i]
		if f.Proto != ProtoUnix || f.Path != path {
			continue
		}
		if found == nil {
			found = &Flow{FlowKey: f.FlowKey}
		}
		found.FlowStats.Add(f.FlowStats)
	}
	return found
}

func findUnixListener(listeners []Listener, path string) *Listener {
	for i := range listeners {
		if l := &listeners[i]; l.Proto == ProtoUnix && l.Path == path {
			return l
		}
	}
	return nil
}

// socketPath returns a path for a socket in a temporary directory, short
// enough for sun_path.
func socketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "shawk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func TestUnixConnections(t *testing.T) {
	abstract := fmt.Sprintf("@shawk-test-%d", os.Getpid())
	for _, tc := range []struct{ name, network, addr string }{
		{"path", "unix", ""},
		{"seqpacket", "unixpacket", ""},
		{"abstract", "unix", abstract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTestTracer(t)
			requireUnix(t, tr)
			addr := tc.addr
			if addr == "" {
				addr = socketPath(t, "s.sock")
			}
			ln := echoServer(t, tc.network, addr)
			name := ln.Addr().String()

			const conns = 3
			for range conns {
				c, err := net.Dial(tc.network, addr)
				if err != nil {
					t.Fatal(err)
				}
				roundTrip(t, c, 100)
				c.Close()
			}
			kept, err := net.Dial(tc.network, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer kept.Close()
			roundTrip(t, kept, 100)
			time.Sleep(100 * time.Millisecond)

			snap, err := tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			f := findUnixFlow(snap.Flows, name)
			if f == nil {
				t.Fatalf("no flow to %s in %+v", name, snap.Flows)
			}
			if f.Conns != conns+1 || f.OpenConns != 1 || f.ConnFails != 0 {
				t.Errorf("stats = %+v, want %d connections, one open", f.FlowStats, conns+1)
			}
			if f.BytesSent != 0 || f.BytesRecv != 0 {
				t.Errorf("bytes = %d/%d, but Unix sockets count none", f.BytesSent, f.BytesRecv)
			}
			if f.Direction != DirOut || f.NetNS != tr.netns || f.LocalAddr.IsValid() || f.Port != 0 {
				t.Errorf("key = %+v", f.FlowKey)
			}
			if f.Comm != testComm || f.PID != uint32(os.Getpid()) {
				t.Errorf("owner = %q/%d, want %q/%d", f.Comm, f.PID, testComm, os.Getpid())
			}

			// The connections to a name the last scan did not know request
			// the scan that finds its listener.
			snap, err = tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			f = findUnixFlow(snap.Flows, name)
			if f == nil || f.Conns != 0 || f.OpenConns != 1 {
				t.Errorf("second interval: flow = %+v, want the open connection only", f)
			}
			l := findUnixListener(snap.Listeners, name)
			if l == nil {
				t.Fatalf("listener %s not found in %+v", name, snap.Listeners)
			}
			if l.PID != uint32(os.Getpid()) || l.Comm != testComm || l.NetNS != tr.netns {
				t.Errorf("listener = %+v", l)
			}

			kept.Close()
			time.Sleep(50 * time.Millisecond)
			snap, err = tr.Collect()
			if err != nil {
				t.Fatal(err)
			}
			if f := findUnixFlow(snap.Flows, name); f != nil {
				t.Errorf("third interval: flow = %+v after the connection closed", f)
			}
		})
	}
}

// connectUnix connects a new nonblocking socket to path and returns it with
// the error of connect(2).
func connectUnix(t *testing.T, path string) (int, error) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd, unix.Connect(fd, &unix.SockaddrUnix{Name: path})
}

// boundSocket binds a socket to path and listens with backlog unless it is
// negative.
func boundSocket(t *testing.T, path string, backlog int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if backlog >= 0 {
		if err := unix.Listen(fd, backlog); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnixFailures(t *testing.T) {
	tr := newTestTracer(t)
	requireUnix(t, tr)
	dir := filepath.Dir(socketPath(t, "x"))
	missing := filepath.Join(dir, "missing.sock")
	// A socket file whose socket does not listen, as one left by a server
	// that exited.
	stale := filepath.Join(dir, "stale.sock")
	boundSocket(t, stale, -1)
	// A listener that never accepts, whose backlog of 0 holds one
	// connection.
	full := filepath.Join(dir, "full.sock")
	boundSocket(t, full, 0)

	for _, tc := range []struct {
		path string
		want error
	}{
		{missing, unix.ENOENT},
		{stale, unix.ECONNREFUSED},
		{full, nil},
		{full, unix.EAGAIN},
	} {
		if _, err := connectUnix(t, tc.path); !errors.Is(err, tc.want) {
			t.Fatalf("connecting to %s: %v, want %v", tc.path, err, tc.want)
		}
	}
	// A connect to an address that is not one is no attempt.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 80}); err == nil {
		t.Fatal("connecting a Unix socket to an IPv4 address succeeded")
	}

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path         string
		conns, fails uint64
		reason       FailReason
	}{
		{missing, 0, 1, FailRefused},
		{stale, 0, 1, FailRefused},
		{full, 1, 1, FailTimeout},
	} {
		f := findUnixFlow(snap.Flows, tc.path)
		if f == nil {
			t.Errorf("no flow to %s in %+v", tc.path, snap.Flows)
			continue
		}
		if f.Conns != tc.conns || f.ConnFails != tc.fails || f.Fails[tc.reason] != tc.fails || f.OtherFails() != 0 {
			t.Errorf("%s: stats = %+v, want %d connections and %d failures by %s", tc.path, f.FlowStats, tc.conns, tc.fails, tc.reason)
		}
		if f.Comm != testComm || f.PID != uint32(os.Getpid()) {
			t.Errorf("%s: owner = %q/%d", tc.path, f.Comm, f.PID)
		}
	}
	// The other processes of the host have connections of their own.
	for _, f := range snap.Flows {
		if f.Proto == ProtoUnix && f.Comm == testComm && f.Path != missing && f.Path != stale && f.Path != full {
			t.Errorf("unexpected flow %+v", f)
		}
	}
}

// autobound matches the names the kernel gives sockets without one.
var autobound = regexp.MustCompile(`^@[0-9a-f]{5}$`)

func TestUnixAdopted(t *testing.T) {
	requireRoot(t)
	path := socketPath(t, "s.sock")
	ln := echoServer(t, "unix", path)

	// Connections established before the tracer starts: one whose client
	// has no name, and one whose client the kernel gave a name because it
	// passes credentials.
	pre, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer pre.Close()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	// x/sys/unix names an abstract address with @ for its NUL, as UnixName.
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	if name := sa.(*unix.SockaddrUnix).Name; !autobound.MatchString(name) {
		t.Fatalf("the client with SO_PASSCRED has the name %q, not one the kernel gives", name)
	}
	// An unnamed pair is no connection to a service.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	time.Sleep(50 * time.Millisecond) // the server accepts both

	tr := newTestTracer(t)
	requireUnix(t, tr)
	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	f := findUnixFlow(snap.Flows, ln.Addr().String())
	if f == nil {
		t.Fatalf("no flow to %s in %+v", path, snap.Flows)
	}
	if f.OpenConns != 2 || f.Conns != 0 {
		t.Errorf("stats = %+v, want 2 open connections and none counted", f.FlowStats)
	}
	if f.Comm != testComm || f.NetNS != tr.netns {
		t.Errorf("key = %+v", f.FlowKey)
	}
	// The sides of the server, and the pair, are not taken for clients.
	for _, f := range snap.Flows {
		if f.Proto == ProtoUnix && f.Comm == testComm && f.Path != path {
			t.Errorf("unexpected flow %+v", f)
		}
	}
	if l := findUnixListener(snap.Listeners, path); l == nil || l.PID != uint32(os.Getpid()) {
		t.Errorf("listener = %+v", l)
	}

	pre.Close()
	time.Sleep(50 * time.Millisecond)
	snap, err = tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if f := findUnixFlow(snap.Flows, path); f == nil || f.OpenConns != 1 {
		t.Errorf("after one closed: flow = %+v, want one open connection", f)
	}
}

// TestUnixOpenUnderChurn: open connections are counted exactly while the
// tracer collects and walks the processes at the same time as clients
// connect, so that walks adopt sockets that connect(2) is adding, and
// collections read flows whose first connection is being added; and none
// stays open once all are closed.
func TestUnixOpenUnderChurn(t *testing.T) {
	tr := newTestTracer(t)
	requireUnix(t, tr)
	dir := filepath.Dir(socketPath(t, "x"))
	const names = 64
	paths := make([]string, names)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("%d.sock", i))
		if i > 0 {
			echoServer(t, "unix", paths[i])
		}
	}
	// Short connections to the first name all along, which its server closes
	// as it accepts them, and at most a few at a time: the files of
	// connections that an echo server closes once it reads their end would
	// pile up faster than a slow VM closes them, up to the limit of open
	// files of the process.
	ln, err := net.Listen("unix", paths[0])
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
			c.Close()
		}
	}()
	stop := make(chan struct{})
	var churn sync.WaitGroup
	for range 2 {
		churn.Add(1)
		go func() {
			defer churn.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c, err := net.Dial("unix", paths[0]); err == nil {
					c.Close()
				}
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}
	// One connection kept open to every other name, each the first of its
	// flow.
	kept := make(chan []net.Conn)
	go func() {
		var conns []net.Conn
		for _, p := range paths[1:] {
			c, err := net.Dial("unix", p)
			if err != nil {
				t.Error(err)
				break
			}
			conns = append(conns, c)
			time.Sleep(10 * time.Millisecond)
		}
		kept <- conns
	}()
	var conns []net.Conn
	for conns == nil {
		select {
		case conns = <-kept:
		default:
		}
		tr.mu.Lock()
		err := tr.scanOwners()
		tr.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Collect(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	churn.Wait()
	time.Sleep(50 * time.Millisecond)

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if f := findUnixFlow(snap.Flows, paths[0]); f != nil && f.OpenConns != 0 {
		t.Errorf("%s: %d connections open after the clients closed them", paths[0], f.OpenConns)
	}
	for _, p := range paths[1:] {
		if f := findUnixFlow(snap.Flows, p); f == nil || f.OpenConns != 1 {
			t.Errorf("%s: flow %+v, want one open connection", p, f)
		}
	}
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(50 * time.Millisecond)
	if snap, err = tr.Collect(); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if f := findUnixFlow(snap.Flows, p); f != nil && f.OpenConns != 0 {
			t.Errorf("%s: %d connections open after all closed", p, f.OpenConns)
		}
	}
}
