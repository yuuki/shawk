package tracer

import (
	"bufio"
	"fmt"
	"net"
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

// TestReusePortOwners checks that connections accepted by two processes in
// different cgroups listening on the same port with SO_REUSEPORT are
// attributed to each of them.
func TestReusePortOwners(t *testing.T) {
	tr := newTestTracer(t)
	root := cgroup2Root()
	if root == "" {
		t.Skip("cgroup v2 is not mounted")
	}
	cg := filepath.Join(root, fmt.Sprintf("shawktest-%d", os.Getpid()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
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
		t.Skipf("cannot move a process to the cgroup: %v", err)
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
