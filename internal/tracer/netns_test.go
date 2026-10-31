package tracer

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestOtherNetNS checks that connections and listeners in another network
// namespace than the tracer's are accounted, including a connection that
// existed before the tracer started.
func TestOtherNetNS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip is not available")
	}
	name := fmt.Sprintf("shawktest%d", os.Getpid())
	if out, err := exec.Command(ip, "netns", "add", name).CombinedOutput(); err != nil {
		t.Skipf("cannot create a network namespace: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(ip, "netns", "del", name).Run() })
	if out, err := exec.Command(ip, "-n", name, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}

	helper := exec.Command(ip, "netns", "exec", name, os.Args[0], "-test.run=^TestHelperNetNSPair$")
	helper.Env = append(os.Environ(), "SHAWK_TEST_NETNS_PAIR=1")
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
	time.Sleep(300 * time.Millisecond)
	if _, err := tr.Collect(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
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
	if out == nil || out.OpenConns != 1 || out.BytesSent == 0 || out.PID != pid {
		t.Errorf("outgoing flow in the other namespace = %+v", out)
	}
	if in == nil || in.OpenConns != 1 || in.BytesRecv == 0 || in.PID != pid {
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

// TestHelperNetNSPair is run by TestOtherNetNS inside a network namespace.
// It keeps a connection to its own listener busy until stdin is closed.
func TestHelperNetNSPair(t *testing.T) {
	if os.Getenv("SHAWK_TEST_NETNS_PAIR") == "" {
		t.Skip("helper process for other tests")
	}
	ln := echoServer(t, "tcp4", "127.0.0.1:0")
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Printf("PORT %d\n", ln.Addr().(*net.TCPAddr).Port)
	done := make(chan struct{})
	go func() {
		bufio.NewReader(os.Stdin).ReadString('\n')
		close(done)
	}()
	for {
		select {
		case <-done:
			return
		case <-time.After(50 * time.Millisecond):
			roundTrip(t, c, 100)
		}
	}
}
