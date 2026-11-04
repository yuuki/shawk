package agent

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestNotify checks that the state reaches the socket of NOTIFY_SOCKET as
// one datagram, by path and in the abstract namespace.
func TestNotify(t *testing.T) {
	// The paths of Unix sockets are short, which t.TempDir may exceed.
	dir, err := os.MkdirTemp("", "notify")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addrs := []string{filepath.Join(dir, "notify")}
	if runtime.GOOS == "linux" {
		addrs = append(addrs, "@shawk-notify-test-"+strconv.Itoa(os.Getpid()))
	}
	for _, addr := range addrs {
		ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: addr, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("NOTIFY_SOCKET", addr)
		if err := notify("READY=1"); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		buf := make([]byte, 64)
		ln.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := ln.Read(buf)
		ln.Close()
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if got := string(buf[:n]); got != "READY=1" {
			t.Errorf("%s: received %q, want READY=1", addr, got)
		}
	}
}

func TestNotifyErrors(t *testing.T) {
	// Not started by systemd with Type=notify.
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notify("READY=1"); err != nil {
		t.Errorf("without NOTIFY_SOCKET: %v", err)
	}
	// A socket nobody listens on, e.g. once systemd gave up on the start,
	// or an address the agent cannot use.
	for _, addr := range []string{filepath.Join(t.TempDir(), "none"), "vsock:2:1234"} {
		t.Setenv("NOTIFY_SOCKET", addr)
		if err := notify("READY=1"); err == nil {
			t.Errorf("NOTIFY_SOCKET=%s: no error", addr)
		}
	}
}
