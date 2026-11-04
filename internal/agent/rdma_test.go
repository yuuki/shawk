package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRDMACounters(t *testing.T) {
	root := t.TempDir()
	set := func(dev, port, name, v string) {
		t.Helper()
		dir := filepath.Join(root, dev, "ports", port, "counters")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := newRDMACounters(root)
	if n, ok := r.read(); n != 0 || ok {
		t.Fatalf("no ports: %d, %v", n, ok)
	}

	// The values at the first read are the base.
	set("mlx5_0", "1", "port_xmit_data", "1000")
	set("mlx5_0", "1", "port_rcv_data", "2000")
	set("mlx5_0", "1", "port_xmit_packets", "99") // packets, not data
	set("mlx5_1", "1", "port_rcv_data", "x")      // unreadable
	if n, ok := r.read(); n != 0 || !ok {
		t.Fatalf("first read: %d, %v", n, ok)
	}

	// The counters count octets divided by 4; a new port starts at its
	// base, and a counter that went down was reset.
	set("mlx5_0", "1", "port_xmit_data", "1010")
	set("mlx5_0", "1", "port_rcv_data", "5")
	set("mlx5_0", "1", "port_xmit_packets", "1099")
	set("mlx5_0", "2", "port_xmit_data", "700")
	if n, ok := r.read(); n != 4*(10+5) || !ok {
		t.Errorf("second read: %d, %v", n, ok)
	}
	set("mlx5_0", "2", "port_xmit_data", "701")
	if n, _ := r.read(); n != 4*(10+5+1) {
		t.Errorf("third read: %d", n)
	}

	// A device that is gone is forgotten: back under its name, it starts
	// at a new base.
	if err := os.RemoveAll(filepath.Join(root, "mlx5_0", "ports", "2")); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.read(); n != 4*16 {
		t.Errorf("after removal: %d", n)
	}
	set("mlx5_0", "2", "port_xmit_data", "1000000")
	if n, _ := r.read(); n != 4*16 {
		t.Errorf("back under its name: %d", n)
	}

	// A device registered again between two reads has new counter files.
	dir := filepath.Join(root, "mlx5_0", "ports", "2", "counters")
	if err := os.WriteFile(filepath.Join(dir, "new"), []byte("2000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "new"), filepath.Join(dir, "port_xmit_data")); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.read(); n != 4*16 {
		t.Errorf("registered again: %d", n)
	}
}

func TestRDMACountersRun(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "mlx5_0", "ports", "1", "counters")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "port_xmit_data"), []byte("10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRDMACounters(root)
	if _, ok := r.latest(); ok {
		t.Error("found before a read")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.run(ctx, time.Millisecond); close(done) }()
	// The first read is the base.
	for _, ok := r.latest(); !ok; _, ok = r.latest() {
		time.Sleep(time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(dir, "port_xmit_data"), []byte("20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, ok := r.latest(); ok && n == 40 {
			break
		}
		if time.Now().After(deadline) {
			n, ok := r.latest()
			t.Fatalf("latest = %d, %v", n, ok)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}
