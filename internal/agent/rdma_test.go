package agent

import (
	"os"
	"path/filepath"
	"testing"
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
}
