package shawkconnector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/connector/connectortest"
)

const testInventory = `
hosts:
  - name: cn001.hpc.example
    slurm_node: cn001
    roles: [gpu, compute, gpu]
    addrs: [10.10.1.1, 10.0.1.1, "::ffff:10.20.1.1", 10.0.1.1]
  - name: nfs01
    roles: [nfs]
    addrs: ["2001:db8::10", 10.0.0.10]
  - name: sfa01
    roles: [storage]
    agent: false
    addrs: [10.20.0.5]
`

func TestParseInventory(t *testing.T) {
	inv, err := parseInventory([]byte(testInventory))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range inv.hosts {
		names = append(names, h.name)
	}
	if !slices.Equal(names, []string{"cn001.hpc.example", "nfs01", "sfa01"}) {
		t.Errorf("hosts %v", names)
	}
	cn := inv.hosts[0]
	if cn.slurmNode != "cn001" || !cn.agent || !slices.Equal(cn.roles, []string{"compute", "gpu"}) {
		t.Errorf("cn001: %+v", cn)
	}
	if got := strings.Join(addrStrings(cn.addrs), " "); got != "10.0.1.1 10.10.1.1 10.20.1.1" {
		t.Errorf("cn001 addresses %s", got)
	}
	if inv.hosts[2].agent {
		t.Error("sfa01 expects an agent")
	}
	for addr, want := range map[string]string{"10.20.1.1": "cn001.hpc.example", "::ffff:10.0.0.10": "nfs01",
		"2001:db8::10": "nfs01", "10.20.0.5": "sfa01"} {
		if h, ok := inv.hostOf(addrOf(addr)); !ok || h != want {
			t.Errorf("host of %s: %q, %v", addr, h, ok)
		}
	}
	if _, ok := inv.hostOf(addrOf("10.0.0.99")); ok {
		t.Error("an address outside the inventory has a host")
	}

	// The same contents in another order and layout, in JSON, have the
	// same digest; other contents another.
	json := `{"hosts": [
	  {"name": "sfa01", "agent": false, "roles": ["storage"], "addrs": ["10.20.0.5"]},
	  {"name": "nfs01", "roles": ["nfs"], "addrs": ["10.0.0.10", "2001:db8::10"]},
	  {"name": "cn001.hpc.example", "slurm_node": "cn001", "roles": ["compute", "gpu"],
	   "addrs": ["10.0.1.1", "10.10.1.1", "10.20.1.1"]}]}`
	same, err := parseInventory([]byte(json))
	if err != nil {
		t.Fatal(err)
	}
	if same.digest != inv.digest {
		t.Error("the same contents have another digest")
	}
	other, err := parseInventory([]byte(strings.Replace(json, `"agent": false, `, "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if other.digest == inv.digest {
		t.Error("other contents have the same digest")
	}
}

func TestParseInventoryInvalid(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", "no hosts"},
		{"no hosts", "hosts: []", "no hosts"},
		{"unknown field", "hosts:\n  - name: a\n    adresses: [10.0.0.1]", "adresses"},
		{"no name", "hosts:\n  - addrs: [10.0.0.1]", "name: empty"},
		{"reserved name", "hosts:\n  - name: ~unknown", "starts with ~"},
		{"space", "hosts:\n  - name: 'a b'", "spaces"},
		{"twice", "hosts:\n  - name: a\n  - name: a", "listed twice"},
		{"node twice", "hosts:\n  - name: a\n    slurm_node: n\n  - name: b\n    slurm_node: n", "slurm_node n is given to both a and b"},
		{"address twice", "hosts:\n  - name: a\n    addrs: [10.0.0.1]\n  - name: b\n    addrs: ['::ffff:10.0.0.1']", "address 10.0.0.1 is given to both a and b"},
		{"range", "hosts:\n  - name: a\n    addrs: [10.0.0.0/24]", "host a"},
		{"loopback", "hosts:\n  - name: a\n    addrs: [127.0.0.1]", "names no host"},
		{"unspecified", "hosts:\n  - name: a\n    addrs: ['::']", "names no host"},
		{"zone", "hosts:\n  - name: a\n    addrs: ['fe80::1%eth0']", "zone"},
		{"empty role", "hosts:\n  - name: a\n    roles: ['']", "empty"},
		{"not YAML", "hosts: [", "yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseInventory([]byte(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReadInventoryTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, make([]byte, maxInventoryBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventory(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error %v", err)
	}
}

// TestInventoryReload: the connector reads the inventory at start and every
// write interval; a file that cannot be read or is invalid keeps the
// inventory read before, and its failure is recorded.
func TestInventoryReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(testInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	c, st, _, now := testConnector(t, func(cfg *Config) { cfg.InventoryFile = path })
	if st.inv == nil || len(st.inv.hosts) != 3 || st.invSyncs != 1 {
		t.Fatalf("inventory written at start: %+v, %d", st.inv, st.invSyncs)
	}
	first := c.inventory.Load()

	*now = now.Add(time.Minute)
	if err := os.WriteFile(path, []byte("hosts:\n  - name: cn001.hpc.example\n    adresses: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if c.inventory.Load() != first || st.inv != first {
		t.Error("an invalid file replaced the inventory")
	}
	if len(st.invFailed) != 1 || !strings.Contains(st.invFailed[0], "adresses") {
		t.Errorf("failures recorded %q", st.invFailed)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if c.inventory.Load() != first || len(st.invFailed) != 2 {
		t.Errorf("a missing file replaced the inventory, or its failure is not recorded: %q", st.invFailed)
	}

	if err := os.WriteFile(path, []byte("hosts:\n  - name: login01\n    addrs: [10.0.9.1]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if inv := c.inventory.Load(); inv == first || len(inv.hosts) != 1 || st.inv != inv {
		t.Errorf("the valid file is not read again: %+v", inv)
	}
}

// TestInventoryFromStore: a connector that starts while its file is
// invalid takes the inventory last written to PostgreSQL.
func TestInventoryFromStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte("hosts: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	stored := must(parseInventory([]byte(testInventory)))
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	cfg.InventoryFile = path
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := &fakeStore{inv: stored}
	c.store = st
	c.ready = true
	c.syncInventory(context.Background())
	if c.inventory.Load() != stored || st.invSyncs != 0 || len(st.invFailed) != 1 {
		t.Errorf("inventory %p, want %p; written %d times, failures %q", c.inventory.Load(), stored, st.invSyncs, st.invFailed)
	}
}

// TestInventoryUnset: without an inventory_file, the connector drops the
// inventory from PostgreSQL once.
func TestInventoryUnset(t *testing.T) {
	c, st, _, _ := testConnector(t, nil)
	st.inv = must(parseInventory([]byte(testInventory)))
	st.invSyncs = 0
	c.inventoryDropped = false
	c.prepare(context.Background())
	c.prepare(context.Background())
	if st.inv != nil || st.invSyncs != 1 {
		t.Errorf("inventory %+v, dropped %d times", st.inv, st.invSyncs)
	}
}

// TestInventoryConflicts: an agent that sends an address the inventory
// gives to another host is logged, at most once an hour.
func TestInventoryConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(testInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, sink, now := testConnector(t, func(cfg *Config) { cfg.InventoryFile = path })
	logs := observe(c)
	consume(t, c, sink, tAgent{host: "nfs01", machineID: "m-nfs", addrs: []string{"10.0.0.10"}, time: *now})
	consume(t, c, sink, tAgent{host: "cn001", machineID: "m-cn", addrs: []string{"10.0.1.1", "10.0.0.10", "10.0.5.5"}, time: *now})
	*now = now.Add(time.Minute)
	consume(t, c, sink, tAgent{host: "cn001", machineID: "m-cn", addrs: []string{"10.0.1.1"}, time: *now})
	warnings := logs.FilterMessageSnippet("the inventory gives to other hosts").All()
	if len(warnings) != 1 {
		t.Fatalf("%d warnings", len(warnings))
	}
	f := warnings[0].ContextMap()
	if f["host"] != "cn001" || strings.Join(toStrings(f["addresses"]), " ") != "10.0.1.1=cn001.hpc.example 10.0.0.10=nfs01" {
		t.Errorf("warning %v", f)
	}
}

func addrStrings[T interface{ String() string }](xs []T) []string {
	var out []string
	for _, x := range xs {
		out = append(out, x.String())
	}
	return out
}

func toStrings(v any) []string {
	switch v := v.(type) {
	case []string:
		return v
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, x.(string))
		}
		return out
	}
	return nil
}
