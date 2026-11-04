package shawkconnector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestPGInventory: the connector writes the inventory it reads to
// PostgreSQL, keeps it while the file is invalid, and reports the hosts
// of the inventory never observed.
func TestPGInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(testInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) { cfg.InventoryFile = path })
	ctx := context.Background()

	want := []string{
		"cn001.hpc.example cn001 compute,gpu true 10.0.1.1,10.10.1.1,10.20.1.1",
		"nfs01 - nfs true 10.0.0.10,2001:db8::10",
		"sfa01 - storage false 10.20.0.5",
	}
	const inventory = `SELECT host, coalesce(slurm_node, '-'), array_to_string(roles, ','), agent,
	  (SELECT string_agg(host(a), ',' ORDER BY a) FROM unnest(addrs) a) FROM shawk_v1.inventory`
	if got := queryStrings(t, conn, inventory); !slices.Equal(got, want) {
		t.Errorf("inventory %q", got)
	}
	if got := queryStrings(t, conn, `SELECT host(addr), host FROM shawk_v1.inventory_addrs WHERE addr = '10.10.1.1'`); !slices.Equal(got, []string{"10.10.1.1 cn001.hpc.example"}) {
		t.Errorf("host of 10.10.1.1: %q", got)
	}
	var readAt time.Time
	var hosts int64
	if err := conn.QueryRow(ctx, `SELECT read_at, hosts FROM shawk_v1.inventory_status WHERE failed_at IS NULL`).Scan(&readAt, &hosts); err != nil || hosts != 3 {
		t.Fatalf("status: %v, %d hosts, %v", readAt, hosts, err)
	}

	// nfs01 reports under its name, cn001 under a short name: cn001 is
	// never observed, seen as cn001; sfa01 runs no agent.
	now := time.Now().UTC().Truncate(time.Second)
	consume(t, c, sink, tAgent{host: "nfs01", machineID: "m-nfs", addrs: []string{"10.0.0.10"}, time: now, segment: now.Add(-time.Hour)})
	consume(t, c, sink, tAgent{host: "cn001", machineID: "m-cn", addrs: []string{"10.0.1.1"}, time: now, segment: now.Add(-time.Hour)})
	c.flush(ctx)
	const never = `SELECT host, coalesce(slurm_node, '-'), array_to_string(roles, ','), array_to_string(seen_as, ',')
	  FROM shawk_v1.never_observed()`
	if got := queryStrings(t, conn, never); !slices.Equal(got, []string{"cn001.hpc.example cn001 compute,gpu cn001"}) {
		t.Errorf("never observed %q", got)
	}

	// The same contents are not written again, but their time is.
	var xmin string
	conn.QueryRow(ctx, `SELECT xmin::text FROM shawk.inventory_hosts WHERE host = 'nfs01'`).Scan(&xmin)
	time.Sleep(10 * time.Millisecond)
	c.prepare(ctx)
	var xmin2 string
	var readAt2 time.Time
	conn.QueryRow(ctx, `SELECT xmin::text FROM shawk.inventory_hosts WHERE host = 'nfs01'`).Scan(&xmin2)
	conn.QueryRow(ctx, `SELECT read_at FROM shawk_v1.inventory_status`).Scan(&readAt2)
	if xmin != xmin2 || !readAt2.After(readAt) {
		t.Errorf("rows rewritten (%s, %s) or time not updated (%v, %v)", xmin, xmin2, readAt, readAt2)
	}

	// An invalid file keeps the contents, and tells why.
	if err := os.WriteFile(path, []byte("hosts:\n  - name: a\n  - name: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(ctx)
	if got := queryStrings(t, conn, inventory); !slices.Equal(got, want) {
		t.Errorf("inventory after an invalid file %q", got)
	}
	var errMsg string
	var readAt3 time.Time
	if err := conn.QueryRow(ctx, `SELECT read_at, error FROM shawk_v1.inventory_status WHERE failed_at IS NOT NULL`).Scan(&readAt3, &errMsg); err != nil ||
		!strings.Contains(errMsg, "listed twice") || !readAt3.Equal(readAt2) {
		t.Errorf("status after an invalid file: %v, %q, %v", readAt3, errMsg, err)
	}

	// The store reads back what it wrote.
	inv, err := c.store.inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inv == nil || inv.digest != must(parseInventory([]byte(testInventory))).digest {
		t.Errorf("inventory read back: %+v", inv)
	}

	// Other contents replace the inventory and clear the failure: an
	// address and a node name move to another host.
	if err := os.WriteFile(path, []byte(`
hosts:
  - name: cn001.hpc.example
    addrs: [10.0.1.2]
  - name: cn002.hpc.example
    slurm_node: cn001
    addrs: [10.0.1.1]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(ctx)
	want = []string{"cn001.hpc.example - true 10.0.1.2", "cn002.hpc.example cn001 true 10.0.1.1"}
	if got := queryStrings(t, conn, `SELECT host, coalesce(slurm_node, '-'), agent,
	  (SELECT string_agg(host(a), ',' ORDER BY a) FROM unnest(addrs) a) FROM shawk_v1.inventory`); !slices.Equal(got, want) {
		t.Errorf("inventory after a change %q", got)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.inventory_status WHERE failed_at IS NULL AND error IS NULL`); !slices.Equal(got, []string{"1"}) {
		t.Errorf("failure not cleared: %q", got)
	}

}
