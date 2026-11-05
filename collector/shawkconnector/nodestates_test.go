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

func TestParseNodeStates(t *testing.T) {
	b := []byte(`
generated_at: 2026-10-31T11:59:00Z
nodes:
  - host: cn001
    state: [idle, POWERED_DOWN, IDLE]
  - host: cn002
    state: DOWN+POWERED_DOWN
    reason: ResumeTimeout reached
`)
	ns, err := parseNodeStates(b, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !ns.at.Equal(t0.Add(-time.Minute)) {
		t.Errorf("at = %v", ns.at)
	}
	// Flags are upper case, sorted and once each.
	if len(ns.nodes) != 2 || !slices.Equal(ns.nodes[0].state, []string{"IDLE", "POWERED_DOWN"}) ||
		!slices.Equal(ns.nodes[1].state, []string{"DOWN", "POWERED_DOWN"}) || ns.nodes[1].reason != "ResumeTimeout reached" {
		t.Errorf("nodes = %+v", ns.nodes)
	}

	// JSON, as jq writes it from scontrol show nodes --json.
	ns, err = parseNodeStates([]byte(`{"generated_at":"2026-10-31T12:00:00Z","nodes":[{"host":"cn001","state":["IDLE","POWERING_DOWN"],"reason":""}]}`), t0)
	if err != nil || len(ns.nodes) != 1 || !slices.Equal(ns.nodes[0].state, []string{"IDLE", "POWERING_DOWN"}) {
		t.Errorf("JSON = %+v, %v", ns, err)
	}

	// Flags joined in a list element are split, and * of a node that does
	// not respond is a flag.
	ns, err = parseNodeStates([]byte("generated_at: 2026-10-31T12:00:00Z\nnodes: [{host: cn001, state: [IDLE*+POWERED_DOWN]}]\n"), t0)
	if err != nil || !slices.Equal(ns.nodes[0].state, []string{"IDLE", "NOT_RESPONDING", "POWERED_DOWN"}) {
		t.Errorf("not responding = %+v, %v", ns, err)
	}

	for _, bad := range []struct{ name, doc string }{
		{"empty", ""},
		{"symbol of sinfo", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{host: cn001, state: idle~}]\n"},
		{"unknown field", "generated_at: 2026-10-31T12:00:00Z\nnode: []\n"},
		{"no time", "nodes: [{host: cn001, state: IDLE}]\n"},
		{"future", "generated_at: 2026-10-31T12:00:30Z\nnodes: [{host: cn001, state: IDLE}]\n"},
		{"no host", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{state: IDLE}]\n"},
		{"host and node", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{host: cn001, node: cn001, state: IDLE}]\n"},
		{"node twice", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{node: cn001, state: IDLE}, {node: cn001, state: DOWN}]\n"},
		{"no state", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{host: cn001}]\n"},
		{"empty flag", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{host: cn001, state: IDLE+}]\n"},
		{"twice", "generated_at: 2026-10-31T12:00:00Z\nnodes: [{host: cn001, state: IDLE}, {host: cn001, state: DOWN}]\n"},
	} {
		if ns, err := parseNodeStates([]byte(bad.doc), t0); err == nil {
			t.Errorf("%s: parsed %+v", bad.name, ns)
		}
	}
}

// TestHostsOfNodes: nodes named by their NodeName get the host the
// inventory maps them to; those it does not map are left out.
func TestHostsOfNodes(t *testing.T) {
	ns, err := parseNodeStates([]byte(`
generated_at: 2026-10-31T12:00:00Z
nodes:
  - {node: n1, state: IDLE+POWERED_DOWN}
  - {node: n9, state: IDLE}
  - {host: login01.hpc.example, state: IDLE}
`), t0)
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory{hosts: []inventoryHost{
		{name: "cn001.hpc.example", slurmNode: "n1", agent: true},
		{name: "login01.hpc.example", agent: true},
	}}
	got, unknown, err := hostsOfNodes(ns.nodes, inv)
	if err != nil || len(got) != 2 || got[0].host != "cn001.hpc.example" || got[1].host != "login01.hpc.example" ||
		!slices.Equal(unknown, []string{"n9"}) {
		t.Errorf("hostsOfNodes = %+v, %v, %v", got, unknown, err)
	}
	// Without an inventory, only hosts given by name are kept.
	if got, unknown, err := hostsOfNodes(ns.nodes, nil); err != nil || len(got) != 1 || len(unknown) != 2 {
		t.Errorf("without an inventory = %+v, %v, %v", got, unknown, err)
	}
	// A host given by its name and by its node is an error.
	ns.nodes = append(ns.nodes, nodeState{host: "cn001.hpc.example", state: []string{"IDLE"}})
	if _, _, err := hostsOfNodes(ns.nodes, inv); err == nil {
		t.Error("a host given twice is accepted")
	}
}

func TestParseMaintenance(t *testing.T) {
	ws, err := parseMaintenance([]byte(`
maintenance:
  - hosts: [nfs01, cn003]
    start: 2026-11-01T09:00:00+09:00
    end: 2026-11-01T18:00:00+09:00
    reason: firmware
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 2 || ws[0].host != "cn003" || ws[1].host != "nfs01" ||
		!ws[0].start.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || ws[1].reason != "firmware" {
		t.Errorf("windows = %+v", ws)
	}
	if ws, err := parseMaintenance([]byte("maintenance: []\n")); err != nil || len(ws) != 0 {
		t.Errorf("no windows = %+v, %v", ws, err)
	}
	for _, bad := range []struct{ name, doc string }{
		{"empty", ""},
		{"unknown field", "windows: []\n"},
		{"no end", "maintenance: [{hosts: [cn001], start: 2026-11-01T00:00:00Z}]\n"},
		{"end before start", "maintenance: [{hosts: [cn001], start: 2026-11-01T00:00:00Z, end: 2026-11-01T00:00:00Z}]\n"},
		{"too long", "maintenance: [{hosts: [cn001], start: 2026-11-01T00:00:00Z, end: 2026-12-02T00:00:00Z}]\n"},
		{"no hosts", "maintenance: [{hosts: [], start: 2026-11-01T00:00:00Z, end: 2026-11-02T00:00:00Z}]\n"},
		{"same start", "maintenance: [{hosts: [cn001], start: 2026-11-01T00:00:00Z, end: 2026-11-02T00:00:00Z}," +
			" {hosts: [cn001], start: 2026-11-01T09:00:00+09:00, end: 2026-11-03T00:00:00Z}]\n"},
	} {
		if ws, err := parseMaintenance([]byte(bad.doc)); err == nil {
			t.Errorf("%s: parsed %+v", bad.name, ws)
		}
	}
}

// TestSyncNodeStates: the connector writes the states once per reading of
// Slurm, not stale ones, and the maintenance windows when they change; an
// invalid file leaves what was written from it.
func TestSyncNodeStates(t *testing.T) {
	dir := t.TempDir()
	statesFile := filepath.Join(dir, "node-states.yaml")
	maintFile := filepath.Join(dir, "maintenance.yaml")
	write := func(file, doc string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(statesFile, "generated_at: 2026-10-31T11:59:00Z\nnodes: [{host: cn001, state: IDLE+POWERED_DOWN}]\n")
	write(maintFile, "maintenance: [{hosts: [nfs01], start: 2026-11-01T00:00:00Z, end: 2026-11-02T00:00:00Z}]\n")
	c, st, _, now := testConnector(t, func(cfg *Config) {
		cfg.NodeStatesFile = statesFile
		cfg.MaintenanceFile = maintFile
	})
	logs := observe(c)
	// taken counts the warnings logged since the last call that contain
	// snippet.
	taken := func(snippet string) int {
		n := 0
		for _, e := range logs.TakeAll() {
			if strings.Contains(e.Message, snippet) {
				n++
			}
		}
		return n
	}
	ctx := context.Background()
	if len(st.nodeStates) != 1 || len(st.nodes) != 1 || st.windowSyncs != 1 || len(st.windows) != 1 {
		t.Fatalf("at start: states %v %+v, windows %d %+v", st.nodeStates, st.nodes, st.windowSyncs, st.windows)
	}

	// The same files are not written again.
	*now = now.Add(time.Minute)
	c.syncNodeStates(ctx)
	if len(st.nodeStates) != 1 || st.windowSyncs != 1 {
		t.Errorf("unchanged: states %v, windows %d", st.nodeStates, st.windowSyncs)
	}

	// States read again are written.
	write(statesFile, "generated_at: 2026-10-31T12:01:00Z\nnodes: [{host: cn001, state: IDLE+POWERED_DOWN}]\n")
	c.syncNodeStates(ctx)
	if len(st.nodeStates) != 2 || !st.nodeStates[1].Equal(t0.Add(time.Minute)) || st.windowSyncs != 1 {
		t.Errorf("read again: states %v, windows %d", st.nodeStates, st.windowSyncs)
	}

	// An invalid file leaves what was written, and is logged once; the
	// other file is still read.
	write(statesFile, "nodes: [{host: cn001, state: IDLE}]\n")
	write(maintFile, "maintenance: []\n")
	c.syncNodeStates(ctx)
	c.syncNodeStates(ctx)
	if len(st.nodeStates) != 2 || st.windowSyncs != 2 || len(st.windows) != 0 {
		t.Errorf("invalid: states %v, windows %d %+v", st.nodeStates, st.windowSyncs, st.windows)
	}
	if n := taken("reading node_states_file"); n != 1 {
		t.Errorf("invalid file logged %d times", n)
	}
	write(maintFile, "")
	c.syncNodeStates(ctx)
	if st.windowSyncs != 2 || taken("reading maintenance_file") != 1 {
		t.Errorf("empty maintenance_file: windows %d", st.windowSyncs)
	}

	// A file no longer generated is stale: not written, logged once.
	write(statesFile, "generated_at: 2026-10-31T12:01:00Z\nnodes: [{host: cn001, state: IDLE+POWERED_DOWN}]\n")
	*now = t0.Add(10 * time.Minute)
	c.syncNodeStates(ctx)
	c.syncNodeStates(ctx)
	if len(st.nodeStates) != 2 {
		t.Errorf("stale: states %v", st.nodeStates)
	}
	if n := taken("are stale"); n != 1 {
		t.Errorf("stale states logged %d times", n)
	}

	// What failed to be written is written again.
	write(statesFile, "generated_at: 2026-10-31T12:10:00Z\nnodes: [{host: cn001, state: IDLE}]\n")
	write(maintFile, "maintenance: [{hosts: [cn001], start: 2026-11-01T00:00:00Z, end: 2026-11-02T00:00:00Z}]\n")
	st.mu.Lock()
	st.fail = true
	st.mu.Unlock()
	c.syncNodeStates(ctx)
	st.mu.Lock()
	st.fail = false
	st.mu.Unlock()
	c.syncNodeStates(ctx)
	if len(st.nodeStates) != 3 || !slices.Equal(st.nodes[0].state, []string{"IDLE"}) ||
		st.windowSyncs != 3 || len(st.windows) != 1 {
		t.Errorf("after a failure: states %v %+v, windows %d %+v", st.nodeStates, st.nodes, st.windowSyncs, st.windows)
	}
}

// TestNodeStatesFilesTooLarge: node_states_file and maintenance_file are
// bounded as inventory_file is; a larger one is not written.
func TestNodeStatesFilesTooLarge(t *testing.T) {
	dir := t.TempDir()
	statesFile := filepath.Join(dir, "node-states.yaml")
	maintFile := filepath.Join(dir, "maintenance.yaml")
	pad := "\n#" + strings.Repeat("x", maxFileBytes)
	for file, doc := range map[string]string{
		statesFile: "generated_at: 2026-10-31T11:59:00Z\nnodes: [{host: cn001, state: IDLE+POWERED_DOWN}]" + pad,
		maintFile:  "maintenance: [{hosts: [nfs01], start: 2026-11-01T00:00:00Z, end: 2026-11-02T00:00:00Z}]" + pad,
	} {
		if err := os.WriteFile(file, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, st, _, _ := testConnector(t, func(cfg *Config) {
		cfg.NodeStatesFile = statesFile
		cfg.MaintenanceFile = maintFile
	})
	if len(st.nodeStates) != 0 || st.windowSyncs != 0 {
		t.Errorf("written: states %v, windows %d", st.nodeStates, st.windowSyncs)
	}
	if !strings.Contains(c.nodeStatesErr, "larger than") || !strings.Contains(c.maintenanceErr, "larger than") {
		t.Errorf("errors %q, %q", c.nodeStatesErr, c.maintenanceErr)
	}
}

func TestConfigNodeStatesFile(t *testing.T) {
	// Without the files, nothing is read or written.
	_, st, _, _ := testConnector(t, nil)
	if len(st.nodeStates) != 0 || st.windowSyncs != 0 {
		t.Errorf("without files: states %v, windows %d", st.nodeStates, st.windowSyncs)
	}
}

// TestSyncNodeStatesByNode: nodes named by their NodeName are written under
// the hosts of the inventory_file; those it does not map are left out and
// logged once.
func TestSyncNodeStatesByNode(t *testing.T) {
	dir := t.TempDir()
	invFile := filepath.Join(dir, "inventory.yaml")
	statesFile := filepath.Join(dir, "node-states.json")
	if err := os.WriteFile(invFile, []byte("hosts: [{name: cn001.hpc.example, slurm_node: n1, addrs: [10.0.1.1]}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statesFile, []byte(`{"generated_at": "2026-10-31T12:00:00Z",
	  "nodes": [{"node": "n1", "state": ["IDLE", "POWERED_DOWN"]}, {"node": "n9", "state": ["IDLE"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, st, _, now := testConnector(t, func(cfg *Config) {
		cfg.InventoryFile = invFile
		cfg.NodeStatesFile = statesFile
	})
	if len(st.nodes) != 1 || st.nodes[0].host != "cn001.hpc.example" {
		t.Errorf("nodes = %+v", st.nodes)
	}
	logs := observe(c)
	*now = now.Add(time.Minute)
	c.prepare(context.Background())
	if n := logs.FilterMessageSnippet("does not map").Len(); n != 0 {
		t.Errorf("unknown nodes logged again %d times", n)
	}
	// Once the inventory maps n9, the same reading is written with it.
	if err := os.WriteFile(invFile, []byte("hosts: [{name: cn001.hpc.example, slurm_node: n1, addrs: [10.0.1.1]},"+
		" {name: cn009.hpc.example, slurm_node: n9, addrs: [10.0.1.9]}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if len(st.nodes) != 2 || st.nodes[1].host != "cn009.hpc.example" {
		t.Errorf("after the inventory maps n9: %+v", st.nodes)
	}
	// Then it is not written again.
	writes := len(st.nodeStates)
	c.prepare(context.Background())
	if len(st.nodeStates) != writes {
		t.Errorf("written again although all nodes are mapped")
	}
}

// TestMaintenanceResync: the maintenance windows are written again every
// few minutes although the file did not change, so that what another
// connector wrote from an older file is put right.
func TestMaintenanceResync(t *testing.T) {
	file := filepath.Join(t.TempDir(), "maintenance.yaml")
	if err := os.WriteFile(file, []byte("maintenance: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, st, _, now := testConnector(t, func(cfg *Config) { cfg.MaintenanceFile = file })
	ctx := context.Background()
	*now = now.Add(time.Minute)
	c.syncNodeStates(ctx)
	if st.windowSyncs != 1 {
		t.Errorf("after a minute: %d writes", st.windowSyncs)
	}
	*now = now.Add(maintenanceResync)
	c.syncNodeStates(ctx)
	if st.windowSyncs != 2 {
		t.Errorf("after %s: %d writes", maintenanceResync, st.windowSyncs)
	}
}
