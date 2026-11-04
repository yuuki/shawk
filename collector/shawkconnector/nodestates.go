package shawkconnector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

// nodeStateMaxAge is how long a state read from Slurm holds without being
// read again, as shawk.node_state_max_age() in PostgreSQL.
const nodeStateMaxAge = 5 * time.Minute

// maintenanceResync is how often the maintenance windows are written even
// though the maintenance_file did not change.
const maintenanceResync = 5 * time.Minute

// maxGeneratedAhead is how far the time a node_states_file was generated
// may be ahead of the connector: the file is generated on its host, and
// only a step of the clock moves it ahead.
const maxGeneratedAhead = 10 * time.Second

// maxMaintenanceWindow bounds a maintenance window, so that a mistaken end
// does not exclude a host from the alerts for good.
const maxMaintenanceWindow = 30 * 24 * time.Hour

// nodeStates is what a node_states_file holds: the states of nodes read
// from Slurm at a time.
type nodeStates struct {
	at    time.Time
	nodes []nodeState
}

// nodeState is the state of a node in Slurm: its flags, upper case and
// sorted, e.g. [IDLE POWERED_DOWN], and its reason. The node is a host, or
// a NodeName of Slurm that the inventory maps to a host before it is
// written.
type nodeState struct {
	host, node string
	state      []string
	reason     string
}

// maintenanceWindow is a maintenance window registered for a host.
type maintenanceWindow struct {
	host       string
	start, end time.Time
	reason     string
}

// nodeStatesDoc is the format of a node_states_file, in YAML or JSON, as a
// cron job generates it from scontrol show nodes --json:
//
//	generated_at: 2026-11-04T10:00:00Z
//	nodes:
//	  - node: cn001                 # NodeName, mapped by the inventory
//	    state: [IDLE, POWERED_DOWN]   # or "IDLE+POWERED_DOWN"
//	    reason: ""
//	  - host: cn002.cluster.example # or the host.name of the agent
//	    state: [IDLE]
type nodeStatesDoc struct {
	GeneratedAt string `yaml:"generated_at"`
	Nodes       []struct {
		Host   string     `yaml:"host"`
		Node   string     `yaml:"node"`
		State  stateFlags `yaml:"state"`
		Reason string     `yaml:"reason"`
	} `yaml:"nodes"`
}

// maintenanceDoc is the format of a maintenance_file, in YAML or JSON:
//
//	maintenance:
//	  - hosts: [cn001.cluster.example, nfs01.cluster.example]
//	    start: 2026-11-05T09:00:00+09:00
//	    end: 2026-11-05T18:00:00+09:00
//	    reason: firmware update
type maintenanceDoc struct {
	Maintenance []struct {
		Hosts  []string `yaml:"hosts"`
		Start  string   `yaml:"start"`
		End    string   `yaml:"end"`
		Reason string   `yaml:"reason"`
	} `yaml:"maintenance"`
}

// stateFlags are the flags of a state of Slurm, given as a list (as
// scontrol show nodes --json gives them) or joined by '+' (as scontrol
// show nodes prints them). Only the names of flags are accepted, not the
// symbols of sinfo (idle~).
type stateFlags []string

func (f *stateFlags) UnmarshalYAML(n *yaml.Node) error {
	var list []string
	if n.Kind == yaml.ScalarNode {
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		list = strings.Split(s, "+")
	} else if err := n.Decode(&list); err != nil {
		return err
	}
	*f = list
	return nil
}

// decodeStrict decodes a document in YAML or JSON, refusing unknown fields
// and an empty file: one being written, rather than one without contents,
// which says so ({} or maintenance: []).
func decodeStrict(b []byte, doc any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(doc); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the file is empty")
		}
		return err
	}
	return nil
}

// parseNodeStates parses a node_states_file read at now.
func parseNodeStates(b []byte, now time.Time) (*nodeStates, error) {
	var doc nodeStatesDoc
	if err := decodeStrict(b, &doc); err != nil {
		return nil, err
	}
	out := &nodeStates{}
	if doc.GeneratedAt == "" {
		return nil, errors.New("no generated_at, when the states were read from Slurm")
	}
	t, err := time.Parse(time.RFC3339, doc.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("generated_at: %w", err)
	}
	if t.After(now.Add(maxGeneratedAhead)) {
		// Its states would hold longer than they should, and hide those
		// read after it until the clocks met.
		return nil, fmt.Errorf("generated_at %s is in the future", doc.GeneratedAt)
	}
	out.at = t
	seen := map[string]bool{}
	for i, n := range doc.Nodes {
		if (n.Host == "") == (n.Node == "") {
			return nil, fmt.Errorf("nodes[%d]: give either host or node", i)
		}
		name, key := n.Host, "host "+n.Host
		if n.Node != "" {
			name, key = n.Node, "node "+n.Node
		}
		if seen[key] {
			return nil, fmt.Errorf("nodes[%d]: %s is listed twice", i, key)
		}
		seen[key] = true
		var state []string
		add := func(f string) {
			if !slices.Contains(state, f) {
				state = append(state, f)
			}
		}
		for _, e := range n.State {
			for _, f := range strings.Split(e, "+") {
				f = strings.ToUpper(strings.TrimSpace(f))
				// scontrol show nodes marks a node that does not respond
				// with *, as in DOWN*.
				if g, ok := strings.CutSuffix(f, "*"); ok {
					f = g
					add("NOT_RESPONDING")
				}
				if f == "" || strings.IndexFunc(f, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') }) >= 0 {
					return nil, fmt.Errorf("nodes[%d]: invalid flag %q in the state of %s", i, f, name)
				}
				add(f)
			}
		}
		if len(state) == 0 {
			return nil, fmt.Errorf("nodes[%d]: no state for %s", i, name)
		}
		slices.Sort(state)
		out.nodes = append(out.nodes, nodeState{host: n.Host, node: n.Node, state: state, reason: n.Reason})
	}
	return out, nil
}

// parseMaintenance parses a maintenance_file. The windows are sorted by
// host and start.
func parseMaintenance(b []byte) ([]maintenanceWindow, error) {
	var doc maintenanceDoc
	if err := decodeStrict(b, &doc); err != nil {
		return nil, err
	}
	type windowKey struct {
		host  string
		start time.Time
	}
	seen := map[windowKey]bool{}
	var out []maintenanceWindow
	for i, m := range doc.Maintenance {
		start, err := time.Parse(time.RFC3339, m.Start)
		if err != nil {
			return nil, fmt.Errorf("maintenance[%d]: start: %w", i, err)
		}
		end, err := time.Parse(time.RFC3339, m.End)
		if err != nil {
			return nil, fmt.Errorf("maintenance[%d]: end: %w", i, err)
		}
		if !end.After(start) {
			return nil, fmt.Errorf("maintenance[%d]: the end is not after the start", i)
		}
		if end.Sub(start) > maxMaintenanceWindow {
			return nil, fmt.Errorf("maintenance[%d]: longer than %s", i, maxMaintenanceWindow)
		}
		if len(m.Hosts) == 0 {
			return nil, fmt.Errorf("maintenance[%d]: no hosts", i)
		}
		for _, h := range m.Hosts {
			if h == "" {
				return nil, fmt.Errorf("maintenance[%d]: an empty host", i)
			}
			k := windowKey{h, start.UTC()}
			if seen[k] {
				return nil, fmt.Errorf("maintenance[%d]: %s has two windows that start at %s", i, h, m.Start)
			}
			seen[k] = true
			out = append(out, maintenanceWindow{host: h, start: start, end: end, reason: m.Reason})
		}
	}
	slices.SortFunc(out, func(a, b maintenanceWindow) int {
		if c := strings.Compare(a.host, b.host); c != 0 {
			return c
		}
		return a.start.Compare(b.start)
	})
	return out, nil
}

// hostsOfNodes gives the nodes named by their NodeName the hosts the
// inventory maps them to. Nodes it does not map are left out, and
// returned; a host given twice is an error.
func hostsOfNodes(nodes []nodeState, inv *inventory) ([]nodeState, []string, error) {
	byNode := map[string]string{}
	if inv != nil {
		for _, h := range inv.hosts {
			if h.slurmNode != "" {
				byNode[h.slurmNode] = h.name
			}
		}
	}
	out := make([]nodeState, 0, len(nodes))
	var unknown []string
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.node != "" {
			h, ok := byNode[n.node]
			if !ok {
				unknown = append(unknown, n.node)
				continue
			}
			n.host = h
		}
		if seen[n.host] {
			return nil, nil, fmt.Errorf("host %s is given twice, by its name and its node in Slurm", n.host)
		}
		seen[n.host] = true
		out = append(out, n)
	}
	return out, unknown, nil
}

// windowsKey identifies a list of maintenance windows, to tell whether it
// changed since it was written.
func windowsKey(ws []maintenanceWindow) string {
	var b strings.Builder
	for _, w := range ws {
		fmt.Fprintf(&b, "%q %d %d %q\n", w.host, w.start.UnixNano(), w.end.UnixNano(), w.reason)
	}
	return b.String()
}

// syncNodeStates reads the node_states_file and the maintenance_file and
// writes what changed since they were last written: the states when they
// were read from Slurm again, the maintenance windows when they changed.
// When a file cannot be read or is invalid, what was written from it stays,
// and the states become stale.
func (c *shawkConnector) syncNodeStates(ctx context.Context) {
	now := c.now()
	if path := c.cfg.NodeStatesFile; path != "" {
		b, err := os.ReadFile(path)
		var ns *nodeStates
		var unknown []string
		if err == nil {
			ns, err = parseNodeStates(b, now)
		}
		if err == nil {
			ns.nodes, unknown, err = hostsOfNodes(ns.nodes, c.inventory.Load())
		}
		// Nodes without a host are logged when they change: their states
		// are not written, and they stop no alert.
		leftOut := c.unknownNodes != ""
		if key := strings.Join(unknown, " "); key != c.unknownNodes {
			if key != "" {
				c.log.Warn("nodes in node_states_file that the inventory does not map to hosts; their states are left out",
					zap.String("file", path), zap.Strings("nodes", unknown))
			}
			c.unknownNodes = key
		}
		switch {
		case c.fileError(&c.nodeStatesErr, "node_states_file", path, err):
		case now.Sub(ns.at) > nodeStateMaxAge:
			// The file is not being generated. Written, the states would
			// explain nothing.
			if !c.nodeStatesStale {
				c.log.Warn("the states in node_states_file are stale; they stop no alert until it is generated again",
					zap.String("file", path), zap.Time("generated_at", ns.at), zap.Duration("max_age", nodeStateMaxAge))
				c.nodeStatesStale = true
			}
		case ns.at.After(c.nodeStatesAt) || leftOut:
			// After nodes were left out, the same reading is written again,
			// so that they are once the inventory maps them; what was
			// written changes nothing.
			c.nodeStatesStale = false
			if err := c.store.writeNodeStates(ctx, ns.at, ns.nodes); err != nil {
				c.log.Warn("writing the node states to PostgreSQL", zap.Error(err))
			} else {
				c.nodeStatesAt = ns.at
			}
		default:
			c.nodeStatesStale = false
		}
	}
	if path := c.cfg.MaintenanceFile; path != "" {
		b, err := os.ReadFile(path)
		var ws []maintenanceWindow
		if err == nil {
			ws, err = parseMaintenance(b)
		}
		if c.fileError(&c.maintenanceErr, "maintenance_file", path, err) {
			return
		}
		// Written when they change, and again every few minutes, so that
		// windows another connector wrote from an older file are put right.
		if key := windowsKey(ws); key != c.windowsKey || now.Sub(c.windowsSynced) >= maintenanceResync {
			if err := c.store.syncMaintenance(ctx, ws); err != nil {
				c.log.Warn("writing the maintenance windows to PostgreSQL", zap.Error(err))
			} else {
				c.windowsKey, c.windowsSynced = key, now
			}
		}
	}
}

// fileError logs an error reading the file of an option when it differs
// from the one logged last, held in last, and reports whether there is one.
func (c *shawkConnector) fileError(last *string, option, path string, err error) bool {
	if err == nil {
		*last = ""
		return false
	}
	if msg := err.Error(); msg != *last {
		c.log.Warn("reading "+option+"; what was written from it stays", zap.String("file", path), zap.Error(err))
		*last = msg
	}
	return true
}
