package shawkconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

// maxFileBytes bounds the size of the files the connector reads every
// write interval: inventory_file, node_states_file and maintenance_file. A
// host takes a few hundred bytes in each, so this is far above a cluster of
// thousands of hosts.
const maxFileBytes = 16 << 20

// inventoryFile is the format of inventory_file, in YAML or JSON:
//
//	hosts:
//	  - name: cn001.hpc.example   # host.name, as the agent of the host sends it
//	    slurm_node: cn001         # the NodeName of the host in Slurm, if any
//	    roles: [compute, gpu]
//	    addrs: [10.0.1.1, 10.10.1.1]
//	  - name: sfa01
//	    roles: [storage]
//	    agent: false              # no agent is expected to run there
//	    addrs: [10.20.0.5]
type inventoryFile struct {
	Hosts []inventoryFileHost `yaml:"hosts"`
}

type inventoryFileHost struct {
	Name      string   `yaml:"name"`
	SlurmNode string   `yaml:"slurm_node"`
	Roles     []string `yaml:"roles"`
	Agent     *bool    `yaml:"agent"`
	Addrs     []string `yaml:"addrs"`
}

// inventoryHost is a host of the inventory.
type inventoryHost struct {
	name      string
	slurmNode string // empty if the host is not a node of Slurm
	roles     []string
	agent     bool // an agent is expected to run on the host
	addrs     []netip.Addr
}

// inventory is the valid contents of inventory_file: the hosts, by name,
// and the host of every address. An address belongs to one host at most.
type inventory struct {
	hosts  []inventoryHost // sorted by name
	byAddr map[netip.Addr]string
	// digest identifies the contents, whatever the order and the layout of
	// the file, so that the connector writes them to PostgreSQL only when
	// they change.
	digest string
}

// hostOf returns the host the inventory gives an address to.
func (inv *inventory) hostOf(a netip.Addr) (string, bool) {
	if inv == nil {
		return "", false
	}
	h, ok := inv.byAddr[a.Unmap()]
	return h, ok
}

// readInventory reads and validates inventory_file.
func readInventory(path string) (*inventory, error) {
	b, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	return parseInventory(b)
}

// readBoundedFile reads a file of at most maxFileBytes.
func readBoundedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxFileBytes)
	}
	return b, nil
}

// errNoHosts refuses a file without hosts.
var errNoHosts = errors.New("no hosts")

// parseInventory parses and validates the contents of inventory_file.
// Unknown fields are refused, so that a misspelt field is not taken as
// absent.
func parseInventory(b []byte) (*inventory, error) {
	var f inventoryFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errNoHosts
		}
		return nil, err
	}
	// Files concatenated by mistake would leave the hosts after the first
	// document unchecked and dropped.
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	if len(f.Hosts) == 0 {
		// A generator that failed may leave an empty list, which would
		// drop the whole inventory.
		return nil, errNoHosts
	}
	inv := &inventory{byAddr: map[netip.Addr]string{}}
	names := map[string]bool{}
	nodes := map[string]string{}
	for i, fh := range f.Hosts {
		h := inventoryHost{name: fh.Name, slurmNode: fh.SlurmNode, agent: fh.Agent == nil || *fh.Agent}
		if err := checkInventoryName(h.name); err != nil {
			return nil, fmt.Errorf("hosts[%d]: name: %w", i, err)
		}
		if names[h.name] {
			return nil, fmt.Errorf("host %s is listed twice", h.name)
		}
		names[h.name] = true
		if h.slurmNode != "" {
			if err := checkInventoryName(h.slurmNode); err != nil {
				return nil, fmt.Errorf("host %s: slurm_node: %w", h.name, err)
			}
			if other, dup := nodes[h.slurmNode]; dup {
				return nil, fmt.Errorf("slurm_node %s is given to both %s and %s", h.slurmNode, other, h.name)
			}
			nodes[h.slurmNode] = h.name
		}
		for _, r := range fh.Roles {
			if err := checkInventoryRole(r); err != nil {
				return nil, fmt.Errorf("host %s: role %q: %w", h.name, r, err)
			}
			if !slices.Contains(h.roles, r) {
				h.roles = append(h.roles, r)
			}
		}
		slices.Sort(h.roles)
		for _, s := range fh.Addrs {
			a, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("host %s: %w", h.name, err)
			}
			a = a.Unmap()
			switch {
			case a.Zone() != "":
				return nil, fmt.Errorf("host %s: address %s has a zone", h.name, s)
			case a.IsUnspecified(), a.IsLoopback(), a.IsMulticast():
				// Every host has these, or none.
				return nil, fmt.Errorf("host %s: address %s names no host", h.name, s)
			}
			if other, dup := inv.byAddr[a]; dup {
				if other == h.name {
					continue
				}
				return nil, fmt.Errorf("address %s is given to both %s and %s", a, other, h.name)
			}
			inv.byAddr[a] = h.name
			h.addrs = append(h.addrs, a)
		}
		slices.SortFunc(h.addrs, netip.Addr.Compare)
		inv.hosts = append(inv.hosts, h)
	}
	slices.SortFunc(inv.hosts, func(a, b inventoryHost) int { return strings.Compare(a.name, b.name) })
	inv.digest = inventoryDigest(inv.hosts)
	return inv, nil
}

// checkInventoryName checks a host name or a node name of Slurm: a name
// of shawk starts with ~, and a name with spaces or control characters is
// a mistake of the generator.
func checkInventoryName(s string) error {
	switch {
	case s == "":
		return errors.New("empty")
	case strings.HasPrefix(s, "~"):
		return errors.New("starts with ~")
	case len(s) > 255:
		return errors.New("longer than 255 bytes")
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return errors.New("has spaces or control characters")
	}
	return nil
}

// checkInventoryRole checks a role. Roles are free text, labels of the
// operator such as compute, login or lustre-oss.
func checkInventoryRole(s string) error {
	switch {
	case strings.TrimSpace(s) == "":
		return errors.New("empty")
	case strings.HasPrefix(s, "~"):
		return errors.New("starts with ~")
	case len(s) > 255:
		return errors.New("longer than 255 bytes")
	case strings.IndexFunc(s, unicode.IsControl) >= 0:
		return errors.New("has control characters")
	}
	return nil
}

// inventoryDigest hashes hosts sorted by name, with sorted roles and
// addresses.
func inventoryDigest(hosts []inventoryHost) string {
	h := sha256.New()
	for _, x := range hosts {
		fmt.Fprintf(h, "%q %q %t %q", x.name, x.slurmNode, x.agent, x.roles)
		for _, a := range x.addrs {
			fmt.Fprintf(h, " %s", a)
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// syncInventory reads inventory_file and writes it to PostgreSQL. It runs
// every write interval, once the schema is ready. Without an
// inventory_file it does nothing, so that a connector without one leaves
// the inventory of the others.
func (c *shawkConnector) syncInventory(ctx context.Context) {
	if c.cfg.InventoryFile == "" {
		return
	}
	at := c.now()
	inv, err := readInventory(c.cfg.InventoryFile)
	if err != nil {
		c.inventoryUnreadable(ctx, err, at)
		return
	}
	if prev := c.inventory.Load(); prev == nil || c.inventoryFromStore || prev.digest != inv.digest {
		c.log.Info("read the inventory", zap.String("file", c.cfg.InventoryFile),
			zap.Int("hosts", len(inv.hosts)), zap.Int("addresses", len(inv.byAddr)))
	}
	c.inventory.Store(inv)
	c.inventoryFromStore = false
	c.inventoryErr = ""
	c.inventoryReadAt = at
	c.writeInventory(ctx, inv, at)
}

// writeInventory writes the inventory read at readAt, and remembers
// whether it is written, so that it is written again while the file cannot
// be read.
func (c *shawkConnector) writeInventory(ctx context.Context, inv *inventory, readAt time.Time) {
	if err := c.store.syncInventory(ctx, inv, readAt); err != nil {
		c.log.Warn("writing the inventory to PostgreSQL", zap.Error(err))
		c.inventoryUnwritten = true
		return
	}
	c.inventoryUnwritten = false
}

// inventoryUnreadable keeps the inventory read before, from PostgreSQL if
// the connector has read none since it started, writes it if it could not
// be written when it was read, and records the failure.
// A failure is logged when it changes, and at most once an hour while it
// lasts.
func (c *shawkConnector) inventoryUnreadable(ctx context.Context, err error, at time.Time) {
	msg := err.Error()
	if msg != c.inventoryErr || at.Sub(c.lastInventoryLog) >= foldWarnInterval {
		c.log.Error("reading inventory_file; the inventory read before stays", zap.String("file", c.cfg.InventoryFile),
			zap.Error(err))
		c.inventoryErr, c.lastInventoryLog = msg, at
	}
	if inv := c.inventory.Load(); inv != nil && c.inventoryUnwritten {
		c.writeInventory(ctx, inv, c.inventoryReadAt)
	}
	if c.inventory.Load() == nil {
		inv, err := c.store.inventory(ctx)
		if err != nil {
			c.log.Warn("reading the inventory from PostgreSQL", zap.Error(err))
		} else if inv != nil {
			c.inventory.Store(inv)
			c.inventoryFromStore = true
		}
	}
	if err := c.store.inventoryFailed(ctx, at, msg); err != nil {
		c.log.Warn("recording the failure to read inventory_file in PostgreSQL", zap.Error(err))
	}
}

// inventoryConflicts logs a host whose agent sends addresses that the
// inventory gives to other hosts, at most once an hour per host. The
// inventory wins: it names the host of such an address, and is fixed
// where it is wrong. c.mu is held.
func (c *shawkConnector) inventoryConflicts(b *hostBatch, now time.Time) {
	inv := c.inventory.Load()
	if inv == nil {
		return
	}
	var conflicts []string
	for _, a := range b.addrs {
		if h, ok := inv.hostOf(a); ok && h != b.hostname {
			conflicts = append(conflicts, a.String()+"="+h)
		}
	}
	if len(conflicts) == 0 {
		return
	}
	if t, ok := c.inventoryWarned[b.hostname]; ok && now.Sub(t) < foldWarnInterval {
		return
	}
	c.inventoryWarned[b.hostname] = now
	c.log.Warn("an agent sends addresses that the inventory gives to other hosts; the inventory wins, "+
		"fix it or the address of the host", zap.String("host", b.hostname), zap.Strings("addresses", conflicts))
}
