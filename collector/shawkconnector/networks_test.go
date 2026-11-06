package shawkconnector

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// clusterNetworks are the networks of a cluster: a management network, a
// storage network and IPoIB, which a compute node reaches through a
// narrower range of the management network.
var clusterNetworks = map[string]string{
	"mgmt":    "10.0.0.0/16",
	"compute": "10.0.2.0/24",
	"storage": "10.20.0.0/16",
	"ib":      "10.10.0.0/16, fd00:10::/32",
}

// nfsAgents are an NFS server on the management and the storage network,
// and a compute node that mounts it over the storage network, and also over
// the management network by mistake. The node also reaches a private
// address in no network, a public one and folded peers.
func nfsAgents(ts time.Time) (nfs, node tAgent) {
	nfs = tAgent{host: "nfs-01", addrs: []string{"10.0.0.50", "10.20.0.50"}, time: ts,
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 2049, svc: "nfsd", comm: "nfsd"}},
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.20.0.50", peer: "10.20.2.1", port: 2049, svc: "nfsd", comm: "nfsd",
				opened: 5, tx: 5000, rx: 500},
			{role: "server", proto: "tcp", local: "10.0.0.50", peer: "10.0.2.1", port: 2049, svc: "nfsd", comm: "nfsd",
				opened: 1, tx: 1000, rx: 100},
		}}
	node = tAgent{host: "node-01", addrs: []string{"10.0.2.1", "10.20.2.1", "fd00:10::2:1"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.20.2.1", peer: "10.20.0.50", port: 2049, svc: "mount", comm: "mount",
				opened: 5, tx: 500, rx: 5000, handshakes: []uint64{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, hsSum: 0.005},
			{role: "client", proto: "tcp", local: "10.0.2.1", peer: "10.0.0.50", port: 2049, svc: "mount", comm: "mount",
				opened: 1, tx: 100, rx: 1000, handshakes: []uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, hsSum: 0.001},
			{role: "client", proto: "tcp", local: "10.0.2.1", peer: "192.168.1.1", port: 443, svc: "mount", comm: "mount", opened: 1},
			{role: "client", proto: "tcp", local: "10.0.2.1", peer: "203.0.113.5", port: 443, svc: "mount", comm: "mount", opened: 1},
			{role: "client", proto: "tcp", local: "10.0.2.1", peer: "0.0.0.0", folded: true, port: 443, svc: "mount", comm: "mount", opened: 1},
			{role: "client", proto: "tcp", local: "fd00:10::2:1", peer: "::", folded: true, port: 443, svc: "mount", comm: "mount", opened: 1},
			{role: "client", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 111, svc: "mount", comm: "mount", opened: 1},
		}}
	return nfs, node
}

// networksOf returns the values of the outputs per peer host of a metric of
// a local service that are not zero, by peer host, peer service and the
// networks of the two addresses.
func networksOf(out []series, metric, job, role, dir string) map[string]float64 {
	got := map[string]float64{}
	for _, s := range find(out, metric, job, "*", role, dir) {
		if s.value == 0 && s.count == 0 {
			continue
		}
		got[fmt.Sprintf("%s %s %s>%s", s.peerHost, s.peer, s.localNet, s.peerNet)] += s.value + float64(s.count)
	}
	return got
}

// TestNetworksOff: without networks, no output carries a network.
func TestNetworksOff(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) { cfg.PeerHosts = true })
	nfs, node := nfsAgents(t0.Add(15 * time.Second))
	consume(t, c, sink, nfs)
	for _, s := range consume(t, c, sink, node) {
		if s.localNet != "" || s.peerNet != "" {
			t.Errorf("a network without networks: %+v", s)
		}
	}
}

// TestNetworkOutputs: networks split the outputs per peer host by the
// networks of the local and the peer address of their edges, and change no
// other output.
func TestNetworkOutputs(t *testing.T) {
	run := func(networks map[string]string) []series {
		c, _, sink, _ := testConnector(t, func(cfg *Config) {
			cfg.PeerHosts = true
			cfg.Networks = networks
		})
		nfs, node := nfsAgents(t0.Add(15 * time.Second))
		consume(t, c, sink, nfs)
		out := consume(t, c, sink, node)
		// The server side, now that its client is known.
		nfs.time = nfs.time.Add(15 * time.Second)
		for i := range nfs.edges {
			nfs.edges[i].opened *= 2
			nfs.edges[i].tx *= 2
		}
		return append(out, consume(t, c, sink, nfs)...)
	}
	without := run(nil)
	with := run(clusterNetworks)

	// The outputs without networks are those with networks, but for the
	// networks of the family per peer host, which add up to them.
	key := func(s series) string {
		if strings.HasPrefix(s.metric, "shawk.host.") {
			s.value, s.count, s.localNet, s.peerNet = 0, 0, "", ""
		}
		return fmt.Sprintf("%+v", s)
	}
	sum := func(ss []series) map[string]float64 {
		m := map[string]float64{}
		for _, s := range ss {
			m[key(s)] += s.value + float64(s.count)
		}
		return m
	}
	if a, b := sum(without), sum(with); !maps.Equal(a, b) {
		t.Errorf("the outputs changed beyond the networks:\n%v\n%v", a, b)
	}
	for _, s := range with {
		if !strings.HasPrefix(s.metric, "shawk.host.") && (s.localNet != "" || s.peerNet != "") {
			t.Errorf("an output not per peer host has a network: %+v", s)
		}
		if strings.HasPrefix(s.metric, "shawk.host.") && (s.localNet == "" || s.peerNet == "") {
			t.Errorf("an output per peer host has no network: %+v", s)
		}
	}

	// The narrowest range wins: the node is in compute, within mgmt. A
	// private address in no range is ~unknown, a public one ~external, and
	// so are folded peers; loopback is in no range either.
	if got, want := networksOf(with, metricHostConnOpened, "mount", roleClient, ""), map[string]float64{
		"nfs-01 nfsd storage>storage":           5,
		"nfs-01 nfsd compute>mgmt":              1,
		"~unknown ~unresolved compute>~unknown": 1,
		"~external ~external compute>~external": 2,
		"~external ~external ib>~external":      1,
		"node-01 ~unresolved ~unknown>~unknown": 1,
	}; !maps.Equal(got, want) {
		t.Errorf("client connections by network = %v, want %v", got, want)
	}
	if got, want := networksOf(with, metricHostHandshake, "mount", roleClient, ""), map[string]float64{
		"nfs-01 nfsd storage>storage": 5.005,
		"nfs-01 nfsd compute>mgmt":    1.001,
	}; !maps.Equal(got, want) {
		t.Errorf("handshakes by network = %v, want %v", got, want)
	}
	// The server side names its own address as local. Its first interval
	// came before its client was known, with the same networks.
	if got, want := networksOf(with, metricHostNetworkIO, "nfsd", roleServer, dirTransmit), map[string]float64{
		"node-01 mount storage>storage":        5000,
		"node-01 mount mgmt>compute":           1000,
		"~unknown ~unresolved storage>storage": 5000,
		"~unknown ~unresolved mgmt>compute":    1000,
	}; !maps.Equal(got, want) {
		t.Errorf("server bytes by network = %v, want %v", got, want)
	}
}

// TestNetworkOf: the network of an address, of a folded peer, and the
// parsing of networks.
func TestNetworkOf(t *testing.T) {
	a := newAggregator(time.Minute, 1, 1, false, t0)
	a.setNetworks(must(parseNetworks(map[string]string{
		"mgmt":    "10.0.0.0/16",
		"compute": "10.0.2.0/24",
		"ib":      "10.10.0.0/16, fd00:10::/32",
		"mapped":  "::ffff:10.30.0.0/112",
	})))
	for addr, want := range map[string]string{
		"10.0.1.1":    "mgmt",
		"10.0.2.1":    "compute",
		"10.10.0.1":   "ib",
		"fd00:10::1":  "ib",
		"10.30.1.1":   "mapped",
		"10.40.0.1":   networkUnknown,
		"127.0.0.1":   networkUnknown,
		"fe80::1":     networkUnknown,
		"100.64.0.1":  networkUnknown,
		"8.8.8.8":     networkExternal,
		"2001:db8::1": networkExternal,
	} {
		if got := a.networkOf(addrOf(addr), false); got != want {
			t.Errorf("network of %s = %s, want %s", addr, got, want)
		}
	}
	if got := a.networkOf(netip.IPv4Unspecified(), true); got != networkExternal {
		t.Errorf("network of a folded peer = %s", got)
	}

	// A range that holds a whole network names the folded peers of its
	// family, and the public addresses.
	a.setNetworks(must(parseNetworks(map[string]string{"internet": "0.0.0.0/0", "mgmt": "10.0.0.0/16"})))
	for _, c := range []struct {
		addr   netip.Addr
		folded bool
		want   string
	}{
		{netip.IPv4Unspecified(), true, "internet"},
		{netip.IPv6Unspecified(), true, networkExternal},
		{addrOf("8.8.8.8"), false, "internet"},
		{addrOf("10.0.0.1"), false, "mgmt"},
	} {
		if got := a.networkOf(c.addr, c.folded); got != c.want {
			t.Errorf("network of %s (folded %v) = %s, want %s", c.addr, c.folded, got, c.want)
		}
	}

	// Names are cut as labels.
	long := strings.Repeat("n", 300)
	a.setNetworks(must(parseNetworks(map[string]string{long: "10.0.0.0/8"})))
	if got := a.networkOf(addrOf("10.0.0.1"), false); len(got) != maxLabelValue || !strings.HasPrefix(long, got) {
		t.Errorf("a long name = %d bytes", len(got))
	}
}

// TestParseRanges: the ranges of peer_cidrs and networks are sorted
// narrowest first, and IPv4-mapped prefixes are unmapped, so that one and
// the IPv4 prefix it holds are the same prefix.
func TestParseRanges(t *testing.T) {
	ps := must(parseRanges("networks", map[string]string{"wide": "10.0.0.0/8", "narrow": "::ffff:10.1.0.0/112", "v6": "fd00::/8"}))
	var got []string
	for _, p := range ps {
		got = append(got, p.name+" "+p.prefix.String())
	}
	if want := []string{"narrow 10.1.0.0/16", "wide 10.0.0.0/8", "v6 fd00::/8"}; !slices.Equal(got, want) {
		t.Errorf("ranges = %v, want %v", got, want)
	}
	if _, err := parseRanges("networks", map[string]string{"a": "10.1.0.0/16", "b": "::ffff:10.1.0.0/112"}); err == nil ||
		!strings.HasPrefix(err.Error(), "networks: ") {
		t.Errorf("a prefix named twice, once mapped: %v", err)
	}
	// The whole mapped range is every IPv4 address; a wider prefix holds
	// other addresses and is kept as it is.
	for v, want := range map[string]string{"::ffff:0:0/96": "0.0.0.0/0", "::/80": "::/80"} {
		if ps := must(parseRanges("networks", map[string]string{"x": v})); ps[0].prefix.String() != want {
			t.Errorf("%s = %s, want %s", v, ps[0].prefix, want)
		}
	}
}

// TestNetworksUnix: the outputs per peer host of a Unix socket, which has
// no address and uses no network, carry no network.
func TestNetworksUnix(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.PeerHosts = true
		cfg.Networks = clusterNetworks
	})
	out := consume(t, c, sink, tAgent{host: "node-01", addrs: []string{"10.0.2.1"}, time: t0.Add(15 * time.Second),
		listeners: []tListener{{proto: transportUnix, path: "/run/munge/munge.socket.2", svc: "munged", unit: "munge.service", comm: "munged"}},
		edges: []tEdge{{role: roleClient, proto: transportUnix, path: "/run/munge/munge.socket.2", svc: "slurmd",
			unit: "slurmd.service", comm: "slurmd", opened: 3}}})
	got := networksOf(out, metricHostConnOpened, "slurmd", roleClient, "")
	if want := map[string]float64{"node-01 munged >": 3}; !maps.Equal(got, want) {
		t.Errorf("outputs per peer host = %v, want %v", got, want)
	}
}
