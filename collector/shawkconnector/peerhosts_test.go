package shawkconnector

import (
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/confmap"
	"go.yaml.in/yaml/v3"
)

// hostsOf returns the values of the outputs per peer host of a metric of a
// local service that are not zero, by peer host and peer service.
func hostsOf(out []series, metric, job, role, dir string) map[string]float64 {
	got := map[string]float64{}
	for _, s := range find(out, metric, job, "*", role, dir) {
		if s.value == 0 {
			continue
		}
		key := s.peerHost + " " + s.peer
		if s.errType != "" {
			key += " " + s.errType
		}
		got[key] += s.value
	}
	return got
}

// slurmAgents are slurmctld on ctl-01 and the slurmd of two compute nodes,
// a third node without an agent that refuses or does not answer, a loopback
// peer and a public one.
func slurmAgents(ts time.Time) (ctl, node1, node2 tAgent) {
	ctl = tAgent{host: "ctl-01", addrs: []string{"127.0.0.1", "10.0.0.1"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.1", peer: "10.0.2.1", port: 6818, svc: "slurmctld", comm: "slurmctld",
				opened: 4, tx: 400, rx: 40, retrans: 1, handshakes: []uint64{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, hsSum: 0.004, synRetrans: 1},
			{role: "client", proto: "tcp", local: "10.0.0.1", peer: "10.0.2.2", port: 6818, svc: "slurmctld", comm: "slurmctld",
				opened: 2, tx: 200, rx: 20, handshakes: []uint64{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, hsSum: 0.002},
			{role: "client", proto: "tcp", local: "10.0.0.1", peer: "10.0.2.3", port: 6818, svc: "slurmctld", comm: "slurmctld",
				failed: 3, reasons: map[string]tReason{"timeout": {value: 2}, "refused": {value: 1}},
				handshakes: make([]uint64, 11), synRetrans: 4},
			{role: "client", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 6819, svc: "slurmctld", comm: "slurmctld", opened: 1},
			{role: "client", proto: "tcp", local: "10.0.0.1", peer: "203.0.113.5", port: 443, svc: "slurmctld", comm: "slurmctld", opened: 1},
		}}
	node := func(host, addr string, opened int64) tAgent {
		return tAgent{host: host, addrs: []string{"127.0.0.1", addr}, time: ts,
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 6818, svc: "slurmd", comm: "slurmd"}},
			edges: []tEdge{{role: "server", proto: "tcp", local: addr, peer: "10.0.0.1", port: 6818, svc: "slurmd",
				comm: "slurmd", opened: opened, tx: 10 * opened, rx: 100 * opened}}}
	}
	return ctl, node("node-01", "10.0.2.1", 4), node("node-02", "10.0.2.2", 2)
}

// TestPeerHostsOff: without peer_hosts, there are no outputs per peer host
// and no shawk.peer.host.
func TestPeerHostsOff(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ctl, n1, n2 := slurmAgents(t0.Add(15 * time.Second))
	consume(t, c, sink, n1)
	consume(t, c, sink, n2)
	for _, s := range consume(t, c, sink, ctl) {
		if !strings.HasPrefix(s.metric, "shawk.host.") && s.peerHost == "" {
			continue
		}
		t.Errorf("output per peer host without peer_hosts: %+v", s)
	}
}

// TestPeerHostOutputs: the outputs per peer host split those of a peer
// service by the host of the peer, and the existing outputs do not change.
func TestPeerHostOutputs(t *testing.T) {
	run := func(mod func(*Config)) []series {
		c, _, sink, _ := testConnector(t, mod)
		ctl, n1, n2 := slurmAgents(t0.Add(15 * time.Second))
		consume(t, c, sink, n1)
		consume(t, c, sink, n2)
		return consume(t, c, sink, ctl)
	}
	without := run(nil)
	with := run(func(cfg *Config) { cfg.PeerHosts = true })

	var existing []series
	for _, s := range with {
		if !strings.HasPrefix(s.metric, "shawk.host.") {
			existing = append(existing, s)
		}
	}
	key := func(s series) string { return fmt.Sprintf("%+v", s) }
	a, b := mapSlice(without, key), mapSlice(existing, key)
	slices.Sort(a)
	slices.Sort(b)
	if len(a) != len(b) || !slices.Equal(a, b) {
		t.Errorf("the existing outputs changed:\n%v\n%v", a, b)
	}

	// Nothing listens on the loopback peer, which is the host itself.
	if got, want := hostsOf(with, metricHostConnOpened, "slurmctld", roleClient, ""),
		map[string]float64{"node-01 slurmd": 4, "node-02 slurmd": 2, "ctl-01 ~unresolved": 1, "~external ~external": 1}; !maps.Equal(got, want) {
		t.Errorf("connections by peer host = %v, want %v", got, want)
	}
	// A failure reason emits 0 first.
	var reasons []string
	for _, s := range find(with, metricHostConnFailedByReason, "slurmctld", "*", roleClient, "") {
		reasons = append(reasons, s.peerHost+" "+s.peer+" "+s.errType)
	}
	slices.Sort(reasons)
	if want := []string{"~unknown ~unresolved refused", "~unknown ~unresolved timeout"}; !slices.Equal(reasons, want) {
		t.Errorf("failures by peer host = %v, want %v", reasons, want)
	}
	if got, want := hostsOf(with, metricHostSynRetransmits, "slurmctld", roleClient, ""),
		map[string]float64{"node-01 slurmd": 1, "~unknown ~unresolved": 4}; !maps.Equal(got, want) {
		t.Errorf("SYN retransmissions by peer host = %v, want %v", got, want)
	}
	if got, want := hostsOf(with, metricHostNetworkIO, "slurmctld", roleClient, dirTransmit),
		map[string]float64{"node-01 slurmd": 400, "node-02 slurmd": 200}; !maps.Equal(got, want) {
		t.Errorf("bytes by peer host = %v, want %v", got, want)
	}
	hs := find(with, metricHostHandshake, "slurmctld", "slurmd", roleClient, "")
	if len(hs) != 2 || hs[0].count+hs[1].count != 6 {
		t.Errorf("handshakes by peer host = %+v", hs)
	}
	for _, m := range []string{metricConnFailed, metricConnCount, metricUDPDatagrams, metricRTT} {
		for _, s := range find(with, m, "slurmctld", "*", "*", "*") {
			if s.peerHost != "" {
				t.Errorf("%s has a peer host: %+v", m, s)
			}
		}
	}
}

func mapSlice[T, U any](s []T, f func(T) U) []U {
	out := make([]U, 0, len(s))
	for _, v := range s {
		out = append(out, f(v))
	}
	return out
}

// TestPeerHostServerSide: the server side names the host of its client, and
// a client on the server's own shared address is the server itself.
func TestPeerHostServerSide(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) { cfg.PeerHosts = true })
	ctl, n1, _ := slurmAgents(t0.Add(15 * time.Second))
	consume(t, c, sink, ctl)
	out := consume(t, c, sink, n1)
	if got, want := hostsOf(out, metricHostConnOpened, "slurmd", roleServer, ""),
		map[string]float64{"ctl-01 slurmctld": 4}; !maps.Equal(got, want) {
		t.Errorf("server side = %v, want %v", got, want)
	}
}

// TestPeerHostEvidence: the steps of §1.3 of the proposal, in order.
func TestPeerHostEvidence(t *testing.T) {
	now := t0
	r := newResolver(nil, nil)
	r.peerHosts = true
	alive := agentHost{seen: now, name: "node-01"}
	r.load(peerRows{
		agents: []agentAddrRow{
			{addr: addrOf("10.0.2.1"), host: "id-node-01", seen: now, agent: alive},
			// A shared address: the gateway of a container bridge.
			{addr: addrOf("172.17.0.1"), host: "id-node-01", seen: now, agent: alive},
			{addr: addrOf("172.17.0.1"), host: "id-node-02", seen: now, agent: agentHost{seen: now, name: "node-02"}},
			{addr: addrOf("10.0.2.2"), host: "id-node-02", seen: now, agent: agentHost{seen: now, name: "node-02"}},
		},
		former: []formerHolderRow{
			// node-03 is down.
			{addr: addrOf("10.0.2.3"), formerHolder: formerHolder{host: "id-node-03", name: "node-03"}},
			// The address left node-02, whose agent is alive.
			{addr: addrOf("10.0.2.4"), formerHolder: formerHolder{host: "id-node-02", name: "node-02"}},
			// A former holder of an address node-01 holds now.
			{addr: addrOf("10.0.2.1"), formerHolder: formerHolder{host: "id-node-09", name: "node-09"}},
		},
	}, now)
	host := func(self, peer string) string {
		p := r.peer(self, &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf(peer), port: 6818}, now)
		if p.self {
			return "self"
		}
		return p.host
	}
	for peer, want := range map[string]string{
		"10.0.2.1":    "node-01",
		"10.0.2.3":    "node-03",
		"10.0.2.4":    hostUnknown,
		"10.0.2.5":    hostUnknown,
		"172.17.0.1":  hostUnknown,
		"127.0.0.1":   "self",
		"203.0.113.5": hostExternal,
	} {
		if got := host("id-ctl-01", peer); got != want {
			t.Errorf("host of %s = %s, want %s", peer, got, want)
		}
	}
	if got := host("id-node-01", "172.17.0.1"); got != "self" {
		t.Errorf("a shared address of the host itself = %s", got)
	}
	if got := host("id-node-01", "10.0.2.1"); got != "self" {
		t.Errorf("an address of the host itself = %s", got)
	}
	// Names of peer_cidrs are ranges, not hosts.
	r.cidrs = []namedPrefix{{name: "compute", prefix: netip.MustParsePrefix("10.0.2.0/24")}}
	if got := host("id-ctl-01", "10.0.2.5"); got != hostUnknown {
		t.Errorf("an address in peer_cidrs = %s", got)
	}
	// A folded peer.
	p := r.peer("id-ctl-01", &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("0.0.0.0"),
		port: 443, folded: true}, now)
	if p.host != hostExternal {
		t.Errorf("a folded peer = %+v", p)
	}

	// The inventory comes first.
	r.inventory = fakeInventory{addrOf("10.0.2.5"): "nas-01", addrOf("10.0.2.3"): "node-03-ib"}
	for peer, want := range map[string]string{"10.0.2.5": "nas-01", "10.0.2.3": "node-03-ib", "10.0.2.1": "node-01"} {
		if got := host("id-ctl-01", peer); got != want {
			t.Errorf("with an inventory, host of %s = %s, want %s", peer, got, want)
		}
	}
}

type fakeInventory map[netip.Addr]string

func (f fakeInventory) hostOf(a netip.Addr) (string, bool) {
	h, ok := f[a]
	return h, ok
}

// TestPeerHostTranslations: through a translation, the backend is the host
// of the peer only when it is the only one; the names of services do not
// change.
func TestPeerHostTranslations(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		translationConfig(cfg)
		cfg.PeerHosts = true
	})
	ts := t0.Add(15 * time.Second)
	app, db1, db2, web := translationAgents(ts)
	consume(t, c, sink, db1)
	consume(t, c, sink, db2)
	consume(t, c, sink, web)
	out := consume(t, c, sink, app)
	got := map[string]float64{}
	for _, s := range find(out, metricHostConnOpened, "shop/app", "*", roleClient, "") {
		got[fmt.Sprintf("%s %s:%d", s.peerHost, s.peer, s.port)] += s.value
	}
	// postgres-vip has three backends, api-lb a range; web-lb one.
	want := map[string]float64{"~unknown postgres:5432": 4, "web-01 web:8080": 2, "~unknown ~unresolved:443": 1}
	if !maps.Equal(got, want) {
		t.Errorf("hosts through translations = %v, want %v", got, want)
	}
	// Behind web-lb, the server sees the relay, which has no agent.
	web.time = ts.Add(15 * time.Second)
	web.edges[0].opened = 11
	out = consume(t, c, sink, web)
	if got, want := hostsOf(out, metricHostConnOpened, "web", roleServer, ""), map[string]float64{"~unknown lb": 11}; !maps.Equal(got, want) {
		t.Errorf("server behind a relay = %v, want %v", got, want)
	}
}

// TestPeerHostLearned: through a learned translation, the backend is the
// host of the peer when it is the only address the client was sent to.
func TestPeerHostLearned(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) { cfg.PeerHosts = true })
	ts := t0.Add(15 * time.Second)
	db := func(host, addr string) tAgent {
		return tAgent{host: host, addrs: []string{addr}, time: ts,
			edges: []tEdge{{role: "server", proto: "tcp", local: addr, peer: "10.0.0.11", port: 6432,
				svc: "postgres", comm: "postgres", opened: 3}}}
	}
	consume(t, c, sink, db("db-01", "10.0.1.10"))
	consume(t, c, sink, db("db-02", "10.0.1.11"))
	app := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.10", port: 5432, svc: "app", comm: "app", opened: 3},
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.11", port: 5432, svc: "app", comm: "app", opened: 5},
		},
		translations: []tTranslation{
			{client: "10.0.0.11", virtual: "10.96.0.10", vport: 5432, backend: "10.0.1.10", bport: 6432},
			{client: "10.0.0.11", virtual: "10.96.0.11", vport: 5432, backend: "10.0.1.10", bport: 6432},
			{client: "10.0.0.11", virtual: "10.96.0.11", vport: 5432, backend: "10.0.1.11", bport: 6432},
		}}
	out := consume(t, c, sink, app)
	if got, want := hostsOf(out, metricHostConnOpened, "app", roleClient, ""),
		map[string]float64{"db-01 postgres": 3, "~unknown postgres": 5}; !maps.Equal(got, want) {
		t.Errorf("hosts through learned translations = %v, want %v", got, want)
	}
}

// TestPeerHostBounds: max_peer_hosts folds further hosts into ~other, and
// peer_host_services restricts the family to some local services.
func TestPeerHostBounds(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.PeerHosts = true
		cfg.MaxPeerHosts = 1
		cfg.PeerHostServices = []string{"slurmctld"}
	})
	ctl, n1, n2 := slurmAgents(t0.Add(15 * time.Second))
	consume(t, c, sink, n1)
	out := consume(t, c, sink, n2)
	if got := hostsOf(out, metricHostConnOpened, "slurmd", "*", ""); len(got) != 0 {
		t.Errorf("a local service outside peer_host_services: %v", got)
	}
	out = consume(t, c, sink, ctl)
	got := hostsOf(out, metricHostConnOpened, "slurmctld", roleClient, "")
	var slurmd []string
	for k := range got {
		if k == "node-01 slurmd" || k == "node-02 slurmd" || k == "~other slurmd" {
			slurmd = append(slurmd, k)
		}
	}
	if len(slurmd) != 2 || got["~other slurmd"] == 0 {
		t.Errorf("max_peer_hosts 1: %v", got)
	}
	if got["~external ~external"] != 1 {
		t.Errorf("another peer service has its own bound: %v", got)
	}
}

// TestPackagedPeerHostsExample: the example of the outputs per peer host
// commented out in the packaged configuration is valid.
func TestPackagedPeerHostsExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(packaging, "collector/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		for _, k := range []string{"peer_hosts:", "max_peer_hosts:", "peer_host_services:"} {
			if strings.HasPrefix(l, "    # "+k) {
				lines = append(lines, strings.TrimPrefix(l, "    # "))
			}
		}
	}
	if len(lines) != 3 {
		t.Fatalf("example = %q", lines)
	}
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &raw); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	if err := confmap.NewFromStringMap(raw).Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}
	if !cfg.PeerHosts || cfg.MaxPeerHosts != 500 || !slices.Equal(cfg.PeerHostServices, []string{"slurmctld", "prometheus"}) {
		t.Errorf("config = %+v", cfg)
	}
}
