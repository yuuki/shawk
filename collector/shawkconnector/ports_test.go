package shawkconnector

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/confmap"
	"go.yaml.in/yaml/v3"
)

func TestParsePortRules(t *testing.T) {
	r, err := parsePortRules([]string{"srun", "salloc", "srun"}, map[string]DynamicPortsConfig{
		"srun":  {Hosts: []string{"10.1.0.0/16", "2001:db8::/64"}, Transport: "tcp", Ports: "60001-63000"},
		"pmix":  {Ports: " 50000 "},
		"empty": {Hosts: []string{"10.1.0.1"}, Ports: "40000-40000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.services, []string{"salloc", "srun"}) {
		t.Errorf("services = %v", r.services)
	}
	for _, c := range []struct {
		service, addr string
		port          uint16
		proto         string
		want          bool
	}{
		{"srun", "10.9.9.9", 41234, "tcp", true},
		{"salloc", "10.9.9.9", 41234, "udp", true},
		{"slurmctld", "10.1.0.5", 6817, "tcp", false},
		{"mpi", "10.1.0.5", 60001, "tcp", true},
		{"mpi", "10.1.0.5", 63000, "tcp", true},
		{"mpi", "10.1.0.5", 63001, "tcp", false},
		{"mpi", "10.1.0.5", 60001, "udp", false},
		{"mpi", "10.2.0.5", 60001, "tcp", false},
		{"mpi", "2001:db8::5", 61000, "tcp", true},
		{"pmix", "192.168.0.1", 50000, "udp", true},
		{"pmix", "192.168.0.1", 50001, "udp", false},
		{"x", "10.1.0.1", 40000, "tcp", true},
		{"x", "10.1.0.2", 40000, "tcp", false},
	} {
		if got := r.portAgnostic(c.service, addrOf(c.addr), c.port, c.proto); got != c.want {
			t.Errorf("portAgnostic(%s, %s, %d, %s) = %v", c.service, c.addr, c.port, c.proto, got)
		}
	}
	// A range for every address has a row per family.
	rows := map[string]bool{}
	for _, row := range r.dynamicPortsRows() {
		rows[fmt.Sprintf("%s %s %s %d-%d", row.name, row.proto, row.prefix, row.from, row.to)] = true
	}
	want := map[string]bool{
		"empty tcp 10.1.0.1/32 40000-40000": true, "empty udp 10.1.0.1/32 40000-40000": true,
		"pmix tcp 0.0.0.0/0 50000-50000": true, "pmix tcp ::/0 50000-50000": true,
		"pmix udp 0.0.0.0/0 50000-50000": true, "pmix udp ::/0 50000-50000": true,
		"srun tcp 10.1.0.0/16 60001-63000": true, "srun tcp 2001:db8::/64 60001-63000": true,
	}
	if !maps.Equal(rows, want) {
		t.Errorf("rows = %v", rows)
	}
	var none *portRules
	if none.portAgnostic("srun", addrOf("10.0.0.1"), 1, "tcp") || none.dynamicPortsRows() != nil {
		t.Error("no rules match")
	}

	for name, c := range map[string]DynamicPortsConfig{
		"no ports":       {},
		"port 0":         {Ports: "0-100"},
		"reversed":       {Ports: "63000-60001"},
		"beyond 65535":   {Ports: "60000-70000"},
		"not a number":   {Ports: "high"},
		"open range":     {Ports: "60000-"},
		"bad transport":  {Ports: "1-2", Transport: "sctp"},
		"bad host":       {Ports: "1-2", Hosts: []string{"node01"}},
		"host with port": {Ports: "1-2", Hosts: []string{"10.0.0.1:80"}},
	} {
		if _, err := parsePortRules(nil, map[string]DynamicPortsConfig{"x": c}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parsePortRules([]string{" "}, nil); err == nil {
		t.Error("a service without a name was accepted")
	}
	if _, err := parsePortRules([]string{" srun"}, nil); err == nil {
		t.Error("a service with spaces around its name was accepted")
	}
}

func TestConfigValidatePortRules(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://x"
	cfg.PortAgnosticServices = []string{"srun", "salloc", "slurm-job"}
	cfg.DynamicPorts = map[string]DynamicPortsConfig{"srun": {Transport: "tcp", Ports: "60001-63000"}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
	// As in the configuration of the collector.
	cfg = createDefaultConfig()
	cfg.Postgres.DSN = "postgres://x"
	if err := confmap.NewFromStringMap(map[string]any{
		"port_agnostic_services": []any{"srun", "salloc"},
		"dynamic_ports": map[string]any{
			"srun": map[string]any{"hosts": []any{"10.1.0.0/16"}, "transport": "tcp", "ports": "60001-63000"},
		},
	}).Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.PortAgnosticServices, []string{"srun", "salloc"}) ||
		cfg.DynamicPorts["srun"].Ports != "60001-63000" || cfg.DynamicPorts["srun"].Transport != "tcp" ||
		!slices.Equal(cfg.DynamicPorts["srun"].Hosts, []string{"10.1.0.0/16"}) {
		t.Errorf("config = %+v %+v", cfg.PortAgnosticServices, cfg.DynamicPorts)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
	cfg.DynamicPorts = map[string]DynamicPortsConfig{"srun": {Ports: "63000-60001"}}
	if err := cfg.Validate(); err == nil {
		t.Error("a reversed range of ports was accepted")
	}
}

// TestPackagedPortRulesExample: the example of port_agnostic_services and
// dynamic_ports commented out in the packaged configuration is valid.
func TestPackagedPortRulesExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(packaging, "collector/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "    # port_agnostic_services:"):
			in = true
		case in && !strings.HasPrefix(l, "    #"):
			in = false
		}
		if in {
			lines = append(lines, strings.Replace(l, "# ", "", 1))
		}
	}
	if len(lines) < 2 {
		t.Fatal("no example of the rules of ports")
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
	r := must(parsePortRules(cfg.PortAgnosticServices, cfg.DynamicPorts))
	if !slices.Equal(r.services, []string{"salloc", "srun"}) || len(r.ranges) != 1 ||
		r.ranges[0].from != 60001 || r.ranges[0].to != 63000 {
		t.Errorf("rules = %+v", r)
	}
}

// TestPortAgnosticOutputs: the outputs of dependencies on a service of
// port_agnostic_services or on a range of dynamic_ports have server.port
// 0, so that each run of srun on another port adds no series; the other
// dependencies keep their port.
func TestPortAgnosticOutputs(t *testing.T) {
	c, st, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.PortAgnosticServices = []string{"srun"}
		cfg.DynamicPorts = map[string]DynamicPortsConfig{
			"cluster": {Hosts: []string{"10.1.0.0/16"}, Transport: "tcp", Ports: "60001-63000"},
		}
	})
	st.mu.Lock()
	if st.ports == nil || !slices.Equal(st.ports.services, []string{"srun"}) || len(st.ports.ranges) != 1 {
		t.Errorf("rules of ports written: %+v", st.ports)
	}
	st.mu.Unlock()
	ts := t0.Add(15 * time.Second)
	// Two runs of srun on node01, an MPI rank on a port of the range, and
	// sshd.
	out := consume(t, c, sink, tAgent{host: "node01", addrs: []string{"10.1.0.1"}, time: ts,
		listeners: []tListener{
			{proto: "tcp", addr: "0.0.0.0", port: 41234, svc: "srun", comm: "srun"},
			{proto: "tcp", addr: "0.0.0.0", port: 52345, svc: "srun", comm: "srun"},
			{proto: "tcp", addr: "0.0.0.0", port: 60010, svc: "mpi", comm: "mpi"},
			{proto: "tcp", addr: "0.0.0.0", port: 22, svc: "sshd", comm: "sshd"},
		},
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.1.0.1", peer: "10.1.0.100", port: 41234, svc: "srun", comm: "srun", opened: 2},
			{role: "server", proto: "tcp", local: "10.1.0.1", peer: "10.1.0.100", port: 52345, svc: "srun", comm: "srun", opened: 3},
			{role: "server", proto: "tcp", local: "10.1.0.1", peer: "10.1.0.2", port: 60010, svc: "mpi", comm: "mpi", opened: 4},
			{role: "server", proto: "tcp", local: "10.1.0.1", peer: "10.1.0.100", port: 22, svc: "sshd", comm: "sshd", opened: 1},
		}})
	ports := func(out []series, job, role string) map[string]float64 {
		got := map[string]float64{}
		for _, s := range find(out, metricConnOpened, job, "*", role, "") {
			got[fmt.Sprintf("%s:%d", s.peer, s.port)] += s.value
		}
		return got
	}
	for job, want := range map[string]map[string]float64{
		"srun": {"~unresolved:0": 5},
		"mpi":  {"~unresolved:0": 4},
		"sshd": {"~unresolved:22": 1},
	} {
		if got := ports(out, job, roleServer); !maps.Equal(got, want) {
			t.Errorf("server outputs of %s = %v, want %v", job, got, want)
		}
	}
	// The client sides: slurmctld connects to both runs of srun, and to a
	// port of the range outside its hosts, which keeps its port.
	out = consume(t, c, sink, tAgent{host: "ctl01", addrs: []string{"10.1.0.100"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.1.0.1", port: 41234, svc: "slurmctld", comm: "slurmctld", opened: 2},
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.1.0.1", port: 52345, svc: "slurmctld", comm: "slurmctld", opened: 3},
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.1.0.1", port: 60010, svc: "slurmctld", comm: "slurmctld", opened: 1},
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.2.0.5", port: 60010, svc: "slurmctld", comm: "slurmctld", opened: 1},
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.1.0.1", port: 22, svc: "slurmctld", comm: "slurmctld", opened: 1},
		}})
	want := map[string]float64{"srun:0": 5, "mpi:0": 1, "~unresolved:60010": 1, "sshd:22": 1}
	if got := ports(out, "slurmctld", roleClient); !maps.Equal(got, want) {
		t.Errorf("client outputs = %v, want %v", got, want)
	}
}

// TestPortAgnosticThroughTranslations: through a translation, a range of
// dynamic_ports is matched with the address and port of the backend, as in
// PostgreSQL, rather than with the virtual address the client connected
// to.
func TestPortAgnosticThroughTranslations(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		translationConfig(cfg)
		cfg.DynamicPorts = map[string]DynamicPortsConfig{
			"db":  {Hosts: []string{"10.0.1.0/24"}, Transport: "tcp", Ports: "5432-5432"},
			"web": {Hosts: []string{"10.0.1.20"}, Ports: "8080-8080"},
		}
	})
	app, db1, db2, web := translationAgents(t0.Add(15 * time.Second))
	consume(t, c, sink, db1)
	consume(t, c, sink, db2)
	consume(t, c, sink, web)
	out := consume(t, c, sink, app)
	got := map[string]float64{}
	for _, s := range find(out, metricConnOpened, "shop/app", "*", roleClient, "") {
		got[fmt.Sprintf("%s:%d", s.peer, s.port)] += s.value
	}
	// Nothing listens behind api-lb yet: its virtual address is not in a
	// range, and keeps its port.
	if want := map[string]float64{"postgres:0": 4, "web:0": 2, "~unresolved:443": 1}; !maps.Equal(got, want) {
		t.Errorf("client outputs = %v, want %v", got, want)
	}
}

// TestPortRulesMismatchLogged: a connector whose rules of ports are not
// those PostgreSQL has, as during a rolling update of the configuration,
// logs it at most once an hour; the same rules log nothing.
func TestPortRulesMismatchLogged(t *testing.T) {
	c, st, _, now := testConnector(t, func(cfg *Config) { cfg.PortAgnosticServices = []string{"srun"} })
	logs := observe(c)
	mismatches := func() int {
		n := 0
		for _, e := range logs.TakeAll() {
			if _, ok := e.ContextMap()["postgres"]; ok {
				n++
			}
		}
		return n
	}
	c.refreshIfDue(context.Background())
	if n := mismatches(); n != 0 {
		t.Errorf("%d warnings with the same rules", n)
	}
	st.mu.Lock()
	st.ruleKeys = []string{}
	st.mu.Unlock()
	*now = now.Add(refreshInterval)
	c.refreshIfDue(context.Background())
	*now = now.Add(refreshInterval)
	c.refreshIfDue(context.Background())
	if n := mismatches(); n != 1 {
		t.Errorf("%d warnings with other rules, want 1", n)
	}
	*now = now.Add(time.Hour)
	c.refreshIfDue(context.Background())
	if n := mismatches(); n != 1 {
		t.Errorf("%d warnings an hour later, want 1", n)
	}
}

// TestPortAgnosticPeerHosts: the outputs per peer host of a dependency on
// a port-agnostic service have server.port 0 too.
func TestPortAgnosticPeerHosts(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.PortAgnosticServices = []string{"srun"}
		cfg.PeerHosts = true
	})
	ts := t0.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "node01", addrs: []string{"10.1.0.1"}, time: ts,
		listeners: []tListener{
			{proto: "tcp", addr: "0.0.0.0", port: 41234, svc: "srun", comm: "srun"},
			{proto: "tcp", addr: "0.0.0.0", port: 52345, svc: "srun", comm: "srun"},
		}})
	out := consume(t, c, sink, tAgent{host: "ctl01", addrs: []string{"10.1.0.100"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.1.0.1", port: 41234, svc: "slurmctld", comm: "slurmctld", opened: 2},
			{role: "client", proto: "tcp", local: "10.1.0.100", peer: "10.1.0.1", port: 52345, svc: "slurmctld", comm: "slurmctld", opened: 3},
		}})
	got := map[string]float64{}
	for _, s := range find(out, metricHostConnOpened, "slurmctld", "*", roleClient, "") {
		got[fmt.Sprintf("%s:%d", s.peer, s.port)] += s.value
	}
	if want := map[string]float64{"srun:0": 5}; !maps.Equal(got, want) {
		t.Errorf("outputs per peer host = %v, want %v", got, want)
	}
}
