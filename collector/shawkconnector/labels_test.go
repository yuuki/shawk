package shawkconnector

import (
	"context"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// These tests check that an agent cannot make series in Prometheus beyond
// those of the metrics, attributes and values the agents send, nor labels
// of any length.

// consumeRequest consumes a request built by the test, as consume does.
func consumeRequest(t *testing.T, c *shawkConnector, sink *consumertest.MetricsSink, md pmetric.Metrics) []series {
	t.Helper()
	sink.Reset()
	if err := c.ConsumeMetrics(context.Background(), md); err != nil {
		t.Fatal(err)
	}
	var out []series
	for _, md := range sink.AllMetrics() {
		out = append(out, flatten(md)...)
	}
	return out
}

// tPoint is a point of a metric of the agent, with its attributes.
type tPoint struct {
	attrs map[string]string
	value int64
}

// addMetric appends a gauge or a cumulative sum with its points to the
// first scope of a request.
func addMetric(md pmetric.Metrics, name, unit string, kind pmetric.MetricType, points ...tPoint) {
	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().AppendEmpty()
	m.SetName(name)
	m.SetUnit(unit)
	var dps pmetric.NumberDataPointSlice
	if kind == pmetric.MetricTypeGauge {
		dps = m.SetEmptyGauge().DataPoints()
	} else {
		sum := m.SetEmptySum()
		sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		sum.SetIsMonotonic(true)
		dps = sum.DataPoints()
	}
	for _, p := range points {
		dp := dps.AppendEmpty()
		for k, v := range p.attrs {
			dp.Attributes().PutStr(k, v)
		}
		dp.SetStartTimestamp(pcommon.NewTimestampFromTime(t0))
		dp.SetTimestamp(pcommon.NewTimestampFromTime(t0.Add(15 * time.Second)))
		dp.SetIntValue(p.value)
	}
}

// agentOutput is a metric of agents forwarded to Prometheus.
type agentOutput struct {
	unit   string
	kind   pmetric.MetricType
	points []map[string]any // their attributes
}

// agentOutputs returns the metrics of agents that the sink received.
func agentOutputs(sink *consumertest.MetricsSink) map[string]*agentOutput {
	out := map[string]*agentOutput{}
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			if getString(rms.At(i).Resource().Attributes(), attrServiceName) != agentServiceName {
				continue
			}
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					m := ms.At(k)
					o := out[m.Name()]
					if o == nil {
						o = &agentOutput{unit: m.Unit(), kind: m.Type()}
						out[m.Name()] = o
					}
					var dps pmetric.NumberDataPointSlice
					switch m.Type() {
					case pmetric.MetricTypeGauge:
						dps = m.Gauge().DataPoints()
					case pmetric.MetricTypeSum:
						dps = m.Sum().DataPoints()
					}
					for l := range dps.Len() {
						o.points = append(o.points, dps.At(l).Attributes().AsRaw())
					}
				}
			}
		}
	}
	return out
}

// TestAgentMetricsForwarded: the metrics of an agent are forwarded as the
// agents send them: the metrics they send, with their type and unit, their
// attributes with the values they send, and one point per metric or per
// BPF program. The rest is dropped and logged at most once a minute.
func TestAgentMetricsForwarded(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	logs := observe(c)
	gauge, sum := pmetric.MetricTypeGauge, pmetric.MetricTypeSum
	request := func(i int) pmetric.Metrics {
		md := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now.Add(-time.Second), dropped: 7}.metrics()
		// Metrics the agents do not send, with an attribute of a new value
		// in every request.
		for j := range 100 {
			addMetric(md, fmt.Sprintf("shawk.agent.x%d", j), "", gauge, tPoint{attrs: map[string]string{"random": fmt.Sprint(i, j)}})
		}
		// Another shawk.agent.up, with a scope the agents do not send, and
		// one they do.
		addMetric(md, metricAgentUp, "", gauge, tPoint{attrs: map[string]string{attrNetNSScope: "x"}},
			tPoint{attrs: map[string]string{attrNetNSScope: "4026532000"}})
		// A unit and an attribute of its own.
		addMetric(md, metricAgentExportFailures, fmt.Sprintf("By%d", i), sum,
			tPoint{attrs: map[string]string{"random": fmt.Sprint(i)}, value: 3})
		// A BPF program of the agent twice, one it does not have, and none.
		addMetric(md, metricAgentBPFRunCount, "{run}", sum,
			tPoint{attrs: map[string]string{attrBPFProgram: "shawk_iter_tcp"}, value: 5},
			tPoint{attrs: map[string]string{attrBPFProgram: "shawk_iter_tcp"}, value: 6},
			tPoint{attrs: map[string]string{attrBPFProgram: fmt.Sprint("shawk_", i)}, value: 1},
			tPoint{value: 1})
		// Metrics of another type than the agents send.
		addMetric(md, metricAgentTranslationsTraced, "", sum, tPoint{value: 1})
		addMetric(md, metricAgentCgroupsDropped, "{event}", gauge, tPoint{value: 1})
		return md
	}
	// Dropped from each request: the metrics the agents do not send, the
	// points of shawk.agent.up and of BPF programs beyond the first of the
	// agent, and the metrics of another type.
	const dropped = 100 + 2 + 3 + 2

	*now = now.Add(15 * time.Second)
	consumeRequest(t, c, sink, request(0))
	want := map[string]*agentOutput{
		metricAgentUp:             {kind: gauge, points: []map[string]any{{attrNetNSScope: "all"}}},
		metricAgentUDPTraced:      {kind: gauge, points: []map[string]any{{}}},
		metricAgentFlowsDropped:   {unit: "{update}", kind: sum, points: []map[string]any{{}}},
		metricAgentExportFailures: {unit: "{request}", kind: sum, points: []map[string]any{{}}},
		metricAgentBPFRunCount:    {unit: "{run}", kind: sum, points: []map[string]any{{attrBPFProgram: "shawk_iter_tcp"}}},
	}
	got := agentOutputs(sink)
	if !maps.EqualFunc(got, want, func(a, b *agentOutput) bool {
		return a.unit == b.unit && a.kind == b.kind &&
			slices.EqualFunc(a.points, b.points, func(x, y map[string]any) bool { return maps.Equal(x, y) })
	}) {
		for name, m := range got {
			t.Errorf("forwarded %s: %+v", name, *m)
		}
	}
	warnings := func() []string {
		var out []string
		for _, e := range logs.TakeAll() {
			if m := e.ContextMap(); m["dropped"] != nil {
				out = append(out, fmt.Sprint(m["host"], " ", m["metric"], " ", m["dropped"]))
			}
		}
		return out
	}
	if w := warnings(); !slices.Equal(w, []string{fmt.Sprint("app-01 shawk.agent.x0 ", dropped)}) {
		t.Errorf("warnings = %q", w)
	}

	// Within a minute, the drops are counted but not logged.
	*now = now.Add(15 * time.Second)
	consumeRequest(t, c, sink, request(1))
	if w := warnings(); len(w) != 0 {
		t.Errorf("logged again within a minute: %q", w)
	}
	*now = now.Add(time.Minute)
	consumeRequest(t, c, sink, request(2))
	if w := warnings(); !slices.Equal(w, []string{fmt.Sprint("app-01 shawk.agent.x0 ", 2*dropped)}) {
		t.Errorf("warnings after a minute = %q", w)
	}
}

// TestGoldenAgentMetricsForwarded: the metrics of the agent in the request
// written by the agent's tests are forwarded as they are, but for the start
// of its segment, which is written to PostgreSQL only.
func TestGoldenAgentMetricsForwarded(t *testing.T) {
	b, err := os.ReadFile("testdata/agent-request.json")
	if err != nil {
		t.Fatal(err)
	}
	md, err := (&pmetric.JSONUnmarshaler{}).UnmarshalMetrics(b)
	if err != nil {
		t.Fatal(err)
	}
	sent := pmetric.NewMetricSlice()
	ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	for i := range ms.Len() {
		if m := ms.At(i); strings.HasPrefix(m.Name(), metricAgentPrefix) && m.Name() != metricAgentSegmentStart {
			m.CopyTo(sent.AppendEmpty())
		}
	}
	hb, err := parseResource(md.ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if hb.agentDropped != 0 || len(agentMetrics) != sent.Len() {
		t.Errorf("%d metrics or points of the agent dropped; %d metrics forwarded, the agent sends %d",
			hb.agentDropped, len(agentMetrics), sent.Len())
	}
	a, b2 := pmetric.NewMetrics(), pmetric.NewMetrics()
	sent.CopyTo(a.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics())
	hb.agent.CopyTo(b2.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics())
	ja, _ := (&pmetric.JSONMarshaler{}).MarshalMetrics(a)
	jb, _ := (&pmetric.JSONMarshaler{}).MarshalMetrics(b2)
	if string(ja) != string(jb) {
		t.Errorf("forwarded metrics of the agent:\n%s\nthe agent sends:\n%s", jb, ja)
	}
}

// TestBPFProgramsOfTheAgent: the run counts and times of every BPF program
// of the agent are forwarded.
func TestBPFProgramsOfTheAgent(t *testing.T) {
	b, err := os.ReadFile("../../internal/tracer/bpf_bpfel.go")
	if err != nil {
		t.Fatal(err)
	}
	progs := map[string]bool{}
	for _, m := range regexp.MustCompile("\\*ebpf\\.ProgramSpec\\s+`ebpf:\"(\\w+)\"`").FindAllSubmatch(b, -1) {
		progs[string(m[1])] = true
	}
	if len(progs) == 0 || !maps.Equal(progs, bpfPrograms) {
		t.Errorf("the agent has the programs %v, the connector knows %v", slices.Sorted(maps.Keys(progs)),
			slices.Sorted(maps.Keys(bpfPrograms)))
	}
}

func TestNetNSScope(t *testing.T) {
	for s, want := range map[string]bool{
		"all": true, "4026531840": true, "4294967295": true,
		"": false, "0": false, "04026531840": false, "+1": false, "4294967296": false, "self": false, "all ": false,
	} {
		if netnsScope(s) != want {
			t.Errorf("netnsScope(%q) = %v", s, !want)
		}
	}
}

// TestUnknownDirections: bytes in a direction that agents do not send are
// output as _OTHER, with those of every such direction, as failures of an
// unknown reason are, so that an agent cannot make a series per value.
func TestUnknownDirections(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	request := func(v int64) pmetric.Metrics {
		*now = now.Add(15 * time.Second)
		md := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{{role: roleClient, proto: "tcp",
			local: "10.0.0.11", peer: "1.1.1.1", port: 443, svc: "app", comm: "app", tx: 10, rx: 20, start: t0}}}.metrics()
		// The bytes of the edge in two more directions.
		ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
		for i := range ms.Len() {
			if ms.At(i).Name() != metricNetworkIO {
				continue
			}
			dps := ms.At(i).Sum().DataPoints()
			for j, dir := range []string{"sideways", "up"} {
				dp := dps.AppendEmpty()
				dps.At(0).CopyTo(dp)
				dp.Attributes().PutStr(attrIODirection, dir)
				dp.SetIntValue(int64(j+1) * v)
			}
		}
		return md
	}
	consumeRequest(t, c, sink, request(1))
	out := consumeRequest(t, c, sink, request(5))
	dirs := map[string]float64{}
	for _, s := range out {
		if s.metric == metricNetworkIO {
			dirs[s.dir] += s.value
		}
	}
	if want := map[string]float64{dirTransmit: 10, dirReceive: 20, directionOther: 15}; !maps.Equal(dirs, want) {
		t.Errorf("bytes by direction = %v, want %v", dirs, want)
	}
}

// TestMaxServices: the local services of a host beyond max_services are
// folded into the job ~other, whose peers max_peers bounds as those of one
// service. A service unused for idle_ttl leaves its place to another.
// PostgreSQL keeps every service.
func TestMaxServices(t *testing.T) {
	c, st, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxServices, cfg.MaxPeers = 2, 2 })
	var edges []tEdge
	var rows []endpointRow
	for i := range 6 {
		peer := fmt.Sprintf("10.0.1.%d", i)
		edges = append(edges, tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: peer, port: 5432,
			svc: fmt.Sprintf("svc-%d", i), comm: "app", opened: 1, start: t0})
		rows = append(rows, endpointRow{key: endpointKey{addrOf(peer), 5432, "tcp"},
			endpoint: endpoint{host: "db", service: fmt.Sprintf("db-%d", i)}})
	}
	c.resolver.load(peerRows{endpoints: rows}, *now)
	// jobs returns the connections opened by job and peer.
	jobs := func(edges []tEdge) map[string]map[string]float64 {
		*now = now.Add(15 * time.Second)
		out := map[string]map[string]float64{}
		for _, s := range consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: edges}) {
			if s.metric != metricConnOpened {
				continue
			}
			if out[s.job] == nil {
				out[s.job] = map[string]float64{}
			}
			out[s.job][s.peer] += s.value
		}
		return out
	}
	named := func(jobs map[string]map[string]float64) []string {
		var out []string
		for j, peers := range jobs {
			if j != serviceOther {
				if _, ok := peers["db-"+strings.TrimPrefix(j, "svc-")]; !ok || len(peers) != 1 {
					t.Errorf("peers of %s = %v", j, peers)
				}
				out = append(out, j)
			}
		}
		slices.Sort(out)
		return out
	}

	out := jobs(edges)
	first := named(out)
	other := out[serviceOther]
	total := 0.0
	for _, v := range other {
		total += v
	}
	if len(first) != 2 || len(other) != 3 || other[peerOther] != 2 || total != 4 {
		t.Fatalf("connections by job and peer = %v, want 2 services and 4 folded with 2 of their peers", out)
	}
	c.flush(context.Background())
	if n := len(st.writes[0].processes); n != 6 {
		t.Errorf("%d processes written, want 6", n)
	}

	// The services forwarded under their own job stop; the others take
	// their place once they have not been used for idle_ttl.
	var rest []tEdge
	for _, e := range edges {
		if !slices.Contains(first, e.svc) {
			rest = append(rest, e)
		}
	}
	// The outputs of the services that stopped are sent until idle_ttl.
	others := func(jobs []string) []string {
		return slices.DeleteFunc(jobs, func(j string) bool { return slices.Contains(first, j) })
	}
	for range 15 {
		*now = now.Add(time.Minute - 15*time.Second)
		c.agg.expire(*now)
		if out := jobs(rest); len(others(named(out))) != 0 {
			t.Fatalf("%v took the place of %v before idle_ttl", out, first)
		}
	}
	*now = now.Add(time.Minute)
	c.agg.expire(*now)
	if got := named(jobs(rest)); len(others(slices.Clone(got))) != 2 || len(got) != 2 {
		t.Errorf("services after idle_ttl = %v, before %v", got, first)
	}
}

// TestSlurmJobs: the processes of Slurm jobs, whose units start with
// slurm/, are forwarded under the job slurm-job, whatever their users named
// them, and take one place of max_services; PostgreSQL keeps their names
// (#173).
func TestSlurmJobs(t *testing.T) {
	c, st, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxServices = 3 })
	edge := func(peer, unit, comm, svc, ns string) tEdge {
		return tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: peer, port: 5432,
			unit: unit, comm: comm, svc: svc, ns: ns, exe: "/opt/app/" + comm, opened: 1, start: t0}
	}
	edges := []tEdge{
		edge("10.0.1.1", "slurm/batch", "python3", "python3", ""),
		edge("10.0.1.2", "slurm/step", "vasp_std", "vasp_std", ""),
		edge("10.0.1.3", "slurm/extern", "sshd", "sshd", ""),
		edge("10.0.1.4", "slurm/interactive", "bash", "slurmctld", "hpc"),
		edge("10.0.1.5", "slurmstepd", "slurmstepd", "slurmstepd", ""),
		// A process that is not in a job keeps its name.
		edge("10.0.1.6", "slurmd.service", "slurmd", "slurmd", ""),
	}
	*now = now.Add(15 * time.Second)
	jobs := map[string]float64{}
	for _, s := range consume(t, c, sink, tAgent{host: "node-01", addrs: []string{"10.0.0.11"}, time: *now, edges: edges}) {
		if s.metric == metricConnOpened {
			jobs[s.job] += s.value
		}
	}
	if want := map[string]float64{slurmJobService: 4, "slurmstepd": 1, "slurmd": 1}; !maps.Equal(jobs, want) {
		t.Errorf("connections by job = %v, want %v", jobs, want)
	}
	c.flush(context.Background())
	var got []procKey
	for k := range st.writes[0].processes {
		got = append(got, k)
	}
	slices.SortFunc(got, func(a, b procKey) int { return strings.Compare(a.unit, b.unit) })
	want := []procKey{{"slurm/batch", "python3", "python3"}, {"slurm/extern", "sshd", "sshd"},
		{"slurm/interactive", "bash", "hpc/slurmctld"}, {"slurm/step", "vasp_std", "vasp_std"},
		{"slurmd.service", "slurmd", "slurmd"}, {"slurmstepd", "slurmstepd", "slurmstepd"}}
	if !slices.Equal(got, want) {
		t.Errorf("processes written = %v, want %v", got, want)
	}
}

// TestLongLabelsCut: the names of services and namespaces, host names, host
// ids and versions of agents that are forwarded are cut to 255 bytes, at
// the start of a character, and names of peers to twice that; PostgreSQL
// keeps them whole.
func TestLongLabelsCut(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	long := func(n int) string { return strings.Repeat("é", n) } // 2 bytes each
	svc, ns, host, id := long(500), long(300), "h"+long(300), long(300)
	c.resolver.load(peerRows{endpoints: []endpointRow{{key: endpointKey{addrOf("10.0.0.10"), 5432, "tcp"},
		endpoint: endpoint{host: "db", service: long(400) + "/" + long(400), exact: true}}}}, *now)
	*now = now.Add(15 * time.Second)
	md := tAgent{host: host, machineID: id, addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{{role: roleClient,
		proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: svc, ns: ns, comm: "app", opened: 1}}}.metrics()
	md.ResourceMetrics().At(0).Resource().Attributes().PutStr(attrServiceVersion, long(300))
	out := consumeRequest(t, c, sink, md)
	if s := find(out, metricConnOpened, long(127)+"/"+long(127), long(255), roleClient, ""); len(s) != 1 ||
		s[0].instance != "h"+long(127) {
		t.Errorf("outputs = %v", out)
	}
	rms := sink.AllMetrics()[0].ResourceMetrics()
	for i := range rms.Len() {
		for k, v := range rms.At(i).Resource().Attributes().All() {
			want := map[string]string{attrServiceName: long(127), attrServiceNS: long(127), attrServiceInstanceID: "h" + long(127),
				attrHostName: "h" + long(127), attrHostID: long(127), attrServiceVersion: long(127)}[k]
			if s := v.Str(); s != agentServiceName && s != want {
				t.Errorf("%s = %q (%d bytes, valid UTF-8 %v)", k, s, len(s), utf8.ValidString(s))
			}
		}
	}
	c.flush(context.Background())
	h := st.writes[0]
	if _, ok := h.processes[procKey{"", "app", ns + "/" + svc}]; !ok || h.hostname != host || h.machineID != id ||
		h.version != long(300) {
		t.Errorf("written %q %q %q %v", h.hostname, h.machineID, h.version, slices.Collect(maps.Keys(h.processes)))
	}
}
