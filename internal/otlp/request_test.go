package otlp

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

func attrMap(kvs []*commonpb.KeyValue) map[string]any {
	m := map[string]any{}
	for _, kv := range kvs {
		switch v := kv.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			m[kv.Key] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			m[kv.Key] = v.IntValue
		case *commonpb.AnyValue_ArrayValue:
			var ss []string
			for _, e := range v.ArrayValue.Values {
				ss = append(ss, e.GetStringValue())
			}
			m[kv.Key] = ss
		}
	}
	return m
}

func TestRequest(t *testing.T) {
	s := NewState(15 * time.Minute)
	tcp := clientEdge()
	tcp.ServiceNamespace = "shop"
	udp := EdgeKey{
		Role: RoleServer, Proto: "udp",
		LocalAddr: netip.MustParseAddr("10.0.0.10"), PeerAddr: netip.MustParseAddr("10.0.0.11"),
		Port: 53, NetNS: 1,
		Process: Process{Unit: "named.service", Comm: "named", Exe: "/usr/sbin/named", Service: "named"},
	}
	end := t0.Add(15 * time.Second)
	s.AddEdge(tcp, EdgeStats{Conns: 3, ConnFails: 1, OpenConns: 2, BytesSent: 100, BytesRecv: 200, Retrans: 4,
		RTTSumUs: 1500, RTTSamples: 3}, t0, end)
	s.AddEdge(udp, EdgeStats{MsgsSent: 5, MsgsRecv: 6, BytesSent: 50, BytesRecv: 60}, t0, end)
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080, NetNS: 1,
		Process: tcp.Process}, end)

	res := Resource{
		MachineID: "0123", Hostname: "app-01", Kernel: "5.14.0", AgentVersion: "1.2.3",
		Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")},
	}
	started := t0.Add(-time.Hour)
	req := s.Request(res, AgentStatus{
		Started: started, SegmentStart: started, NetNSScope: "all", UDPTraced: true,
		FlowsDropped: 7, ExportFailures: 2,
	}, end)

	if n := len(req.ResourceMetrics); n != 1 {
		t.Fatalf("%d resources", n)
	}
	rm := req.ResourceMetrics[0]
	ra := attrMap(rm.Resource.Attributes)
	for k, v := range map[string]string{"host.id": "0123", "host.name": "app-01", "os.version": "5.14.0",
		"service.name": "shawk-agent", "service.version": "1.2.3"} {
		if ra[k] != v {
			t.Errorf("resource %s = %v, want %v", k, ra[k], v)
		}
	}
	if ips, _ := ra["host.ip"].([]string); len(ips) != 1 || ips[0] != "10.0.0.11" {
		t.Errorf("host.ip = %v", ra["host.ip"])
	}

	metrics := map[string]*metricspb.Metric{}
	for _, m := range rm.ScopeMetrics[0].Metrics {
		if metrics[m.Name] != nil {
			t.Errorf("metric %s repeated", m.Name)
		}
		metrics[m.Name] = m
	}
	sumPoints := func(name string) []*metricspb.NumberDataPoint {
		m := metrics[name]
		if m == nil {
			t.Fatalf("metric %s missing", name)
		}
		sum := m.GetSum()
		if sum == nil || sum.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
			t.Fatalf("metric %s is not a cumulative sum", name)
		}
		return sum.DataPoints
	}

	opened := sumPoints(MetricConnOpened)
	if len(opened) != 1 || opened[0].GetAsInt() != 3 || opened[0].StartTimeUnixNano != uint64(t0.UnixNano()) ||
		opened[0].TimeUnixNano != uint64(end.UnixNano()) {
		t.Errorf("connection.opened = %v", opened)
	}
	a := attrMap(opened[0].Attributes)
	for k, v := range map[string]any{
		"service.name": "app", "service.namespace": "shop", "process.executable.name": "ruby",
		"process.executable.path": "/usr/bin/ruby", "process.command": "puma", "shawk.unit": "app.service",
		"shawk.role": "client", "network.transport": "tcp", "network.local.address": "10.0.0.11",
		"network.peer.address": "10.0.0.10", "server.port": int64(5432), "shawk.netns": "4026531840",
	} {
		if a[k] != v {
			t.Errorf("edge attribute %s = %v, want %v", k, a[k], v)
		}
	}
	if _, ok := a["process.pid"]; ok {
		t.Error("the PID is an attribute")
	}
	if !metrics[MetricConnOpened].GetSum().IsMonotonic || metrics[MetricConnCount].GetSum().IsMonotonic {
		t.Error("wrong monotonicity")
	}
	if p := sumPoints(MetricConnFailed); len(p) != 1 || p[0].GetAsInt() != 1 {
		t.Errorf("connection.failed = %v", p)
	}
	if p := sumPoints(MetricConnCount); len(p) != 1 || p[0].GetAsInt() != 2 {
		t.Errorf("connection.count = %v", p)
	}
	if p := sumPoints(MetricRetransmits); len(p) != 1 || p[0].GetAsInt() != 4 {
		t.Errorf("tcp.retransmits = %v", p)
	}
	io := map[string]int64{}
	for _, p := range sumPoints(MetricNetworkIO) {
		a := attrMap(p.Attributes)
		io[a["shawk.role"].(string)+"/"+a["network.io.direction"].(string)] = p.GetAsInt()
	}
	if len(io) != 4 || io["client/transmit"] != 100 || io["client/receive"] != 200 ||
		io["server/transmit"] != 50 || io["server/receive"] != 60 {
		t.Errorf("network.io = %v", io)
	}
	dg := sumPoints(MetricUDPDatagrams)
	if len(dg) != 2 {
		t.Errorf("udp.datagrams = %v", dg)
	}
	h := metrics[MetricRTT].GetHistogram().GetDataPoints()
	if len(h) != 1 || h[0].Count != 3 || h[0].GetSum() != 0.0015 || len(h[0].ExplicitBounds) != 0 ||
		len(h[0].BucketCounts) != 1 || h[0].BucketCounts[0] != 3 {
		t.Errorf("tcp.rtt = %v", h)
	}
	for _, name := range []string{MetricEdgeFirst, MetricEdgeLast} {
		g := metrics[name].GetGauge().GetDataPoints()
		if len(g) != 2 || g[0].GetAsInt() != end.Unix() {
			t.Errorf("%s = %v", name, g)
		}
	}
	if g := metrics[MetricListenerLast].GetGauge().GetDataPoints(); len(g) != 1 || attrMap(g[0].Attributes)["server.port"] != int64(8080) {
		t.Errorf("listener.last_seen = %v", g)
	}

	up := metrics[MetricAgentUp].GetGauge().GetDataPoints()
	if len(up) != 1 || up[0].GetAsInt() != 1 || attrMap(up[0].Attributes)["shawk.netns.scope"] != "all" {
		t.Errorf("agent.up = %v", up)
	}
	if g := metrics[MetricAgentSegmentStart].GetGauge().GetDataPoints(); g[0].GetAsInt() != started.Unix() {
		t.Errorf("segment.start = %v", g)
	}
	if g := metrics[MetricAgentUDPTraced].GetGauge().GetDataPoints(); g[0].GetAsInt() != 1 {
		t.Errorf("udp.traced = %v", g)
	}
	if p := sumPoints(MetricAgentFlowsDropped); p[0].GetAsInt() != 7 || p[0].StartTimeUnixNano != uint64(started.UnixNano()) {
		t.Errorf("flows.dropped = %v", p)
	}
	if p := sumPoints(MetricAgentExportFailures); p[0].GetAsInt() != 2 {
		t.Errorf("export.failures = %v", p)
	}
	if metrics[MetricAgentBPFRunCount] != nil {
		t.Error("BPF statistics without programs")
	}
}

func TestRequestWithoutMachineID(t *testing.T) {
	req := NewState(time.Minute).Request(Resource{Hostname: "h"}, AgentStatus{}, t0)
	if _, ok := attrMap(req.ResourceMetrics[0].Resource.Attributes)["host.id"]; ok {
		t.Error("empty host.id sent")
	}
}

func TestRequestsSplit(t *testing.T) {
	s := NewState(15 * time.Minute)
	for i := range 5 {
		k := clientEdge()
		k.Port = uint16(1000 + i)
		s.AddEdge(k, EdgeStats{Conns: 1}, t0, t0)
	}
	for i := range 2 {
		s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: uint16(80 + i)}, t0)
	}
	st := AgentStatus{Started: t0, SegmentStart: t0, NetNSScope: "all"}
	reqs := s.Requests(Resource{Hostname: "h"}, st, t0, 3)
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3", len(reqs))
	}
	edges, listeners := 0, 0
	for i, req := range reqs {
		agent := false
		series := map[string]bool{}
		for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
			switch m.Name {
			case MetricAgentUp:
				agent = true
			case MetricEdgeLast:
				edges += len(m.GetGauge().DataPoints)
				for _, p := range m.GetGauge().DataPoints {
					series[fmt.Sprint(attrMap(p.Attributes)["server.port"])] = true
				}
			case MetricListenerLast:
				listeners += len(m.GetGauge().DataPoints)
				for _, p := range m.GetGauge().DataPoints {
					series[fmt.Sprint(attrMap(p.Attributes)["server.port"])] = true
				}
			}
		}
		if len(series) > 3 {
			t.Errorf("request %d has %d series", i, len(series))
		}
		// Only the last request carries the agent and closes the interval.
		if agent != (i == len(reqs)-1) {
			t.Errorf("request %d: agent metrics %v", i, agent)
		}
		if attrMap(req.ResourceMetrics[0].Resource.Attributes)["host.name"] != "h" {
			t.Errorf("request %d lacks the resource", i)
		}
	}
	if edges != 5 || listeners != 2 {
		t.Errorf("%d edges and %d listeners sent", edges, listeners)
	}
	// Without series there is one request, with the agent.
	if reqs := NewState(time.Minute).Requests(Resource{Hostname: "h"}, st, t0, 3); len(reqs) != 1 {
		t.Errorf("%d requests without series", len(reqs))
	}
}

// Requests stay below the byte limit whatever the size of the attributes,
// and are made of whole series.
func TestRequestsByteLimit(t *testing.T) {
	s := NewState(15 * time.Minute)
	exe := "/" + strings.Repeat("venv/lib/python3.12/site-packages/", 30) + "bin/worker"
	for i := range 1000 {
		k := clientEdge()
		k.LocalAddr = netip.MustParseAddr(fmt.Sprintf("2001:db8:aaaa:bbbb:cccc:dddd:%x:1", i))
		k.PeerAddr = netip.MustParseAddr(fmt.Sprintf("2001:db8:aaaa:bbbb:cccc:eeee:%x:2", i))
		k.Exe = exe
		k.Service = "worker-with-a-long-service-name"
		s.AddEdge(k, EdgeStats{Conns: 1, RTTSamples: 1, RTTSumUs: 100}, t0, t0)
		u := k
		u.Proto = "udp"
		s.AddEdge(u, EdgeStats{MsgsSent: 1}, t0, t0)
	}
	st := AgentStatus{Started: t0, SegmentStart: t0, NetNSScope: "all"}
	var addrs []netip.Addr
	for i := range 300 {
		addrs = append(addrs, netip.MustParseAddr(fmt.Sprintf("fd00::%x", i)))
	}
	reqs := s.Requests(Resource{Hostname: "h", Addrs: addrs}, st, t0, 1000)
	if len(reqs) < 2 {
		t.Fatalf("%d requests", len(reqs))
	}
	edges := 0
	for i, req := range reqs {
		if n := proto.Size(req); n > MaxRequestBytes {
			t.Errorf("request %d has %d bytes, more than %d", i, n, MaxRequestBytes)
		}
		for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
			if m.Name == MetricEdgeLast {
				edges += len(m.GetGauge().DataPoints)
			}
		}
	}
	if edges != 2000 {
		t.Errorf("%d edges sent, want 2000", edges)
	}
}

// Listeners come first and server edges before client edges, so that the
// connector knows the services of the host when it names the peers of
// client edges.
func TestRequestsOrder(t *testing.T) {
	s := NewState(15 * time.Minute)
	c := clientEdge()
	srv := clientEdge()
	srv.Role = RoleServer
	s.AddEdge(c, EdgeStats{Conns: 1}, t0, t0)
	s.AddEdge(srv, EdgeStats{Conns: 1}, t0, t0)
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 6379}, t0)
	reqs := s.Requests(Resource{Hostname: "h"}, AgentStatus{}, t0, 1)
	if len(reqs) != 3 {
		t.Fatalf("%d requests", len(reqs))
	}
	kinds := []string{}
	for _, req := range reqs {
		for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
			switch m.Name {
			case MetricListenerLast:
				kinds = append(kinds, "listener")
			case MetricEdgeLast:
				kinds = append(kinds, fmt.Sprint(attrMap(m.GetGauge().DataPoints[0].Attributes)["shawk.role"]))
			}
		}
	}
	if fmt.Sprint(kinds) != "[listener server client]" {
		t.Errorf("order = %v", kinds)
	}
}

// A command name cut in the middle of a multibyte character is sent as
// valid UTF-8; protobuf refuses to marshal it otherwise.
func TestRequestInvalidUTF8(t *testing.T) {
	s := NewState(15 * time.Minute)
	k := clientEdge()
	k.Comm = "サービスワ\xe3\x83"
	s.AddEdge(k, EdgeStats{Conns: 1}, t0, t0)
	req := s.Request(Resource{Hostname: "h"}, AgentStatus{}, t0)
	if _, err := proto.Marshal(req); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}
