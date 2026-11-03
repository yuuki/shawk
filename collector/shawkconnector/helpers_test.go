package shawkconnector

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// tEdge is an edge in a request built by tAgent, in the format of the agent.
type tEdge struct {
	role, proto, local, peer string
	port                     int64
	svc, ns, unit, comm, exe string
	containerID              string
	start, first, last       time.Time
	opened, failed, count    int64
	tx, rx, retrans          int64
	rttSum                   float64
	rttCount                 uint64
	// folded marks the peer as folded (shawk.peer.folded); peer is then
	// 0.0.0.0 or ::.
	folded bool
	// handshakes are the buckets of shawk.tcp.handshake of a TCP client
	// edge, sent with hsSum and synRetrans when not nil, as agents since
	// the handshakes were measured do; hsBounds replaces its bounds.
	handshakes []uint64
	hsSum      float64
	hsBounds   []float64
	synRetrans int64
	// reasons are sent as shawk.connection.failed.by_reason.
	reasons map[string]tReason
	// netns is the network namespace, 4026531840 if empty.
	netns string
}

// tReason is a reason of failure of an edge: its count since start, t0 if
// zero.
type tReason struct {
	value int64
	start time.Time
}

type tListener struct {
	proto, addr              string
	port                     int64
	svc, ns, unit, comm, exe string
	first, last              time.Time
}

// tTranslation is a translation of addresses the host of an agent made:
// client -> virtual:vport, seen by backend:bport from source (the client
// if empty).
type tTranslation struct {
	proto, client, virtual string
	vport                  int64
	source, backend        string
	bport                  int64
	netns                  string // 4026531840 if empty
	first, last            time.Time
}

type tAgent struct {
	host, machineID string
	addrs           []string
	time            time.Time
	segment         time.Time
	edges           []tEdge
	listeners       []tListener
	translations    []tTranslation
	// partial omits the metrics of the agent: a request of an interval that
	// is not its last.
	partial bool
	// noUDP reports that UDP is not traced; netnsScope defaults to "all".
	noUDP      bool
	netnsScope string
	// dropped is sent as shawk.agent.flows.dropped, counted since
	// droppedSince (t0 if zero), when either is set.
	dropped      int64
	droppedSince time.Time
	// fold and internal are sent as shawk.peer.fold and shawk.peer.internal
	// when set.
	fold     string
	internal []string
}

func putProcess(a pcommon.Map, svc, ns, unit, comm, exe string) {
	a.PutStr(attrServiceName, svc)
	if ns != "" {
		a.PutStr(attrServiceNS, ns)
	}
	if exe != "" {
		a.PutStr(attrExePath, exe)
	}
	a.PutStr(attrCommand, comm)
	a.PutStr(attrUnit, unit)
}

func (ta tAgent) metrics() pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	ra := rm.Resource().Attributes()
	if ta.machineID != "" {
		ra.PutStr(attrHostID, ta.machineID)
	}
	ra.PutStr(attrHostName, ta.host)
	ips := ra.PutEmptySlice(attrHostIP)
	for _, a := range ta.addrs {
		ips.AppendEmpty().SetStr(a)
	}
	ra.PutStr(attrOSVersion, "5.14.0")
	ra.PutStr(attrServiceName, agentServiceName)
	ra.PutStr(attrServiceVersion, "test")
	if ta.fold != "" {
		ra.PutStr(attrPeerFold, ta.fold)
	}
	if ta.internal != nil {
		s := ra.PutEmptySlice(attrPeerInternal)
		for _, p := range ta.internal {
			s.AppendEmpty().SetStr(p)
		}
	}
	ms := rm.ScopeMetrics().AppendEmpty().Metrics()
	now := pcommon.NewTimestampFromTime(ta.time)
	metrics := map[string]pmetric.Metric{}
	metric := func(name string, kind pmetric.MetricType) pmetric.Metric {
		m, ok := metrics[name]
		if !ok {
			m = ms.AppendEmpty()
			m.SetName(name)
			switch kind {
			case pmetric.MetricTypeSum:
				m.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				m.Sum().SetIsMonotonic(name != metricConnCount)
			case pmetric.MetricTypeGauge:
				m.SetEmptyGauge()
			case pmetric.MetricTypeHistogram:
				m.SetEmptyHistogram().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
			}
			metrics[name] = m
		}
		return m
	}
	for _, e := range ta.edges {
		attrs := func(a pcommon.Map) {
			putProcess(a, e.svc, e.ns, e.unit, e.comm, e.exe)
			if e.containerID != "" {
				a.PutStr(attrContainerID, e.containerID)
			}
			a.PutStr(attrRole, e.role)
			a.PutStr(attrTransport, e.proto)
			a.PutStr(attrLocalAddr, e.local)
			a.PutStr(attrPeerAddr, e.peer)
			a.PutInt(attrServerPort, e.port)
			netns := e.netns
			if netns == "" {
				netns = "4026531840"
			}
			a.PutStr(attrNetNS, netns)
			if e.folded {
				a.PutBool(attrPeerFolded, true)
			}
		}
		start := e.start
		if start.IsZero() {
			start = t0
		}
		sum := func(name string, v int64, dir string) {
			dp := metric(name, pmetric.MetricTypeSum).Sum().DataPoints().AppendEmpty()
			attrs(dp.Attributes())
			if dir != "" {
				dp.Attributes().PutStr(attrIODirection, dir)
			}
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
			dp.SetTimestamp(now)
			dp.SetIntValue(v)
		}
		if e.proto == "tcp" {
			sum(metricConnOpened, e.opened, "")
			if e.role == roleClient {
				sum(metricConnFailed, e.failed, "")
			}
			sum(metricConnCount, e.count, "")
			sum(metricRetransmits, e.retrans, "")
			dp := metric(metricRTT, pmetric.MetricTypeHistogram).Histogram().DataPoints().AppendEmpty()
			attrs(dp.Attributes())
			dp.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
			dp.SetTimestamp(now)
			dp.SetSum(e.rttSum)
			dp.SetCount(e.rttCount)
			dp.BucketCounts().FromRaw([]uint64{e.rttCount})
			if e.handshakes != nil {
				dp := metric(metricHandshake, pmetric.MetricTypeHistogram).Histogram().DataPoints().AppendEmpty()
				attrs(dp.Attributes())
				dp.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
				dp.SetTimestamp(now)
				dp.SetSum(e.hsSum)
				var n uint64
				for _, c := range e.handshakes {
					n += c
				}
				dp.SetCount(n)
				dp.BucketCounts().FromRaw(e.handshakes)
				bounds := e.hsBounds
				if bounds == nil {
					bounds = handshakeBounds
				}
				dp.ExplicitBounds().FromRaw(bounds)
				sum(metricSynRetransmits, e.synRetrans, "")
			}
			for r, v := range e.reasons {
				dp := metric(metricConnFailedByReason, pmetric.MetricTypeSum).Sum().DataPoints().AppendEmpty()
				attrs(dp.Attributes())
				dp.Attributes().PutStr(attrErrorType, r)
				rs := v.start
				if rs.IsZero() {
					rs = t0
				}
				dp.SetStartTimestamp(pcommon.NewTimestampFromTime(rs))
				dp.SetTimestamp(now)
				dp.SetIntValue(v.value)
			}
		} else {
			sum(metricUDPDatagrams, 1, "transmit")
			sum(metricUDPDatagrams, 1, "receive")
		}
		sum(metricNetworkIO, e.tx, "transmit")
		sum(metricNetworkIO, e.rx, "receive")
		first, last := e.first, e.last
		if last.IsZero() {
			last = ta.time
		}
		if first.IsZero() {
			first = last
		}
		for name, t := range map[string]time.Time{metricEdgeFirst: first, metricEdgeLast: last} {
			dp := metric(name, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
			attrs(dp.Attributes())
			dp.SetTimestamp(now)
			dp.SetIntValue(t.Unix())
		}
	}
	for _, l := range ta.listeners {
		first, last := l.first, l.last
		if last.IsZero() {
			last = ta.time
		}
		if first.IsZero() {
			first = last
		}
		for name, t := range map[string]time.Time{metricListenerFirst: first, metricListenerLast: last} {
			dp := metric(name, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
			putProcess(dp.Attributes(), l.svc, l.ns, l.unit, l.comm, l.exe)
			dp.Attributes().PutStr(attrTransport, l.proto)
			dp.Attributes().PutStr(attrLocalAddr, l.addr)
			dp.Attributes().PutInt(attrServerPort, l.port)
			dp.Attributes().PutStr(attrNetNS, "4026531840")
			dp.SetTimestamp(now)
			dp.SetIntValue(t.Unix())
		}
	}
	for _, x := range ta.translations {
		first, last := x.first, x.last
		if last.IsZero() {
			last = ta.time
		}
		if first.IsZero() {
			first = last
		}
		source, netns, proto := x.source, x.netns, x.proto
		if source == "" {
			source = x.client
		}
		if netns == "" {
			netns = "4026531840"
		}
		if proto == "" {
			proto = "tcp"
		}
		for name, t := range map[string]time.Time{metricTranslationFirst: first, metricTranslationLast: last} {
			dp := metric(name, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
			a := dp.Attributes()
			a.PutStr(attrTransport, proto)
			a.PutStr(attrNetNS, netns)
			a.PutStr(attrTranslationClient, x.client)
			a.PutStr(attrTranslationVirtual, x.virtual)
			a.PutInt(attrTranslationVirtualPort, x.vport)
			a.PutStr(attrTranslationSource, source)
			a.PutStr(attrTranslationBackend, x.backend)
			a.PutInt(attrTranslationBackendPort, x.bport)
			dp.SetTimestamp(now)
			dp.SetIntValue(t.Unix())
		}
	}
	if ta.partial {
		return md
	}
	up := metric(metricAgentUp, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
	scope := ta.netnsScope
	if scope == "" {
		scope = "all"
	}
	up.Attributes().PutStr(attrNetNSScope, scope)
	up.SetTimestamp(now)
	up.SetIntValue(1)
	udp := metric(metricAgentUDPTraced, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
	udp.SetTimestamp(now)
	if !ta.noUDP {
		udp.SetIntValue(1)
	}
	seg := ta.segment
	if seg.IsZero() {
		seg = t0
	}
	sp := metric(metricAgentSegmentStart, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
	sp.SetTimestamp(now)
	sp.SetIntValue(seg.Unix())
	if ta.dropped != 0 || !ta.droppedSince.IsZero() {
		since := ta.droppedSince
		if since.IsZero() {
			since = t0
		}
		dp := metric(metricAgentFlowsDropped, pmetric.MetricTypeSum).Sum().DataPoints().AppendEmpty()
		dp.SetStartTimestamp(pcommon.NewTimestampFromTime(since))
		dp.SetTimestamp(now)
		dp.SetIntValue(ta.dropped)
	}
	return md
}

// fakeStore records writes in memory.
type fakeStore struct {
	mu       sync.Mutex
	writes   []*hostChanges
	fail     bool
	rows     peerRows
	prunes   int
	err      error
	migrated int
	version  int // of the schema; SchemaVersion() if zero
	cidrs    []namedPrefix
	trans    []translation
	refresh  int
}

func (s *fakeStore) schemaVersion(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version == 0 {
		return SchemaVersion(), nil
	}
	return s.version, nil
}

func (s *fakeStore) syncConfig(_ context.Context, cidrs []namedPrefix, ts []translation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cidrs, s.trans = cidrs, ts
	return nil
}

func (s *fakeStore) refreshDependencies(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh++
	return 0, nil
}

func (s *fakeStore) migrate(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.migrated++
	return nil, nil
}

func (s *fakeStore) write(_ context.Context, h *hostChanges) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errFake
	}
	if s.err != nil {
		return s.err
	}
	s.writes = append(s.writes, h)
	return nil
}

func (s *fakeStore) peers(context.Context, time.Duration) (peerRows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows, nil
}

func (s *fakeStore) prune(context.Context, time.Duration, int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunes++
	return 0, nil
}

func (s *fakeStore) close() {}

type fakeErr struct{}

func (fakeErr) Error() string { return "fake failure" }

var errFake = fakeErr{}

// testConnector returns a started connector with a fake store and a clock
// that the test sets.
func testConnector(t *testing.T, mod func(*Config)) (*shawkConnector, *fakeStore, *consumertest.MetricsSink, *time.Time) {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.WriteInterval = time.Hour // flushes are driven by the test
	sink := new(consumertest.MetricsSink)
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	st := &fakeStore{}
	c.newStore = func(context.Context, string) (store, error) { return st, nil }
	now := t0
	c.now = func() time.Time { return now }
	c.agg.started = t0.Add(-time.Hour)
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown(context.Background()) })
	return c, st, sink, &now
}

// series is an output data point flattened for comparisons.
type series struct {
	job, instance, metric, peer, role, dir string
	errType                                string
	agent                                  bool
	port                                   int64
	value                                  float64
	count                                  uint64
	// buckets are those of a histogram, nil for one without bounds.
	buckets []uint64
}

func flatten(md pmetric.Metrics) []series {
	var out []series
	rms := md.ResourceMetrics()
	for i := range rms.Len() {
		ra := rms.At(i).Resource().Attributes()
		job := getString(ra, attrServiceName)
		if ns := getString(ra, attrServiceNS); ns != "" {
			job = ns + "/" + job
		}
		inst := getString(ra, attrServiceInstanceID)
		sms := rms.At(i).ScopeMetrics()
		for j := range sms.Len() {
			ms := sms.At(j).Metrics()
			for k := range ms.Len() {
				m := ms.At(k)
				add := func(a pcommon.Map, v float64, c uint64) {
					port, _ := getInt(a, attrServerPort)
					agent, _ := a.Get(attrPeerAgent)
					out = append(out, series{job: job, instance: inst, metric: m.Name(), peer: getString(a, attrPeerService),
						agent: agent.Bool(), errType: getString(a, attrErrorType),
						role: getString(a, attrRole), dir: getString(a, attrIODirection), port: port, value: v, count: c})
				}
				switch m.Type() {
				case pmetric.MetricTypeSum:
					for l := range m.Sum().DataPoints().Len() {
						dp := m.Sum().DataPoints().At(l)
						add(dp.Attributes(), numberValue(dp), 0)
					}
				case pmetric.MetricTypeGauge:
					for l := range m.Gauge().DataPoints().Len() {
						dp := m.Gauge().DataPoints().At(l)
						add(dp.Attributes(), numberValue(dp), 0)
					}
				case pmetric.MetricTypeHistogram:
					for l := range m.Histogram().DataPoints().Len() {
						dp := m.Histogram().DataPoints().At(l)
						add(dp.Attributes(), dp.Sum(), dp.Count())
						if dp.ExplicitBounds().Len() > 0 {
							out[len(out)-1].buckets = dp.BucketCounts().AsRaw()
						}
					}
				}
			}
		}
	}
	return out
}

// find returns the data points of the last output that match.
func find(ss []series, metric, job, peer, role, dir string) []series {
	var out []series
	for _, s := range ss {
		if s.metric == metric && s.job == job && (peer == "*" || s.peer == peer) && (role == "*" || s.role == role) && s.dir == dir {
			out = append(out, s)
		}
	}
	return out
}

func consume(t *testing.T, c *shawkConnector, sink *consumertest.MetricsSink, ta tAgent) []series {
	t.Helper()
	sink.Reset()
	if err := c.ConsumeMetrics(context.Background(), ta.metrics()); err != nil {
		t.Fatal(err)
	}
	var out []series
	for _, md := range sink.AllMetrics() {
		out = append(out, flatten(md)...)
	}
	return out
}

func addrOf(s string) netip.Addr { return netip.MustParseAddr(s) }
