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
	start, first, last       time.Time
	opened, failed, count    int64
	tx, rx, retrans          int64
	rttSum                   float64
	rttCount                 uint64
}

type tListener struct {
	proto, addr              string
	port                     int64
	svc, ns, unit, comm, exe string
	first, last              time.Time
}

type tAgent struct {
	host, machineID string
	addrs           []string
	time            time.Time
	segment         time.Time
	edges           []tEdge
	listeners       []tListener
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
			a.PutStr(attrRole, e.role)
			a.PutStr(attrTransport, e.proto)
			a.PutStr(attrLocalAddr, e.local)
			a.PutStr(attrPeerAddr, e.peer)
			a.PutInt(attrServerPort, e.port)
			a.PutStr(attrNetNS, "4026531840")
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
	up := metric(metricAgentUp, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
	up.Attributes().PutStr(attrNetNSScope, "all")
	up.SetTimestamp(now)
	up.SetIntValue(1)
	seg := ta.segment
	if seg.IsZero() {
		seg = t0
	}
	sp := metric(metricAgentSegmentStart, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
	sp.SetTimestamp(now)
	sp.SetIntValue(seg.Unix())
	return md
}

// fakeStore records writes in memory.
type fakeStore struct {
	mu       sync.Mutex
	writes   []*hostChanges
	fail     bool
	rows     peerRows
	prunes   int
	migrated int
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
	s.writes = append(s.writes, h)
	return nil
}

func (s *fakeStore) peers(context.Context) (peerRows, error) {
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
	cfg.WriteInterval = 10 * time.Minute // flushes are driven by the test
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
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
	agent                                  bool
	port                                   int64
	value                                  float64
	count                                  uint64
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
						agent: agent.Bool(),
						role:  getString(a, attrRole), dir: getString(a, attrIODirection), port: port, value: v, count: c})
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
