package shawkconnector

import (
	"context"
	"net/netip"
	"strconv"
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
// An edge of proto unix has path, the name of the socket, rather than
// addresses and a port, and its connections only.
type tEdge struct {
	role, proto, local, peer string
	path                     string
	port                     int64
	svc, ns, unit, comm, exe string
	containerID              string
	// user is the process.user.id, not sent if empty.
	user                  string
	start, first, last    time.Time
	opened, failed, count int64
	tx, rx, retrans       int64
	rttSum                float64
	rttCount              uint64
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
	path                     string // of a listener of proto unix, which has no address and port
	netns                    string // 4026531840 if empty
	port                     int64
	svc, ns, unit, comm, exe string
	user                     string // process.user.id, not sent if empty
	kernelChosen             bool   // shawk.port.kernel_chosen, sent only if true
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
	noUDP bool
	// unixTraced is sent as shawk.agent.unix.traced if not nil.
	unixTraced *bool
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

// putUser sends process.user.id, if user is not empty.
func putUser(a pcommon.Map, user string) {
	if user == "" {
		return
	}
	uid, err := strconv.ParseInt(user, 10, 64)
	if err != nil {
		panic(err)
	}
	a.PutInt(attrUserID, uid)
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
			putUser(a, e.user)
			a.PutStr(attrRole, e.role)
			a.PutStr(attrTransport, e.proto)
			if e.proto == transportUnix {
				a.PutStr(attrServerAddr, e.path)
			} else {
				a.PutStr(attrLocalAddr, e.local)
				a.PutStr(attrPeerAddr, e.peer)
				a.PutInt(attrServerPort, e.port)
			}
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
		reasons := func() {
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
		}
		switch e.proto {
		case transportUnix:
			sum(metricConnOpened, e.opened, "")
			sum(metricConnFailed, e.failed, "")
			sum(metricConnCount, e.count, "")
			reasons()
		case "tcp":
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
			reasons()
		default:
			sum(metricUDPDatagrams, 1, "transmit")
			sum(metricUDPDatagrams, 1, "receive")
		}
		if e.proto != transportUnix {
			sum(metricNetworkIO, e.tx, "transmit")
			sum(metricNetworkIO, e.rx, "receive")
		}
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
			putUser(dp.Attributes(), l.user)
			dp.Attributes().PutStr(attrTransport, l.proto)
			if l.proto == transportUnix {
				dp.Attributes().PutStr(attrServerAddr, l.path)
			} else {
				dp.Attributes().PutStr(attrLocalAddr, l.addr)
				dp.Attributes().PutInt(attrServerPort, l.port)
			}
			netns := l.netns
			if netns == "" {
				netns = "4026531840"
			}
			dp.Attributes().PutStr(attrNetNS, netns)
			if l.kernelChosen {
				dp.Attributes().PutBool(attrKernelChosen, true)
			}
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
	if ta.unixTraced != nil {
		dp := metric(metricAgentUnixTraced, pmetric.MetricTypeGauge).Gauge().DataPoints().AppendEmpty()
		dp.SetTimestamp(now)
		if *ta.unixTraced {
			dp.SetIntValue(1)
		}
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
	// behind is how many versions the schema is behind the connector.
	behind  int
	cidrs   []namedPrefix
	ports   *portRules
	trans   []translation
	refresh int
	// ruleKeys replaces the rules of ports read back when not nil.
	ruleKeys []string
	// inv is the inventory written, invSyncs how many times it was
	// written, and invFailed the failures recorded.
	inv       *inventory
	invSyncs  int
	invFailed []string
	invErr    error
	// nodeStates are the times of the states written, nodes the latest
	// states and windows the latest maintenance windows.
	nodeStates  []time.Time
	nodes       []nodeState
	windowSyncs int
	windows     []maintenanceWindow
	// hold, when not nil, is called by write before it writes, outside the
	// lock: it may block, and the error it returns fails the write.
	hold func(*hostChanges) error
}

func (s *fakeStore) schemaVersion(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SchemaVersion() - s.behind, nil
}

func (s *fakeStore) syncConfig(_ context.Context, cidrs []namedPrefix, ts []translation, ports *portRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cidrs, s.trans, s.ports = cidrs, ts, ports
	return nil
}

func (s *fakeStore) portRuleKeys(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ruleKeys != nil {
		return s.ruleKeys, nil
	}
	return s.ports.keys(), nil
}

func (s *fakeStore) syncInventory(_ context.Context, inv *inventory, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invErr != nil {
		return s.invErr
	}
	s.inv = inv
	s.invSyncs++
	return nil
}

func (s *fakeStore) inventoryFailed(_ context.Context, _ time.Time, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invFailed = append(s.invFailed, msg)
	return nil
}

func (s *fakeStore) inventory(context.Context) (*inventory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inv, nil
}

func (s *fakeStore) writeNodeStates(_ context.Context, at time.Time, nodes []nodeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errFake
	}
	s.nodeStates = append(s.nodeStates, at)
	s.nodes = nodes
	return nil
}

func (s *fakeStore) syncMaintenance(_ context.Context, windows []maintenanceWindow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errFake
	}
	s.windowSyncs++
	s.windows = windows
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
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		if err := hold(h); err != nil {
			return err
		}
	}
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

func (s *fakeStore) peers(context.Context, time.Duration, time.Duration) (peerRows, error) {
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
	transport                              string
	errType                                string
	peerHost                               string // shawk.peer.host
	localNet, peerNet                      string // shawk.local.network, shawk.peer.network
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
						agent: agent.Bool(), errType: getString(a, attrErrorType), peerHost: getString(a, attrPeerHost),
						localNet: getString(a, attrLocalNetwork), peerNet: getString(a, attrPeerNetwork),
						role: getString(a, attrRole), dir: getString(a, attrIODirection), port: port, value: v, count: c,
						transport: getString(a, attrTransport)})
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

// pointTimes returns the timestamps of the data points the sink received.
func pointTimes(sink *consumertest.MetricsSink) []pcommon.Timestamp {
	var out []pcommon.Timestamp
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					m := ms.At(k)
					switch m.Type() {
					case pmetric.MetricTypeSum:
						for l := range m.Sum().DataPoints().Len() {
							out = append(out, m.Sum().DataPoints().At(l).Timestamp())
						}
					case pmetric.MetricTypeGauge:
						for l := range m.Gauge().DataPoints().Len() {
							out = append(out, m.Gauge().DataPoints().At(l).Timestamp())
						}
					case pmetric.MetricTypeHistogram:
						for l := range m.Histogram().DataPoints().Len() {
							out = append(out, m.Histogram().DataPoints().At(l).Timestamp())
						}
					}
				}
			}
		}
	}
	return out
}

func opened(t *testing.T, out []series, job, peer, role string) float64 {
	t.Helper()
	s := find(out, metricConnOpened, job, peer, role, "")
	if len(s) != 1 {
		t.Fatalf("connection.opened of %s to %s = %v", job, peer, s)
	}
	return s[0].value
}
