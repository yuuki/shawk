package shawkconnector

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// process identifies the local process of an edge or a listener.
type process struct {
	unit, comm, exe string
	service, svcNS  string
}

// job is the name of the local service as Prometheus shows it in the job
// label, which is also the service name kept in PostgreSQL.
func (p *process) job() string {
	if p.svcNS == "" {
		return p.service
	}
	return p.svcNS + "/" + p.service
}

// edgeID identifies an input edge series of a host.
type edgeID struct {
	role, proto string
	local, peer netip.Addr
	port        uint16
	netns       uint64
	process
}

// valueKey identifies one of the metrics of an edge.
type valueKey struct {
	metric string
	dir    string // network.io.direction, for bytes and datagrams
}

// point is a cumulative value of an input series.
type point struct {
	start pcommon.Timestamp
	time  pcommon.Timestamp
	value float64
	count uint64 // of a histogram
}

type edgeInput struct {
	id          edgeID
	first, last time.Time
	values      map[valueKey]point
}

type listenerID struct {
	proto string
	addr  netip.Addr
	port  uint16
	netns uint64
	process
}

type listenerInput struct {
	id          listenerID
	first, last time.Time
}

// hostBatch is the content of one request of an agent.
type hostBatch struct {
	key          string // hosts.id
	machineID    string
	hostname     string
	kernel       string
	agentVersion string
	addrs        []netip.Addr
	time         time.Time // of the latest data point

	edges     map[edgeID]*edgeInput
	listeners map[listenerID]*listenerInput

	segmentStart time.Time
	udpTraced    bool
	netnsScope   string
	dropped      int64

	// agent holds the metrics of the agent itself to forward.
	agent pmetric.MetricSlice
	// final tells that the request closes an interval of the agent: it is
	// the last of the requests of the interval, which carries the metrics
	// of the agent.
	final bool
	// invalid counts the data points that could not be decoded.
	invalid int
}

var errNotAgent = errors.New("the resource is not a shawk agent")

// parseResource decodes the metrics of one agent.
func parseResource(rm pmetric.ResourceMetrics) (*hostBatch, error) {
	res := rm.Resource().Attributes()
	if s, _ := res.Get(attrServiceName); s.AsString() != agentServiceName {
		return nil, errNotAgent
	}
	b := &hostBatch{
		machineID:    getString(res, attrHostID),
		hostname:     getString(res, attrHostName),
		kernel:       getString(res, attrOSVersion),
		agentVersion: getString(res, attrServiceVersion),
		edges:        map[edgeID]*edgeInput{},
		listeners:    map[listenerID]*listenerInput{},
		agent:        pmetric.NewMetricSlice(),
	}
	if b.hostname == "" {
		return nil, errors.New("the resource has no host.name")
	}
	b.key = hostKey(b.machineID, b.hostname)
	if v, ok := res.Get(attrHostIP); ok && v.Type() == pcommon.ValueTypeSlice {
		s := v.Slice()
		for i := range s.Len() {
			if a, err := parseAddr(s.At(i).AsString()); err == nil {
				b.addrs = append(b.addrs, a.Unmap())
			}
		}
	}

	sms := rm.ScopeMetrics()
	for i := range sms.Len() {
		ms := sms.At(i).Metrics()
		for j := range ms.Len() {
			b.addMetric(ms.At(j))
		}
	}
	return b, nil
}

func (b *hostBatch) observe(ts pcommon.Timestamp) {
	if t := ts.AsTime(); t.After(b.time) {
		b.time = t
	}
}

func (b *hostBatch) addMetric(m pmetric.Metric) {
	name := m.Name()
	switch name {
	case metricConnOpened, metricConnFailed, metricConnCount, metricNetworkIO, metricUDPDatagrams, metricRetransmits:
		if m.Type() != pmetric.MetricTypeSum {
			b.invalid++
			return
		}
		dps := m.Sum().DataPoints()
		for i := range dps.Len() {
			dp := dps.At(i)
			b.observe(dp.Timestamp())
			e := b.edge(dp.Attributes())
			if e == nil {
				continue
			}
			k := valueKey{metric: name}
			if name == metricNetworkIO || name == metricUDPDatagrams {
				k.dir = getString(dp.Attributes(), attrIODirection)
			}
			e.values[k] = point{start: dp.StartTimestamp(), time: dp.Timestamp(), value: numberValue(dp)}
		}
	case metricRTT:
		if m.Type() != pmetric.MetricTypeHistogram {
			b.invalid++
			return
		}
		dps := m.Histogram().DataPoints()
		for i := range dps.Len() {
			dp := dps.At(i)
			b.observe(dp.Timestamp())
			if e := b.edge(dp.Attributes()); e != nil {
				e.values[valueKey{metric: name}] = point{start: dp.StartTimestamp(), time: dp.Timestamp(),
					value: dp.Sum(), count: dp.Count()}
			}
		}
	case metricEdgeFirst, metricEdgeLast:
		forGauge(b, m, func(dp pmetric.NumberDataPoint, t time.Time) {
			if e := b.edge(dp.Attributes()); e != nil {
				if name == metricEdgeFirst {
					e.first = t
				} else {
					e.last = t
				}
			}
		})
	case metricListenerFirst, metricListenerLast:
		forGauge(b, m, func(dp pmetric.NumberDataPoint, t time.Time) {
			if l := b.listener(dp.Attributes()); l != nil {
				if name == metricListenerFirst {
					l.first = t
				} else {
					l.last = t
				}
			}
		})
	default:
		if !strings.HasPrefix(name, metricAgentPrefix) {
			return
		}
		switch name {
		case metricAgentSegmentStart:
			forGauge(b, m, func(_ pmetric.NumberDataPoint, t time.Time) { b.segmentStart = t })
			return
		case metricAgentUDPTraced:
			forGauge(b, m, func(dp pmetric.NumberDataPoint, _ time.Time) { b.udpTraced = numberValue(dp) != 0 })
		case metricAgentUp:
			b.final = true
			forGauge(b, m, func(dp pmetric.NumberDataPoint, _ time.Time) {
				b.netnsScope = getString(dp.Attributes(), attrNetNSScope)
			})
		case metricAgentFlowsDropped:
			if m.Type() == pmetric.MetricTypeSum && m.Sum().DataPoints().Len() > 0 {
				b.dropped = int64(numberValue(m.Sum().DataPoints().At(0)))
			}
		}
		m.CopyTo(b.agent.AppendEmpty())
	}
}

// forGauge calls f with the data points of a gauge of Unix seconds.
func forGauge(b *hostBatch, m pmetric.Metric, f func(pmetric.NumberDataPoint, time.Time)) {
	if m.Type() != pmetric.MetricTypeGauge {
		b.invalid++
		return
	}
	dps := m.Gauge().DataPoints()
	for i := range dps.Len() {
		dp := dps.At(i)
		b.observe(dp.Timestamp())
		f(dp, time.Unix(int64(numberValue(dp)), 0).UTC())
	}
}

func numberValue(dp pmetric.NumberDataPoint) float64 {
	if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
		return float64(dp.IntValue())
	}
	return dp.DoubleValue()
}

func getString(m pcommon.Map, k string) string {
	if v, ok := m.Get(k); ok {
		return v.AsString()
	}
	return ""
}

func getInt(m pcommon.Map, k string) (int64, bool) {
	v, ok := m.Get(k)
	if !ok {
		return 0, false
	}
	switch v.Type() {
	case pcommon.ValueTypeInt:
		return v.Int(), true
	case pcommon.ValueTypeStr:
		n, err := strconv.ParseInt(v.Str(), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func parseProcess(a pcommon.Map) process {
	p := process{
		unit:    getString(a, attrUnit),
		comm:    getString(a, attrCommand),
		exe:     getString(a, attrExePath),
		service: getString(a, attrServiceName),
	}
	p.svcNS = getString(a, attrServiceNS)
	return p
}

// edge returns the edge of the attributes of a data point, or nil if they
// are invalid.
func (b *hostBatch) edge(a pcommon.Map) *edgeInput {
	role := getString(a, attrRole)
	proto := getString(a, attrTransport)
	local, err1 := parseAddr(getString(a, attrLocalAddr))
	peer, err2 := parseAddr(getString(a, attrPeerAddr))
	port, ok1 := getInt(a, attrServerPort)
	netns, ok2 := getInt(a, attrNetNS)
	if (role != roleClient && role != roleServer) || (proto != "tcp" && proto != "udp") ||
		err1 != nil || err2 != nil || !ok1 || !ok2 || port < 0 || port > 65535 {
		b.invalid++
		return nil
	}
	id := edgeID{role: role, proto: proto, local: local.Unmap(), peer: peer.Unmap(), port: uint16(port),
		netns: uint64(netns), process: parseProcess(a)}
	e, ok := b.edges[id]
	if !ok {
		e = &edgeInput{id: id, values: map[valueKey]point{}}
		b.edges[id] = e
	}
	return e
}

func (b *hostBatch) listener(a pcommon.Map) *listenerInput {
	proto := getString(a, attrTransport)
	addr, err := parseAddr(getString(a, attrLocalAddr))
	port, ok1 := getInt(a, attrServerPort)
	netns, ok2 := getInt(a, attrNetNS)
	if (proto != "tcp" && proto != "udp") || err != nil || !ok1 || !ok2 || port < 0 || port > 65535 {
		b.invalid++
		return nil
	}
	id := listenerID{proto: proto, addr: addr.Unmap(), port: uint16(port), netns: uint64(netns), process: parseProcess(a)}
	l, ok := b.listeners[id]
	if !ok {
		l = &listenerInput{id: id}
		b.listeners[id] = l
	}
	return l
}

// parseAddr parses an address without its IPv6 zone, which PostgreSQL's
// inet does not accept and which does not identify a peer across hosts.
func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return a, err
	}
	return a.WithZone("").Unmap(), nil
}
