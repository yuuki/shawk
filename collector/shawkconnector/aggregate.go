package shawkconnector

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// outMetric describes an output metric.
type outMetric struct {
	unit string
	// gauge is true for shawk.connection.count, a non-monotonic sum whose
	// output is the sum of the current values of its inputs.
	gauge     bool
	histogram bool
}

// outMetrics are the metrics aggregated and forwarded.
var outMetrics = map[string]outMetric{
	metricConnOpened:   {unit: "{connection}"},
	metricConnFailed:   {unit: "{connection}"},
	metricConnCount:    {unit: "{connection}", gauge: true},
	metricNetworkIO:    {unit: "By"},
	metricUDPDatagrams: {unit: "{datagram}"},
	metricRetransmits:  {unit: "{segment}"},
	metricRTT:          {unit: "s", histogram: true},
}

// outMetricOrder is the order of the metrics in the output.
var outMetricOrder = []string{
	metricConnOpened, metricConnFailed, metricConnCount, metricNetworkIO,
	metricUDPDatagrams, metricRetransmits, metricRTT,
}

type inputKey struct {
	host  string
	edge  edgeID
	value valueKey
}

type inputState struct {
	start pcommon.Timestamp
	value float64
	count uint64
	seen  time.Time
}

// outResKey identifies an output resource: a local service on a host.
type outResKey struct {
	host           string
	service, svcNS string
}

type outResource struct {
	machineID, hostname string
	series              map[outKey]*outSeries
}

// outKey identifies an output series within its resource.
type outKey struct {
	metric    string
	dir       string
	peer      string // service.peer.name
	role      string
	transport string
	port      uint16
	peerAddr  string // with keep_peer_address
}

type outSeries struct {
	start time.Time
	value float64
	count uint64
	seen  time.Time
}

type peerGroup struct {
	host, service, svcNS, role string
}

// aggregator sums the cumulative input series of edges into output series
// without addresses. It keeps the last value of every input series and
// adds the difference to the output, so that an output series never
// decreases when one of its inputs disappears.
type aggregator struct {
	ttl          time.Duration
	maxPeers     int
	keepPeerAddr bool
	// started is when the connector started. An input series that started
	// before it was counted by an earlier instance; its first value is a
	// baseline rather than an increase.
	started time.Time

	inputs  map[inputKey]*inputState
	outputs map[outResKey]*outResource
	// peers are the values of service.peer.name in use per group, with
	// when they were last used.
	peers map[peerGroup]map[string]time.Time
}

func newAggregator(ttl time.Duration, maxPeers int, keepPeerAddr bool, started time.Time) *aggregator {
	return &aggregator{
		ttl:          ttl,
		maxPeers:     maxPeers,
		keepPeerAddr: keepPeerAddr,
		started:      started,
		inputs:       map[inputKey]*inputState{},
		outputs:      map[outResKey]*outResource{},
		peers:        map[peerGroup]map[string]time.Time{},
	}
}

// peer returns the value of service.peer.name to use, folding peers beyond
// max_peers into ~other.
func (a *aggregator) peer(g peerGroup, name string, now time.Time) string {
	m := a.peers[g]
	if m == nil {
		m = map[string]time.Time{}
		a.peers[g] = m
	}
	if _, ok := m[name]; !ok && len(m) >= a.maxPeers {
		return peerOther
	}
	m[name] = now
	return name
}

// add accounts the request of a host and appends the output of the host to
// out: every live output series of the host, and the agent's own metrics.
func (a *aggregator) add(b *hostBatch, peerName func(*edgeID) string, now time.Time, out pmetric.Metrics) {
	ts := b.time
	if ts.IsZero() {
		ts = now
	}
	// The open connections are those of this request only.
	for k, r := range a.outputs {
		if k.host != b.key {
			continue
		}
		for ok, s := range r.series {
			if outMetrics[ok.metric].gauge {
				s.value = 0
			}
		}
	}

	for _, e := range b.edges {
		rk := outResKey{host: b.key, service: e.id.service, svcNS: e.id.svcNS}
		r := a.outputs[rk]
		if r == nil {
			r = &outResource{series: map[outKey]*outSeries{}}
			a.outputs[rk] = r
		}
		r.machineID, r.hostname = b.machineID, b.hostname
		peer := a.peer(peerGroup{b.key, e.id.service, e.id.svcNS, e.id.role}, peerName(&e.id), now)
		for vk, p := range e.values {
			m, ok := outMetrics[vk.metric]
			if !ok {
				continue
			}
			key := outKey{metric: vk.metric, dir: vk.dir, peer: peer, role: e.id.role, transport: e.id.proto, port: e.id.port}
			if a.keepPeerAddr {
				key.peerAddr = e.id.peer.String()
			}
			s := r.series[key]
			if s == nil {
				start := p.start.AsTime()
				if start.Before(a.started) || start.After(ts) {
					start = a.started
				}
				s = &outSeries{start: start}
				r.series[key] = s
			}
			s.seen = now
			if m.gauge {
				s.value += p.value
				continue
			}
			dv, dc := a.delta(inputKey{b.key, e.id, vk}, p, now)
			s.value += dv
			s.count += dc
		}
	}

	for k, r := range a.outputs {
		if k.host != b.key {
			continue
		}
		a.expireSeries(r, now)
		if len(r.series) == 0 {
			delete(a.outputs, k)
			continue
		}
		r.appendTo(k, ts, out)
	}
	if b.agent.Len() > 0 {
		rm := out.ResourceMetrics().AppendEmpty()
		attrs := rm.Resource().Attributes()
		attrs.PutStr(attrServiceName, agentServiceName)
		if b.agentVersion != "" {
			attrs.PutStr(attrServiceVersion, b.agentVersion)
		}
		putHostAttrs(attrs, b.machineID, b.hostname)
		sm := rm.ScopeMetrics().AppendEmpty()
		sm.Scope().SetName(scopeName)
		b.agent.MoveAndAppendTo(sm.Metrics())
	}
}

// delta returns how much an input series increased since its last value.
func (a *aggregator) delta(k inputKey, p point, now time.Time) (float64, uint64) {
	in := a.inputs[k]
	if in == nil {
		in = &inputState{start: p.start, value: p.value, count: p.count, seen: now}
		a.inputs[k] = in
		if p.start.AsTime().Before(a.started) {
			return 0, 0
		}
		return p.value, p.count
	}
	in.seen = now
	var dv float64
	var dc uint64
	if p.start != in.start || p.value < in.value || p.count < in.count {
		// The series restarted, e.g. the agent restarted or dropped the
		// series after its idle TTL and saw it again.
		dv, dc = p.value, p.count
	} else {
		dv, dc = p.value-in.value, p.count-in.count
	}
	in.start, in.value, in.count = p.start, p.value, p.count
	return dv, dc
}

func (a *aggregator) expireSeries(r *outResource, now time.Time) {
	for k, s := range r.series {
		if now.Sub(s.seen) > a.ttl {
			delete(r.series, k)
		}
	}
}

// expire drops the state of inputs, outputs and peers unused for the TTL,
// including those of hosts that stopped sending.
func (a *aggregator) expire(now time.Time) {
	for k, in := range a.inputs {
		if now.Sub(in.seen) > a.ttl {
			delete(a.inputs, k)
		}
	}
	for k, r := range a.outputs {
		a.expireSeries(r, now)
		if len(r.series) == 0 {
			delete(a.outputs, k)
		}
	}
	for g, m := range a.peers {
		for p, t := range m {
			if now.Sub(t) > a.ttl {
				delete(m, p)
			}
		}
		if len(m) == 0 {
			delete(a.peers, g)
		}
	}
}

func putHostAttrs(attrs pcommon.Map, machineID, hostname string) {
	attrs.PutStr(attrServiceInstanceID, hostname)
	if machineID != "" {
		attrs.PutStr(attrHostID, machineID)
	}
	attrs.PutStr(attrHostName, hostname)
}

// appendTo appends the series of a resource at ts to out.
func (r *outResource) appendTo(k outResKey, ts time.Time, out pmetric.Metrics) {
	rm := out.ResourceMetrics().AppendEmpty()
	attrs := rm.Resource().Attributes()
	// Prometheus makes the job label from service.namespace/service.name and
	// the instance label from service.instance.id.
	attrs.PutStr(attrServiceName, k.service)
	if k.svcNS != "" {
		attrs.PutStr(attrServiceNS, k.svcNS)
	}
	putHostAttrs(attrs, r.machineID, r.hostname)
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(scopeName)

	now := pcommon.NewTimestampFromTime(ts)
	metrics := map[string]pmetric.Metric{}
	for _, name := range outMetricOrder {
		for key, s := range r.series {
			if key.metric != name {
				continue
			}
			desc := outMetrics[name]
			m, ok := metrics[name]
			if !ok {
				m = sm.Metrics().AppendEmpty()
				m.SetName(name)
				m.SetUnit(desc.unit)
				switch {
				case desc.histogram:
					m.SetEmptyHistogram().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				default:
					sum := m.SetEmptySum()
					sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
					sum.SetIsMonotonic(!desc.gauge)
				}
				metrics[name] = m
			}
			var dpAttrs pcommon.Map
			start := pcommon.NewTimestampFromTime(s.start)
			if desc.histogram {
				dp := m.Histogram().DataPoints().AppendEmpty()
				dp.SetStartTimestamp(start)
				dp.SetTimestamp(now)
				dp.SetCount(s.count)
				dp.SetSum(s.value)
				dp.BucketCounts().FromRaw([]uint64{s.count})
				dpAttrs = dp.Attributes()
			} else {
				dp := m.Sum().DataPoints().AppendEmpty()
				dp.SetStartTimestamp(start)
				dp.SetTimestamp(now)
				dp.SetIntValue(int64(s.value))
				dpAttrs = dp.Attributes()
			}
			dpAttrs.PutStr(attrPeerService, key.peer)
			dpAttrs.PutStr(attrRole, key.role)
			dpAttrs.PutInt(attrServerPort, int64(key.port))
			dpAttrs.PutStr(attrTransport, key.transport)
			if key.dir != "" {
				dpAttrs.PutStr(attrIODirection, key.dir)
			}
			if key.peerAddr != "" {
				dpAttrs.PutStr(attrPeerAddr, key.peerAddr)
			}
		}
	}
}
