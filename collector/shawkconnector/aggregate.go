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

// inputState is the latest point of an input series.
type inputState struct {
	start pcommon.Timestamp
	time  pcommon.Timestamp
	value float64
	count uint64
	seen  time.Time // by the clock of the connector
}

// svcKey identifies the local service of an output resource on a host.
type svcKey struct {
	service, svcNS string
}

// hostOutputs are the output resources of a host.
type hostOutputs struct {
	machineID, hostname string
	resources           map[svcKey]*outResource
	// emitted is the time of the latest request whose outputs were emitted,
	// by the clock of the agent.
	emitted time.Time
}

type outResource struct {
	series map[outKey]*outSeries
}

// outKey identifies an output series within its resource.
type outKey struct {
	metric    string
	dir       string
	peer      string // service.peer.name
	peerAgent bool   // shawk.peer.agent
	role      string
	transport string
	port      uint16
	peerAddr  string // with keep_peer_address
}

type outSeries struct {
	start time.Time // by the clock of the agent, like the points
	value float64
	count uint64
	seen  time.Time
	// gauge holds the current value of each input of a gauge since the
	// outputs of the host were last emitted.
	gauge map[inputKey]float64
}

type peerGroup struct {
	host, service, svcNS, role string
}

// aggregator sums the cumulative input series of edges into output series
// without addresses. It keeps the last point of every input series and
// adds the difference to the output, so that an output series never
// decreases when one of its inputs disappears.
//
// An agent may send an interval in several requests; the last one carries
// the metrics of the agent. The outputs of a host are emitted when that
// request arrives, once per interval, so that a series is never emitted
// twice with the same timestamp.
type aggregator struct {
	ttl          time.Duration
	maxPeers     int
	keepPeerAddr bool
	// started is when the connector started. An input series that started
	// before it was counted by an earlier instance; its first value is a
	// baseline rather than an increase.
	started time.Time

	inputs map[inputKey]*inputState
	hosts  map[string]*hostOutputs
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
		hosts:        map[string]*hostOutputs{},
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

// add accounts a request of a host received at now. If the request closes
// an interval, it appends to out every live output series of the host and
// the metrics of the agent.
func (a *aggregator) add(b *hostBatch, peerOf func(*edgeID) peer, now time.Time, out pmetric.Metrics) {
	ts := b.time
	if ts.IsZero() {
		ts = now
	}
	// The start of the connector by the clock of the agent.
	started := a.started.Add(-now.Sub(ts))

	h := a.hosts[b.key]
	if h == nil {
		h = &hostOutputs{resources: map[svcKey]*outResource{}}
		a.hosts[b.key] = h
	}
	h.machineID, h.hostname = b.machineID, b.hostname

	for _, e := range b.edges {
		sk := svcKey{service: e.id.service, svcNS: e.id.svcNS}
		r := h.resources[sk]
		if r == nil {
			r = &outResource{series: map[outKey]*outSeries{}}
			h.resources[sk] = r
		}
		p := peerOf(&e.id)
		name := a.peer(peerGroup{b.key, e.id.service, e.id.svcNS, e.id.role}, p.name, now)
		for vk, pt := range e.values {
			m, ok := outMetrics[vk.metric]
			if !ok {
				continue
			}
			ik := inputKey{b.key, e.id, vk}
			dv, dc, fresh := a.delta(ik, pt, started, now)
			if !fresh {
				continue
			}
			key := outKey{metric: vk.metric, dir: vk.dir, peer: name, peerAgent: p.agent, role: e.id.role,
				transport: e.id.proto, port: e.id.port}
			if a.keepPeerAddr {
				key.peerAddr = e.id.peer.String()
			}
			s := r.series[key]
			if s == nil {
				start := pt.start.AsTime()
				if start.Before(started) || start.After(ts) {
					start = started
				}
				s = &outSeries{start: start}
				r.series[key] = s
			}
			s.seen = now
			if m.gauge {
				if s.gauge == nil {
					s.gauge = map[inputKey]float64{}
				}
				s.gauge[ik] = pt.value
				continue
			}
			s.value += dv
			s.count += dc
		}
	}

	// Emit once per interval, and never a request older than one emitted.
	if !b.final || !ts.After(h.emitted) {
		return
	}
	h.emitted = ts
	for sk, r := range h.resources {
		a.expireSeries(r, now)
		if len(r.series) == 0 {
			delete(h.resources, sk)
			continue
		}
		r.appendTo(sk, h, ts, out)
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

// delta returns how much an input series increased since its last point,
// and whether the point is newer than that one. A point that is not newer
// (a request that arrived late or twice) changes nothing. started is the
// start of the connector by the clock of the agent.
func (a *aggregator) delta(k inputKey, p point, started, now time.Time) (float64, uint64, bool) {
	in := a.inputs[k]
	if in == nil {
		a.inputs[k] = &inputState{start: p.start, time: p.time, value: p.value, count: p.count, seen: now}
		if p.start.AsTime().Before(started) {
			return 0, 0, true
		}
		return p.value, p.count, true
	}
	switch {
	case p.start < in.start:
		// A late point of a series that has restarted since.
		return 0, 0, false
	case p.start == in.start && p.time <= in.time:
		return 0, 0, false
	}
	var dv float64
	var dc uint64
	if p.start != in.start || p.value < in.value || p.count < in.count {
		// The series restarted, e.g. the agent restarted or dropped the
		// series after its idle TTL and saw it again.
		dv, dc = p.value, p.count
	} else {
		dv, dc = p.value-in.value, p.count-in.count
	}
	in.start, in.time, in.value, in.count, in.seen = p.start, p.time, p.value, p.count, now
	return dv, dc, true
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
	for host, h := range a.hosts {
		for sk, r := range h.resources {
			a.expireSeries(r, now)
			if len(r.series) == 0 {
				delete(h.resources, sk)
			}
		}
		if len(h.resources) == 0 {
			delete(a.hosts, host)
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

// appendTo appends the series of a resource at ts to out. The value of a
// gauge is the sum of its inputs since the last emission.
func (r *outResource) appendTo(k svcKey, h *hostOutputs, ts time.Time, out pmetric.Metrics) {
	rm := out.ResourceMetrics().AppendEmpty()
	attrs := rm.Resource().Attributes()
	// Prometheus makes the job label from service.namespace/service.name and
	// the instance label from service.instance.id.
	attrs.PutStr(attrServiceName, k.service)
	if k.svcNS != "" {
		attrs.PutStr(attrServiceNS, k.svcNS)
	}
	putHostAttrs(attrs, h.machineID, h.hostname)
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
			if desc.gauge {
				s.value = 0
				for _, v := range s.gauge {
					s.value += v
				}
				clear(s.gauge)
			}
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
			dpAttrs.PutBool(attrPeerAgent, key.peerAgent)
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
