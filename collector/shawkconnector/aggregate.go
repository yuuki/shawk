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
	gauge bool
	// histogram is true for a histogram without buckets, whose sum and
	// count give the mean.
	histogram bool
	// sparse is true for a metric whose inputs are sent from their first
	// increase only, the failures by reason: an output series is created
	// at its first increase, emits 0 the first time, and the increase from
	// the next interval on, since rate() and increase() of Prometheus take
	// the first sample of a series as its start. Other outputs start with
	// their edge, when the increases of a dependency that is new are rarely
	// what matters.
	sparse bool
}

// outMetrics are the metrics aggregated and forwarded.
var outMetrics = map[string]outMetric{
	metricConnOpened:         {unit: "{connection}"},
	metricConnFailed:         {unit: "{connection}"},
	metricConnCount:          {unit: "{connection}", gauge: true},
	metricNetworkIO:          {unit: "By"},
	metricUDPDatagrams:       {unit: "{datagram}"},
	metricRetransmits:        {unit: "{segment}"},
	metricRTT:                {unit: "s", histogram: true},
	metricHandshake:          {unit: "s", histogram: true},
	metricSynRetransmits:     {unit: "{segment}"},
	metricConnFailedByReason: {unit: "{connection}", sparse: true},
}

// outMetricOrder is the order of the metrics in the output.
var outMetricOrder = []string{
	metricConnOpened, metricConnFailed, metricConnCount, metricNetworkIO,
	metricUDPDatagrams, metricRetransmits, metricRTT, metricHandshake,
	metricSynRetransmits, metricConnFailedByReason,
}

// inputKey identifies an input series within its host.
type inputKey struct {
	edge  edgeID
	value valueKey
}

// inputState is the latest point of an input series.
type inputState struct {
	start   pcommon.Timestamp
	time    pcommon.Timestamp
	value   float64
	count   uint64
	buckets []uint64
	seen    time.Time // by the clock of the connector
	// rebase tells that the clock of the agent went back: the next point is
	// a new baseline, whatever its time.
	rebase bool
}

// svcKey identifies the local service of an output resource on a host.
type svcKey struct {
	service, svcNS string
}

// hostOutputs are the input and output series of a host.
type hostOutputs struct {
	machineID, hostname string
	inputs              map[inputKey]*inputState
	resources           map[svcKey]*outResource
	// services are the local services forwarded under their own job, with
	// when they were last used: at most max_services.
	services map[svcKey]time.Time
	// latest is the time of the newest request of the host, and emitted the
	// time of the latest request whose outputs were emitted, which closed an
	// interval, both by the clock of the agent. emitted is zero until the
	// first interval of the host closes here, and after its clock went back.
	latest, emitted time.Time
}

type outResource struct {
	series map[outKey]*outSeries
}

// outKey identifies an output series within its resource.
type outKey struct {
	metric    string
	dir       string
	errType   string // error.type
	peer      string // service.peer.name
	peerAgent bool   // shawk.peer.agent
	role      string
	transport string
	port      uint16
	peerAddr  string // with keep_peer_address
}

type outSeries struct {
	start time.Time // by the clock of the connector
	value float64
	count uint64
	seen  time.Time
	// held is the increase of a sparse series that has not been emitted
	// yet, which emits 0 first; pending tells that it has not.
	held    float64
	pending bool
	// gauge holds the latest value of each input of a gauge, with the time
	// of its point.
	gauge map[inputKey]gaugePoint
}

type gaugePoint struct {
	value float64
	time  pcommon.Timestamp
}

type peerGroup struct {
	host, service, svcNS, role string
}

// clockStepBack is how far the time of a request may be older than the
// newest request of its host before the clock of the agent is taken to have
// gone back. A request can arrive late by an export timeout or so.
const clockStepBack = 2 * time.Minute

// newSeriesWindow bounds how long ago a series seen for the first time may
// have started for its whole value to count, on a host that has not closed
// an interval here yet: about the longest interval of an agent.
const newSeriesWindow = 2 * time.Minute

// aggregator sums the cumulative input series of edges into output series
// without addresses. It keeps the last point of every input series and
// adds the difference to the output, so that an output series never
// decreases when one of its inputs disappears.
//
// An agent may send an interval in several requests; the last one carries
// the metrics of the agent. The outputs of a host are emitted when that
// request arrives, once per interval. Outputs carry the time of the
// connector, so that the clock of a host does not place them out of the
// range a time series database accepts for all the hosts of a batch.
type aggregator struct {
	ttl          time.Duration
	maxPeers     int
	maxServices  int
	keepPeerAddr bool
	// started is when the connector started.
	started time.Time

	hosts map[string]*hostOutputs
	// peers are the values of service.peer.name in use per group, with
	// when they were last used.
	peers map[peerGroup]map[string]time.Time

	// maxInputs bounds the input series of a host (0: unbounded); dropped
	// counts the new ones dropped beyond it, until they are taken.
	maxInputs int
	dropped   int
}

// maxValuesPerEdge is how many input series an edge may have on average
// within the bound of a host: an edge of the agent has at most 15, those of
// TCP clients with the six reasons of failure.
const maxValuesPerEdge = 16

func newAggregator(ttl time.Duration, maxPeers, maxServices int, keepPeerAddr bool, started time.Time) *aggregator {
	return &aggregator{
		ttl:          ttl,
		maxPeers:     maxPeers,
		maxServices:  maxServices,
		keepPeerAddr: keepPeerAddr,
		started:      started,
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

// service returns the local service of the outputs of a process on a
// host: its name and namespace cut to maxLabelValue bytes, slurm-job for
// the processes of Slurm jobs, or ~other for the services beyond
// max_services. PostgreSQL keeps the names of the processes of jobs.
func (a *aggregator) service(h *hostOutputs, p *process, now time.Time) svcKey {
	k := svcKey{service: cutLabel(p.service, maxLabelValue), svcNS: cutLabel(p.svcNS, maxLabelValue)}
	if p.slurmJob() {
		k = svcKey{service: slurmJobService}
	}
	if _, ok := h.services[k]; !ok && len(h.services) >= a.maxServices {
		return svcKey{service: serviceOther}
	}
	h.services[k] = now
	return k
}

// add accounts a request of a host received at now. If the request closes
// an interval, it appends to out every live output series of the host and
// the metrics of the agent.
func (a *aggregator) add(b *hostBatch, peerOf func(*edgeID) peer, now time.Time, out pmetric.Metrics) {
	ts := b.time
	if ts.IsZero() {
		ts = now
	}
	// toConnector converts a time of the agent to the clock of the
	// connector.
	skew := now.Sub(ts)
	toConnector := func(t time.Time) time.Time { return t.Add(skew) }

	h := a.hosts[b.key]
	if h == nil {
		h = &hostOutputs{inputs: map[inputKey]*inputState{}, resources: map[svcKey]*outResource{},
			services: map[svcKey]time.Time{}}
		a.hosts[b.key] = h
	}
	h.machineID, h.hostname = b.machineID, b.hostname
	if !h.latest.IsZero() && ts.Before(h.latest.Add(-clockStepBack)) {
		// The clock of the agent went back, e.g. NTP corrected a clock that
		// was ahead. Points are compared by time, so every input takes its
		// next point as a baseline, and the next interval is emitted.
		for _, in := range h.inputs {
			in.rebase = true
		}
		h.latest, h.emitted = ts, time.Time{}
	}
	if ts.After(h.latest) {
		h.latest = ts
	}

	for _, e := range b.edges {
		sk := a.service(h, &e.id.process, now)
		r := h.resources[sk]
		if r == nil {
			r = &outResource{series: map[outKey]*outSeries{}}
			h.resources[sk] = r
		}
		p := peerOf(&e.id)
		name := a.peer(peerGroup{b.key, sk.service, sk.svcNS, e.id.role}, cutLabel(p.name, maxPeerName), now)
		for vk, pt := range e.values {
			m, ok := outMetrics[vk.metric]
			if !ok {
				continue
			}
			ik := inputKey{e.id, vk}
			dv, dc, fresh := a.delta(h, ik, pt, ts, now)
			if !fresh {
				continue
			}
			// Inputs of unknown reasons or directions keep series of their
			// own, which add up in the output of _OTHER.
			key := outKey{metric: vk.metric, dir: outDirection(vk.dir), errType: outErrorType(vk.errType), peer: name,
				peerAgent: p.agent, role: e.id.role, transport: e.id.proto, port: e.id.port}
			if p.port != 0 {
				// Through a translation, the port of the server.
				key.port = p.port
			}
			if a.keepPeerAddr {
				key.peerAddr = e.id.peerString()
			}
			s := r.series[key]
			if s == nil {
				if m.sparse && dv == 0 {
					continue
				}
				s = &outSeries{start: clampTime(toConnector(pt.start.AsTime()), a.started, now), pending: m.sparse}
				r.series[key] = s
			}
			s.seen = now
			if m.gauge {
				if s.gauge == nil {
					s.gauge = map[inputKey]gaugePoint{}
				}
				s.gauge[ik] = gaugePoint{pt.value, pt.time}
				continue
			}
			if s.pending {
				s.held += dv
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
	interval := pcommon.NewTimestampFromTime(ts)
	for sk, r := range h.resources {
		a.expireSeries(r, now)
		if len(r.series) == 0 {
			delete(h.resources, sk)
			continue
		}
		r.appendTo(sk, h, interval, now, out)
	}
	if b.agent.Len() > 0 {
		rm := out.ResourceMetrics().AppendEmpty()
		attrs := rm.Resource().Attributes()
		attrs.PutStr(attrServiceName, agentServiceName)
		if b.agentVersion != "" {
			attrs.PutStr(attrServiceVersion, cutLabel(b.agentVersion, maxLabelValue))
		}
		putHostAttrs(attrs, b.machineID, b.hostname)
		sm := rm.ScopeMetrics().AppendEmpty()
		sm.Scope().SetName(scopeName)
		restamp(b.agent, toConnector, now)
		b.agent.MoveAndAppendTo(sm.Metrics())
	}
}

// clampTime returns t within [lo, hi].
func clampTime(t, lo, hi time.Time) time.Time {
	if t.Before(lo) {
		return lo
	}
	if t.After(hi) {
		return hi
	}
	return t
}

// restamp moves the points of the metrics of an agent to the clock of the
// connector.
func restamp(ms pmetric.MetricSlice, toConnector func(time.Time) time.Time, now time.Time) {
	t := pcommon.NewTimestampFromTime(now)
	start := func(s pcommon.Timestamp) pcommon.Timestamp {
		if s == 0 {
			return 0
		}
		return pcommon.NewTimestampFromTime(clampTime(toConnector(s.AsTime()), time.Time{}, now))
	}
	for i := range ms.Len() {
		m := ms.At(i)
		switch m.Type() {
		case pmetric.MetricTypeGauge:
			dps := m.Gauge().DataPoints()
			for j := range dps.Len() {
				dps.At(j).SetTimestamp(t)
			}
		case pmetric.MetricTypeSum:
			dps := m.Sum().DataPoints()
			for j := range dps.Len() {
				dp := dps.At(j)
				dp.SetStartTimestamp(start(dp.StartTimestamp()))
				dp.SetTimestamp(t)
			}
		case pmetric.MetricTypeHistogram:
			dps := m.Histogram().DataPoints()
			for j := range dps.Len() {
				dp := dps.At(j)
				dp.SetStartTimestamp(start(dp.StartTimestamp()))
				dp.SetTimestamp(t)
			}
		}
	}
}

// delta returns how much an input series increased since its last point,
// and whether the point is newer than that one. A point that is not newer
// (a request that arrived late or twice) changes nothing. ts is the time of
// the request by the clock of the agent. A new input series beyond
// maxInputs is dropped.
func (a *aggregator) delta(h *hostOutputs, k inputKey, p point, ts, now time.Time) (float64, uint64, bool) {
	in := h.inputs[k]
	if in == nil {
		if a.maxInputs > 0 && len(h.inputs) >= a.maxInputs {
			a.dropped++
			return 0, 0, false
		}
		h.inputs[k] = &inputState{start: p.start, time: p.time, value: p.value, count: p.count, buckets: p.buckets, seen: now}
		if a.isNew(h, p.start.AsTime(), ts, now) {
			return p.value, p.count, true
		}
		return 0, 0, true
	}
	if in.rebase {
		in.start, in.time, in.value, in.count, in.buckets, in.seen, in.rebase = p.start, p.time, p.value, p.count, p.buckets, now, false
		return 0, 0, true
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
	if p.start != in.start || p.value < in.value || p.count < in.count || decreased(p.buckets, in.buckets) {
		// The series restarted, e.g. the agent restarted or dropped the
		// series after its idle TTL and saw it again. A histogram restarts
		// as a whole, so that its buckets never decrease either.
		dv, dc = p.value, p.count
	} else {
		dv, dc = p.value-in.value, p.count-in.count
	}
	in.start, in.time, in.value, in.count, in.buckets, in.seen = p.start, p.time, p.value, p.count, p.buckets, now
	return dv, dc, true
}

// decreased tells whether any of the buckets of a histogram is below its
// previous count.
func decreased(buckets, prev []uint64) bool {
	if len(buckets) != len(prev) {
		return len(prev) > 0
	}
	for i, c := range buckets {
		if c < prev[i] {
			return true
		}
	}
	return false
}

// isNew tells whether the whole value of an input series seen for the first
// time is new: whether the series started after the latest interval of its
// host closed here. Otherwise its value was counted before, by this
// connector before the input expired, by an earlier instance of the
// connector, or by another connector the host was routed to, and its first
// point is a baseline. Before the first interval of a host closes here,
// only series that started within the last interval or so, and after the
// connector started, are new.
func (a *aggregator) isNew(h *hostOutputs, start, ts, now time.Time) bool {
	if start.After(ts) {
		return false
	}
	if !h.emitted.IsZero() {
		return !start.Before(h.emitted)
	}
	started := a.started.Add(-now.Sub(ts)) // by the clock of the agent
	return !start.Before(started) && ts.Sub(start) <= newSeriesWindow
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
	for host, h := range a.hosts {
		for k, in := range h.inputs {
			if now.Sub(in.seen) > a.ttl {
				delete(h.inputs, k)
			}
		}
		for sk, r := range h.resources {
			a.expireSeries(r, now)
			if len(r.series) == 0 {
				delete(h.resources, sk)
			}
		}
		for sk, t := range h.services {
			if now.Sub(t) > a.ttl {
				delete(h.services, sk)
			}
		}
		if len(h.resources) == 0 && len(h.inputs) == 0 && len(h.services) == 0 {
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

// putHostAttrs puts the attributes of a host on a resource, cut to
// maxLabelValue bytes: Prometheus makes labels of them all.
func putHostAttrs(attrs pcommon.Map, machineID, hostname string) {
	hostname = cutLabel(hostname, maxLabelValue)
	attrs.PutStr(attrServiceInstanceID, hostname)
	if machineID != "" {
		attrs.PutStr(attrHostID, cutLabel(machineID, maxLabelValue))
	}
	attrs.PutStr(attrHostName, hostname)
}

// appendTo appends the series of a resource to out at now. The value of a
// gauge is the sum of the values its inputs had in the interval that
// closes, at the time interval by the clock of the agent; values of an
// interval whose last request was lost are left out.
func (r *outResource) appendTo(k svcKey, h *hostOutputs, interval pcommon.Timestamp, now time.Time, out pmetric.Metrics) {
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

	ts := pcommon.NewTimestampFromTime(now)
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
					if v.time == interval {
						s.value += v.value
					}
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
				dp.SetTimestamp(ts)
				dp.SetCount(s.count)
				dp.SetSum(s.value)
				dp.BucketCounts().FromRaw([]uint64{s.count})
				dpAttrs = dp.Attributes()
			} else {
				dp := m.Sum().DataPoints().AppendEmpty()
				dp.SetStartTimestamp(start)
				dp.SetTimestamp(ts)
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
			if key.errType != "" {
				dpAttrs.PutStr(attrErrorType, key.errType)
			}
			if s.pending {
				s.value += s.held
				s.held, s.pending = 0, false
			}
			if key.peerAddr != "" {
				dpAttrs.PutStr(attrPeerAddr, key.peerAddr)
			}
		}
	}
}
