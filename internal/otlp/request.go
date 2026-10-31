package otlp

import (
	"cmp"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// Resource describes the host and the agent.
type Resource struct {
	MachineID    string // host.id; omitted when empty
	Hostname     string
	Addrs        []netip.Addr
	Kernel       string
	AgentVersion string
}

// AgentStatus are the metrics of the agent itself.
type AgentStatus struct {
	// Started is when the agent started; its counters start then.
	Started        time.Time
	SegmentStart   time.Time
	NetNSScope     string // "all" or the inode of the traced namespace
	UDPTraced      bool
	FlowsDropped   uint64 // cumulative
	ExportFailures uint64 // cumulative
	BPFPrograms    []BPFProgram
}

// BPFProgram is the run time statistic of a BPF program.
type BPFProgram struct {
	Name     string
	RunCount uint64
	RunTime  time.Duration
}

// Request builds one request that carries all live series at now.
func (s *State) Request(res Resource, st AgentStatus, now time.Time) *colmetricspb.ExportMetricsServiceRequest {
	return s.Requests(res, st, now, 0)[0]
}

// Requests builds the requests that carry all live series at now, each with
// at most maxSeries edges and listeners (0 means no limit), so that every
// request stays below the size limits of the receiver. The metrics of the
// agent itself are in the last request only: it closes the interval, and
// the connector emits the aggregated metrics of the host when it arrives.
func (s *State) Requests(res Resource, st AgentStatus, now time.Time, maxSeries int) []*colmetricspb.ExportMetricsServiceRequest {
	edges := make([]EdgeKey, 0, len(s.edges))
	for k := range s.edges {
		edges = append(edges, k)
	}
	// A stable order makes requests easy to compare and compress.
	slices.SortFunc(edges, compareEdgeKeys)
	listeners := make([]ListenerKey, 0, len(s.listeners))
	for k := range s.listeners {
		listeners = append(listeners, k)
	}
	slices.SortFunc(listeners, compareListenerKeys)

	total := len(edges) + len(listeners)
	if maxSeries <= 0 || maxSeries > total {
		maxSeries = max(total, 1)
	}
	resource := res.proto()
	var reqs []*colmetricspb.ExportMetricsServiceRequest
	for first := 0; first < total || len(reqs) == 0; first += maxSeries {
		last := min(first+maxSeries, total)
		b := newBuilder(now)
		for i := first; i < last; i++ {
			if i < len(edges) {
				s.addEdge(b, &edges[i])
			} else {
				s.addListener(b, &listeners[i-len(edges)])
			}
		}
		if last == total {
			addAgent(b, &st)
		}
		reqs = append(reqs, &colmetricspb.ExportMetricsServiceRequest{
			ResourceMetrics: []*metricspb.ResourceMetrics{{
				Resource: resource,
				ScopeMetrics: []*metricspb.ScopeMetrics{{
					Scope:   &commonpb.InstrumentationScope{Name: ScopeName, Version: res.AgentVersion},
					Metrics: b.metrics,
				}},
			}},
		})
	}
	return reqs
}

func (s *State) addEdge(b *builder, k *EdgeKey) {
	e := s.edges[*k]
	attrs := edgeAttrs(k)
	start := e.Start
	t := &e.Total
	switch k.Proto {
	case "tcp":
		b.sum(MetricConnOpened, "{connection}", true, start, t.Conns, attrs)
		if k.Role == RoleClient {
			b.sum(MetricConnFailed, "{connection}", true, start, t.ConnFails, attrs)
		}
		b.sum(MetricConnCount, "{connection}", false, start, t.OpenConns, attrs)
		b.sum(MetricRetransmits, "{segment}", true, start, t.Retrans, attrs)
		b.rtt(start, t.RTTSamples, float64(t.RTTSumUs)/1e6, attrs)
	case "udp":
		b.sum(MetricUDPDatagrams, "{datagram}", true, start, t.MsgsSent, with(attrs, AttrIODirection, DirTransmit))
		b.sum(MetricUDPDatagrams, "{datagram}", true, start, t.MsgsRecv, with(attrs, AttrIODirection, DirReceive))
	}
	b.sum(MetricNetworkIO, "By", true, start, t.BytesSent, with(attrs, AttrIODirection, DirTransmit))
	b.sum(MetricNetworkIO, "By", true, start, t.BytesRecv, with(attrs, AttrIODirection, DirReceive))
	b.gauge(MetricEdgeFirst, "s", e.FirstSeen.Unix(), attrs)
	b.gauge(MetricEdgeLast, "s", e.LastSeen.Unix(), attrs)
}

func (s *State) addListener(b *builder, k *ListenerKey) {
	l := s.listeners[*k]
	attrs := listenerAttrs(k)
	b.gauge(MetricListenerFirst, "s", l.FirstSeen.Unix(), attrs)
	b.gauge(MetricListenerLast, "s", l.LastSeen.Unix(), attrs)
}

func addAgent(b *builder, st *AgentStatus) {
	// No unit "1": Prometheus would add the suffix _ratio to the names.
	b.gauge(MetricAgentUp, "", 1, []*commonpb.KeyValue{str(AttrNetNSScope, st.NetNSScope)})
	b.gauge(MetricAgentSegmentStart, "s", st.SegmentStart.Unix(), nil)
	udp := int64(0)
	if st.UDPTraced {
		udp = 1
	}
	b.gauge(MetricAgentUDPTraced, "", udp, nil)
	b.sum(MetricAgentFlowsDropped, "{update}", true, st.Started, st.FlowsDropped, nil)
	b.sum(MetricAgentExportFailures, "{request}", true, st.Started, st.ExportFailures, nil)
	for _, p := range st.BPFPrograms {
		attrs := []*commonpb.KeyValue{str(AttrBPFProgram, p.Name)}
		b.sum(MetricAgentBPFRunCount, "{run}", true, st.Started, p.RunCount, attrs)
		b.sumDouble(MetricAgentBPFRunTime, "s", st.Started, p.RunTime.Seconds(), attrs)
	}
}

func (r *Resource) proto() *resourcepb.Resource {
	var attrs []*commonpb.KeyValue
	if r.MachineID != "" {
		attrs = append(attrs, str(AttrHostID, r.MachineID))
	}
	attrs = append(attrs, str(AttrHostName, r.Hostname))
	ips := make([]*commonpb.AnyValue, 0, len(r.Addrs))
	for _, a := range r.Addrs {
		ips = append(ips, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: a.String()}})
	}
	attrs = append(attrs,
		&commonpb.KeyValue{Key: AttrHostIP, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
			ArrayValue: &commonpb.ArrayValue{Values: ips}}}},
		str(AttrOSVersion, r.Kernel),
		str(AttrServiceName, AgentServiceName),
		str(AttrServiceVersion, r.AgentVersion),
	)
	return &resourcepb.Resource{Attributes: attrs}
}

func processAttrs(p *Process) []*commonpb.KeyValue {
	attrs := []*commonpb.KeyValue{str(AttrServiceName, p.Service)}
	if p.ServiceNamespace != "" {
		attrs = append(attrs, str(AttrServiceNS, p.ServiceNamespace))
	}
	if p.Exe != "" {
		attrs = append(attrs, str(AttrExeName, path.Base(p.Exe)), str(AttrExePath, p.Exe))
	}
	return append(attrs, str(AttrCommand, p.Comm), str(AttrUnit, p.Unit))
}

func edgeAttrs(k *EdgeKey) []*commonpb.KeyValue {
	return append(processAttrs(&k.Process),
		str(AttrRole, k.Role),
		str(AttrTransport, k.Proto),
		str(AttrLocalAddr, k.LocalAddr.String()),
		str(AttrPeerAddr, k.PeerAddr.String()),
		integer(AttrServerPort, int64(k.Port)),
		str(AttrNetNS, strconv.FormatUint(uint64(k.NetNS), 10)),
	)
}

func listenerAttrs(k *ListenerKey) []*commonpb.KeyValue {
	return append(processAttrs(&k.Process),
		str(AttrTransport, k.Proto),
		str(AttrLocalAddr, k.Addr.String()),
		integer(AttrServerPort, int64(k.Port)),
		str(AttrNetNS, strconv.FormatUint(uint64(k.NetNS), 10)),
	)
}

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func integer(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

// with returns attrs with one more attribute, without modifying attrs.
func with(attrs []*commonpb.KeyValue, k, v string) []*commonpb.KeyValue {
	return append(slices.Clip(attrs), str(k, v))
}

// builder collects data points into one metric per name.
type builder struct {
	now     uint64
	metrics []*metricspb.Metric
	byName  map[string]*metricspb.Metric
}

func newBuilder(now time.Time) *builder {
	return &builder{now: nanos(now), byName: map[string]*metricspb.Metric{}}
}

func nanos(t time.Time) uint64 { return uint64(t.UnixNano()) }

func (b *builder) metric(name, unit string, mk func() *metricspb.Metric) *metricspb.Metric {
	m, ok := b.byName[name]
	if !ok {
		m = mk()
		m.Name, m.Unit = name, unit
		b.byName[name] = m
		b.metrics = append(b.metrics, m)
	}
	return m
}

func (b *builder) sum(name, unit string, monotonic bool, start time.Time, v uint64, attrs []*commonpb.KeyValue) {
	m := b.metric(name, unit, func() *metricspb.Metric {
		return &metricspb.Metric{Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			IsMonotonic:            monotonic,
		}}}
	})
	sum := m.GetSum()
	sum.DataPoints = append(sum.DataPoints, &metricspb.NumberDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: nanos(start),
		TimeUnixNano:      b.now,
		Value:             &metricspb.NumberDataPoint_AsInt{AsInt: int64(v)},
	})
}

func (b *builder) sumDouble(name, unit string, start time.Time, v float64, attrs []*commonpb.KeyValue) {
	m := b.metric(name, unit, func() *metricspb.Metric {
		return &metricspb.Metric{Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			IsMonotonic:            true,
		}}}
	})
	sum := m.GetSum()
	sum.DataPoints = append(sum.DataPoints, &metricspb.NumberDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: nanos(start),
		TimeUnixNano:      b.now,
		Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: v},
	})
}

func (b *builder) gauge(name, unit string, v int64, attrs []*commonpb.KeyValue) {
	m := b.metric(name, unit, func() *metricspb.Metric {
		return &metricspb.Metric{Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{}}}
	})
	g := m.GetGauge()
	g.DataPoints = append(g.DataPoints, &metricspb.NumberDataPoint{
		Attributes:   attrs,
		TimeUnixNano: b.now,
		Value:        &metricspb.NumberDataPoint_AsInt{AsInt: v},
	})
}

// rtt adds a histogram without buckets, whose sum and count give the mean.
func (b *builder) rtt(start time.Time, count uint64, sum float64, attrs []*commonpb.KeyValue) {
	m := b.metric(MetricRTT, "s", func() *metricspb.Metric {
		return &metricspb.Metric{Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
		}}}
	})
	h := m.GetHistogram()
	h.DataPoints = append(h.DataPoints, &metricspb.HistogramDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: nanos(start),
		TimeUnixNano:      b.now,
		Count:             count,
		Sum:               &sum,
		BucketCounts:      []uint64{count},
	})
}

func compareProcess(a, b *Process) int {
	return cmp.Or(
		strings.Compare(a.Unit, b.Unit),
		strings.Compare(a.Comm, b.Comm),
		strings.Compare(a.Exe, b.Exe),
		strings.Compare(a.Service, b.Service),
		strings.Compare(a.ServiceNamespace, b.ServiceNamespace),
	)
}

func compareEdgeKeys(a, b EdgeKey) int {
	return cmp.Or(
		strings.Compare(a.Role, b.Role),
		strings.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Port, b.Port),
		a.PeerAddr.Compare(b.PeerAddr),
		a.LocalAddr.Compare(b.LocalAddr),
		cmp.Compare(a.NetNS, b.NetNS),
		compareProcess(&a.Process, &b.Process),
	)
}

func compareListenerKeys(a, b ListenerKey) int {
	return cmp.Or(
		strings.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Port, b.Port),
		a.Addr.Compare(b.Addr),
		cmp.Compare(a.NetNS, b.NetNS),
		compareProcess(&a.Process, &b.Process),
	)
}
