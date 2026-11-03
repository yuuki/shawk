package otlp

import (
	"cmp"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Resource describes the host and the agent.
type Resource struct {
	MachineID    string // host.id; omitted when empty
	Hostname     string
	Addrs        []netip.Addr
	Kernel       string
	AgentVersion string
	// PeerFold tells which edges fold their peers outside InternalPeers:
	// "none", "in" or "all"; omitted when empty.
	PeerFold      string
	InternalPeers []netip.Prefix
}

// AgentStatus are the metrics of the agent itself.
type AgentStatus struct {
	// Started is when the agent started; its counters start then.
	Started      time.Time
	SegmentStart time.Time
	NetNSScope   string // "all" or the inode of the traced namespace
	UDPTraced    bool
	FlowsDropped uint64 // cumulative
	// CgroupEventsDropped counts the cgroups created whose event the
	// kernel dropped (cumulative).
	CgroupEventsDropped uint64
	// ContainerReadsDrops counts the reads of the state of containers of
	// new cgroups not queued because the queue was full (cumulative).
	ContainerReadsDrops uint64
	ExportFailures      uint64 // cumulative
	BPFPrograms         []BPFProgram
	// TranslationsTraced tells whether translations of addresses are
	// learned from conntrack; TranslationsDropped is the cumulative number
	// of those not learned because the in-kernel tables were full.
	TranslationsTraced  bool
	TranslationsDropped uint64
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

// MaxRequestBytes bounds the encoded size of a request, below the 4 MiB a
// gRPC receiver accepts by default (after decompression).
const MaxRequestBytes = 3 << 20

// maxRequestBytes is MaxRequestBytes; replaced in tests.
var maxRequestBytes = MaxRequestBytes

// agentReserve is room left in every request for the metrics of the agent.
const agentReserve = 16 << 10

// Requests builds the requests that carry all live series at now, each with
// at most maxSeries edges, listeners and translations (0 means no limit) and at most
// MaxRequestBytes, so that every request stays below the size limits of
// the receiver. The metrics of the agent itself are in the last request
// only: it closes the interval, and the connector emits the aggregated
// metrics of the host when it arrives.
//
// Listeners come first, then translations, then server edges, then client
// edges, so that the connector has learned the services and translations
// of the host before it names the peers of client edges, such as a client
// of a service on the same host, or through a translation the host makes.
func (s *State) Requests(res Resource, st AgentStatus, now time.Time, maxSeries int) []*colmetricspb.ExportMetricsServiceRequest {
	listeners := make([]ListenerKey, 0, len(s.listeners))
	for k := range s.listeners {
		listeners = append(listeners, k)
	}
	// A stable order makes requests easy to compare and compress.
	slices.SortFunc(listeners, compareListenerKeys)
	edges := make([]EdgeKey, 0, len(s.edges))
	for k := range s.edges {
		edges = append(edges, k)
	}
	slices.SortFunc(edges, compareEdgeKeys)
	xlats := make([]TranslationKey, 0, len(s.translations))
	for k := range s.translations {
		xlats = append(xlats, k)
	}
	slices.SortFunc(xlats, compareTranslationKeys)

	resource := res.proto()
	budget := maxRequestBytes - proto.Size(resource) - agentReserve
	var reqs []*colmetricspb.ExportMetricsServiceRequest
	b := newBuilder(now)
	count, size := 0, 0
	flush := func(last bool) {
		if last {
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
		b = newBuilder(now)
		count, size = 0, 0
	}
	// add starts a new request if a series of n bytes would not fit.
	add := func(n int) {
		if count > 0 && ((maxSeries > 0 && count >= maxSeries) || size+n > budget) {
			flush(false)
		}
		count++
		size += n
	}
	for i := range listeners {
		k := &listeners[i]
		attrs := listenerAttrs(k)
		add(listenerSize(attrs))
		s.addListener(b, k, attrs)
	}
	for i := range xlats {
		k := &xlats[i]
		attrs := translationAttrs(k)
		add(listenerSize(attrs))
		s.addTranslation(b, k, attrs)
	}
	for i := range edges {
		k := &edges[i]
		attrs := edgeAttrs(k)
		add(edgeSize(k, attrs))
		s.addEdge(b, k, attrs)
	}
	flush(true)
	return reqs
}

// pointOverhead bounds the encoded size of a data point besides its
// attributes: timestamps, value, count and sum, the bucket of a histogram,
// and the tag and length of the point.
const pointOverhead = 64

// directionSize bounds the size of the attribute network.io.direction.
var directionSize = attrsSize([]*commonpb.KeyValue{str(AttrIODirection, DirTransmit)})

// edgeSize bounds the encoded size of the data points of an edge.
func edgeSize(k *EdgeKey, attrs []*commonpb.KeyValue) int {
	a := attrsSize(attrs)
	// Two gauges, first and last seen, and two directions of bytes.
	n := 2*(a+pointOverhead) + 2*(a+directionSize+pointOverhead)
	switch k.Proto {
	case "tcp":
		// Opened, failed, open connections, retransmits and RTT.
		n += 5 * (a + pointOverhead)
	case "udp":
		n += 2 * (a + directionSize + pointOverhead)
	}
	return n
}

// listenerSize bounds the encoded size of the data points of a listener.
func listenerSize(attrs []*commonpb.KeyValue) int {
	return 2 * (attrsSize(attrs) + pointOverhead)
}

// attrsSize is the encoded size of attributes as a repeated field.
func attrsSize(attrs []*commonpb.KeyValue) int {
	n := 0
	for _, kv := range attrs {
		s := proto.Size(kv)
		n += 1 + protowire.SizeVarint(uint64(s)) + s
	}
	return n
}

func (s *State) addEdge(b *builder, k *EdgeKey, attrs []*commonpb.KeyValue) {
	e := s.edges[*k]
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

func (s *State) addListener(b *builder, k *ListenerKey, attrs []*commonpb.KeyValue) {
	l := s.listeners[*k]
	b.gauge(MetricListenerFirst, "s", l.FirstSeen.Unix(), attrs)
	b.gauge(MetricListenerLast, "s", l.LastSeen.Unix(), attrs)
}

func (s *State) addTranslation(b *builder, k *TranslationKey, attrs []*commonpb.KeyValue) {
	x := s.translations[*k]
	b.gauge(MetricTranslationFirst, "s", x.FirstSeen.Unix(), attrs)
	b.gauge(MetricTranslationLast, "s", x.LastSeen.Unix(), attrs)
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
	b.sum(MetricAgentCgroupsDropped, "{event}", true, st.Started, st.CgroupEventsDropped, nil)
	b.sum(MetricAgentReadsDropped, "{read}", true, st.Started, st.ContainerReadsDrops, nil)
	b.sum(MetricAgentExportFailures, "{request}", true, st.Started, st.ExportFailures, nil)
	traced := int64(0)
	if st.TranslationsTraced {
		traced = 1
	}
	b.gauge(MetricAgentTranslationsTraced, "", traced, nil)
	b.sum(MetricAgentTranslationsDropped, "{translation}", true, st.Started, st.TranslationsDropped, nil)
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
	if r.PeerFold != "" {
		internal := make([]string, 0, len(r.InternalPeers))
		for _, p := range r.InternalPeers {
			internal = append(internal, p.String())
		}
		attrs = append(attrs, str(AttrPeerFold, r.PeerFold), stringArray(AttrPeerInternal, internal))
	}
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
	attrs = append(attrs, str(AttrCommand, p.Comm), str(AttrUnit, p.Unit))
	if p.ContainerID != "" {
		attrs = append(attrs, str(AttrContainerID, p.ContainerID))
	}
	return attrs
}

func edgeAttrs(k *EdgeKey) []*commonpb.KeyValue {
	attrs := append(processAttrs(&k.Process),
		str(AttrRole, k.Role),
		str(AttrTransport, k.Proto),
		str(AttrLocalAddr, k.LocalAddr.String()),
		str(AttrPeerAddr, k.PeerAddr.String()),
		integer(AttrServerPort, int64(k.Port)),
		str(AttrNetNS, strconv.FormatUint(uint64(k.NetNS), 10)),
	)
	// network.peer.address stays an address, 0.0.0.0 or ::, which connectors
	// that predate folding store as is.
	if k.PeerFolded {
		attrs = append(attrs, boolean(AttrPeerFolded, true))
	}
	return attrs
}

func translationAttrs(k *TranslationKey) []*commonpb.KeyValue {
	return []*commonpb.KeyValue{
		str(AttrTransport, k.Proto),
		str(AttrNetNS, strconv.FormatUint(uint64(k.NetNS), 10)),
		str(AttrTranslationClient, k.Client.String()),
		str(AttrTranslationVirtual, k.Virtual.String()),
		integer(AttrTranslationVirtualPort, int64(k.VirtualPort)),
		str(AttrTranslationSource, k.Source.String()),
		str(AttrTranslationBackend, k.Backend.String()),
		integer(AttrTranslationBackendPort, int64(k.BackendPort)),
	}
}

func listenerAttrs(k *ListenerKey) []*commonpb.KeyValue {
	return append(processAttrs(&k.Process),
		str(AttrTransport, k.Proto),
		str(AttrLocalAddr, k.Addr.String()),
		integer(AttrServerPort, int64(k.Port)),
		str(AttrNetNS, strconv.FormatUint(uint64(k.NetNS), 10)),
	)
}

// str returns a string attribute. A string field of protobuf must be valid
// UTF-8, and Marshal fails otherwise; a command name cut at 15 bytes may
// end in the middle of a character.
func str(k, v string) *commonpb.KeyValue {
	if !utf8.ValidString(v) {
		v = strings.ToValidUTF8(v, "\uFFFD")
	}
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func integer(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

func boolean(k string, v bool) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: v}}}
}

// stringArray returns an attribute of an array of strings.
func stringArray(k string, vs []string) *commonpb.KeyValue {
	values := make([]*commonpb.AnyValue, 0, len(vs))
	for _, v := range vs {
		values = append(values, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}})
	}
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
		ArrayValue: &commonpb.ArrayValue{Values: values}}}}
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
		strings.Compare(a.ContainerID, b.ContainerID),
	)
}

// roleOrder puts server edges before client edges.
func roleOrder(role string) int {
	if role == RoleServer {
		return 0
	}
	return 1
}

func compareEdgeKeys(a, b EdgeKey) int {
	return cmp.Or(
		cmp.Compare(roleOrder(a.Role), roleOrder(b.Role)),
		strings.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Port, b.Port),
		a.PeerAddr.Compare(b.PeerAddr),
		compareBool(a.PeerFolded, b.PeerFolded),
		a.LocalAddr.Compare(b.LocalAddr),
		cmp.Compare(a.NetNS, b.NetNS),
		compareProcess(&a.Process, &b.Process),
	)
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

func compareTranslationKeys(a, b TranslationKey) int {
	return cmp.Or(
		strings.Compare(a.Proto, b.Proto),
		a.Virtual.Compare(b.Virtual),
		cmp.Compare(a.VirtualPort, b.VirtualPort),
		a.Client.Compare(b.Client),
		a.Backend.Compare(b.Backend),
		cmp.Compare(a.BackendPort, b.BackendPort),
		a.Source.Compare(b.Source),
		cmp.Compare(a.NetNS, b.NetNS),
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
