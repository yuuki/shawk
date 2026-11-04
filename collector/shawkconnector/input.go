package shawkconnector

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// process identifies the local process of an edge or a listener.
type process struct {
	unit, comm, exe string
	service, svcNS  string
	// containerID is the container of the process (container.id). The
	// series of the containers of one unit, such as the replicas of a
	// service or a container and the one that replaced it, are separate
	// inputs; they make the same rows and output series.
	containerID string
	// user is the user id of the process (process.user.id) in decimal, ""
	// if the agent does not send it. The series of the users of one unit
	// and comm are separate inputs; their rows are apart with job_users.
	user string
}

// job is the name of the local service as Prometheus shows it in the job
// label, which is also the service name kept in PostgreSQL.
func (p *process) job() string {
	if p.svcNS == "" {
		return p.service
	}
	return p.svcNS + "/" + p.service
}

// slurmJob tells whether a process is a process of a Slurm job (see
// slurmJobUnit).
func (p *process) slurmJob() bool { return strings.HasPrefix(p.unit, slurmJobUnit) }

// peerName is the name of the service of a process as a peer of other
// services in Prometheus (service.peer.name): its job, or slurm-job for the
// processes of Slurm jobs, as the job of their outputs (aggregator.service).
func (p *process) peerName() string {
	if p.slurmJob() {
		return slurmJobService
	}
	return p.job()
}

// edgeID identifies an input edge series of a host.
type edgeID struct {
	role, proto string
	local, peer netip.Addr
	// folded tells that the peer stands for every peer outside the internal
	// ranges of the agent: the network 0.0.0.0/0 or ::/0, whose address is
	// peer.
	folded bool
	port   uint16
	netns  uint64
	process
}

// peerString returns the peer of an edge as PostgreSQL's inet takes it: an
// address, or the network of a folded peer.
func (id *edgeID) peerString() string { return peerString(id.peer, id.folded) }

func peerString(peer netip.Addr, folded bool) string {
	if folded {
		return netip.PrefixFrom(peer, 0).String()
	}
	return peer.String()
}

// valueKey identifies one of the metrics of an edge.
type valueKey struct {
	metric  string
	dir     string // network.io.direction, for bytes and datagrams
	errType string // error.type, for failures by reason
}

// point is a cumulative value of an input series.
type point struct {
	start pcommon.Timestamp
	time  pcommon.Timestamp
	value float64
	count uint64 // of a histogram
	// buckets are the counts of a histogram with explicit bounds.
	buckets []uint64
}

type edgeInput struct {
	id          edgeID
	first, last time.Time
	values      map[valueKey]point
}

// translationID identifies a translation of addresses that a host made:
// the client connected to virtual on vport, and the backend at backend on
// bport saw the connection from source, which is the client unless the
// host replaced its address (SNAT).
type translationID struct {
	proto           string
	netns           uint64
	client, virtual netip.Addr
	vport           uint16
	source, backend netip.Addr
	bport           uint16
}

// dnat tells whether the backend sees the address of the client.
func (id *translationID) dnat() bool { return id.source == id.client }

type translationInput struct {
	id          translationID
	first, last time.Time
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

	edges        map[edgeID]*edgeInput
	listeners    map[listenerID]*listenerInput
	translations map[translationID]*translationInput

	segmentStart time.Time
	udpTraced    bool
	netnsScope   string
	dropped      int64
	// droppedSince is the start of the counter of dropped flows, when the
	// agent started, by the clock of the agent; zero if unknown.
	droppedSince time.Time
	// peerFold is what the agent folds (foldNone, foldIn or foldAll), and
	// peerInternal the ranges it keeps exact, nil if it does not tell.
	peerFold     string
	peerInternal []netip.Prefix

	// agent holds the metrics of the agent itself to forward, and
	// agentPoints their points by name (see addAgentMetric).
	agent       pmetric.MetricSlice
	agentPoints map[string]pmetric.NumberDataPointSlice
	// agentDropped counts the metrics and points of the agent that are not
	// forwarded, and agentDroppedName names one of them.
	agentDropped     int
	agentDroppedName string
	// final tells that the request closes an interval of the agent: it is
	// the last of the requests of the interval, which carries the metrics
	// of the agent.
	final bool
	// invalid counts the data points that could not be decoded.
	invalid int
	// limited tells, of a request that closes an interval, that series of
	// the host were dropped in the interval, beyond max_series_per_host.
	limited bool
}

var errNotAgent = errors.New("the resource is not a shawk agent")

// maxInternalPeers bounds the ranges of shawk.peer.internal the connector
// keeps of a host: an agent keeps at most 4096 ranges exact, with the
// addresses of its host.
const maxInternalPeers = 4096

// maxStringBytes bounds the strings of agents the connector keeps, so that
// every series it holds has a bounded size: a longer string is cut. Agents
// send names and paths, of which the longest, a path of an executable, is
// below PATH_MAX (4096 bytes).
const maxStringBytes = 4096

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
		translations: map[translationID]*translationInput{},
		agent:        pmetric.NewMetricSlice(),
		agentPoints:  map[string]pmetric.NumberDataPointSlice{},
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
	b.peerFold = getString(res, attrPeerFold)
	if b.peerFold == "" {
		b.peerFold = foldNone
	}
	if v, ok := res.Get(attrPeerInternal); ok && v.Type() == pcommon.ValueTypeSlice {
		s := v.Slice()
		ss := make([]string, min(s.Len(), maxInternalPeers))
		for i := range ss {
			ss[i] = s.At(i).AsString()
		}
		b.peerInternal = parsePrefixes(ss)
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
	case metricConnOpened, metricConnFailed, metricConnCount, metricNetworkIO, metricUDPDatagrams, metricRetransmits,
		metricSynRetransmits, metricConnFailedByReason:
		if m.Type() != pmetric.MetricTypeSum {
			b.invalid++
			return
		}
		dps := m.Sum().DataPoints()
		for i := range dps.Len() {
			dp := dps.At(i)
			b.observe(dp.Timestamp())
			k := valueKey{metric: name}
			switch name {
			case metricNetworkIO, metricUDPDatagrams:
				// Another direction than the agents send is output as
				// _OTHER (outDirection).
				k.dir = getString(dp.Attributes(), attrIODirection)
			case metricConnFailedByReason:
				if k.errType = getString(dp.Attributes(), attrErrorType); k.errType == "" {
					b.invalid++
					continue
				}
			}
			e := b.edge(dp.Attributes())
			if e == nil {
				continue
			}
			e.values[k] = point{start: dp.StartTimestamp(), time: dp.Timestamp(), value: numberValue(dp)}
		}
	case metricRTT, metricHandshake:
		if m.Type() != pmetric.MetricTypeHistogram {
			b.invalid++
			return
		}
		dps := m.Histogram().DataPoints()
		for i := range dps.Len() {
			dp := dps.At(i)
			b.observe(dp.Timestamp())
			p := point{start: dp.StartTimestamp(), time: dp.Timestamp(), value: dp.Sum(), count: dp.Count()}
			if name == metricHandshake {
				// The buckets of an agent with other bounds would not add
				// up with those of the others.
				if !slices.Equal(dp.ExplicitBounds().AsRaw(), handshakeBounds) ||
					dp.BucketCounts().Len() != len(handshakeBounds)+1 {
					b.invalid++
					continue
				}
				p.buckets = dp.BucketCounts().AsRaw()
			}
			if e := b.edge(dp.Attributes()); e != nil {
				e.values[valueKey{metric: name}] = p
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
	case metricTranslationFirst, metricTranslationLast:
		forGauge(b, m, func(dp pmetric.NumberDataPoint, t time.Time) {
			if x := b.translation(dp.Attributes()); x != nil {
				if name == metricTranslationFirst {
					x.first = t
				} else {
					x.last = t
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
				dp := m.Sum().DataPoints().At(0)
				b.dropped = int64(numberValue(dp))
				if dp.StartTimestamp() != 0 {
					b.droppedSince = dp.StartTimestamp().AsTime()
				}
			}
		}
		b.addAgentMetric(m)
	}
}

// agentMetric describes a metric of the agent that is forwarded.
type agentMetric struct {
	gauge bool // a gauge, or a cumulative monotonic sum
	unit  string
	// attr is the attribute of the points, if any, and valid tells which
	// of its values the agent sends.
	attr  string
	valid func(string) bool
	// perValue tells that the metric has a point per value of attr; the
	// others have one point.
	perValue bool
}

// agentMetrics are the metrics of the agent that are forwarded, as the
// agent sends them (addAgent in internal/otlp), which must be kept in sync.
// shawk.agent.segment.start is written to PostgreSQL only.
var agentMetrics = map[string]agentMetric{
	metricAgentUp:                  {gauge: true, attr: attrNetNSScope, valid: netnsScope},
	metricAgentUDPTraced:           {gauge: true},
	metricAgentFlowsDropped:        {unit: "{update}"},
	metricAgentCgroupsDropped:      {unit: "{event}"},
	metricAgentReadsDropped:        {unit: "{read}"},
	metricAgentExportFailures:      {unit: "{request}"},
	metricAgentTranslationsTraced:  {gauge: true},
	metricAgentTranslationsDropped: {unit: "{translation}"},
	metricAgentRDMAIO:              {unit: "By"},
	metricAgentBPFRunCount:         {unit: "{run}", attr: attrBPFProgram, valid: isBPFProgram, perValue: true},
	metricAgentBPFRunTime:          {unit: "s", attr: attrBPFProgram, valid: isBPFProgram, perValue: true},
}

func isBPFProgram(s string) bool { return bpfPrograms[s] }

// addAgentMetric keeps a metric of the agent to forward. It is made anew
// from its description in agentMetrics, with the time and value of each
// point and the attribute it may have; other attributes are left out. A
// metric the agent does not send, or of another type, a point with a value
// of the attribute the agent does not send, and a point beyond one per
// metric, or per value of its attribute, are dropped: an agent cannot make
// series in Prometheus other than those of the agents.
func (b *hostBatch) addAgentMetric(m pmetric.Metric) {
	name := m.Name()
	desc, ok := agentMetrics[name]
	var dps pmetric.NumberDataPointSlice
	switch {
	case ok && desc.gauge && m.Type() == pmetric.MetricTypeGauge:
		dps = m.Gauge().DataPoints()
	case ok && !desc.gauge && m.Type() == pmetric.MetricTypeSum:
		dps = m.Sum().DataPoints()
	default:
		b.dropAgent(name)
		return
	}
	for i := range dps.Len() {
		dp := dps.At(i)
		var v string
		if desc.attr != "" {
			v = getString(dp.Attributes(), desc.attr)
		}
		out, kept := b.agentPoints[name]
		if (desc.attr != "" && !desc.valid(v)) || dp.ValueType() == pmetric.NumberDataPointValueTypeEmpty ||
			(kept && (!desc.perValue || hasValue(out, desc.attr, v))) {
			b.dropAgent(name)
			continue
		}
		if !kept {
			om := b.agent.AppendEmpty()
			om.SetName(name)
			om.SetUnit(desc.unit)
			if desc.gauge {
				out = om.SetEmptyGauge().DataPoints()
			} else {
				sum := om.SetEmptySum()
				sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				sum.SetIsMonotonic(true)
				out = sum.DataPoints()
			}
			b.agentPoints[name] = out
		}
		p := out.AppendEmpty()
		p.SetStartTimestamp(dp.StartTimestamp())
		p.SetTimestamp(dp.Timestamp())
		if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
			p.SetIntValue(dp.IntValue())
		} else {
			p.SetDoubleValue(dp.DoubleValue())
		}
		if desc.attr != "" {
			p.Attributes().PutStr(desc.attr, v)
		}
	}
}

// hasValue tells whether one of the points has the value v of attr.
func hasValue(dps pmetric.NumberDataPointSlice, attr, v string) bool {
	for i := range dps.Len() {
		if getString(dps.At(i).Attributes(), attr) == v {
			return true
		}
	}
	return false
}

// dropAgent counts a metric or a point of the agent that is not forwarded.
func (b *hostBatch) dropAgent(name string) {
	b.agentDropped++
	if b.agentDroppedName == "" {
		b.agentDroppedName = cutLabel(name, maxLabelValue)
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

// getString returns a string attribute, made acceptable to PostgreSQL
// (see cleanString): a value it refuses would drop the changes of the host.
// It is cut to maxStringBytes, at the start of a character.
func getString(m pcommon.Map, k string) string {
	if v, ok := m.Get(k); ok {
		s := v.AsString()
		if len(s) > maxStringBytes {
			n := maxStringBytes
			for n > 0 && !utf8.RuneStart(s[n]) {
				n--
			}
			// A copy, so that the long string is not held.
			s = strings.Clone(s[:n])
		}
		return cleanString(s)
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
	p.containerID = getString(a, attrContainerID)
	if uid, ok := getInt(a, attrUserID); ok && uid >= 0 && uid <= math.MaxUint32 {
		p.user = strconv.FormatInt(uid, 10)
	}
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
	if getString(a, attrPeerFolded) == "true" {
		// The agent sends the unspecified address of the family of the
		// folded peers.
		id.folded = true
		if id.peer.Is4() {
			id.peer = netip.IPv4Unspecified()
		} else {
			id.peer = netip.IPv6Unspecified()
		}
	}
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

// translation returns the translation of the attributes of a data point,
// or nil if they are invalid.
func (b *hostBatch) translation(a pcommon.Map) *translationInput {
	proto := getString(a, attrTransport)
	netns, ok1 := getInt(a, attrNetNS)
	vport, ok2 := getInt(a, attrTranslationVirtualPort)
	bport, ok3 := getInt(a, attrTranslationBackendPort)
	var addrs [4]netip.Addr
	valid := (proto == "tcp" || proto == "udp") && ok1 && ok2 && ok3 && netns >= 0 && netns <= math.MaxUint32 &&
		vport >= 0 && vport <= 65535 && bport >= 0 && bport <= 65535
	for i, k := range []string{attrTranslationClient, attrTranslationVirtual, attrTranslationSource, attrTranslationBackend} {
		addr, err := parseAddr(getString(a, k))
		valid = valid && err == nil && !addr.IsUnspecified()
		addrs[i] = addr
	}
	if !valid {
		b.invalid++
		return nil
	}
	id := translationID{proto: proto, netns: uint64(netns), client: addrs[0], virtual: addrs[1], vport: uint16(vport),
		source: addrs[2], backend: addrs[3], bport: uint16(bport)}
	x, ok := b.translations[id]
	if !ok {
		x = &translationInput{id: id}
		b.translations[id] = x
	}
	return x
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

// parsePrefix parses an address range without the bits beyond its length,
// which PostgreSQL's cidr rejects; an IPv4-mapped range is taken as the IPv4
// range, as addresses are.
func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, err
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}
