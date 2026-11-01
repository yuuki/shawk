// Package otlp turns the flows observed by the tracer into OTLP metrics and
// sends them to the shawk connector of an OpenTelemetry Collector.
//
// The metrics are cumulative: every request carries all live series with
// their totals since the series started, so that a request lost in transit
// is made up for by the next one. A series that shows no activity for the
// idle TTL is dropped; if it reappears its counters start again from zero.
//
// The names below are an internal contract between the agent and the shawk
// connector (collector/shawkconnector), which keeps its own copy of them.
package otlp

// Names of the metrics.
const (
	MetricConnOpened   = "shawk.connection.opened"
	MetricConnFailed   = "shawk.connection.failed"
	MetricConnCount    = "shawk.connection.count"
	MetricNetworkIO    = "shawk.network.io"
	MetricUDPDatagrams = "shawk.udp.datagrams"
	MetricRetransmits  = "shawk.tcp.retransmits"
	MetricRTT          = "shawk.tcp.rtt"
	MetricEdgeFirst    = "shawk.edge.first_seen"
	MetricEdgeLast     = "shawk.edge.last_seen"

	MetricListenerFirst = "shawk.listener.first_seen"
	MetricListenerLast  = "shawk.listener.last_seen"

	MetricAgentUp             = "shawk.agent.up"
	MetricAgentSegmentStart   = "shawk.agent.segment.start"
	MetricAgentUDPTraced      = "shawk.agent.udp.traced"
	MetricAgentFlowsDropped   = "shawk.agent.flows.dropped"
	MetricAgentExportFailures = "shawk.agent.export.failures"
	MetricAgentBPFRunCount    = "shawk.agent.bpf.run_count"
	MetricAgentBPFRunTime     = "shawk.agent.bpf.run_time"
)

// Names of the attributes.
const (
	AttrHostID         = "host.id"
	AttrHostName       = "host.name"
	AttrHostIP         = "host.ip"
	AttrOSVersion      = "os.version"
	AttrServiceName    = "service.name"
	AttrServiceNS      = "service.namespace"
	AttrServiceVersion = "service.version"

	AttrExeName      = "process.executable.name"
	AttrExePath      = "process.executable.path"
	AttrCommand      = "process.command"
	AttrUnit         = "shawk.unit"
	AttrRole         = "shawk.role"
	AttrTransport    = "network.transport"
	AttrLocalAddr    = "network.local.address"
	AttrPeerAddr     = "network.peer.address"
	AttrServerPort   = "server.port"
	AttrNetNS        = "shawk.netns"
	AttrIODirection  = "network.io.direction"
	AttrNetNSScope   = "shawk.netns.scope"
	AttrBPFProgram   = "shawk.bpf.program"
	ScopeName        = "github.com/yuuki/shawk"
	AgentServiceName = "shawk-agent"
)

// Values of shawk.role and network.io.direction.
const (
	RoleClient = "client"
	RoleServer = "server"

	DirTransmit = "transmit"
	DirReceive  = "receive"
)
