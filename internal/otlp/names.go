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
	// Of the active opens of TCP client edges: the handshakes established,
	// by duration, the SYNs retransmitted, and the failures by error.type.
	MetricHandshake          = "shawk.tcp.handshake"
	MetricSynRetransmits     = "shawk.tcp.syn_retransmits"
	MetricConnFailedByReason = "shawk.connection.failed.by_reason"
	MetricEdgeFirst          = "shawk.edge.first_seen"
	MetricEdgeLast           = "shawk.edge.last_seen"
	// Of TCP edges with -classify-protocols: when a connection whose first
	// payload showed each wire protocol (shawk.wire_protocol) was first and
	// last seen. PostgreSQL keeps them, Prometheus does not.
	MetricEdgeWireFirst = "shawk.edge.wire_protocol.first_seen"
	MetricEdgeWireLast  = "shawk.edge.wire_protocol.last_seen"

	MetricListenerFirst = "shawk.listener.first_seen"
	MetricListenerLast  = "shawk.listener.last_seen"

	MetricTranslationFirst = "shawk.translation.first_seen"
	MetricTranslationLast  = "shawk.translation.last_seen"

	MetricAgentUp           = "shawk.agent.up"
	MetricAgentSegmentStart = "shawk.agent.segment.start"
	MetricAgentUDPTraced    = "shawk.agent.udp.traced"
	MetricAgentUnixTraced   = "shawk.agent.unix.traced"
	// MetricAgentProtocolsClassified tells whether the agent classifies
	// the wire protocols of TCP connections (-classify-protocols).
	MetricAgentProtocolsClassified = "shawk.agent.protocols.classified"
	MetricAgentFlowsDropped        = "shawk.agent.flows.dropped"
	MetricAgentCgroupsDropped      = "shawk.agent.cgroup_events.dropped"
	MetricAgentReadsDropped        = "shawk.agent.container_reads.dropped"
	MetricAgentExportFailures      = "shawk.agent.export.failures"
	MetricAgentBPFRunCount         = "shawk.agent.bpf.run_count"
	MetricAgentBPFRunTime          = "shawk.agent.bpf.run_time"

	MetricAgentTranslationsTraced  = "shawk.agent.translations.traced"
	MetricAgentTranslationsDropped = "shawk.agent.translations.dropped"

	MetricAgentRDMAIO = "shawk.agent.rdma.io"
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
	AttrContainerID  = "container.id"
	AttrUserID       = "process.user.id"
	AttrRole         = "shawk.role"
	AttrTransport    = "network.transport"
	AttrLocalAddr    = "network.local.address"
	AttrPeerAddr     = "network.peer.address"
	AttrPeerFolded   = "shawk.peer.folded"   // the edge bundles the peers outside the internal ranges
	AttrPeerFold     = "shawk.peer.fold"     // resource: which edges fold their peers: none, in or all
	AttrPeerInternal = "shawk.peer.internal" // resource: the internal ranges, whose peers are kept
	AttrServerPort   = "server.port"
	// AttrServerAddr is the name of the Unix socket of an edge or a
	// listener whose network.transport is TransportUnix, whatever the role,
	// like server.port: such series carry it instead of
	// network.local.address, network.peer.address and server.port.
	AttrServerAddr   = "server.address"
	AttrKernelChosen = "shawk.port.kernel_chosen" // listener: the kernel chose the port, sent only when true
	AttrNetNS        = "shawk.netns"
	AttrIODirection  = "network.io.direction"
	AttrNetNSScope   = "shawk.netns.scope"
	AttrBPFProgram   = "shawk.bpf.program"
	AttrErrorType    = "error.type"
	// AttrWireProtocol is one of WireProtocols.
	AttrWireProtocol = "shawk.wire_protocol"

	// Attributes of a translation of addresses (see TranslationKey).
	AttrTranslationClient      = "shawk.translation.client.address"
	AttrTranslationVirtual     = "shawk.translation.virtual.address"
	AttrTranslationVirtualPort = "shawk.translation.virtual.port"
	AttrTranslationSource      = "shawk.translation.source.address"
	AttrTranslationBackend     = "shawk.translation.backend.address"
	AttrTranslationBackendPort = "shawk.translation.backend.port"

	ScopeName        = "github.com/yuuki/shawk"
	AgentServiceName = "shawk-agent"
)

// Values of shawk.role, network.transport and network.io.direction.
const (
	RoleClient = "client"
	RoleServer = "server"

	// TransportUnix is the network.transport of Unix stream and seqpacket
	// sockets; TCP and UDP are "tcp" and "udp".
	TransportUnix = "unix"

	DirTransmit = "transmit"
	DirReceive  = "receive"
)

// HandshakeBounds are the explicit bounds, in seconds, of the histogram
// shawk.tcp.handshake: those of the buckets of handshakes in the kernel
// (tracer.HandshakeBounds), which the shawk connector expects.
var HandshakeBounds = [...]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.01, 0.05, 0.25, 1, 3}

// FailReasons are the values of error.type of
// shawk.connection.failed.by_reason, in the order of EdgeStats.Fails and of
// tracer.FailReason. Failures for another reason have ErrorOther, the value
// OpenTelemetry gives an error without a known type.
var FailReasons = [...]string{"refused", "timeout", "unreachable", "local", "aborted"}

// ErrorOther is the error.type of failures without one of FailReasons.
const ErrorOther = "_OTHER"

// WireProtocols are the values of shawk.wire_protocol, the protocols that
// the first payload of a TCP connection shows, in the order of the bits of
// EdgeStats.Protocols and of tracer.WireProtocol.
var WireProtocols = [...]string{
	"unknown", "tls", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3", "http1", "http2_grpc", "ssh", "postgres", "mysql",
	"redis", "slurm_rpc", "postgres_tls", "mysql_tls",
}
