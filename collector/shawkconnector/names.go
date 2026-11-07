package shawkconnector

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"unicode/utf8"
)

// Names of the metrics sent by the agents. They are a copy of the names in
// internal/otlp of the agent, which must be kept in sync.
const (
	metricConnOpened   = "shawk.connection.opened"
	metricConnFailed   = "shawk.connection.failed"
	metricConnCount    = "shawk.connection.count"
	metricNetworkIO    = "shawk.network.io"
	metricUDPDatagrams = "shawk.udp.datagrams"
	metricRetransmits  = "shawk.tcp.retransmits"
	metricRTT          = "shawk.tcp.rtt"
	// Of the active opens of TCP client edges: the handshakes established,
	// by duration (handshakeBounds), the SYNs retransmitted, and the
	// failures by error.type.
	metricHandshake          = "shawk.tcp.handshake"
	metricSynRetransmits     = "shawk.tcp.syn_retransmits"
	metricConnFailedByReason = "shawk.connection.failed.by_reason"
	metricEdgeFirst          = "shawk.edge.first_seen"
	metricEdgeLast           = "shawk.edge.last_seen"

	metricListenerFirst = "shawk.listener.first_seen"
	metricListenerLast  = "shawk.listener.last_seen"

	metricTranslationFirst = "shawk.translation.first_seen"
	metricTranslationLast  = "shawk.translation.last_seen"

	metricAgentPrefix         = "shawk.agent."
	metricAgentUp             = "shawk.agent.up"
	metricAgentSegmentStart   = "shawk.agent.segment.start"
	metricAgentUDPTraced      = "shawk.agent.udp.traced"
	metricAgentUnixTraced     = "shawk.agent.unix.traced"
	metricAgentFlowsDropped   = "shawk.agent.flows.dropped"
	metricAgentCgroupsDropped = "shawk.agent.cgroup_events.dropped"
	metricAgentReadsDropped   = "shawk.agent.container_reads.dropped"
	metricAgentExportFailures = "shawk.agent.export.failures"
	metricAgentBPFRunCount    = "shawk.agent.bpf.run_count"
	metricAgentBPFRunTime     = "shawk.agent.bpf.run_time"

	metricAgentTranslationsTraced  = "shawk.agent.translations.traced"
	metricAgentTranslationsDropped = "shawk.agent.translations.dropped"

	metricAgentRDMAIO = "shawk.agent.rdma.io"
)

// Names of the outputs per peer host (peer_hosts), which the connector
// makes from the inputs of the same names without .host.
const (
	metricHostConnOpened         = "shawk.host.connection.opened"
	metricHostConnFailedByReason = "shawk.host.connection.failed.by_reason"
	metricHostHandshake          = "shawk.host.tcp.handshake"
	metricHostSynRetransmits     = "shawk.host.tcp.syn_retransmits"
	metricHostNetworkIO          = "shawk.host.network.io"
	metricHostRetransmits        = "shawk.host.tcp.retransmits"
)

// Names of the attributes.
const (
	attrHostID            = "host.id"
	attrHostName          = "host.name"
	attrHostIP            = "host.ip"
	attrOSVersion         = "os.version"
	attrServiceName       = "service.name"
	attrServiceNS         = "service.namespace"
	attrServiceVersion    = "service.version"
	attrServiceInstanceID = "service.instance.id"
	attrPeerService       = "service.peer.name"
	attrPeerAgent         = "shawk.peer.agent"
	attrPeerHost          = "shawk.peer.host"
	// attrLocalNetwork and attrPeerNetwork are the networks of the local
	// and the peer address of the edges of an output per peer host, with
	// networks.
	attrLocalNetwork = "shawk.local.network"
	attrPeerNetwork  = "shawk.peer.network"

	attrExePath     = "process.executable.path"
	attrCommand     = "process.command"
	attrUnit        = "shawk.unit"
	attrContainerID = "container.id"
	attrUserID      = "process.user.id"
	attrRole        = "shawk.role"
	attrTransport   = "network.transport"
	attrLocalAddr   = "network.local.address"
	attrPeerAddr    = "network.peer.address"
	attrServerPort  = "server.port"
	// attrServerAddr is the name of the Unix socket of an edge or a listener
	// of transportUnix, which they carry instead of network.local.address,
	// network.peer.address and server.port.
	attrServerAddr  = "server.address"
	attrNetNS       = "shawk.netns"
	attrIODirection = "network.io.direction"
	attrNetNSScope  = "shawk.netns.scope"
	attrBPFProgram  = "shawk.bpf.program"
	attrErrorType   = "error.type"
	// attrPeerFolded marks an edge whose peer is folded: every peer outside
	// the internal ranges of the agent, sent as the address 0.0.0.0 or ::.
	attrPeerFolded = "shawk.peer.folded"
	// attrKernelChosen marks a listener whose port the kernel chose: the
	// socket was not bound to a port.
	attrKernelChosen = "shawk.port.kernel_chosen"
	// attrPeerFold and attrPeerInternal are resource attributes of the
	// agent: which edges it folds, and the ranges it keeps exact.
	attrPeerFold     = "shawk.peer.fold"
	attrPeerInternal = "shawk.peer.internal"

	// The attributes of a translation of addresses that the host of the
	// agent made (DNAT, SNAT, IPVS), learned from conntrack.
	attrTranslationClient      = "shawk.translation.client.address"
	attrTranslationVirtual     = "shawk.translation.virtual.address"
	attrTranslationVirtualPort = "shawk.translation.virtual.port"
	attrTranslationSource      = "shawk.translation.source.address"
	attrTranslationBackend     = "shawk.translation.backend.address"
	attrTranslationBackendPort = "shawk.translation.backend.port"

	agentServiceName = "shawk-agent"
	scopeName        = "github.com/yuuki/shawk/collector/shawkconnector"

	roleClient = "client"
	roleServer = "server"

	// transportUnix is the network.transport of Unix stream and seqpacket
	// sockets: only client edges, to the name of a socket on their host,
	// and listeners.
	transportUnix = "unix"
)

// errorTypeOther is the error.type of failures without a known reason.
const errorTypeOther = "_OTHER"

// errorTypes are the values of error.type that agents send. Another value
// is output as errorTypeOther, so that an agent cannot make a series per
// value.
var errorTypes = map[string]bool{
	"refused": true, "timeout": true, "unreachable": true, "local": true, "aborted": true, errorTypeOther: true,
}

// outErrorType returns the error.type of an output for that of an input.
func outErrorType(t string) string {
	if t == "" || errorTypes[t] {
		return t
	}
	return errorTypeOther
}

// Values of network.io.direction that agents send.
const (
	dirTransmit = "transmit"
	dirReceive  = "receive"
)

// directionOther is the network.io.direction of the output of an input
// with another direction, so that an agent cannot make a series per value.
const directionOther = "_OTHER"

// outDirection returns the network.io.direction of an output for that of
// an input.
func outDirection(d string) string {
	if d == "" || d == dirTransmit || d == dirReceive {
		return d
	}
	return directionOther
}

// maxLabelValue bounds the length of the names of local services and
// their namespaces, host names, host ids and agent versions that the
// connector forwards. Agents cut the names of services to the same length,
// so that the names they send are forwarded whole; host names are shorter.
const maxLabelValue = 255

// maxPeerName bounds the length of a value of service.peer.name: the name
// of a service with its namespace, each of up to maxLabelValue bytes.
const maxPeerName = 2*maxLabelValue + 1

// cutLabel cuts a value of a label to n bytes, at the start of a character.
func cutLabel(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// netnsScope tells whether a value of shawk.netns.scope is one the agents
// send: all, or the inode of the network namespace they trace.
func netnsScope(s string) bool {
	if s == "all" {
		return true
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == s
}

// bpfPrograms are the values of shawk.bpf.program: the BPF programs of the
// agent (internal/tracer/bpf), which must be kept in sync. The run counts
// and times of other programs are not forwarded, so that an agent cannot
// make a series per value.
var bpfPrograms = map[string]bool{
	"shawk_cgroup_mkdir":        true,
	"shawk_ct_confirm":          true,
	"shawk_ct_destroy":          true,
	"shawk_inet_sock_set_state": true,
	"shawk_ip6_send_skb":        true,
	"shawk_ip6_send_skb_k":      true,
	"shawk_ip_icmp_error":       true,
	"shawk_ip_send_skb":         true,
	"shawk_ip_send_skb_k":       true,
	"shawk_ipv6_icmp_error":     true,
	"shawk_iter_task_file":      true,
	"shawk_iter_tcp":            true,
	"shawk_iter_udp":            true,
	"shawk_skb_consume_udp":     true,
	"shawk_skb_consume_udp_k":   true,
	"shawk_tcp_receive_reset":   true,
	"shawk_unix_release":        true,
	"shawk_unix_stream_connect": true,
}

// handshakeBounds are the explicit bounds, in seconds, of the histogram
// shawk.tcp.handshake of the agents. An input with other bounds is invalid.
var handshakeBounds = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.01, 0.05, 0.25, 1, 3}

// Values of shawk.peer.fold: an agent folds no peers, the peers of its
// servers (in), or the peers of its servers and clients (all). An agent
// that does not send the attribute folds none.
const (
	foldNone = "none"
	foldIn   = "in"
	foldAll  = "all"
)

// Values of service.peer.name for peers without a known service.
const (
	peerUnresolved = "~unresolved" // a private address without a known service
	peerExternal   = "~external"   // a public address
	peerOther      = "~other"      // folded beyond max_peers
)

// Values of shawk.peer.host for peers whose host is not known (§1.3 of
// docs/proposals/slurm-hpc-clusters.md).
const (
	hostUnknown  = "~unknown"  // an internal address
	hostExternal = "~external" // a public address, or a folded peer
	hostOther    = "~other"    // folded beyond max_peer_hosts
)

// Values of shawk.local.network and shawk.peer.network for addresses in no
// range of networks.
const (
	networkUnknown  = "~unknown"  // an address not routed on the Internet
	networkExternal = "~external" // another address, or a folded peer
)

// serviceOther is the service.name of the outputs of the local services
// of a host beyond max_services.
const serviceOther = "~other"

// unknownService is the service.name the agent gives a socket whose owner
// is unknown.
const unknownService = "~unknown"

// The processes of Slurm jobs have units that start with slurmJobUnit
// (slurm/batch, slurm/step, slurm/extern, slurm/interactive), and are
// forwarded to Prometheus under the service slurmJobService: their users
// name them as they like, and every executable of every job would
// otherwise be a job of Prometheus.
const (
	slurmJobUnit    = "slurm/"
	slurmJobService = "slurm-job"
)

// hostKey identifies a host in PostgreSQL from its machine id and its name,
// which tells apart hosts cloned with the same machine id. It is the host
// id of shawk before the connector existed.
func hostKey(machineID, hostname string) string {
	sum := sha256.Sum256([]byte(machineID + "\n" + hostname))
	return hex.EncodeToString(sum[:8])
}
