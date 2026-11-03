package shawkconnector

import (
	"crypto/sha256"
	"encoding/hex"
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

	metricAgentPrefix       = "shawk.agent."
	metricAgentUp           = "shawk.agent.up"
	metricAgentSegmentStart = "shawk.agent.segment.start"
	metricAgentUDPTraced    = "shawk.agent.udp.traced"
	metricAgentFlowsDropped = "shawk.agent.flows.dropped"
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

	attrExePath     = "process.executable.path"
	attrCommand     = "process.command"
	attrUnit        = "shawk.unit"
	attrContainerID = "container.id"
	attrRole        = "shawk.role"
	attrTransport   = "network.transport"
	attrLocalAddr   = "network.local.address"
	attrPeerAddr    = "network.peer.address"
	attrServerPort  = "server.port"
	attrNetNS       = "shawk.netns"
	attrIODirection = "network.io.direction"
	attrNetNSScope  = "shawk.netns.scope"
	attrErrorType   = "error.type"
	// attrPeerFolded marks an edge whose peer is folded: every peer outside
	// the internal ranges of the agent, sent as the address 0.0.0.0 or ::.
	attrPeerFolded = "shawk.peer.folded"
	// attrPeerFold and attrPeerInternal are resource attributes of the
	// agent: which edges it folds, and the ranges it keeps exact.
	attrPeerFold     = "shawk.peer.fold"
	attrPeerInternal = "shawk.peer.internal"

	agentServiceName = "shawk-agent"
	scopeName        = "github.com/yuuki/shawk/collector/shawkconnector"

	roleClient = "client"
	roleServer = "server"
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

// unknownService is the service.name the agent gives a socket whose owner
// is unknown.
const unknownService = "~unknown"

// hostKey identifies a host in PostgreSQL from its machine id and its name,
// which tells apart hosts cloned with the same machine id. It is the host
// id of shawk before the connector existed.
func hostKey(machineID, hostname string) string {
	sum := sha256.Sum256([]byte(machineID + "\n" + hostname))
	return hex.EncodeToString(sum[:8])
}
