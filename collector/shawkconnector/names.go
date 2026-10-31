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
	metricEdgeFirst    = "shawk.edge.first_seen"
	metricEdgeLast     = "shawk.edge.last_seen"

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
	attrRole        = "shawk.role"
	attrTransport   = "network.transport"
	attrLocalAddr   = "network.local.address"
	attrPeerAddr    = "network.peer.address"
	attrServerPort  = "server.port"
	attrNetNS       = "shawk.netns"
	attrIODirection = "network.io.direction"
	attrNetNSScope  = "shawk.netns.scope"

	agentServiceName = "shawk-agent"
	scopeName        = "github.com/yuuki/shawk/collector/shawkconnector"

	roleClient = "client"
	roleServer = "server"
)

// Values of service.peer.name for peers without a known service.
const (
	peerUnresolved = "~unresolved" // a private address without a known service
	peerExternal   = "~external"   // a public address
	peerOther      = "~other"      // folded beyond max_peers
)

// hostKey identifies a host in PostgreSQL from its machine id and its name,
// which tells apart hosts cloned with the same machine id. It is the host
// id of shawk before the connector existed.
func hostKey(machineID, hostname string) string {
	sum := sha256.Sum256([]byte(machineID + "\n" + hostname))
	return hex.EncodeToString(sum[:8])
}
