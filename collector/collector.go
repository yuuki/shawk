package collector

import (
	"github.com/yuuki/lstf/tcpflow"
)

// local cache

func CollectHostFlows() (tcpflow.HostFlows, error) {
	return tcpflow.GetHostFlows(&tcpflow.GetHostFlowsOption{Processes: true})
}
