package collector

import (
	"github.com/yuuki/lstf/tcpflow"
)

// local cache

func CollectHostFlows() (tcpflow.HostFlows, error) {
	processes := true
	return tcpflow.GetHostFlows(processes)
}
