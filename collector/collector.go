package collector

import (
	"github.com/yuuki/lstf/tcpflow"
	"golang.org/x/xerrors"
)

// local cache

func CollectHostFlows() ([]*tcpflow.HostFlow, error) {
	mapFlows, err := tcpflow.GetHostFlows(
		&tcpflow.GetHostFlowsOption{Processes: true},
	)
	if err != nil {
		return nil, xerrors.Errorf("host flows collect failed: %v", err)
	}
	// convert map into slice to solve the order problem in testing
	flows := make([]*tcpflow.HostFlow, 0, len(mapFlows))
	for _, f := range mapFlows {
		flows = append(flows, f)
	}
	return flows, nil
}
