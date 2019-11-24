package collector

import (
	"golang.org/x/xerrors"

	"github.com/yuuki/transtracer/internal/lstf/tcpflow"
)

// CollectHostFlows collects the host flows from localhost.
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
