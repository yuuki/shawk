package streaming

import (
	"time"

	"golang.org/x/xerrors"

	"github.com/yuuki/transtracer/agent"
	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/internal/lstf/tcpflow"
	"github.com/yuuki/transtracer/logging"
	"github.com/yuuki/transtracer/probe/ebpf"
)

type flowAggBuffer chan *tcpflow.HostFlow

const flowBufferSize uint16 = 0xffff

var logger = logging.New("agent/streaming")

// Run starts agent process on streaming mode.
func Run(interval time.Duration, db *db.DB) error {
	ok, err := ebpf.IsSupportedLinux()
	if err != nil {
		return err
	}
	if !ok {
		return xerrors.Errorf("this linux kernel is out of supoort")
	}

	aggBuffer := make(flowAggBuffer, flowBufferSize)
	defer close(aggBuffer)

	go aggregator(db, interval, aggBuffer)

	cb := func(v *tcpflow.HostFlow) {
		logger.Debugf("%s\n", v)
		aggBuffer <- v
	}
	if err := ebpf.StartTracer(cb); err != nil {
		return err
	}

	return agent.Wait(db)
}

func aggregator(db *db.DB, interval time.Duration, buffer chan *tcpflow.HostFlow) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errChan := make(chan error, 1)

	for {
		select {
		case err := <-errChan:
			if err != nil {
				logger.Errorf("%+v\n", err)
			}
		case <-ticker.C:
			flows := aggregate(buffer)
			if err := db.InsertOrUpdateHostFlows(flows); err != nil {
				errChan <- err
			}
			logger.Debugf("completed to insert flows to the CMDB (the number of flows: %d) \n", len(flows))
		}
	}
}

func aggregate(buffer chan *tcpflow.HostFlow) []*tcpflow.HostFlow {
	size := len(buffer)
	if size == 0 {
		return []*tcpflow.HostFlow{}
	}

	aggMap := make(map[string]*tcpflow.HostFlow)
	for i := 0; i < size; i++ {
		flow := <-buffer
		key := flow.UniqKey()

		if _, ok := aggMap[key]; !ok {
			aggMap[key] = flow
		} else {
			if aggMap[key].Process == nil {
				aggMap[key].Process = flow.Process
			}
		}
		aggMap[key].Connections++
	}

	flows := make([]*tcpflow.HostFlow, 0, len(aggMap))
	for _, flow := range aggMap {
		flows = append(flows, flow)
	}

	return flows
}
