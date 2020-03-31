package agent

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/xerrors"

	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/internal/lstf/tcpflow"
	"github.com/yuuki/transtracer/probe/ebpf"
)

const flowBufferSize uint16 = 0xffff

type flowAggBuffer chan *tcpflow.HostFlow

// StartWithStreaming starts agent process on streaming mode.
func StartWithStreaming(interval time.Duration, db *db.DB) error {
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
		logger.Infof("%s\n", v)
		aggBuffer <- v
	}
	if err := ebpf.StartTracer(cb); err != nil {
		return err
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigch
	logger.Infof("Received %s gracefully shutdown...", sig)

	time.Sleep(3 * time.Second)
	logger.Infof("--> Closing db connection...")
	if err := db.Close(); err != nil {
		return xerrors.Errorf("db close error: %w", err)
	}
	logger.Infof("Closed db connection")

	return nil
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
			aggMap := make(map[string]*tcpflow.HostFlow)
			size := len(buffer)
			if size == 0 {
				break
			}

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

			if err := db.InsertOrUpdateHostFlows(flows); err != nil {
				errChan <- err
			}
			logger.Debugf("completed to insert flows to the CMDB (buffer size: %d) \n", size)
		}
	}
}
