package polling

import (
	"time"

	"github.com/yuuki/shawk/agent"
	"github.com/yuuki/shawk/db"
	"github.com/yuuki/shawk/logging"
	"github.com/yuuki/shawk/probe"
	"github.com/yuuki/shawk/probe/netlink"
	"golang.org/x/xerrors"
)

type flowBuffer chan []*probe.HostFlow

var logger = logging.New("agent/polling")

// Run starts agent.
func Run(interval time.Duration, flushInterval time.Duration, db *db.DB) error {
	if interval > flushInterval {
		return xerrors.Errorf(
			"polling interval (%s) must not exceed flush interval (%s)",
			interval, flushInterval)
	}

	buffer := make(flowBuffer, flushInterval/interval+1)
	defer close(buffer)

	go watch(interval, buffer, db)
	go flusher(flushInterval, buffer, db)

	return agent.Wait(db)
}

// RunOnce runs agent once.
func RunOnce(db *db.DB) error {
	errChan := make(chan error, 1)
	buffer := make(flowBuffer, 1)
	scanFlows(db, buffer, errChan)
	return <-errChan
}

// watch watches host flows for localhost.
func watch(interval time.Duration, buffer flowBuffer, db *db.DB) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errChan := make(chan error, 1)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				logger.Errorf("%+v", err)
			}
		case <-ticker.C:
			go scanFlows(db, buffer, errChan)
		}
	}
}

// scanFlows scans host flows and store it to the buffer store.
func scanFlows(db *db.DB, buffer flowBuffer, errChan chan error) {
	start := time.Now()

	mapFlows, err := netlink.GetHostFlows(
		&netlink.GetHostFlowsOption{Processes: true},
	)
	if err != nil {
		errChan <- err
	}
	// convert map into slice to solve the order problem in testing
	flows := make([]*probe.HostFlow, 0, len(mapFlows))
	for _, f := range mapFlows {
		flows = append(flows, f)
	}

	elapsed := time.Since(start)
	for _, f := range flows {
		logger.Debugf("completed to collect flows: %s", f)
	}
	logger.Debugf("elapsed time for collect flows [%s]", elapsed)

	buffer <- flows
}

// flusher flushes data into the CMDB periodically.
func flusher(interval time.Duration, buffer flowBuffer, db *db.DB) {
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
			go flush(db, buffer, errChan)
		}
	}
}

func flush(db *db.DB, buffer flowBuffer, errChan chan error) {
	size := len(buffer)
	for i := 0; i < size; i++ {
		flows := <-buffer
		if err := db.InsertOrUpdateHostFlows(flows); err != nil {
			errChan <- err
			break
		}
	}

	logger.Debugf("completed to insert flows to the CMDB (buffer size: %d) \n", size)
}
