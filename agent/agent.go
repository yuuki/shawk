package agent

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuuki/transtracer/collector"
	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/internal/lstf/tcpflow"
	"github.com/yuuki/transtracer/logging"
	"golang.org/x/xerrors"
)

const (
	STREAMING_MODE = "streaming"
	POLLING_MODE   = "polling"
)

type flowBuffer chan []*tcpflow.HostFlow

var logger = logging.New("agent")

// Start starts agent.
func Start(interval time.Duration, flushInterval time.Duration, db *db.DB) error {
	if interval > flushInterval {
		return xerrors.Errorf(
			"polling interval (%s) must not exceed flush interval (%s)",
			interval, flushInterval)
	}

	buffer := make(flowBuffer, flushInterval/interval+1)
	defer close(buffer)

	go Watch(interval, buffer, db)
	go Flusher(flushInterval, buffer, db)

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

// Watch watches host flows for localhost.
func Watch(interval time.Duration, buffer flowBuffer, db *db.DB) {
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

// RunOnce runs agent once.
func RunOnce(db *db.DB) error {
	errChan := make(chan error, 1)
	buffer := make(flowBuffer, 1)
	scanFlows(db, buffer, errChan)
	return <-errChan
}

// scanFlows scans host flows and
// store it to the buffer store.
func scanFlows(db *db.DB, buffer flowBuffer, errChan chan error) {
	start := time.Now()
	flows, err := collector.CollectHostFlows()
	if err != nil {
		errChan <- err
		return
	}
	elapsed := time.Since(start)
	for _, f := range flows {
		logger.Debugf("completed to collect flows: %s", f)
	}
	logger.Debugf("elapsed time for collect flows [%s]", elapsed)

	buffer <- flows
}

// Flusher flushes data into the CMDB periodically.
func Flusher(interval time.Duration, buffer flowBuffer, db *db.DB) {
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
