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

type flowBPFBuffer chan []*tcpflow.HostFlow

// StartWithStreaming starts agent process on streaming mode.
func StartWithStreaming(db *db.DB) error {
	ok, err := ebpf.IsSupportedLinux()
	if err != nil {
		return err
	}
	if !ok {
		return xerrors.Errorf("this linux kernel is out of supoort")
	}

	// TODO: go launch flusher
	// TODO: pass channel to flusher

	cb := func(v *tcpflow.HostFlow) {
		logger.Infof("%+v\n", v)
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
