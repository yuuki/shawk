package agent

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/logging"
	"golang.org/x/xerrors"
)

var logger = logging.New("agent")

func Wait(db *db.DB) error {
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
