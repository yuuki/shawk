package agent

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuuki/shawk/db"
	"github.com/yuuki/shawk/logging"
	"golang.org/x/xerrors"
)

var logger = logging.New("agent")

// Wait waits a signal or shutdowns the db.
func Wait(db *db.DB) error {
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigch
	logger.Infof("Received %s gracefully shutdown...", sig)

	time.Sleep(3 * time.Second)
	logger.Infof("--> Closing db connection...")
	if err := db.Shutdown(); err != nil {
		return xerrors.Errorf("db close error: %w", err)
	}
	logger.Infof("Closed db connection")

	return nil
}
