package command

import (
	"time"

	"github.com/yuuki/shawk/agent/polling"
	"github.com/yuuki/shawk/agent/streaming"
	"github.com/yuuki/shawk/db"
	"golang.org/x/xerrors"
)

const (
	// StreamingMode indicates that the agent collects flows by streaming.
	StreamingMode = "streaming"
	// PollingMode indicates that the agent collects flows by polling.
	PollingMode = "polling"
)

type ProbeParam struct {
	Mode             string
	Once             bool
	IntervalSec      int
	FlushIntervalSec int
	DB               db.Opt
}

func Probe(param *ProbeParam) error {
	logger.Infof("--> Connecting postgres ...")

	db, err := db.New(&param.DB)
	if err != nil {
		return xerrors.Errorf("postgres connecting error: %w", err)
	}

	logger.Infof("Connected postgres")

	switch param.Mode {
	case PollingMode:
		if param.Once {
			if err := polling.RunOnce(db); err != nil {
				return err
			}
		} else {
			err := polling.Run(
				time.Duration(param.IntervalSec)*time.Second,
				time.Duration(param.FlushIntervalSec)*time.Second,
				db,
			)
			if err != nil {
				return err
			}
		}
	case StreamingMode:
		err := streaming.Run(
			time.Duration(param.IntervalSec)*time.Second,
			db,
		)
		if err != nil {
			return err
		}
	default:
		return nil
	}

	return nil
}
