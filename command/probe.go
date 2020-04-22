package command

import (
	"github.com/yuuki/shawk/agent/polling"
	"github.com/yuuki/shawk/agent/streaming"
	"github.com/yuuki/shawk/config"
	"github.com/yuuki/shawk/db"
	"golang.org/x/xerrors"
)

const (
	// StreamingMode indicates that the agent collects flows by streaming.
	StreamingMode = "streaming"
	// PollingMode indicates that the agent collects flows by polling.
	PollingMode = "polling"
)

// ProbeParam represents a probe command parameter.
type ProbeParam struct {
	Once bool
}

// Probe runs probe subcommand.
func Probe(param *ProbeParam) error {
	logger.Infof("--> Connecting postgres ...")

	db, err := db.New(&db.Opt{
		DBName:         config.Config.CMDB.Name,
		Host:           config.Config.CMDB.Host,
		Port:           config.Config.CMDB.Port,
		User:           config.Config.CMDB.User,
		Password:       config.Config.CMDB.Password,
		ConnectTimeout: config.Config.CMDB.ConnectTimeout,
	})
	if err != nil {
		return xerrors.Errorf("postgres connecting error: %w", err)
	}

	logger.Infof("Connected postgres")

	switch config.Config.ProbeMode {
	case PollingMode:
		if param.Once {
			if err := polling.RunOnce(db); err != nil {
				return err
			}
		} else {
			err := polling.Run(
				config.Config.ProbeInterval,
				config.Config.ProbeFlushInterval,
				db,
			)
			if err != nil {
				return err
			}
		}
	case StreamingMode:
		err := streaming.Run(
			config.Config.ProbeInterval,
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
