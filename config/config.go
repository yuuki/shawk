package config

import (
	"time"

	"golang.org/x/xerrors"

	"github.com/kelseyhightower/envconfig"
)

type config struct {
	CMDBName           string        `default:"shawk" split_words:"true"`
	CMDBHost           string        `default:"127.0.0.1" split_words:"true"`
	CMDBPort           string        `default:"5432" split_words:"true"`
	CMDBUser           string        `default:"shawk" split_words:"true"`
	CMDBPassword       string        `default:"shawk" split_words:"true"`
	CMDBConnectTimeout time.Duration `default:"5s" split_words:"true"`

	ProbeMode          string        `default:"polling" split_words:"true"`
	ProbeInterval      time.Duration `default:"1s" split_words:"true"`
	ProbeFlushInterval time.Duration `default:"30s" split_words:"true"`

	Debug bool `default:"false" splot_words:"true"`
}

// Config is set from the environment variables.
var Config = &config{}

// Load loads into Config from environment values.
func Load() error {
	err := envconfig.Process("shawk", Config)
	if err != nil {
		return xerrors.Errorf("envconfig process error: %w", err)
	}
	return nil
}
