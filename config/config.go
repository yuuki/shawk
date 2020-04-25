package config

import (
	"fmt"
	"time"

	"golang.org/x/xerrors"

	"github.com/kelseyhightower/envconfig"
)

type config struct {
	CMDB struct {
		Name           string        `default:"shawk" split_words:"true"`
		Host           string        `default:"127.0.0.1" split_words:"true"`
		Port           string        `default:"5432" split_words:"true"`
		User           string        `default:"shawk" split_words:"true"`
		Password       string        `default:"shawk" split_words:"true"`
		ConnectTimeout time.Duration `default:"5s" split_words:"true"`
		URL            string        `default:"postgres://shawk:shawk@127.0.0.1:5432/shawk?sslmode=disable&connect_timeout=5"`
	}
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
	switch Config.ProbeMode {
	case "streaming", "polling":
	default:
		return fmt.Errorf("the value of probe mode should be 'streaming' or 'polling'")
	}

	return nil
}
