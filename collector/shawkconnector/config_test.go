package shawkconnector

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	ok := createDefaultConfig()
	ok.Postgres.DSNFile = "/etc/shawk/postgres-dsn"
	ok.PeerCIDRs = map[string]string{"office-lan": "192.168.10.0/24"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
	for name, mod := range map[string]func(*Config){
		"no dsn":            func(c *Config) { c.Postgres.DSNFile = "" },
		"both dsn":          func(c *Config) { c.Postgres.DSN = "postgres://x" },
		"no write interval": func(c *Config) { c.WriteInterval = 0 },
		"short ttl":         func(c *Config) { c.IdleTTL = time.Second },
		"no peers":          func(c *Config) { c.MaxPeers = 0 },
		"no services":       func(c *Config) { c.MaxServices = 0 },
		"bad cidr":          func(c *Config) { c.PeerCIDRs = map[string]string{"x": "10.0.0.0/33"} },
		"reserved name":     func(c *Config) { c.PeerCIDRs = map[string]string{"~other": "10.0.0.0/8"} },
		"short retention":   func(c *Config) { c.Retention = time.Hour },
	} {
		c := *ok
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestConfigValidateBounds: a prefix under two names in peer_cidrs and an
// idle_ttl shorter than 2m are refused.
func TestConfigValidateBounds(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://x"
	cfg.PeerCIDRs = map[string]string{"lan": "10.0.0.0/8", "office": "10.0.0.0/8"}
	if err := cfg.Validate(); err == nil {
		t.Error("the same prefix under two names was accepted")
	}
	cfg.PeerCIDRs = nil
	cfg.WriteInterval = time.Second
	cfg.IdleTTL = 30 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("an idle_ttl shorter than 2m was accepted")
	}
}

func TestWriteIntervalBound(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://x"
	cfg.WriteInterval = 2 * time.Minute
	if err := cfg.Validate(); err == nil {
		t.Error("a write_interval beyond the alive window of agents was accepted")
	}
}
