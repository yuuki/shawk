package shawkconnector

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Config configures the shawk connector.
type Config struct {
	Postgres PostgresConfig `mapstructure:"postgres"`
	// WriteInterval is how often the changes of every host are written to
	// PostgreSQL and the names of peers are reloaded from it.
	WriteInterval time.Duration `mapstructure:"write_interval"`
	// IdleTTL is how long an output series is sent after its input stopped.
	IdleTTL time.Duration `mapstructure:"idle_ttl"`
	// MaxPeers bounds the values of service.peer.name per host, local
	// service and role; the others are folded into ~other.
	MaxPeers int `mapstructure:"max_peers"`
	// PeerCIDRs names address ranges of peers that are not resolved to a
	// service, e.g. office-lan: 192.168.10.0/24. A value may list several
	// prefixes separated by commas. The narrowest matching range wins.
	PeerCIDRs map[string]string `mapstructure:"peer_cidrs"`
	// KeepPeerAddress keeps network.peer.address in the output. It raises
	// the number of series with the number of peer addresses.
	KeepPeerAddress bool `mapstructure:"keep_peer_address"`
	// Retention is how long rows are kept in PostgreSQL after they were
	// last seen; zero keeps them forever. The connector deletes older rows
	// every hour.
	Retention time.Duration `mapstructure:"retention"`
}

// PostgresConfig configures the connection to PostgreSQL.
type PostgresConfig struct {
	// DSN is a connection string, e.g. postgres://shawk@db/shawk.
	DSN string `mapstructure:"dsn"`
	// DSNFile is a file that holds the connection string, so that the
	// password stays out of the configuration.
	DSNFile string `mapstructure:"dsn_file"`
	// Migrate applies the bundled migrations at start. The role then needs
	// to own the schemas shawk and shawk_v1.
	Migrate bool `mapstructure:"migrate"`
}

func createDefaultConfig() *Config {
	return &Config{
		WriteInterval: time.Minute,
		IdleTTL:       15 * time.Minute,
		MaxPeers:      50,
		Retention:     3 * 365 * 24 * time.Hour,
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if (c.Postgres.DSN == "") == (c.Postgres.DSNFile == "") {
		errs = append(errs, errors.New("postgres: set exactly one of dsn and dsn_file"))
	}
	if c.WriteInterval <= 0 {
		errs = append(errs, errors.New("write_interval must be positive"))
	}
	if c.IdleTTL < c.WriteInterval || c.IdleTTL < 2*time.Minute {
		// Inputs must outlive a few intervals of the agents (15s) and delays.
		errs = append(errs, errors.New("idle_ttl must be at least 2m and not shorter than write_interval"))
	}
	if c.Retention != 0 && c.Retention < 24*time.Hour {
		errs = append(errs, errors.New("retention must be zero (keep forever) or at least 24h"))
	}
	if c.MaxPeers < 1 {
		errs = append(errs, errors.New("max_peers must be at least 1"))
	}
	if _, err := parsePeerCIDRs(c.PeerCIDRs); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type namedPrefix struct {
	name   string
	prefix netip.Prefix
}

// parsePeerCIDRs parses peer_cidrs, narrowest prefixes first.
func parsePeerCIDRs(m map[string]string) ([]namedPrefix, error) {
	var out []namedPrefix
	seen := map[netip.Prefix]string{}
	for name, v := range m {
		if name == "" || strings.HasPrefix(name, "~") {
			return nil, fmt.Errorf("peer_cidrs: invalid name %q", name)
		}
		for _, s := range strings.Split(v, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("peer_cidrs: %s: %w", name, err)
			}
			p = p.Masked()
			if other, dup := seen[p]; dup {
				return nil, fmt.Errorf("peer_cidrs: %s is named both %s and %s", p, other, name)
			}
			seen[p] = name
			out = append(out, namedPrefix{name: name, prefix: p})
		}
	}
	sortPrefixes(out)
	return out, nil
}
