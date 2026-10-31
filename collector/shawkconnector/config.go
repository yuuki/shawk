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
	if c.IdleTTL < c.WriteInterval {
		errs = append(errs, errors.New("idle_ttl must not be shorter than write_interval"))
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
	for name, v := range m {
		if name == "" || strings.HasPrefix(name, "~") {
			return nil, fmt.Errorf("peer_cidrs: invalid name %q", name)
		}
		for _, s := range strings.Split(v, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("peer_cidrs: %s: %w", name, err)
			}
			out = append(out, namedPrefix{name: name, prefix: p.Masked()})
		}
	}
	sortPrefixes(out)
	return out, nil
}
