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
	// MaxServices bounds the local services per host, whose service.name
	// and service.namespace make the job of the outputs; the others are
	// folded into ~other. PostgreSQL keeps them all.
	MaxServices int `mapstructure:"max_services"`
	// PeerCIDRs names address ranges of peers that are not resolved to a
	// service, e.g. office-lan: 192.168.10.0/24. A value may list several
	// prefixes separated by commas. The narrowest matching range wins.
	PeerCIDRs map[string]string `mapstructure:"peer_cidrs"`
	// InventoryFile is a file in YAML or JSON that lists the hosts expected
	// in the fleet, with all their addresses, roles and node names in
	// Slurm (inventory.go). The connector reads it every write interval and
	// writes it to PostgreSQL; while it cannot be read or is invalid, the
	// contents last read stay. Unset, the connector drops the inventory
	// from PostgreSQL at start.
	InventoryFile string `mapstructure:"inventory_file"`
	// KeepPeerAddress keeps network.peer.address in the output. It raises
	// the number of series with the number of peer addresses.
	KeepPeerAddress bool `mapstructure:"keep_peer_address"`
	// Retention is how long rows are kept in PostgreSQL after they were
	// last seen; zero keeps them forever. The connector deletes older rows
	// every hour.
	Retention time.Duration `mapstructure:"retention"`
	// Translations are relays without an agent that rewrite the addresses of
	// connections (load balancers, virtual addresses, TCP proxies), by name.
	// The client edges to their virtual addresses are matched with the
	// server edges of their backends, in PostgreSQL and in the names of
	// peers.
	Translations map[string]TranslationConfig `mapstructure:"translations"`
	// HostIdentity tells whom the connector believes about the host of a
	// request. "certificate" accepts the metrics of a host only over gRPC
	// from an agent whose verified client certificate names the host.name
	// it sends (as a DNS name, or as the common name of a certificate
	// without DNS names), so that an agent cannot write as another host;
	// the receiver must require client certificates. "none" (the default)
	// believes the host.name and host.id of every request.
	HostIdentity string `mapstructure:"host_identity"`
	// MaxHosts bounds the hosts the connector holds: those that sent within
	// idle_ttl. The requests of further hosts are refused until hosts
	// expire; the hosts held are never evicted.
	MaxHosts int `mapstructure:"max_hosts"`
	// MaxSeriesPerHost bounds the edges, listeners, translations and
	// addresses the connector holds per host, from their first request
	// until idle_ttl after their latest. Further ones are dropped until
	// some expire, and the host is not observed meanwhile.
	MaxSeriesPerHost int `mapstructure:"max_series_per_host"`
	// MaxPendingRows bounds the rows kept for PostgreSQL while they cannot
	// be written. Beyond it, the changes of the hosts pending the longest
	// are dropped, and the hosts are not observed over them.
	MaxPendingRows int `mapstructure:"max_pending_rows"`
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

// maxWriteInterval is the longest write interval.
const maxWriteInterval = time.Minute

// The defaults of max_hosts, max_series_per_host and max_pending_rows are
// far above what one connector serves (it takes the requests of its hosts
// one at a time), what a large host sends (the flow table of an agent holds
// 16384 flows per interval by default), and the rows of such a fleet.
const (
	defaultMaxHosts         = 10000
	defaultMaxSeriesPerHost = 100000
	defaultMaxPendingRows   = 10000000
)

func createDefaultConfig() *Config {
	return &Config{
		WriteInterval:    time.Minute,
		IdleTTL:          15 * time.Minute,
		MaxPeers:         50,
		MaxServices:      200,
		Retention:        3 * 365 * 24 * time.Hour,
		MaxHosts:         defaultMaxHosts,
		MaxSeriesPerHost: defaultMaxSeriesPerHost,
		MaxPendingRows:   defaultMaxPendingRows,
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if (c.Postgres.DSN == "") == (c.Postgres.DSNFile == "") {
		errs = append(errs, errors.New("postgres: set exactly one of dsn and dsn_file"))
	}
	if c.WriteInterval <= 0 || c.WriteInterval > maxWriteInterval {
		// Connectors learn the agents of the hosts they do not receive from
		// PostgreSQL, which must be fresh within the alive window.
		errs = append(errs, fmt.Errorf("write_interval must be positive and at most %s", maxWriteInterval))
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
	if c.MaxServices < 1 {
		errs = append(errs, errors.New("max_services must be at least 1"))
	}
	if c.MaxHosts < 1 {
		errs = append(errs, errors.New("max_hosts must be at least 1"))
	}
	if c.MaxSeriesPerHost < 1 {
		errs = append(errs, errors.New("max_series_per_host must be at least 1"))
	}
	if c.MaxPendingRows < 1 {
		errs = append(errs, errors.New("max_pending_rows must be at least 1"))
	}
	if _, err := parsePeerCIDRs(c.PeerCIDRs); err != nil {
		errs = append(errs, err)
	}
	if _, err := parseTranslations(c.Translations); err != nil {
		errs = append(errs, err)
	}
	switch c.HostIdentity {
	case "", hostIdentityNone, hostIdentityCertificate:
	default:
		errs = append(errs, fmt.Errorf("host_identity must be %s or %s", hostIdentityNone, hostIdentityCertificate))
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
