package shawkconnector

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// store persists the changes of hosts and reads the names of peers.
type store interface {
	// migrate brings the schema up to date.
	migrate(ctx context.Context) ([]string, error)
	// write writes the changes of a host in one transaction.
	write(ctx context.Context, h *hostChanges) error
	// prune deletes up to maxRows rows per table last seen more than
	// retention ago, by the clock of the database, and returns how many it
	// deleted.
	prune(ctx context.Context, retention time.Duration, maxRows int) (int64, error)
	// peers reads the endpoints of services, the client sides of
	// connections and the addresses of agents.
	peers(ctx context.Context) (peerRows, error)
	close()
}

type pgStore struct {
	pool *pgxpool.Pool
}

// newPGStore returns a store backed by PostgreSQL. It connects lazily, so
// that the collector starts while the database is down.
func newPGStore(ctx context.Context, dsn string) (store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// The error may quote the DSN, which may hold a password.
		return nil, fmt.Errorf("invalid PostgreSQL connection string")
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "shawk-connector"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &pgStore{pool: pool}, nil
}

func (s *pgStore) close() { s.pool.Close() }

func (s *pgStore) migrate(ctx context.Context) ([]string, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	return Migrate(ctx, conn.Conn())
}

func (s *pgStore) write(ctx context.Context, h *hostChanges) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) })
}

func writeHost(ctx context.Context, tx pgx.Tx, h *hostChanges) error {
	b := &pgx.Batch{}
	b.Queue(`
INSERT INTO shawk.hosts AS h (id, machine_id, hostname, kernel, agent_version, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
  machine_id    = CASE WHEN excluded.last_seen >= h.last_seen THEN excluded.machine_id ELSE h.machine_id END,
  hostname      = CASE WHEN excluded.last_seen >= h.last_seen THEN excluded.hostname ELSE h.hostname END,
  kernel        = CASE WHEN excluded.last_seen >= h.last_seen THEN excluded.kernel ELSE h.kernel END,
  agent_version = CASE WHEN excluded.last_seen >= h.last_seen THEN excluded.agent_version ELSE h.agent_version END,
  first_seen    = least(h.first_seen, excluded.first_seen),
  last_seen     = greatest(h.last_seen, excluded.last_seen)`,
		h.key, h.machineID, h.hostname, h.kernel, h.version, h.first, h.last)

	if len(h.sessions) > 0 {
		var starts, beats []time.Time
		var udp []bool
		var scopes []string
		var dropped []int64
		var skews []float64
		for t, s := range h.sessions {
			starts = append(starts, t)
			beats = append(beats, s.lastHeartbeat)
			udp = append(udp, s.udpTraced)
			scopes = append(scopes, s.netnsScope)
			dropped = append(dropped, s.dropped)
			skews = append(skews, s.clockSkew.Seconds())
		}
		b.Queue(`
INSERT INTO shawk.agent_sessions AS s (host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows, clock_skew)
SELECT $1, u.started, u.beat, u.udp, u.scope, u.dropped, make_interval(secs => u.skew)
FROM unnest($2::timestamptz[], $3::timestamptz[], $4::boolean[], $5::text[], $6::bigint[], $7::float8[])
  AS u(started, beat, udp, scope, dropped, skew)
ON CONFLICT (host_id, started_at) DO UPDATE SET
  clock_skew     = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat THEN excluded.clock_skew ELSE s.clock_skew END,
  udp_traced     = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat THEN excluded.udp_traced ELSE s.udp_traced END,
  netns_scope    = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat THEN excluded.netns_scope ELSE s.netns_scope END,
  dropped_flows  = greatest(s.dropped_flows, excluded.dropped_flows),
  last_heartbeat = greatest(s.last_heartbeat, excluded.last_heartbeat)`,
			h.key, starts, beats, udp, scopes, dropped, skews)
	}

	if len(h.addrs) > 0 {
		var addrs []string
		var firsts, lasts []time.Time
		for a, s := range h.addrs {
			addrs = append(addrs, a.String())
			firsts = append(firsts, s.first)
			lasts = append(lasts, s.last)
		}
		b.Queue(`
INSERT INTO shawk.host_addrs AS a (host_id, addr, first_seen, last_seen)
SELECT $1, u.addr::inet, u.f, u.l FROM unnest($2::text[], $3::timestamptz[], $4::timestamptz[]) AS u(addr, f, l)
ON CONFLICT (host_id, addr) DO UPDATE SET
  first_seen = least(a.first_seen, excluded.first_seen),
  last_seen  = greatest(a.last_seen, excluded.last_seen)`,
			h.key, addrs, firsts, lasts)
	}

	if len(h.processes) > 0 {
		var units, comms, exes, services []string
		var firsts, lasts []time.Time
		for k, p := range h.processes {
			units = append(units, k.unit)
			comms = append(comms, k.comm)
			exes = append(exes, p.exe)
			services = append(services, k.service)
			firsts = append(firsts, p.first)
			lasts = append(lasts, p.last)
		}
		b.Queue(`
INSERT INTO shawk.processes AS p (host_id, unit, comm, exe, service_name, first_seen, last_seen)
SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::timestamptz[])
ON CONFLICT (host_id, unit, comm, service_name) DO UPDATE SET
  exe          = CASE WHEN excluded.last_seen >= p.last_seen THEN excluded.exe ELSE p.exe END,
  first_seen   = least(p.first_seen, excluded.first_seen),
  last_seen    = greatest(p.last_seen, excluded.last_seen)`,
			h.key, units, comms, exes, services, firsts, lasts)
	}

	if len(h.edges) > 0 {
		var units, comms, services, roles, protos, locals, peers []string
		var ports []int32
		var netns []int64
		var firsts, lasts []time.Time
		for k, s := range h.edges {
			units = append(units, k.unit)
			comms = append(comms, k.comm)
			services = append(services, k.service)
			roles = append(roles, k.role)
			protos = append(protos, k.proto)
			locals = append(locals, k.local.String())
			peers = append(peers, k.peer.String())
			ports = append(ports, int32(k.port))
			netns = append(netns, int64(k.netns))
			firsts = append(firsts, s.first)
			lasts = append(lasts, s.last)
		}
		b.Queue(`
INSERT INTO shawk.edges AS e (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
SELECT $1, p.id, u.role, u.proto, u.local::inet, u.peer::inet, u.port, u.netns, u.f, u.l
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::integer[],
            $10::bigint[], $11::timestamptz[], $12::timestamptz[])
  AS u(unit, comm, service, role, proto, local, peer, port, netns, f, l)
JOIN shawk.processes p ON p.host_id = $1 AND p.unit = u.unit AND p.comm = u.comm AND p.service_name = u.service
ON CONFLICT (host_id, role, proto, local_addr, remote_addr, port, netns, process_id) DO UPDATE SET
  first_seen = least(e.first_seen, excluded.first_seen),
  last_seen  = greatest(e.last_seen, excluded.last_seen)`,
			h.key, units, comms, services, roles, protos, locals, peers, ports, netns, firsts, lasts)
	}

	if len(h.listeners) > 0 {
		var units, comms, services, protos, addrs []string
		var ports []int32
		var netns []int64
		var firsts, lasts []time.Time
		for k, l := range h.listeners {
			units = append(units, l.proc.unit)
			comms = append(comms, l.proc.comm)
			services = append(services, l.proc.service)
			protos = append(protos, k.proto)
			addrs = append(addrs, k.addr.String())
			ports = append(ports, int32(k.port))
			netns = append(netns, int64(k.netns))
			firsts = append(firsts, l.first)
			lasts = append(lasts, l.last)
		}
		b.Queue(`
INSERT INTO shawk.listeners AS l (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
SELECT $1, p.id, u.proto, u.addr::inet, u.port, u.netns, u.f, u.l
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::integer[], $8::bigint[],
            $9::timestamptz[], $10::timestamptz[]) AS u(unit, comm, service, proto, addr, port, netns, f, l)
LEFT JOIN shawk.processes p ON p.host_id = $1 AND p.unit = u.unit AND p.comm = u.comm
  AND p.service_name = u.service AND (u.unit <> '' OR u.comm <> '')
ON CONFLICT (host_id, proto, addr, port, netns) DO UPDATE SET
  process_id = CASE WHEN excluded.last_seen >= l.last_seen THEN coalesce(excluded.process_id, l.process_id)
                    ELSE l.process_id END,
  first_seen = least(l.first_seen, excluded.first_seen),
  last_seen  = greatest(l.last_seen, excluded.last_seen)`,
			h.key, units, comms, services, protos, addrs, ports, netns, firsts, lasts)
	}
	return tx.SendBatch(ctx, b).Close()
}

func (s *pgStore) prune(ctx context.Context, retention time.Duration, maxRows int) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT shawk.prune(now() - make_interval(secs => $1), $2)`,
		retention.Seconds(), maxRows).Scan(&n)
	return n, err
}

func (s *pgStore) peers(ctx context.Context) (peerRows, error) {
	var out peerRows
	err := queryRows(ctx, s.pool, `SELECT host(addr), port, proto, host_id, service, last_seen, exact FROM shawk_v1.service_endpoints`,
		func(rows pgx.Rows) error {
			var addr string
			var port int32
			var e endpointRow
			if err := rows.Scan(&addr, &port, &e.key.proto, &e.host, &e.service, &e.lastSeen, &e.exact); err != nil {
				return err
			}
			if a, err := netip.ParseAddr(addr); err == nil {
				e.key.addr, e.key.port = a.Unmap(), uint16(port)
				out.endpoints = append(out.endpoints, e)
			}
			return nil
		})
	if err != nil {
		return out, err
	}
	err = queryRows(ctx, s.pool, `SELECT host(client_addr), host(server_addr), port, proto, host_id, service, last_seen
FROM shawk_v1.client_endpoints`,
		func(rows pgx.Rows) error {
			var client, server string
			var port int32
			var c clientRow
			if err := rows.Scan(&client, &server, &port, &c.key.proto, &c.host, &c.service, &c.lastSeen); err != nil {
				return err
			}
			ca, err1 := netip.ParseAddr(client)
			sa, err2 := netip.ParseAddr(server)
			if err1 == nil && err2 == nil {
				c.key.client, c.key.server, c.key.port = ca.Unmap(), sa.Unmap(), uint16(port)
				c.exact = true
				out.clients = append(out.clients, c)
			}
			return nil
		})
	if err != nil {
		return out, err
	}
	err = queryRows(ctx, s.pool, `SELECT host(addr), host_id, last_seen, udp_traced, netns_scope = 'all' FROM shawk_v1.agent_addrs`,
		func(rows pgx.Rows) error {
			var addr string
			var r agentAddrRow
			if err := rows.Scan(&addr, &r.host, &r.seen, &r.udpTraced, &r.allNetNS); err != nil {
				return err
			}
			if a, err := netip.ParseAddr(addr); err == nil {
				r.addr = a.Unmap()
				out.agents = append(out.agents, r)
			}
			return nil
		})
	return out, err
}

func queryRows(ctx context.Context, pool *pgxpool.Pool, sql string, scan func(pgx.Rows) error) error {
	rows, err := pool.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
