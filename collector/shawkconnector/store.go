package shawkconnector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	// schemaVersion returns the version of the schema, 0 if it predates
	// the function that tells it.
	schemaVersion(ctx context.Context) (int, error)
	// syncPeerCIDRs replaces the named address ranges of peers.
	syncPeerCIDRs(ctx context.Context, cidrs []namedPrefix) error
	// refreshDependencies brings the history of dependencies between
	// services up to date.
	refreshDependencies(ctx context.Context) (int64, error)
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
	// Writes wait for a migration in progress, which holds this lock, so
	// that they do not deadlock with it. The lock is taken before the batch:
	// preparing its statements already locks the tables they write.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, int64(migrationLock)); err != nil {
		return err
	}
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
		queueSessions(b, h)
	}

	if len(h.addrs) > 0 {
		var addrs []string
		var firsts, lasts []time.Time
		for a, s := range h.addrs {
			addrs = append(addrs, a.String())
			firsts = append(firsts, s.first)
			lasts = append(lasts, s.last)
		}
		// An address continues the latest period the host held it in, unless
		// it was not seen for longer than the alive window, which starts a
		// new period: an address that moved away and came back was not held
		// in between.
		b.Queue(`
WITH u AS (
  SELECT u.addr::inet AS addr, u.f, u.l FROM unnest($2::text[], $3::timestamptz[], $4::timestamptz[]) AS u(addr, f, l)
),
latest AS (
  SELECT DISTINCT ON (a.addr) a.addr, a.first_seen, a.last_seen
  FROM shawk.host_addrs a JOIN u ON u.addr = a.addr
  WHERE a.host_id = $1
  ORDER BY a.addr, a.first_seen DESC
),
continued AS (
  UPDATE shawk.host_addrs a SET last_seen = greatest(a.last_seen, u.l)
  FROM u JOIN latest ON latest.addr = u.addr
  WHERE a.host_id = $1 AND a.addr = u.addr AND a.first_seen = latest.first_seen
    AND u.f <= latest.last_seen + shawk.alive_window()
  RETURNING a.addr
)
INSERT INTO shawk.host_addrs AS a (host_id, addr, first_seen, last_seen)
SELECT $1, u.addr, u.f, u.l FROM u WHERE u.addr NOT IN (SELECT addr FROM continued)
ON CONFLICT (host_id, addr, first_seen) DO UPDATE SET last_seen = greatest(a.last_seen, excluded.last_seen)`,
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
			peers = append(peers, peerString(k.peer, k.folded))
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
		queueListeners(b, h)
	}
	return tx.SendBatch(ctx, b).Close()
}

// queueSessions writes the sessions of a host, and the periods in which its
// agent dropped flows.
//
// The dropped flows of a session are compared with what PostgreSQL holds,
// so that a restart of the connector, or several connectors, record the same
// periods: an increase since the heartbeat written before is recorded as a
// period from that heartbeat to the new one, which extends the latest period
// of the session when they meet. A session written for the first time
// continues the latest session of the host if the counter of the agent ran
// then (the agent did not restart: a new segment, or a new connector, starts
// a new session) and did not decrease; its drops since that session are
// recorded from the start of the session, or the end of that session if it
// ends later. Otherwise every drop it counts is recorded from its start.
// Times are by the clock of the connector, like heartbeats.
//
// The upsert of the host before has locked its row, so that the writes of a
// host wait for each other and each compares with the one before.
func queueSessions(b *pgx.Batch, h *hostChanges) {
	var starts, beats []time.Time
	var counters []*time.Time // nil if unknown
	var udp []bool
	var scopes, folds []string
	var internals []*string
	var dropped []int64
	var skews []float64
	var anyDropped bool
	for t, s := range h.sessions {
		starts = append(starts, t)
		beats = append(beats, s.lastHeartbeat)
		udp = append(udp, s.udpTraced)
		scopes = append(scopes, s.netnsScope)
		dropped = append(dropped, s.dropped)
		skews = append(skews, s.clockSkew.Seconds())
		var counter *time.Time
		if !s.droppedSince.IsZero() {
			counter = &s.droppedSince
		}
		counters = append(counters, counter)
		folds = append(folds, s.peerFold)
		var internal *string
		if s.peerInternal != nil {
			ps := make([]string, len(s.peerInternal))
			for i, p := range s.peerInternal {
				ps[i] = p.String()
			}
			v := strings.Join(ps, ",")
			internal = &v
		}
		internals = append(internals, internal)
		anyDropped = anyDropped || s.dropped > 0
	}
	if anyDropped {
		b.Queue(`
WITH u AS (
  SELECT * FROM unnest($2::timestamptz[], $3::timestamptz[], $4::bigint[], $5::float8[], $6::timestamptz[])
    AS u(started, beat, dropped, skew, counter_start)
),
d AS (
  SELECT u.started, u.beat, u.dropped,
         least(u.started + make_interval(secs => u.skew), u.beat) AS start,
         cur.last_heartbeat AS cur_beat, cur.dropped_flows AS cur_dropped,
         prev.last_heartbeat AS prev_beat, prev.dropped_flows AS prev_dropped,
         prev.last_heartbeat IS NOT NULL AND prev.dropped_flows <= u.dropped
           AND coalesce(u.counter_start <= prev.last_heartbeat, true) AS same_run
  FROM u
  LEFT JOIN shawk.agent_sessions cur ON cur.host_id = $1 AND cur.started_at = u.started
  LEFT JOIN LATERAL (
    SELECT p.last_heartbeat, p.dropped_flows FROM shawk.agent_sessions p
    WHERE p.host_id = $1 AND p.last_heartbeat <= u.beat
    ORDER BY p.last_heartbeat DESC LIMIT 1
  ) prev ON cur.started_at IS NULL
),
inc AS (
  SELECT started, beat,
         CASE WHEN cur_beat IS NOT NULL THEN cur_beat
              WHEN same_run THEN greatest(start, prev_beat)
              ELSE start END AS since,
         dropped - CASE WHEN cur_beat IS NOT NULL THEN cur_dropped
                        WHEN same_run THEN prev_dropped
                        ELSE 0 END AS n
  FROM d
),
p AS (SELECT * FROM inc WHERE n > 0 AND beat > since),
latest AS (
  SELECT DISTINCT ON (o.started_at) o.started_at, o.period_start, o.period_end
  FROM shawk.partial_observations o JOIN p ON p.started = o.started_at
  WHERE o.host_id = $1
  ORDER BY o.started_at, o.period_start DESC
),
extended AS (
  UPDATE shawk.partial_observations o
  SET period_end = greatest(o.period_end, p.beat), dropped_flows = o.dropped_flows + p.n
  FROM p JOIN latest ON latest.started_at = p.started
  WHERE o.host_id = $1 AND o.started_at = p.started AND o.period_start = latest.period_start
    AND p.since <= latest.period_end
  RETURNING o.started_at
)
INSERT INTO shawk.partial_observations AS o (host_id, started_at, period_start, period_end, dropped_flows)
SELECT $1, p.started, p.since, p.beat, p.n FROM p
WHERE p.started NOT IN (SELECT started_at FROM extended)
ON CONFLICT (host_id, started_at, period_start) DO UPDATE SET
  period_end    = greatest(o.period_end, excluded.period_end),
  dropped_flows = o.dropped_flows + excluded.dropped_flows`,
			h.key, starts, beats, dropped, skews, counters)
	}
	// What the agent folds is kept as of the latest heartbeat, unless the
	// session row does not tell it.
	b.Queue(`
INSERT INTO shawk.agent_sessions AS s (host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows, clock_skew,
                                       peer_fold, peer_internal)
SELECT $1, u.started, u.beat, u.udp, u.scope, u.dropped, make_interval(secs => u.skew),
       nullif(u.fold, ''), CASE WHEN u.fold <> '' THEN string_to_array(u.internal, ',')::cidr[] END
FROM unnest($2::timestamptz[], $3::timestamptz[], $4::boolean[], $5::text[], $6::bigint[], $7::float8[],
            $8::text[], $9::text[])
  AS u(started, beat, udp, scope, dropped, skew, fold, internal)
ON CONFLICT (host_id, started_at) DO UPDATE SET
  clock_skew     = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat THEN excluded.clock_skew ELSE s.clock_skew END,
  udp_traced     = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat THEN excluded.udp_traced ELSE s.udp_traced END,
  netns_scope    = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat THEN excluded.netns_scope ELSE s.netns_scope END,
  peer_fold      = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat AND excluded.peer_fold IS NOT NULL
                        THEN excluded.peer_fold ELSE s.peer_fold END,
  peer_internal  = CASE WHEN excluded.last_heartbeat >= s.last_heartbeat AND excluded.peer_fold IS NOT NULL
                        THEN excluded.peer_internal ELSE s.peer_internal END,
  dropped_flows  = greatest(s.dropped_flows, excluded.dropped_flows),
  last_heartbeat = greatest(s.last_heartbeat, excluded.last_heartbeat)`,
		h.key, starts, beats, udp, scopes, dropped, skews, folds, internals)
}

// queueListeners writes the listeners of a host: a row per listener with
// its latest owner, and a row per known owner of a listener, which keeps its
// history when it changes hands.
func queueListeners(b *pgx.Batch, h *hostChanges) {
	type listener struct {
		proto string
		addr  netip.Addr
		port  uint16
		netns uint64
	}
	type latest struct {
		proc procKey
		span
		known time.Time // last_seen of the latest known owner
	}
	// The latest owner of a listener in this write; one whose owner is
	// unknown at the end keeps the latest known one.
	rows := map[listener]*latest{}
	var units, comms, services, protos, addrs []string
	var ports []int32
	var netns []int64
	var firsts, lasts []time.Time
	for k, s := range h.listeners {
		l := listener{k.proto, k.addr, k.port, k.netns}
		r := rows[l]
		if r == nil {
			r = &latest{span: s}
			rows[l] = r
		}
		r.span.merge(s)
		if k.procKey != (procKey{}) && !s.last.Before(r.known) {
			r.proc, r.known = k.procKey, s.last
		}
		if k.procKey == (procKey{}) {
			continue
		}
		units = append(units, k.unit)
		comms = append(comms, k.comm)
		services = append(services, k.service)
		protos = append(protos, k.proto)
		addrs = append(addrs, k.addr.String())
		ports = append(ports, int32(k.port))
		netns = append(netns, int64(k.netns))
		firsts = append(firsts, s.first)
		lasts = append(lasts, s.last)
	}
	if len(units) > 0 {
		b.Queue(`
INSERT INTO shawk.listener_owners AS o (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
SELECT $1, p.id, u.proto, u.addr::inet, u.port, u.netns, u.f, u.l
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::integer[], $8::bigint[],
            $9::timestamptz[], $10::timestamptz[]) AS u(unit, comm, service, proto, addr, port, netns, f, l)
JOIN shawk.processes p ON p.host_id = $1 AND p.unit = u.unit AND p.comm = u.comm AND p.service_name = u.service
ON CONFLICT (host_id, proto, addr, port, netns, process_id) DO UPDATE SET
  first_seen = least(o.first_seen, excluded.first_seen),
  last_seen  = greatest(o.last_seen, excluded.last_seen)`,
			h.key, units, comms, services, protos, addrs, ports, netns, firsts, lasts)
	}

	units, comms, services, protos, addrs = nil, nil, nil, nil, nil
	ports, netns, firsts, lasts = nil, nil, nil, nil
	for l, r := range rows {
		units = append(units, r.proc.unit)
		comms = append(comms, r.proc.comm)
		services = append(services, r.proc.service)
		protos = append(protos, l.proto)
		addrs = append(addrs, l.addr.String())
		ports = append(ports, int32(l.port))
		netns = append(netns, int64(l.netns))
		firsts = append(firsts, r.first)
		lasts = append(lasts, r.last)
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

func (s *pgStore) schemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.pool.QueryRow(ctx, `SELECT shawk.schema_version()`).Scan(&v)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "42883" || pgErr.Code == "3F000") {
		// No such function or schema: older than the check.
		return 0, nil
	}
	return v, err
}

func (s *pgStore) syncPeerCIDRs(ctx context.Context, cidrs []namedPrefix) error {
	prefixes := make([]string, 0, len(cidrs))
	names := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		prefixes = append(prefixes, c.prefix.String())
		names = append(names, c.name)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		b.Queue(`DELETE FROM shawk.peer_cidrs WHERE NOT (prefix = ANY ($1::cidr[]))`, prefixes)
		b.Queue(`
INSERT INTO shawk.peer_cidrs (prefix, name)
SELECT * FROM unnest($1::cidr[], $2::text[])
ON CONFLICT (prefix) DO UPDATE SET name = excluded.name`, prefixes, names)
		return tx.SendBatch(ctx, b).Close()
	})
}

func (s *pgStore) refreshDependencies(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT shawk.refresh_known_dependencies()`).Scan(&n)
	return n, err
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
	// A folded server address, a network, is no server.
	err = queryRows(ctx, s.pool, `SELECT host(client_addr), host(server_addr), port, proto, host_id, service, last_seen
FROM shawk_v1.client_endpoints
WHERE masklen(server_addr) = CASE family(server_addr) WHEN 4 THEN 32 ELSE 128 END`,
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
	err = queryRows(ctx, s.pool, `SELECT host(addr), host_id, last_seen, last_heartbeat, udp_traced, host,
  coalesce(peer_fold, ''), peer_internal::text[]
FROM shawk_v1.agent_addrs`,
		func(rows pgx.Rows) error {
			var addr string
			var internal []string
			var r agentAddrRow
			if err := rows.Scan(&addr, &r.host, &r.seen, &r.agent.seen, &r.agent.udpTraced, &r.agent.name,
				&r.agent.fold, &internal); err != nil {
				return err
			}
			if internal != nil {
				r.agent.internal = parsePrefixes(internal)
			}
			if a, err := netip.ParseAddr(addr); err == nil {
				r.addr = a.Unmap()
				out.agents = append(out.agents, r)
			}
			return nil
		})
	return out, err
}

// parsePrefixes parses address ranges, leaving out those that are invalid.
func parsePrefixes(ss []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		if p, err := parsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
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
