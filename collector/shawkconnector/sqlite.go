package shawkconnector

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	sqliteSchemaVersion      = 1
	defaultSQLiteBusyTimeout = 5 * time.Second
)

const sqliteSchemaDDL = `
CREATE TABLE IF NOT EXISTS hosts (
  id             TEXT PRIMARY KEY,
  hostname       TEXT NOT NULL,
  last_seen      INTEGER NOT NULL,
  last_heartbeat INTEGER NOT NULL,
  udp_traced     INTEGER NOT NULL DEFAULT 0,
  peer_fold      TEXT NOT NULL DEFAULT 'none',
  peer_internal  TEXT
);
CREATE INDEX IF NOT EXISTS hosts_last_seen ON hosts (last_seen);
CREATE INDEX IF NOT EXISTS hosts_last_heartbeat ON hosts (last_heartbeat);

CREATE TABLE IF NOT EXISTS host_addrs (
  host_id    TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  addr       TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  PRIMARY KEY (host_id, addr, first_seen)
);
CREATE INDEX IF NOT EXISTS host_addrs_addr ON host_addrs (addr, last_seen);
CREATE INDEX IF NOT EXISTS host_addrs_last_seen ON host_addrs (last_seen);

CREATE TABLE IF NOT EXISTS listeners (
  host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  proto        TEXT NOT NULL,
  addr         TEXT NOT NULL,
  port         INTEGER NOT NULL,
  netns        INTEGER NOT NULL,
  service_name TEXT,
  slurm_job    INTEGER NOT NULL DEFAULT 0,
  last_seen    INTEGER NOT NULL,
  PRIMARY KEY (host_id, proto, addr, port, netns)
);
CREATE INDEX IF NOT EXISTS listeners_host_last ON listeners (host_id, last_seen);
CREATE INDEX IF NOT EXISTS listeners_last_seen ON listeners (last_seen);

CREATE TABLE IF NOT EXISTS unix_listeners (
  host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  path         TEXT NOT NULL,
  netns        INTEGER NOT NULL,
  service_name TEXT NOT NULL,
  slurm_job    INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  PRIMARY KEY (host_id, path, netns, service_name, slurm_job)
);
CREATE INDEX IF NOT EXISTS unix_listeners_host_last ON unix_listeners (host_id, last_seen);
CREATE INDEX IF NOT EXISTS unix_listeners_last_seen ON unix_listeners (last_seen);

CREATE TABLE IF NOT EXISTS server_endpoints (
  host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  proto        TEXT NOT NULL,
  local_addr   TEXT NOT NULL,
  port         INTEGER NOT NULL,
  service_name TEXT NOT NULL,
  slurm_job    INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  PRIMARY KEY (host_id, proto, local_addr, port, service_name, slurm_job)
);
CREATE INDEX IF NOT EXISTS server_endpoints_host_last ON server_endpoints (host_id, last_seen);
CREATE INDEX IF NOT EXISTS server_endpoints_last_seen ON server_endpoints (last_seen);

CREATE TABLE IF NOT EXISTS client_endpoints (
  host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  proto        TEXT NOT NULL,
  client_addr  TEXT NOT NULL,
  server_addr  TEXT NOT NULL,
  port         INTEGER NOT NULL,
  service_name TEXT NOT NULL,
  slurm_job    INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  PRIMARY KEY (host_id, proto, client_addr, server_addr, port, service_name, slurm_job)
);
CREATE INDEX IF NOT EXISTS client_endpoints_last_seen ON client_endpoints (last_seen);

CREATE TABLE IF NOT EXISTS learned_translations (
  host_id      TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  proto        TEXT NOT NULL,
  netns        INTEGER NOT NULL,
  client_addr  TEXT NOT NULL,
  virtual_addr TEXT NOT NULL,
  virtual_port INTEGER NOT NULL,
  source_addr  TEXT NOT NULL,
  backend_addr TEXT NOT NULL,
  backend_port INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  PRIMARY KEY (host_id, proto, netns, client_addr, virtual_addr, virtual_port, source_addr, backend_addr, backend_port)
);
CREATE INDEX IF NOT EXISTS learned_translations_last_seen ON learned_translations (last_seen);

CREATE TABLE IF NOT EXISTS inventory_hosts (
  host       TEXT PRIMARY KEY,
  slurm_node TEXT UNIQUE,
  roles_json TEXT NOT NULL DEFAULT '[]',
  agent      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS inventory_addrs (
  addr TEXT PRIMARY KEY,
  host TEXT NOT NULL REFERENCES inventory_hosts(host) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS inventory_addrs_host ON inventory_addrs (host);

CREATE TABLE IF NOT EXISTS inventory_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  digest    TEXT,
  read_at   INTEGER,
  failed_at INTEGER,
  error     TEXT
);
`

// sqliteStore persists the connector's peer-resolution state and inventory in
// an embedded SQLite database for single-connector lightweight mode without
// PostgreSQL.
type sqliteStore struct {
	mu         sync.Mutex
	db         *sql.DB
	lockFile   *os.File
	inMemory   bool
	learnedTTL time.Duration
	now        func() time.Time
}

type sqliteDriverConnector struct {
	drv *sqlite.Driver
	dsn string
}

func (c *sqliteDriverConnector) Connect(context.Context) (driver.Conn, error) {
	return c.drv.Open(c.dsn)
}

func (c *sqliteDriverConnector) Driver() driver.Driver {
	return c.drv
}

// newSQLiteStore opens or creates the embedded SQLite database configured by
// cfg, acquires an exclusive flock for file-backed databases so that two
// connector processes cannot share one file, and applies WAL and per-connection
// PRAGMAs on every physical connection opened by database/sql.
func newSQLiteStore(ctx context.Context, cfg SQLiteConfig, learnedTTL time.Duration) (*sqliteStore, error) {
	if err := validateSQLitePath(cfg.Path); err != nil {
		return nil, err
	}
	busy := cfg.BusyTimeout
	if busy <= 0 {
		busy = defaultSQLiteBusyTimeout
	}
	inMem := cfg.Path == ":memory:"
	dbPath := cfg.Path
	var lockFile *os.File
	if !inMem {
		dbPath = filepath.Clean(cfg.Path)
		lf, err := acquireSQLiteLock(dbPath)
		if err != nil {
			return nil, err
		}
		lockFile = lf
	}

	perConnPragmas := []string{
		"PRAGMA foreign_keys = ON",
		fmt.Sprintf("PRAGMA busy_timeout = %d", busy.Milliseconds()),
		"PRAGMA temp_store = MEMORY",
		"PRAGMA cache_size = -16384",
		"PRAGMA mmap_size = 0",
	}
	if !inMem {
		perConnPragmas = append(perConnPragmas, "PRAGMA synchronous = NORMAL")
	}

	drv := &sqlite.Driver{}
	drv.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, _ string) error {
		for _, p := range perConnPragmas {
			if _, err := conn.ExecContext(context.Background(), p, nil); err != nil {
				return fmt.Errorf("sqlite %s: %w", p, err)
			}
		}
		return nil
	})
	db := sql.OpenDB(&sqliteDriverConnector{drv: drv, dsn: dbPath})
	// One connection serializes writes and avoids SQLITE_BUSY contention inside
	// this process while the connection hook re-applies PRAGMAs if database/sql
	// ever replaces the underlying connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		releaseSQLiteLock(lockFile)
		return nil, fmt.Errorf("opening sqlite %s: %w", dbPath, err)
	}
	if !inMem {
		// auto_vacuum must be set before tables are created on a new database.
		for _, p := range []string{"PRAGMA auto_vacuum = INCREMENTAL", "PRAGMA journal_mode = WAL"} {
			if _, err := db.ExecContext(ctx, p); err != nil {
				_ = db.Close()
				releaseSQLiteLock(lockFile)
				return nil, fmt.Errorf("sqlite %s: %w", p, err)
			}
		}
	}
	return &sqliteStore{
		db:         db,
		lockFile:   lockFile,
		inMemory:   inMem,
		learnedTTL: learnedTTL,
		now:        time.Now,
	}, nil
}

func acquireSQLiteLock(dbPath string) (*os.File, error) {
	lockPath := dbPath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite lock %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("sqlite database %s is locked by another shawk-connector process", dbPath)
		}
		return nil, fmt.Errorf("locking sqlite %s: %w", lockPath, err)
	}
	return f, nil
}

func releaseSQLiteLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

func (s *sqliteStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
	releaseSQLiteLock(s.lockFile)
	s.lockFile = nil
}

func (s *sqliteStore) schemaVersion(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.schemaVersionLocked(ctx)
}

func (s *sqliteStore) schemaVersionLocked(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

func (s *sqliteStore) migrate(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.schemaVersionLocked(ctx)
	if err != nil {
		return nil, err
	}
	if v > sqliteSchemaVersion {
		return nil, fmt.Errorf("sqlite schema version %d is newer than connector version %d", v, sqliteSchemaVersion)
	}
	if v == sqliteSchemaVersion {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, sqliteSchemaDDL); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", sqliteSchemaVersion)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return []string{"0001_sqlite_schema"}, nil
}

func (s *sqliteStore) write(ctx context.Context, h *hostChanges) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := sqliteWriteHost(ctx, tx, h); err != nil {
		return err
	}
	return tx.Commit()
}

func sqliteWriteHost(ctx context.Context, tx *sql.Tx, h *hostChanges) error {
	var lastHB int64
	var udpTraced int
	peerFold := foldNone
	var peerInternal sql.NullString
	for _, sess := range h.sessions {
		hb := sess.lastHeartbeat.UnixNano()
		if hb >= lastHB {
			lastHB = hb
			if sess.udpTraced {
				udpTraced = 1
			} else {
				udpTraced = 0
			}
			if sess.peerFold != "" {
				peerFold = sess.peerFold
			} else {
				peerFold = foldNone
			}
			if sess.peerInternal != nil {
				ps := make([]string, len(sess.peerInternal))
				for i, p := range sess.peerInternal {
					ps[i] = p.String()
				}
				b, err := json.Marshal(ps)
				if err != nil {
					return err
				}
				peerInternal = sql.NullString{String: string(b), Valid: true}
			} else {
				peerInternal = sql.NullString{}
			}
		}
	}
	var lastSeen int64
	if !h.last.IsZero() {
		lastSeen = h.last.UnixNano()
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO hosts (id, hostname, last_seen, last_heartbeat, udp_traced, peer_fold, peer_internal)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  hostname       = CASE WHEN excluded.last_seen >= hosts.last_seen THEN excluded.hostname ELSE hosts.hostname END,
  last_seen      = max(hosts.last_seen, excluded.last_seen),
  last_heartbeat = CASE WHEN excluded.last_heartbeat >= hosts.last_heartbeat THEN excluded.last_heartbeat ELSE hosts.last_heartbeat END,
  udp_traced     = CASE WHEN excluded.last_heartbeat >= hosts.last_heartbeat AND excluded.last_heartbeat > 0 THEN excluded.udp_traced ELSE hosts.udp_traced END,
  peer_fold      = CASE WHEN excluded.last_heartbeat >= hosts.last_heartbeat AND excluded.last_heartbeat > 0 THEN excluded.peer_fold ELSE hosts.peer_fold END,
  peer_internal  = CASE WHEN excluded.last_heartbeat >= hosts.last_heartbeat AND excluded.last_heartbeat > 0 THEN excluded.peer_internal ELSE hosts.peer_internal END`,
		h.key, h.hostname, lastSeen, lastHB, udpTraced, peerFold, peerInternal); err != nil {
		return err
	}

	if err := sqliteWriteAddrs(ctx, tx, h); err != nil {
		return err
	}
	if err := sqliteWriteListeners(ctx, tx, h); err != nil {
		return err
	}
	if err := sqliteWriteEdges(ctx, tx, h); err != nil {
		return err
	}
	return sqliteWriteTranslations(ctx, tx, h)
}

func sqliteWriteAddrs(ctx context.Context, tx *sql.Tx, h *hostChanges) error {
	if len(h.addrs) == 0 {
		return nil
	}
	selStmt, err := tx.PrepareContext(ctx, `
SELECT first_seen, last_seen FROM host_addrs
WHERE host_id = ? AND addr = ?
ORDER BY first_seen DESC LIMIT 1`)
	if err != nil {
		return err
	}
	defer selStmt.Close()
	updStmt, err := tx.PrepareContext(ctx, `
UPDATE host_addrs SET last_seen = max(last_seen, ?)
WHERE host_id = ? AND addr = ? AND first_seen = ?`)
	if err != nil {
		return err
	}
	defer updStmt.Close()
	insStmt, err := tx.PrepareContext(ctx, `
INSERT INTO host_addrs (host_id, addr, first_seen, last_seen)
VALUES (?, ?, ?, ?)
ON CONFLICT(host_id, addr, first_seen) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer insStmt.Close()

	for a, sp := range h.addrs {
		addr := a.Unmap().String()
		f, l := sp.first.UnixNano(), sp.last.UnixNano()
		var latestFirst, latestLast int64
		err := selStmt.QueryRowContext(ctx, h.key, addr).Scan(&latestFirst, &latestLast)
		if err == nil && f <= latestLast+int64(aliveWindow) {
			if _, err := updStmt.ExecContext(ctx, l, h.key, addr, latestFirst); err != nil {
				return err
			}
			continue
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := insStmt.ExecContext(ctx, h.key, addr, f, l); err != nil {
			return err
		}
	}
	return nil
}

func sqliteWriteListeners(ctx context.Context, tx *sql.Tx, h *hostChanges) error {
	if len(h.listeners) == 0 {
		return nil
	}
	type netKey struct {
		proto string
		addr  string
		port  uint16
		netns int64
	}
	type netVal struct {
		lastSeen  int64
		hasOwner  bool
		ownerLast int64
		service   string
		slurmJob  int
	}
	type unixKeyRow struct {
		path     string
		netns    int64
		service  string
		slurmJob int
	}
	netRows := map[netKey]*netVal{}
	unixRows := map[unixKeyRow]int64{}

	for k, sp := range h.listeners {
		last := sp.last.UnixNano()
		if k.proto == transportUnix {
			if k.procKey == (procKey{}) {
				continue
			}
			uk := unixKeyRow{path: k.path, netns: int64(k.netns), service: k.service, slurmJob: boolToInt(strings.HasPrefix(k.unit, slurmJobUnit))}
			if last > unixRows[uk] {
				unixRows[uk] = last
			}
			continue
		}
		nk := netKey{proto: k.proto, addr: k.addr.Unmap().String(), port: k.port, netns: int64(k.netns)}
		v := netRows[nk]
		if v == nil {
			v = &netVal{}
			netRows[nk] = v
		}
		if last > v.lastSeen {
			v.lastSeen = last
		}
		if k.procKey != (procKey{}) && (!v.hasOwner || last >= v.ownerLast) {
			v.hasOwner = true
			v.ownerLast = last
			v.service = k.service
			v.slurmJob = boolToInt(strings.HasPrefix(k.unit, slurmJobUnit))
		}
	}

	if len(netRows) > 0 {
		upsertStmt, err := tx.PrepareContext(ctx, `
INSERT INTO listeners (host_id, proto, addr, port, netns, service_name, slurm_job, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id, proto, addr, port, netns) DO UPDATE SET
  service_name = CASE WHEN excluded.last_seen >= listeners.last_seen AND excluded.service_name IS NOT NULL THEN excluded.service_name ELSE listeners.service_name END,
  slurm_job    = CASE WHEN excluded.last_seen >= listeners.last_seen AND excluded.service_name IS NOT NULL THEN excluded.slurm_job ELSE listeners.slurm_job END,
  last_seen    = max(listeners.last_seen, excluded.last_seen)`)
		if err != nil {
			return err
		}
		defer upsertStmt.Close()
		for nk, v := range netRows {
			var svc sql.NullString
			var job int
			if v.hasOwner {
				svc = sql.NullString{String: v.service, Valid: true}
				job = v.slurmJob
			}
			if _, err := upsertStmt.ExecContext(ctx, h.key, nk.proto, nk.addr, int(nk.port), nk.netns, svc, job, v.lastSeen); err != nil {
				return err
			}
		}
	}

	if len(unixRows) > 0 {
		stmt, err := tx.PrepareContext(ctx, `
INSERT INTO unix_listeners (host_id, path, netns, service_name, slurm_job, last_seen)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id, path, netns, service_name, slurm_job) DO UPDATE SET
  last_seen = max(unix_listeners.last_seen, excluded.last_seen)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for uk, last := range unixRows {
			if _, err := stmt.ExecContext(ctx, h.key, uk.path, uk.netns, uk.service, uk.slurmJob, last); err != nil {
				return err
			}
		}
	}
	return nil
}

func sqliteWriteEdges(ctx context.Context, tx *sql.Tx, h *hostChanges) error {
	if len(h.edges) == 0 {
		return nil
	}
	type srvKey struct {
		proto, local, service string
		port                  uint16
		slurmJob              int
	}
	type cliKey struct {
		proto, client, server, service string
		port                           uint16
		slurmJob                       int
	}
	srvs := map[srvKey]int64{}
	clis := map[cliKey]int64{}

	for k, sp := range h.edges {
		if k.proto == transportUnix {
			continue
		}
		last := sp.last.UnixNano()
		job := boolToInt(strings.HasPrefix(k.unit, slurmJobUnit))
		switch k.role {
		case roleServer:
			sk := srvKey{proto: k.proto, local: k.local.Unmap().String(), port: k.port, service: k.service, slurmJob: job}
			if last > srvs[sk] {
				srvs[sk] = last
			}
		case roleClient:
			if k.folded {
				continue
			}
			ck := cliKey{proto: k.proto, client: k.local.Unmap().String(), server: k.peer.Unmap().String(), port: k.port, service: k.service, slurmJob: job}
			if last > clis[ck] {
				clis[ck] = last
			}
		}
	}

	if len(srvs) > 0 {
		stmt, err := tx.PrepareContext(ctx, `
INSERT INTO server_endpoints (host_id, proto, local_addr, port, service_name, slurm_job, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id, proto, local_addr, port, service_name, slurm_job) DO UPDATE SET
  last_seen = max(server_endpoints.last_seen, excluded.last_seen)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for sk, last := range srvs {
			if _, err := stmt.ExecContext(ctx, h.key, sk.proto, sk.local, int(sk.port), sk.service, sk.slurmJob, last); err != nil {
				return err
			}
		}
	}

	if len(clis) > 0 {
		stmt, err := tx.PrepareContext(ctx, `
INSERT INTO client_endpoints (host_id, proto, client_addr, server_addr, port, service_name, slurm_job, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id, proto, client_addr, server_addr, port, service_name, slurm_job) DO UPDATE SET
  last_seen = max(client_endpoints.last_seen, excluded.last_seen)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for ck, last := range clis {
			if _, err := stmt.ExecContext(ctx, h.key, ck.proto, ck.client, ck.server, int(ck.port), ck.service, ck.slurmJob, last); err != nil {
				return err
			}
		}
	}
	return nil
}

func sqliteWriteTranslations(ctx context.Context, tx *sql.Tx, h *hostChanges) error {
	if len(h.translations) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO learned_translations (host_id, proto, netns, client_addr, virtual_addr, virtual_port,
                                  source_addr, backend_addr, backend_port, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host_id, proto, netns, client_addr, virtual_addr, virtual_port, source_addr, backend_addr, backend_port)
DO UPDATE SET last_seen = max(learned_translations.last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, sp := range h.translations {
		if _, err := stmt.ExecContext(ctx, h.key, k.proto, int64(k.netns),
			k.client.Unmap().String(), k.virtual.Unmap().String(), int(k.vport),
			k.source.Unmap().String(), k.backend.Unmap().String(), int(k.bport),
			sp.last.UnixNano()); err != nil {
			return err
		}
	}
	return nil
}

type sqliteHostInfo struct {
	hostname      string
	lastSeen      int64
	lastHeartbeat int64
	udpTraced     bool
	peerFold      string
	peerInternal  []netip.Prefix
}

type sqliteHostAddrKey struct {
	hostID string
	addr   netip.Addr
}

func (s *sqliteStore) peers(ctx context.Context, learnedTTL, formerWindow time.Duration) (peerRows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out peerRows
	now := s.now()
	recentCutoff := now.Add(-30 * 24 * time.Hour).UnixNano()
	aliveCutoff := now.Add(-aliveWindow).UnixNano()
	var formerCutoff int64
	hostCutoff := recentCutoff
	if formerWindow > 0 {
		formerCutoff = now.Add(-formerWindow).UnixNano()
		if formerCutoff < hostCutoff {
			hostCutoff = formerCutoff
		}
	}

	allHosts := map[string]sqliteHostInfo{}
	recentHosts := map[string]sqliteHostInfo{}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, hostname, last_seen, last_heartbeat, udp_traced, peer_fold, peer_internal
FROM hosts
WHERE last_seen > ?`, hostCutoff)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var id string
		var hi sqliteHostInfo
		var udp int
		var internal sql.NullString
		if err := rows.Scan(&id, &hi.hostname, &hi.lastSeen, &hi.lastHeartbeat, &udp, &hi.peerFold, &internal); err != nil {
			rows.Close()
			return out, err
		}
		hi.udpTraced = udp != 0
		if internal.Valid {
			var ps []string
			if err := json.Unmarshal([]byte(internal.String), &ps); err == nil {
				hi.peerInternal = parsePrefixes(ps)
			}
		}
		allHosts[id] = hi
		if hi.lastSeen > recentCutoff {
			recentHosts[id] = hi
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()

	// Scan relevant host_addrs once to compute currentAddrs, moved addresses,
	// agentAddrs and formerHolders with the same semantics as PostgreSQL.
	type addrPeriod struct {
		first, last int64
	}
	type rawAddr struct {
		hostID string
		addr   netip.Addr
		first  int64
		last   int64
	}
	var allAddrs []rawAddr
	hostMaxLast := map[string]int64{}
	mine := map[sqliteHostAddrKey]int64{}
	newest := map[netip.Addr]int64{}
	formerByAddrHost := map[sqliteHostAddrKey]addrPeriod{}

	rows, err = s.db.QueryContext(ctx, `
SELECT host_id, addr, first_seen, last_seen
FROM host_addrs
WHERE last_seen > ?`, hostCutoff)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var hostID, addrStr string
		var first, last int64
		if err := rows.Scan(&hostID, &addrStr, &first, &last); err != nil {
			rows.Close()
			return out, err
		}
		a, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}
		a = a.Unmap()
		allAddrs = append(allAddrs, rawAddr{hostID: hostID, addr: a, first: first, last: last})
		if first > newest[a] {
			newest[a] = first
		}
		if _, ok := recentHosts[hostID]; ok {
			if last > hostMaxLast[hostID] {
				hostMaxLast[hostID] = last
			}
			k := sqliteHostAddrKey{hostID: hostID, addr: a}
			if last > mine[k] {
				mine[k] = last
			}
		}
		if formerWindow > 0 && last > formerCutoff && !a.IsLoopback() {
			k := sqliteHostAddrKey{hostID: hostID, addr: a}
			cur, ok := formerByAddrHost[k]
			if !ok || last > cur.last || (last == cur.last && first > cur.first) {
				formerByAddrHost[k] = addrPeriod{first: first, last: last}
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()

	moved := map[sqliteHostAddrKey]bool{}
	for k, myLast := range mine {
		if !k.addr.IsLoopback() && newest[k.addr] > myLast+int64(aliveWindow) {
			moved[k] = true
		}
	}

	currentAddrs := map[string]map[netip.Addr]bool{}
	aliveAddrs := map[sqliteHostAddrKey]int64{}
	for _, r := range allAddrs {
		hi, ok := recentHosts[r.hostID]
		if !ok {
			continue
		}
		if r.last >= hostMaxLast[r.hostID]-int64(aliveWindow) {
			m := currentAddrs[r.hostID]
			if m == nil {
				m = map[netip.Addr]bool{}
				currentAddrs[r.hostID] = m
			}
			m[r.addr] = true
		}
		if hi.lastHeartbeat > aliveCutoff && r.last > aliveCutoff {
			k := sqliteHostAddrKey{hostID: r.hostID, addr: r.addr}
			if r.last > aliveAddrs[k] {
				aliveAddrs[k] = r.last
			}
		}
	}
	for k, seen := range aliveAddrs {
		hi := recentHosts[k.hostID]
		out.agents = append(out.agents, agentAddrRow{
			addr: k.addr,
			host: k.hostID,
			seen: time.Unix(0, seen).UTC(),
			agent: agentHost{
				seen:      time.Unix(0, hi.lastHeartbeat).UTC(),
				udpTraced: hi.udpTraced,
				name:      hi.hostname,
				fold:      hi.peerFold,
				internal:  hi.peerInternal,
			},
		})
	}

	if formerWindow > 0 {
		type candidate struct {
			hostID string
			addrPeriod
		}
		byAddr := map[netip.Addr][]candidate{}
		for k, p := range formerByAddrHost {
			byAddr[k.addr] = append(byAddr[k.addr], candidate{hostID: k.hostID, addrPeriod: p})
		}
		for a, cs := range byAddr {
			best := cs[0]
			for _, c := range cs[1:] {
				if c.last > best.last || (c.last == best.last && c.hostID < best.hostID) {
					best = c
				}
			}
			shared := false
			for _, o := range cs {
				if o.hostID != best.hostID && o.last > best.first+int64(shareWindow) {
					shared = true
					break
				}
			}
			if shared {
				continue
			}
			hi, ok := allHosts[best.hostID]
			if !ok {
				continue
			}
			out.former = append(out.former, formerHolderRow{
				addr: a,
				formerHolder: formerHolder{
					host:     best.hostID,
					name:     hi.hostname,
					lastSeen: time.Unix(0, best.last).UTC(),
				},
			})
		}
	}

	if out.endpoints, err = s.queryServiceEndpoints(ctx, recentCutoff, currentAddrs, moved); err != nil {
		return out, err
	}
	if out.clients, err = s.queryClientEndpoints(ctx, now.Add(-time.Hour).UnixNano()); err != nil {
		return out, err
	}
	if out.unix, err = s.queryUnixEndpoints(ctx, recentCutoff); err != nil {
		return out, err
	}
	if out.learned, err = s.queryLearnedTranslations(ctx, now.Add(-learnedTTL).UnixNano()); err != nil {
		return out, err
	}
	return out, nil
}

func (s *sqliteStore) queryServiceEndpoints(
	ctx context.Context,
	recentCutoff int64,
	currentAddrs map[string]map[netip.Addr]bool,
	moved map[sqliteHostAddrKey]bool,
) ([]endpointRow, error) {
	type groupKey struct {
		addr    netip.Addr
		port    uint16
		proto   string
		hostID  string
		service string
	}
	type groupVal struct {
		lastSeen int64
		exact    bool
		slurmJob bool
	}
	merged := map[groupKey]*groupVal{}
	add := func(hostID, proto string, addr netip.Addr, port uint16, service string, lastSeen int64, exact, slurmJob bool) {
		if moved[sqliteHostAddrKey{hostID: hostID, addr: addr}] {
			return
		}
		k := groupKey{addr: addr, port: port, proto: proto, hostID: hostID, service: service}
		v := merged[k]
		if v == nil {
			merged[k] = &groupVal{lastSeen: lastSeen, exact: exact, slurmJob: slurmJob}
			return
		}
		if lastSeen > v.lastSeen {
			v.lastSeen = lastSeen
		}
		v.exact = v.exact || exact
		v.slurmJob = v.slurmJob || slurmJob
	}

	rows, err := s.db.QueryContext(ctx, `
WITH recent_hosts AS (SELECT id FROM hosts WHERE last_seen > ?),
listened AS (
  SELECT l.host_id, max(l.last_seen) AS max_last
  FROM listeners l
  JOIN recent_hosts h ON h.id = l.host_id
  GROUP BY l.host_id
)
SELECT l.host_id, l.proto, l.addr, l.port, l.service_name, l.slurm_job, l.last_seen
FROM listened li
JOIN listeners l ON l.host_id = li.host_id AND l.last_seen >= li.max_last - ?
WHERE l.service_name IS NOT NULL`, recentCutoff, int64(time.Hour))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hostID, proto, addrStr, svc string
		var port, job int
		var lastSeen int64
		if err := rows.Scan(&hostID, &proto, &addrStr, &port, &svc, &job, &lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		a, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if !a.IsUnspecified() {
			add(hostID, proto, a, uint16(port), svc, lastSeen, true, job != 0)
			continue
		}
		for ca := range currentAddrs[hostID] {
			if a.Is6() || ca.Is4() {
				add(hostID, proto, ca, uint16(port), svc, lastSeen, false, job != 0)
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `
WITH recent_hosts AS (SELECT id FROM hosts WHERE last_seen > ?),
reported AS (
  SELECT host_id, max(max_last) AS max_last
  FROM (
    SELECT l.host_id, max(l.last_seen) AS max_last
    FROM listeners l
    JOIN recent_hosts h ON h.id = l.host_id
    GROUP BY l.host_id
    UNION ALL
    SELECT se.host_id, max(se.last_seen) AS max_last
    FROM server_endpoints se
    JOIN recent_hosts h ON h.id = se.host_id
    GROUP BY se.host_id
  )
  GROUP BY host_id
)
SELECT se.host_id, se.proto, se.local_addr, se.port, se.service_name, se.slurm_job, se.last_seen
FROM reported r
JOIN server_endpoints se ON se.host_id = r.host_id AND se.last_seen >= r.max_last - ?`, recentCutoff, int64(7*24*time.Hour))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hostID, proto, addrStr, svc string
		var port, job int
		var lastSeen int64
		if err := rows.Scan(&hostID, &proto, &addrStr, &port, &svc, &job, &lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		a, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}
		add(hostID, proto, a.Unmap(), uint16(port), svc, lastSeen, true, job != 0)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	out := make([]endpointRow, 0, len(merged))
	for k, v := range merged {
		svc := k.service
		if v.slurmJob {
			svc = slurmJobService
		}
		out = append(out, endpointRow{
			key: endpointKey{addr: k.addr, port: k.port, proto: k.proto},
			endpoint: endpoint{
				host:     k.hostID,
				service:  svc,
				exact:    v.exact,
				lastSeen: time.Unix(0, v.lastSeen).UTC(),
			},
		})
	}
	return out, nil
}

func (s *sqliteStore) queryClientEndpoints(ctx context.Context, cutoff int64) ([]clientRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT client_addr, server_addr, port, proto, host_id, service_name, slurm_job, last_seen
FROM client_endpoints
WHERE last_seen > ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []clientRow
	for rows.Next() {
		var clientStr, serverStr, proto, hostID, svc string
		var port, job int
		var last int64
		if err := rows.Scan(&clientStr, &serverStr, &port, &proto, &hostID, &svc, &job, &last); err != nil {
			return nil, err
		}
		ca, err1 := netip.ParseAddr(clientStr)
		sa, err2 := netip.ParseAddr(serverStr)
		if err1 != nil || err2 != nil {
			continue
		}
		if job != 0 {
			svc = slurmJobService
		}
		out = append(out, clientRow{
			key: clientKey{client: ca.Unmap(), server: sa.Unmap(), port: uint16(port), proto: proto},
			endpoint: endpoint{
				host:     hostID,
				service:  svc,
				exact:    true,
				lastSeen: time.Unix(0, last).UTC(),
			},
		})
	}
	return out, rows.Err()
}

func (s *sqliteStore) queryUnixEndpoints(ctx context.Context, recentCutoff int64) ([]unixEndpointRow, error) {
	type groupKey struct {
		hostID  string
		path    string
		netns   uint64
		service string
	}
	type groupVal struct {
		lastSeen int64
		slurmJob bool
	}
	merged := map[groupKey]*groupVal{}
	rows, err := s.db.QueryContext(ctx, `
WITH recent_hosts AS (SELECT id FROM hosts WHERE last_seen > ?),
latest AS (
  SELECT u.host_id, max(u.last_seen) AS max_last
  FROM unix_listeners u
  JOIN recent_hosts h ON h.id = u.host_id
  GROUP BY u.host_id
)
SELECT u.host_id, u.path, u.netns, u.service_name, u.slurm_job, u.last_seen
FROM latest la
JOIN unix_listeners u ON u.host_id = la.host_id AND u.last_seen >= la.max_last - ?`, recentCutoff, int64(time.Hour))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hostID, path, svc string
		var netns, lastSeen int64
		var job int
		if err := rows.Scan(&hostID, &path, &netns, &svc, &job, &lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		k := groupKey{hostID: hostID, path: path, netns: uint64(netns), service: svc}
		v := merged[k]
		if v == nil {
			merged[k] = &groupVal{lastSeen: lastSeen, slurmJob: job != 0}
			continue
		}
		if lastSeen > v.lastSeen {
			v.lastSeen = lastSeen
		}
		v.slurmJob = v.slurmJob || (job != 0)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	out := make([]unixEndpointRow, 0, len(merged))
	for k, v := range merged {
		svc := k.service
		if v.slurmJob {
			svc = slurmJobService
		}
		out = append(out, unixEndpointRow{
			key:          unixKey{host: k.hostID, path: k.path},
			unixEndpoint: unixEndpoint{netns: k.netns, service: svc},
			lastSeen:     time.Unix(0, v.lastSeen).UTC(),
		})
	}
	return out, nil
}

func (s *sqliteStore) queryLearnedTranslations(ctx context.Context, cutoff int64) ([]learnedRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT host_id, proto, netns, client_addr, virtual_addr, virtual_port,
       source_addr, backend_addr, backend_port, last_seen
FROM learned_translations
WHERE last_seen > ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []learnedRow
	for rows.Next() {
		var r learnedRow
		var netns, last int64
		var client, virtual, source, backend string
		var vport, bport int
		if err := rows.Scan(&r.host, &r.id.proto, &netns, &client, &virtual, &vport, &source, &backend, &bport, &last); err != nil {
			return nil, err
		}
		var addrs [4]netip.Addr
		valid := true
		for i, a := range []string{client, virtual, source, backend} {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				valid = false
				break
			}
			addrs[i] = addr.Unmap()
		}
		if !valid {
			continue
		}
		r.id.netns, r.id.vport, r.id.bport = uint64(netns), uint16(vport), uint16(bport)
		r.id.client, r.id.virtual, r.id.source, r.id.backend = addrs[0], addrs[1], addrs[2], addrs[3]
		r.lastSeen = time.Unix(0, last).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// prune deletes expired rows from the internal peer-resolution cache tables
// using fixed windows (up to 31 days for stopped hosts, shorter per-host
// windows for stale endpoints of active hosts) and reclaims pages
// incrementally. Parent host rows are removed only after all child rows are
// drained so maxRows is never bypassed by ON DELETE CASCADE.
func (s *sqliteStore) prune(ctx context.Context, _ time.Duration, maxRows int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	learnedWindow := s.learnedTTL
	if learnedWindow < time.Hour {
		learnedWindow = time.Hour
	}
	deadHostCutoff := now.Add(-31 * 24 * time.Hour).UnixNano()

	type pruneStmt struct {
		query string
		args  []any
	}
	stmts := []pruneStmt{
		{
			query: `DELETE FROM learned_translations WHERE rowid IN (SELECT rowid FROM learned_translations WHERE last_seen < ? LIMIT ?)`,
			args:  []any{now.Add(-learnedWindow).UnixNano(), maxRows},
		},
		{
			query: `DELETE FROM client_endpoints WHERE rowid IN (SELECT rowid FROM client_endpoints WHERE last_seen < ? LIMIT ?)`,
			args:  []any{now.Add(-2 * time.Hour).UnixNano(), maxRows},
		},
		{
			query: `
DELETE FROM server_endpoints
WHERE rowid IN (
  SELECT se.rowid
  FROM server_endpoints se
  JOIN hosts h ON h.id = se.host_id
  LEFT JOIN (
    SELECT host_id, max(max_last) AS max_last
    FROM (
      SELECT host_id, max(last_seen) AS max_last FROM listeners GROUP BY host_id
      UNION ALL
      SELECT host_id, max(last_seen) AS max_last FROM server_endpoints GROUP BY host_id
    )
    GROUP BY host_id
  ) r ON r.host_id = se.host_id
  WHERE h.last_seen < ? OR se.last_seen < r.max_last - ?
  LIMIT ?
)`,
			args: []any{deadHostCutoff, int64(8 * 24 * time.Hour), maxRows},
		},
		{
			query: `
DELETE FROM listeners
WHERE rowid IN (
  SELECT l.rowid
  FROM listeners l
  JOIN hosts h ON h.id = l.host_id
  LEFT JOIN (
    SELECT host_id, max(last_seen) AS max_last FROM listeners GROUP BY host_id
  ) m ON m.host_id = l.host_id
  WHERE h.last_seen < ? OR l.last_seen < m.max_last - ?
  LIMIT ?
)`,
			args: []any{deadHostCutoff, int64(2 * time.Hour), maxRows},
		},
		{
			query: `
DELETE FROM unix_listeners
WHERE rowid IN (
  SELECT u.rowid
  FROM unix_listeners u
  JOIN hosts h ON h.id = u.host_id
  LEFT JOIN (
    SELECT host_id, max(last_seen) AS max_last FROM unix_listeners GROUP BY host_id
  ) m ON m.host_id = u.host_id
  WHERE h.last_seen < ? OR u.last_seen < m.max_last - ?
  LIMIT ?
)`,
			args: []any{deadHostCutoff, int64(2 * time.Hour), maxRows},
		},
		{
			query: `DELETE FROM host_addrs WHERE rowid IN (SELECT rowid FROM host_addrs WHERE last_seen < ? LIMIT ?)`,
			args:  []any{deadHostCutoff, maxRows},
		},
		{
			query: `
DELETE FROM hosts
WHERE rowid IN (
  SELECT h.rowid FROM hosts h
  WHERE h.last_seen < ?
    AND NOT EXISTS (SELECT 1 FROM host_addrs x WHERE x.host_id = h.id)
    AND NOT EXISTS (SELECT 1 FROM listeners x WHERE x.host_id = h.id)
    AND NOT EXISTS (SELECT 1 FROM unix_listeners x WHERE x.host_id = h.id)
    AND NOT EXISTS (SELECT 1 FROM server_endpoints x WHERE x.host_id = h.id)
    AND NOT EXISTS (SELECT 1 FROM client_endpoints x WHERE x.host_id = h.id)
    AND NOT EXISTS (SELECT 1 FROM learned_translations x WHERE x.host_id = h.id)
  LIMIT ?
)`,
			args: []any{deadHostCutoff, maxRows},
		},
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	for _, st := range stmts {
		res, err := tx.ExecContext(ctx, st.query, st.args...)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if total > 0 && !s.inMemory {
		_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(1000)`)
		_, _ = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`)
	}
	return total, nil
}

func (s *sqliteStore) syncConfig(context.Context, []namedPrefix, []translation, *portRules) error {
	return nil
}

func (s *sqliteStore) portRuleKeys(context.Context) ([]string, error) {
	return nil, nil
}

func (s *sqliteStore) refreshDependencies(context.Context) (int64, error) {
	return 0, nil
}

func (s *sqliteStore) writeNodeStates(context.Context, time.Time, []nodeState) error {
	return nil
}

func (s *sqliteStore) syncMaintenance(context.Context, []maintenanceWindow) error {
	return nil
}

func (s *sqliteStore) syncInventory(ctx context.Context, inv *inventory, readAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var digest sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT digest FROM inventory_state WHERE singleton = 1`).Scan(&digest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if !digest.Valid || digest.String != inv.digest {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inventory_addrs`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inventory_hosts`); err != nil {
			return err
		}
		hostStmt, err := tx.PrepareContext(ctx, `INSERT INTO inventory_hosts (host, slurm_node, roles_json, agent) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer hostStmt.Close()
		addrStmt, err := tx.PrepareContext(ctx, `INSERT INTO inventory_addrs (addr, host) VALUES (?, ?)`)
		if err != nil {
			return err
		}
		defer addrStmt.Close()
		for _, h := range inv.hosts {
			var node sql.NullString
			if h.slurmNode != "" {
				node = sql.NullString{String: h.slurmNode, Valid: true}
			}
			roles := h.roles
			if roles == nil {
				roles = []string{}
			}
			rb, err := json.Marshal(roles)
			if err != nil {
				return err
			}
			if _, err := hostStmt.ExecContext(ctx, h.name, node, string(rb), boolToInt(h.agent)); err != nil {
				return err
			}
			for _, a := range h.addrs {
				if _, err := addrStmt.ExecContext(ctx, a.Unmap().String(), h.name); err != nil {
					return err
				}
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO inventory_state (singleton, digest, read_at, failed_at, error)
VALUES (1, ?, ?, NULL, NULL)
ON CONFLICT(singleton) DO UPDATE SET digest = excluded.digest, read_at = excluded.read_at, failed_at = NULL, error = NULL`,
		inv.digest, readAt.UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqliteStore) inventoryFailed(ctx context.Context, failedAt time.Time, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO inventory_state (singleton, failed_at, error)
VALUES (1, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET failed_at = excluded.failed_at, error = excluded.error`,
		failedAt.UnixNano(), msg)
	return err
}

func (s *sqliteStore) inventory(ctx context.Context) (*inventory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, `SELECT host, slurm_node, roles_json, agent FROM inventory_hosts ORDER BY host`)
	if err != nil {
		return nil, err
	}
	byName := map[string]*inventoryHost{}
	var hosts []inventoryHost
	for rows.Next() {
		var h inventoryHost
		var node sql.NullString
		var rolesJSON string
		var agent int
		if err := rows.Scan(&h.name, &node, &rolesJSON, &agent); err != nil {
			rows.Close()
			return nil, err
		}
		if node.Valid {
			h.slurmNode = node.String
		}
		h.agent = agent != 0
		if err := json.Unmarshal([]byte(rolesJSON), &h.roles); err != nil {
			rows.Close()
			return nil, err
		}
		if len(h.roles) == 0 {
			h.roles = nil
		}
		slices.Sort(h.roles)
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(hosts) == 0 {
		return nil, nil
	}
	slices.SortFunc(hosts, func(a, b inventoryHost) int { return strings.Compare(a.name, b.name) })
	for i := range hosts {
		byName[hosts[i].name] = &hosts[i]
	}

	arows, err := s.db.QueryContext(ctx, `SELECT addr, host FROM inventory_addrs`)
	if err != nil {
		return nil, err
	}
	defer arows.Close()
	byAddr := map[netip.Addr]string{}
	for arows.Next() {
		var addrStr, host string
		if err := arows.Scan(&addrStr, &host); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(addrStr)
		if err != nil {
			return nil, err
		}
		a = a.Unmap()
		if h := byName[host]; h != nil {
			h.addrs = append(h.addrs, a)
			byAddr[a] = host
		}
	}
	if err := arows.Err(); err != nil {
		return nil, err
	}
	for i := range hosts {
		slices.SortFunc(hosts[i].addrs, netip.Addr.Compare)
	}
	return &inventory{hosts: hosts, byAddr: byAddr, digest: inventoryDigest(hosts)}, nil
}

func isSQLiteDataError(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() & 0xff {
	case sqlite3.SQLITE_TOOBIG, sqlite3.SQLITE_CONSTRAINT, sqlite3.SQLITE_MISMATCH:
		return true
	}
	return false
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
