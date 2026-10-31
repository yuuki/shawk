CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- A dependency observed on this host: a bundled flow between a local
-- process and a remote address. port is the service port: the remote port
-- of an outgoing edge and the local port of an incoming edge.
CREATE TABLE IF NOT EXISTS edges (
	id          INTEGER PRIMARY KEY,
	direction   TEXT    NOT NULL CHECK (direction IN ('out', 'in')),
	proto       TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp')),
	local_addr  TEXT    NOT NULL,
	remote_addr TEXT    NOT NULL,
	port        INTEGER NOT NULL,
	netns       INTEGER NOT NULL,
	unit        TEXT    NOT NULL, -- normalized service name derived from the cgroup
	comm        TEXT    NOT NULL,
	cgroup      TEXT    NOT NULL DEFAULT '',
	exe         TEXT    NOT NULL DEFAULT '',
	last_pid    INTEGER NOT NULL DEFAULT 0,
	first_seen  INTEGER NOT NULL, -- unix time
	last_seen   INTEGER NOT NULL,
	UNIQUE (direction, proto, local_addr, remote_addr, port, netns, unit, comm)
);
CREATE INDEX IF NOT EXISTS edges_port ON edges (direction, port, last_seen);
CREATE INDEX IF NOT EXISTS edges_remote ON edges (remote_addr, port);
CREATE INDEX IF NOT EXISTS edges_last_seen ON edges (last_seen);

-- Activity of an edge in buckets of res seconds (60, 3600 or 86400).
CREATE TABLE IF NOT EXISTS activity (
	edge_id        INTEGER NOT NULL REFERENCES edges (id) ON DELETE CASCADE,
	res            INTEGER NOT NULL,
	ts             INTEGER NOT NULL, -- start of the bucket, unix time
	conns          INTEGER NOT NULL DEFAULT 0,
	conn_fails     INTEGER NOT NULL DEFAULT 0,
	max_open_conns INTEGER NOT NULL DEFAULT 0,
	bytes_sent     INTEGER NOT NULL DEFAULT 0,
	bytes_recv     INTEGER NOT NULL DEFAULT 0,
	msgs_sent      INTEGER NOT NULL DEFAULT 0,
	msgs_recv      INTEGER NOT NULL DEFAULT 0,
	retrans        INTEGER NOT NULL DEFAULT 0,
	rtt_sum_us     INTEGER NOT NULL DEFAULT 0,
	rtt_count      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (edge_id, res, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS activity_res_ts ON activity (res, ts);

-- Listening TCP sockets and bound UDP server sockets.
CREATE TABLE IF NOT EXISTS listeners (
	id         INTEGER PRIMARY KEY,
	proto      TEXT    NOT NULL,
	addr       TEXT    NOT NULL,
	port       INTEGER NOT NULL,
	netns      INTEGER NOT NULL,
	unit       TEXT    NOT NULL DEFAULT '',
	comm       TEXT    NOT NULL DEFAULT '',
	cgroup     TEXT    NOT NULL DEFAULT '',
	exe        TEXT    NOT NULL DEFAULT '',
	pid        INTEGER NOT NULL DEFAULT 0,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	UNIQUE (proto, addr, port, netns)
);

-- Periods in which the agent recorded flows. Dependencies in a gap between
-- periods are unknown.
CREATE TABLE IF NOT EXISTS coverage (
	start_ts INTEGER NOT NULL, -- unix time
	end_ts   INTEGER NOT NULL,
	udp      INTEGER NOT NULL, -- 1 if UDP was traced
	drops    INTEGER NOT NULL DEFAULT 0 -- flow updates dropped by the kernel
);
CREATE INDEX IF NOT EXISTS coverage_end ON coverage (end_ts);
