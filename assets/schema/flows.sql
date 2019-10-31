CREATE TABLE IF NOT EXISTS processes (
    process_id bigserial NOT NULL PRIMARY KEY,
    ipv4    inet NOT NULL,
    pgid    integer NOT NULL CHECK (pgid >= 0) DEFAULT 0, -- pgid=0 means failure to capture process information
    pname   varchar(50) NOT NULL DEFAULT '', -- TODO: +cmdline
    created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (ipv4, pgid, pname)
);

-- connect side
CREATE TABLE IF NOT EXISTS active_nodes (
    node_id bigserial NOT NULL PRIMARY KEY,
    process_id bigint NOT NULL REFERENCES processes (process_id) ON DELETE CASCADE,

    UNIQUE (process_id)
);

-- listen side
CREATE TABLE IF NOT EXISTS passive_nodes (
    node_id bigserial NOT NULL PRIMARY KEY,
    port    integer NOT NULL CHECK (port > 0),
    process_id bigint NOT NULL REFERENCES processes (process_id) ON DELETE CASCADE,

    UNIQUE (process_id, port)
);
CREATE INDEX IF NOT EXISTS passive_nodes_port_key ON passive_nodes USING btree (port);

CREATE TABLE IF NOT EXISTS flows (
    flow_id                 bigserial NOT NULL PRIMARY KEY,
    source_node_id          bigint NOT NULL REFERENCES active_nodes (node_id) ON DELETE CASCADE,
    destination_node_id     bigint NOT NULL REFERENCES passive_nodes (node_id) ON DELETE CASCADE,
    connections             integer NOT NULL CHECK (connections > 0),
    created                 timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated                 timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (source_node_id, destination_node_id)
);
CREATE INDEX IF NOT EXISTS flows_destination_node_id_source_node_id_key ON flows USING btree (destination_node_id, source_node_id);
