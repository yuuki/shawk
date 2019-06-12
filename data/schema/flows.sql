CREATE TYPE flow_direction AS ENUM ('active', 'passive');

CREATE TABLE IF NOT EXISTS nodes (
    node_id bigserial NOT NULL PRIMARY KEY,
    ipv4    inet NOT NULL,
    port    integer NOT NULL CHECK (port >= 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_ipv4_port ON nodes USING btree (ipv4, port);

CREATE TABLE IF NOT EXISTS flows (
    flow_id                 bigserial NOT NULL PRIMARY KEY,
    direction               flow_direction NOT NULL,
    source_node_id          bigint NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    destination_node_id     bigint NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    connections             integer NOT NULL CHECK (connections > 0),
    created                 timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated                 timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (source_node_id, destination_node_id, direction)
);
CREATE UNIQUE INDEX IF NOT EXISTS flows_source_dest_direction_idx ON flows USING btree (source_node_id, destination_node_id, direction);
CREATE INDEX IF NOT EXISTS flows_dest_source_idx ON flows USING btree (destination_node_id, source_node_id);
