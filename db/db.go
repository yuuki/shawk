package db

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/log15adapter"
	"golang.org/x/xerrors"
	log15 "gopkg.in/inconshreveable/log15.v2"

	"github.com/yuuki/shawk/config"
	"github.com/yuuki/shawk/probe"
	"github.com/yuuki/shawk/statik"
)

var (
	schemas = []string{
		"/schema/flows.sql",
	}
)

// DB represents a Database handler.
type DB struct {
	*pgx.Conn
}

// New creates the DB object.
func New(dbURL string) (*DB, error) {
	conf, err := pgx.ParseConfig(dbURL)
	if err != nil {
		return nil, xerrors.Errorf("Could not parse postgres config (%s): %v", dbURL, err)
	}
	if config.Config.Debug {
		conf.Logger = log15adapter.NewLogger(log15.New("module", "pgx"))
	}

	ctx := context.Background()
	db, err := pgx.ConnectConfig(ctx, conf)
	if err != nil {
		return nil, xerrors.Errorf("Could not connect to postgres: %v", err)
	}
	if err = db.Ping(ctx); err != nil {
		return nil, xerrors.Errorf("postgres ping error: %v", err)
	}
	return &DB{db}, nil
}

// Shutdown finishes the DB connection.
func (db *DB) Shutdown() error {
	return db.Close(context.Background())
}

// CreateSchema creates the table schemas defined by the paths including Schemas.
func (db *DB) CreateSchema() error {
	ctx := context.Background()
	for _, schema := range schemas {
		sql, err := statik.FindString(schema)
		if err != nil {
			return xerrors.Errorf("get schema error '%s': %v", schema, err)
		}
		_, err = db.Exec(ctx, sql)
		if err != nil {
			return xerrors.Errorf("exec schema error '%s': %s", sql, err)
		}
	}
	return nil
}

const (
	// InsertOrUpdateTimeoutSec is the timeout seconds of InsertOrUpdateHostFlows.
	InsertOrUpdateTimeoutSec = 10

	findActiveNodesSQL = `
		SELECT an.node_id FROM flows
		INNER JOIN (SELECT node_id FROM passive_nodes WHERE port = $1)
			AS pn ON pn.node_id = flows.destination_node_id
		INNER JOIN (SELECT node_id FROM active_nodes WHERE process_id IN (
			SELECT process_id FROM processes WHERE ipv4 = $2
		)) AS an ON an.node_id = flows.source_node_id
	`

	findPassiveNodesSQL = `
		SELECT node_id FROM passive_nodes
		WHERE process_id IN (
			SELECT process_id FROM processes WHERE ipv4 = $1
		) AND port = $2
	`

	insertProcessesSQL = `
		INSERT INTO processes (ipv4, pgid, pname, updated)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		ON CONFLICT (ipv4, pgid, pname)
		DO UPDATE SET updated=CURRENT_TIMESTAMP
		RETURNING process_id
	`

	// do update on conflict to avoid to return no rows
	insertActiveNodesSQL = `
		INSERT INTO active_nodes (process_id) VALUES ($1)
		ON CONFLICT (process_id)
		DO UPDATE SET process_id=$1
		RETURNING node_id
	`

	// do update on conflict to avoid to return no rows
	insertPassiveNodesSQL = `
		INSERT INTO passive_nodes (process_id, port) VALUES ($1, $2)
		ON CONFLICT (process_id, port)
		DO UPDATE SET process_id=$1
		RETURNING node_id
	`

	findActiveNodesByProcessSQL = `
		SELECT node_id FROM active_nodes WHERE process_id = $1
	`

	findPassiveNodesByProcessSQL = `
		SELECT node_id FROM passive_nodes WHERE process_id = $1 AND port = $2
	`

	insertFlowsSQL = `
		INSERT INTO flows
		(source_node_id, destination_node_id, connections)
		VALUES ($1, $2, $3)
		ON CONFLICT (source_node_id, destination_node_id)
		DO UPDATE SET connections=$3, updated=CURRENT_TIMESTAMP
	`
)

// InsertOrUpdateHostFlows insert host flows or update it if the same flow exists.
func (db *DB) InsertOrUpdateHostFlows(flows []*probe.HostFlow) error {
	if len(flows) < 1 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), InsertOrUpdateTimeoutSec*time.Second)
	defer cancel()
	tx, err := db.Begin(ctx)
	if err != nil {
		return xerrors.Errorf("begin transaction error: %v", err)
	}

	for _, flow := range flows {
		if flow.Local.Addr == "127.0.0.1" ||
			flow.Local.Addr == "::1" ||
			flow.Peer.Addr == "127.0.0.1" ||
			flow.Peer.Addr == "::1" {
			continue
		}

		var (
			localNodeID, peerNodeID       int64
			localProcessID, peerProcessID int64
			pgid                          int
			pname                         string
		)
		if flow.Process != nil {
			pgid = flow.Process.Pgid
			pname = flow.Process.Name
		}
		// lookup the same node before insert node
		// - if flow.Direction == probe.FlowActive {
		//   - SELECT node_id, port FROM passive_nodes WHERE process_id IN (SELECT process_id FROM processes WHERE ipv4 = flow.Peer.Addr) AND port = flow.Peer.Port
		//   - if not found
		//     - INSERT INTO processes (ipv4, pgid, pname) INTO (flow.Peer.Addr, 0, "")
		//     - INSERT INTO passive_nodes (process_id, port) INTO (process_id, flow.Peer.Port)
		//   - else
		//     - UPDATE updated
		//   - INSERT INTO flows
		// 		(source_node_id, destination_node_id, connections, updated)
		// 		VALUES (localNodeId, peerNodeID, $3, CURRENT_TIMESTAMP)
		// 		ON CONFLICT (source_node_id, destination_node_id)
		// 		DO UPDATE SET connections=$3, updated=CURRENT_TIMESTAMP
		// - else
		//   - SELECT flows.destination_node_id FROM flows INNER JOIN passive_nodes ON passive_nodes.node_id = flows.source_node_id WHERE passive_nodes.port = flow.Local.Port AND flows.destination_node_id = (SELECT node_id FROM active_nodes WHERE process_id IN (SELECT process_id FROM processes WHERE ipv4 = flow.Peer.Addr))
		//   - if not found
		//     - INSERT INTO processes (ipv4, pgid, pname) INTO (flow.Peer.Addr, 0, "")
		//     - INSERT INTO active_nodes (process_id) INTO (process_id)
		//   - else
		//     - UPDATE processes updated
		//   - INSERT INTO flows

		// Insert or update local process
		err := db.QueryRow(ctx, insertProcessesSQL, flow.Local.Addr, pgid, pname).Scan(&localProcessID)
		if err != nil {
			return xerrors.Errorf("query error: %v", err)
		}

		if flow.Direction == probe.FlowPassive {
			// local node is passive open, peer node is active open.

			// Insert or update local node
			err := db.QueryRow(ctx, insertPassiveNodesSQL, localProcessID, flow.Local.Port).Scan(&localNodeID)
			switch {
			case err == pgx.ErrNoRows:
				err := db.QueryRow(
					ctx,
					findPassiveNodesByProcessSQL,
					localProcessID,
					flow.Local.Port,
				).Scan(&localNodeID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("query error: %v", err)
			}

			// Create or update peer node and process
			err = db.QueryRow(ctx, findActiveNodesSQL, flow.Local.Port, flow.Peer.Addr).Scan(&peerNodeID)
			switch {
			case err == pgx.ErrNoRows:
				err := db.QueryRow(ctx, insertProcessesSQL, flow.Peer.Addr, 0, "").Scan(&peerProcessID)
				if err != nil {
					return xerrors.Errorf("insert processes error: %v", err)
				}
				err = db.QueryRow(ctx, insertActiveNodesSQL, peerProcessID).Scan(&peerNodeID)
				if err != nil {
					return xerrors.Errorf("insert active_nodes error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("find active_nodes error: %v", err)
			default:
				// TODO: update
			}

			_, err = db.Exec(ctx, insertFlowsSQL, peerNodeID, localNodeID, flow.Connections)
			if err != nil {
				return xerrors.Errorf("query error: %v", err)
			}
		} else if flow.Direction == probe.FlowActive {
			// peer node is passive open, local node is active open.

			// Insert or update local node
			err := db.QueryRow(ctx, insertActiveNodesSQL, localProcessID).Scan(&localNodeID)
			switch {
			case err == pgx.ErrNoRows:
				err := db.QueryRow(ctx, findActiveNodesSQL, localProcessID).Scan(&localNodeID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("query error: %v", err)
			}

			// Create or update peer node and process
			err = db.QueryRow(ctx, findPassiveNodesSQL, flow.Peer.Addr, flow.Peer.Port).Scan(&peerNodeID)
			switch {
			case err == pgx.ErrNoRows:
				err := db.QueryRow(ctx, insertProcessesSQL, flow.Peer.Addr, 0, "").Scan(&peerProcessID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
				err = db.QueryRow(ctx, insertPassiveNodesSQL, peerProcessID, flow.Peer.Port).Scan(&peerNodeID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("query error: %v", err)
			default:
				// TODO: update
			}

			_, err = db.Exec(ctx, insertFlowsSQL, localNodeID, peerNodeID, flow.Connections)
			if err != nil {
				return xerrors.Errorf("query error: localNodeID=%d, peerNodeID=%d: %v", localNodeID, peerNodeID, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return xerrors.Errorf("transaction commit error: %v", err)
	}
	return nil
}

// Node represents a minimum unit of a graph tree.
type Node struct {
	IPAddr net.IP
	Port   int    // 0 if active node
	Pgid   int    // Process Group ID (Linux)
	Pname  string // Process Name (Linux)
}

func (n *Node) String() string {
	port := fmt.Sprintf("%d", n.Port)
	if n.Port == 0 {
		port = "many"
	}
	return fmt.Sprintf("%s:%s ('%s', pgid=%d)",
		n.IPAddr, port, n.Pname, n.Pgid)
}

// Flow represents a flow between a active node and a passive node.
type Flow struct {
	ActiveNode  *Node
	PassiveNode *Node
	Connections int
}

// Flows represents a collection of flow.
type Flows map[string][]*Flow // flows group by

// FindFlowsCond represents a query condition for FindActiveFlows or FindPassiveFlows.
type FindFlowsCond struct {
	Addrs []net.IP
	Since time.Time
	Until time.Time
}

// FindPassiveFlows queries passive flows to CMDB by the slice of ipaddrs.
func (db *DB) FindPassiveFlows(cond *FindFlowsCond) (Flows, error) {
	if len(cond.Addrs) < 1 {
		return Flows{}, nil
	}
	if cond.Until.IsZero() {
		cond.Until = time.Now()
	}

	// Avoid that pgtype handles addrs as ipv6 address.
	for i, v := range cond.Addrs {
		cond.Addrs[i] = v.To4()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rows, err := db.Query(ctx, `
	SELECT
		DISTINCT ON (pipv4, pn.pname)
		pn.ipv4 AS pipv4,
		pn.pname AS ppname,
		pn.port AS pport,
		pn.pgid AS ppgid,
		active_processes.ipv4 AS aipv4,
		active_processes.pname AS apname,
		active_processes.pgid AS apgid,
		connections,
		flows.updated AS updated
	FROM flows
	INNER JOIN active_nodes ON active_nodes.node_id = flows.source_node_id
	INNER JOIN processes AS active_processes ON active_nodes.process_id = active_processes.process_id
	INNER JOIN (
		SELECT passive_nodes.node_id, passive_nodes.port, passive_processes.* FROM passive_nodes
		INNER JOIN processes AS passive_processes ON passive_processes.process_id = passive_nodes.process_id
		WHERE passive_processes.ipv4 = ANY($1)
	) AS pn ON pn.node_id = flows.destination_node_id
	WHERE flows.updated BETWEEN $2 AND $3
	ORDER BY pn.ipv4, pn.pname, flows.updated DESC
`, cond.Addrs, cond.Since, cond.Until)
	switch {
	case err == pgx.ErrNoRows:
		return Flows{}, nil
	case err != nil:
		return Flows{}, xerrors.Errorf("find passive flows query error: %v", err)
	}
	defer rows.Close()

	flows := make(Flows)
	for rows.Next() {
		var (
			pipv4       net.IP
			ppname      string
			pport       int
			ppgid       int
			aipv4       net.IP
			apname      string
			apgid       int
			connections int
			updated     time.Time
		)
		if err := rows.Scan(
			&pipv4, &ppname, &pport, &ppgid, &aipv4, &apname, &apgid, &connections, &updated,
		); err != nil {
			return nil, xerrors.Errorf("rows scan error: %v", err)
		}
		key := fmt.Sprintf("%s-%s", pipv4, ppname)
		flows[key] = append(flows[key], &Flow{
			ActiveNode: &Node{
				IPAddr: aipv4,
				Port:   0,
				Pgid:   apgid,
				Pname:  apname,
			},
			PassiveNode: &Node{
				IPAddr: pipv4,
				Port:   pport,
				Pgid:   ppgid,
				Pname:  ppname,
			},
			Connections: connections,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, xerrors.Errorf("rows error: %v", err)
	}

	return flows, nil
}

// FindActiveFlows queries active flows to CMDB by the slice of ipaddrs.
func (db *DB) FindActiveFlows(cond *FindFlowsCond) (Flows, error) {
	if len(cond.Addrs) < 1 {
		return Flows{}, nil
	}
	if cond.Until.IsZero() {
		cond.Until = time.Now()
	}

	// Avoid that pgtype handles addrs as ipv6 address.
	for i, v := range cond.Addrs {
		cond.Addrs[i] = v.To4()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rows, err := db.Query(ctx, `
	SELECT
		DISTINCT ON (aipv4, an.pname)
		an.ipv4 AS aipv4,
		an.pname AS apname,
		passive_nodes.port AS pport,
		an.pgid AS apgid,
		passive_processes.ipv4 AS pipv4,
		passive_processes.pname AS ppname,
		passive_processes.pgid AS ppgid,
		connections,
		flows.updated AS updated
	FROM flows
	INNER JOIN passive_nodes ON passive_nodes.node_id = flows.destination_node_id
	INNER JOIN processes AS passive_processes ON passive_nodes.process_id = passive_processes.process_id
	INNER JOIN (
		SELECT node_id, active_processes.* FROM active_nodes
		INNER JOIN processes AS active_processes ON active_processes.process_id = active_nodes.process_id
		WHERE active_processes.ipv4 = ANY($1)
	) AS an ON an.node_id = flows.source_node_id
	WHERE flows.updated BETWEEN $2 AND $3
	ORDER BY an.ipv4, an.pname, flows.updated DESC
`, cond.Addrs, cond.Since, cond.Until)
	switch {
	case err == pgx.ErrNoRows:
		return Flows{}, nil
	case err != nil:
		return Flows{}, xerrors.Errorf("find active flows query error: %v", err)
	}
	defer rows.Close()

	flows := make(Flows)
	for rows.Next() {
		var (
			aipv4       net.IP
			apname      string
			pport       int
			apgid       int
			pipv4       net.IP
			ppname      string
			ppgid       int
			connections int
			updated     time.Time
		)
		if err := rows.Scan(&aipv4, &apname, &pport, &apgid, &pipv4, &ppname, &ppgid, &connections, &updated); err != nil {
			return nil, xerrors.Errorf("rows scan error: %v", err)
		}
		key := fmt.Sprintf("%s-%s", aipv4, apname)
		flows[key] = append(flows[key], &Flow{
			ActiveNode: &Node{
				IPAddr: aipv4,
				Port:   0,
				Pgid:   apgid,
				Pname:  apname,
			},
			PassiveNode: &Node{
				IPAddr: pipv4,
				Port:   pport,
				Pgid:   ppgid,
				Pname:  ppname,
			},
			Connections: connections,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, xerrors.Errorf("rows error: %v", err)
	}

	return flows, nil
}
