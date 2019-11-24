package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq" // database/sql driver
	"github.com/yuuki/lstf/tcpflow"
	"github.com/yuuki/transtracer/statik"
	"golang.org/x/xerrors"
)

const (
	// DefaultDBName is the default name of postgres database.
	DefaultDBName = "ttracer"
	// DefaultDBUserName is the default postgres user name.
	DefaultDBUserName = "ttracer"
	// DefaultDBHostname is the default postgres host name.
	DefaultDBHostname = "localhost"
	// DefaultDBPort is the default postgres port.
	DefaultDBPort = "5432"
	// ConnectTimeout is the default timeout of the connection to the postgres server.
	ConnectTimeout = 5
)

var (
	schemas = []string{
		"/schema/flows.sql",
	}
)

// DB represents a Database handler.
type DB struct {
	*sql.DB
}

// Opt are options for database connection.
// https://godoc.org/github.com/lib/pq
type Opt struct {
	DBName   string
	User     string
	Password string
	Host     string
	Port     string
	SSLMode  string
}

// New creates the DB object.
func New(opt *Opt) (*DB, error) {
	var user, dbname, host, port, sslmode string
	if user = opt.User; user == "" {
		user = DefaultDBUserName
	}
	if dbname = opt.DBName; dbname == "" {
		dbname = DefaultDBName
	}
	if host = opt.Host; host == "" {
		host = DefaultDBHostname
	}
	if port = opt.Port; port == "" {
		port = DefaultDBPort
	}
	if sslmode = opt.SSLMode; sslmode == "" {
		sslmode = "disable"
	}
	db, err := sql.Open("postgres", fmt.Sprintf(
		"user=%s password=%s host=%s port=%s dbname=%s sslmode=%s connect_timeout=%d",
		user, opt.Password, host, port, dbname, sslmode, ConnectTimeout,
	))
	if err != nil {
		return nil, xerrors.Errorf("postgres open error: %v", err)
	}
	if err = db.Ping(); err != nil {
		return nil, xerrors.Errorf("postgres ping error: %v", err)
	}
	return &DB{db}, nil
}

// CreateSchema creates the table schemas defined by the paths including Schemas.
func (db *DB) CreateSchema() error {
	for _, schema := range schemas {
		sql, err := statik.FindString(schema)
		if err != nil {
			return xerrors.Errorf("get schema error '%s': %v", schema, err)
		}
		_, err = db.Exec(fmt.Sprintf("%s", sql))
		if err != nil {
			return xerrors.Errorf("exec schema error '%s': %s", sql, err)
		}
	}
	return nil
}

const (
	// InsertOrUpdateTimeoutSec is the timeout seconds of InsertOrUpdateHostFlows.
	InsertOrUpdateTimeoutSec = 10
)

// InsertOrUpdateHostFlows insert host flows or update it if the same flow exists.
func (db *DB) InsertOrUpdateHostFlows(flows []*tcpflow.HostFlow) error {
	ctx, cancel := context.WithTimeout(context.Background(), InsertOrUpdateTimeoutSec*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return xerrors.Errorf("begin transaction error: %v", err)
	}

	stmtFindActiveNodes, err := tx.PrepareContext(ctx, `
		SELECT flows.source_node_id FROM flows
		INNER JOIN (SELECT node_id FROM passive_nodes WHERE port = $1)
			AS pn ON pn.node_id = flows.destination_node_id
		INNER JOIN (SELECT node_id FROM active_nodes WHERE process_id IN (
			SELECT process_id FROM processes WHERE ipv4 = $2
		)) AS an ON an.node_id = flows.source_node_id
		LIMIT 1
	`)
	if err != nil {
		return xerrors.Errorf("find active_nodes prepare error: %v", err)
	}

	stmtFindPassiveNodes, err := tx.PrepareContext(ctx, `
	SELECT node_id FROM passive_nodes
	WHERE process_id IN ( SELECT process_id FROM processes WHERE ipv4 = $1) AND port = $2
	`)
	if err != nil {
		return xerrors.Errorf("find passive_nodes prepare error: %v", err)
	}

	stmtInsertProcesses, err := tx.PrepareContext(ctx, `
	INSERT INTO processes (ipv4, pgid, pname, updated) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
	ON CONFLICT (ipv4, pgid, pname)
	DO UPDATE SET updated=CURRENT_TIMESTAMP
	RETURNING process_id
	`)
	if err != nil {
		return xerrors.Errorf("query prepare error 'INSERT INTO processes': %v", err)
	}

	// do update on conflict to avoid to return no rows
	stmtInsertActiveNodes, err := tx.PrepareContext(ctx, `
	INSERT INTO active_nodes (process_id) VALUES ($1)
	ON CONFLICT (process_id)
	DO UPDATE SET process_id=$1
	RETURNING node_id
	`)
	if err != nil {
		return xerrors.Errorf("query prepare error 'INSERT INTO passive_nodes': %v", err)
	}

	// do update on conflict to avoid to return no rows
	stmtInsertPassiveNodes, err := tx.PrepareContext(ctx, `
	INSERT INTO passive_nodes (process_id, port) VALUES ($1, $2)
	ON CONFLICT (process_id, port)
	DO UPDATE SET process_id=$1
	RETURNING node_id
	`)
	if err != nil {
		return xerrors.Errorf("query prepare error 'INSERT INTO passive_nodes': %v", err)
	}

	stmtFindActiveNodesByProcess, err := tx.PrepareContext(ctx, `
	SELECT node_id FROM active_nodes WHERE process_id = $1
	`)
	if err != nil {
		return xerrors.Errorf("query prepare error 'SELECT node_id FROM active_nodes': %v", err)
	}
	stmtFindPassiveNodesByProcess, err := tx.PrepareContext(ctx, `
	SELECT node_id FROM passive_nodes WHERE process_id = $1 AND port = $2
	`)
	if err != nil {
		return xerrors.Errorf("query prepare error 'SELECT node_id FROM passive_node': %v", err)
	}

	stmtInsertFlows, err := tx.PrepareContext(ctx, `
	INSERT INTO flows
	(source_node_id, destination_node_id, connections)
	VALUES ($1, $2, $3)
	ON CONFLICT (source_node_id, destination_node_id)
	DO UPDATE SET connections=$3, updated=CURRENT_TIMESTAMP
	`)
	if err != nil {
		return xerrors.Errorf("query prepare error 'INSERT INTO flows': %v", err)
	}

	for _, flow := range flows {
		if flow.Local.Addr == "127.0.0.1" || flow.Local.Addr == "::1" || flow.Peer.Addr == "127.0.0.1" || flow.Peer.Addr == "::1" {
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
		// - if flow.Direction == tcpflow.FlowActive {
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
		err := stmtInsertProcesses.QueryRowContext(ctx, flow.Local.Addr, pgid, pname).Scan(&localProcessID)
		if err != nil {
			return xerrors.Errorf("query error: %v", err)
		}

		if flow.Direction == tcpflow.FlowPassive {
			// local node is passive open, peer node is active open.

			// Insert or update local node
			err := stmtInsertPassiveNodes.QueryRowContext(ctx, localProcessID, flow.Local.Port).Scan(&localNodeID)
			switch {
			case err == sql.ErrNoRows:
				err := stmtFindPassiveNodesByProcess.QueryRowContext(ctx, localProcessID, flow.Local.Port).Scan(&localNodeID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("query error: %v", err)
			}

			// Create or update peer node and process
			err = stmtFindActiveNodes.QueryRowContext(ctx, flow.Local.Port, flow.Peer.Addr).Scan(&peerNodeID)
			switch {
			case err == sql.ErrNoRows:
				err := stmtInsertProcesses.QueryRowContext(ctx, flow.Peer.Addr, 0, "").Scan(&peerProcessID)
				if err != nil {
					return xerrors.Errorf("insert processes error: %v", err)
				}
				err = stmtInsertActiveNodes.QueryRowContext(ctx, peerProcessID).Scan(&peerNodeID)
				if err != nil {
					return xerrors.Errorf("insert active_nodes error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("find active_nodes error: %v", err)
			default:
				// TODO: update
			}

			_, err = stmtInsertFlows.ExecContext(ctx, peerNodeID, localNodeID, flow.Connections)
			if err != nil {
				return xerrors.Errorf("query error: %v", err)
			}
		} else if flow.Direction == tcpflow.FlowActive {
			// peer node is passive open, local node is active open.

			// Insert or update local node
			err := stmtInsertActiveNodes.QueryRowContext(ctx, localProcessID).Scan(&localNodeID)
			switch {
			case err == sql.ErrNoRows:
				err := stmtFindActiveNodesByProcess.QueryRowContext(ctx, localProcessID).Scan(&localNodeID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("query error: %v", err)
			}

			// Create or update peer node and process
			err = stmtFindPassiveNodes.QueryRowContext(ctx, flow.Peer.Addr, flow.Peer.Port).Scan(&peerNodeID)
			switch {
			case err == sql.ErrNoRows:
				err := stmtInsertProcesses.QueryRowContext(ctx, flow.Peer.Addr, 0, "").Scan(&peerProcessID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
				err = stmtInsertPassiveNodes.QueryRowContext(ctx, peerProcessID, flow.Peer.Port).Scan(&peerNodeID)
				if err != nil {
					return xerrors.Errorf("query error: %v", err)
				}
			case err != nil:
				return xerrors.Errorf("query error: %v", err)
			default:
				// TODO: update
			}

			_, err = stmtInsertFlows.ExecContext(ctx, localNodeID, peerNodeID, flow.Connections)
			if err != nil {
				return xerrors.Errorf("query error: localNodeID:%d, peerNodeID: %d, %v", localNodeID, peerNodeID, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return xerrors.Errorf("transaction commit error: %v", err)
	}
	return nil
}

// AddrPort are IP addr and port.
type AddrPort struct {
	IPAddr      net.IP
	Port        int
	Pgid        int
	Pname       string
	Connections int
}

func (a *AddrPort) String() string {
	port := fmt.Sprintf("%d", a.Port)
	if a.Port == 0 {
		port = "many"
	}
	return fmt.Sprintf("%s:%s ('%s', pgid=%d, connections=%d)", a.IPAddr, port, a.Pname, a.Pgid, a.Connections)
}

// FindListeningPortsByAddrs find listening ports for multiple `addrs`.
func (db *DB) FindListeningPortsByAddrs(addrs []net.IP) (map[string][]*AddrPort, error) {
	ipv4s := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ipv4s = append(ipv4s, addr.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := db.QueryContext(ctx, `
	SELECT ipv4, port, pgid, pname FROM passive_nodes
	INNER JOIN processes ON processes.process_id = passive_nodes.process_id
	WHERE processes.ipv4 = ANY($1)
`, pq.Array(ipv4s))
	if err == sql.ErrNoRows {
		return map[string][]*AddrPort{}, nil
	}
	if err != nil {
		return nil, xerrors.Errorf("query error: %v", err)
	}
	defer rows.Close()

	portsbyaddr := make(map[string][]*AddrPort)
	for rows.Next() {
		var (
			addr  string
			port  int
			pgid  int
			pname string
		)
		if err := rows.Scan(&addr, &port, &pgid, &pname); err != nil {
			return nil, xerrors.Errorf("query error: %v", err)
		}
		if port == 0 { // port == 0 means 'many'
			continue
		}
		portsbyaddr[addr] = append(portsbyaddr[addr], &AddrPort{
			IPAddr: net.ParseIP(addr),
			Port:   port,
			Pgid:   pgid,
			Pname:  pname,
		})
	}
	return portsbyaddr, nil
}

// FindSourceByDestAddrAndPort find source nodes.
func (db *DB) FindSourceByDestAddrAndPort(addr net.IP, port int) ([]*AddrPort, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := db.QueryContext(ctx, `
	SELECT
		connections, flows.updated AS updated, processes.ipv4 AS source_ipv4, pn.port AS source_port, processes.pgid AS pgid, processes.pname AS pname
	FROM flows
	INNER JOIN active_nodes ON active_nodes.node_id = flows.source_node_id
	INNER JOIN processes ON processes.process_id = active_nodes.process_id
    INNER JOIN (
		SELECT passive_nodes.node_id, passive_nodes.port FROM passive_nodes
		INNER JOIN processes ON processes.process_id = passive_nodes.process_id
		WHERE processes.ipv4 = $1 AND passive_nodes.port = $2
	) AS pn ON flows.destination_node_id = pn.node_id
`, addr.String(), port)
	switch {
	case err == sql.ErrNoRows:
		return []*AddrPort{}, nil
	case err != nil:
		return []*AddrPort{}, xerrors.Errorf("find source nodes error: %v", err)
	}
	defer rows.Close()
	addrports := make([]*AddrPort, 0)
	for rows.Next() {
		var (
			connections int
			updated     time.Time
			sipv4       string
			sport       int
			spgid       int
			spname      string
		)
		if err := rows.Scan(&connections, &updated, &sipv4, &sport, &spgid, &spname); err != nil {
			return nil, xerrors.Errorf("rows scan error: %v", err)
		}
		addrports = append(addrports, &AddrPort{
			IPAddr:      net.ParseIP(sipv4),
			Port:        sport,
			Pgid:        spgid,
			Pname:       spname,
			Connections: connections,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, xerrors.Errorf("rows error: %v", err)
	}
	return addrports, nil
}

// FindDestNodes find destination nodes by addr.
func (db *DB) FindDestNodes(addr net.IP) ([]*AddrPort, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := db.QueryContext(ctx, `
	SELECT
		connections,
		flows.updated AS updated,
		processes.ipv4 AS dest_ipv4,
		processes.pgid AS dest_pgid,
		processes.pname AS dest_pname
	FROM flows
	INNER JOIN active_nodes ON active_nodes.node_id = flows.source_node_id
	INNER JOIN processes ON processes.process_id = active_nodes.process_id
    INNER JOIN (
		SELECT passive_nodes.node_id FROM passive_nodes
		INNER JOIN processes ON processes.process_id = passive_nodes.process_id
		WHERE processes.ipv4 = $1
	) AS an ON flows.destination_node_id = an.node_id
`, addr.String())
	switch {
	case err == sql.ErrNoRows:
		return []*AddrPort{}, nil
	case err != nil:
		return []*AddrPort{}, xerrors.Errorf("find destination nodes query error: %v", err)
	}
	defer rows.Close()
	addrports := make([]*AddrPort, 0)
	for rows.Next() {
		var (
			connections int
			updated     time.Time
			dipv4       string
			dpgid       int
			dpname      string
		)
		if err := rows.Scan(&connections, &updated, &dipv4, &dpgid, &dpname); err != nil {
			return nil, xerrors.Errorf("rows scan error: %v", err)
		}
		addrports = append(addrports, &AddrPort{
			IPAddr:      net.ParseIP(dipv4),
			Port:        0,
			Pgid:        dpgid,
			Pname:       dpname,
			Connections: connections,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, xerrors.Errorf("rows error: %v", err)
	}
	return addrports, nil
}
