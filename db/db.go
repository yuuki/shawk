//go:generate go-bindata -o ../data/bindata.go -pkg data ../data/schema/

package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq" // database/sql driver
	"github.com/yuuki/lstf/tcpflow"
	"github.com/yuuki/transtracer/data"
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
		"../data/schema/flows.sql",
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
		sql, err := data.Asset(schema)
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
	q1 := `
	INSERT INTO nodes (ipv4, port, pgid, pname) VALUES ($1, $2, $3, $4)
	ON CONFLICT (ipv4, port, pgid, pname) DO NOTHING
	RETURNING node_id
`
	stmt1, err := tx.PrepareContext(ctx, q1)
	if err != nil {
		return xerrors.Errorf("query prepare error '%s': %v", q1, err)
	}
	stmtFindNodeID, err := tx.PrepareContext(ctx, `
	SELECT node_id FROM nodes WHERE ipv4 = $1 AND port = $2 AND pgid = $3 AND pname = $4
`)
	if err != nil {
		return xerrors.Errorf("query prepare error: %v", err)
	}
	q2 := `
	INSERT INTO flows
	(direction, source_node_id, destination_node_id, connections, updated)
	VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
	ON CONFLICT (source_node_id, destination_node_id, direction)
	DO UPDATE SET
	direction=$1, source_node_id=$2, destination_node_id=$3, connections=$4, updated=CURRENT_TIMESTAMP
`
	stmt2, err := tx.PrepareContext(ctx, q2)
	if err != nil {
		return xerrors.Errorf("query prepare error '%s': %v", q2, err)
	}

	for _, flow := range flows {
		if flow.Local.Addr == "127.0.0.1" || flow.Local.Addr == "::1" || flow.Peer.Addr == "127.0.0.1" || flow.Peer.Addr == "::1" {
			continue
		}
		var (
			localNodeid, peerNodeid int64
			pgid                    int
			pname                   string
		)
		if flow.Process != nil {
			pgid = flow.Process.Pgid
			pname = flow.Process.Name
		}
		err := stmt1.QueryRowContext(ctx, flow.Local.Addr, flow.Local.PortInt(), pgid, pname).Scan(&localNodeid)
		if err == sql.ErrNoRows {
			err = stmtFindNodeID.QueryRowContext(ctx, flow.Local.Addr, flow.Local.PortInt(), pgid, pname).Scan(&localNodeid)
		}
		if err != nil {
			return xerrors.Errorf("query error: %v", err)
		}
		// Set an empty value into process because a local node has no way of knowing a process on a peer node.
		err = stmt1.QueryRowContext(ctx, flow.Peer.Addr, flow.Peer.PortInt(), 0, "").Scan(&peerNodeid)
		if err == sql.ErrNoRows {
			err = stmtFindNodeID.QueryRowContext(ctx, flow.Peer.Addr, flow.Peer.PortInt(), 0, "").Scan(&peerNodeid)
		}
		if err != nil {
			return xerrors.Errorf("query error: %v", err)
		}
		if flow.Direction == tcpflow.FlowActive {
			_, err = stmt2.ExecContext(ctx, flow.Direction.String(), localNodeid, peerNodeid, flow.Connections)
		} else if flow.Direction == tcpflow.FlowPassive {
			_, err = stmt2.ExecContext(ctx, flow.Direction.String(), peerNodeid, localNodeid, flow.Connections)
		}
		if err != nil {
			return xerrors.Errorf("query error: %v", err)
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
	SELECT ipv4, port, pgid, pname FROM nodes WHERE nodes.ipv4 = ANY($1)
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
		connections, updated, source_nodes.ipv4 AS source_ipv4, source_nodes.port AS source_port, source_nodes.pgid AS pgid, source_nodes.pname AS pname
	FROM flows
	INNER JOIN nodes AS source_nodes ON source_nodes.node_id = flows.source_node_id
	INNER JOIN nodes AS dest_nodes on dest_nodes.node_id = flows.destination_node_id
	WHERE direction = 'passive' AND dest_nodes.ipv4 = $1 AND dest_nodes.port = $2
`, addr.String(), port)
	if err == sql.ErrNoRows {
		return []*AddrPort{}, nil
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
			return nil, xerrors.Errorf("query error: %v", err)
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
		return nil, xerrors.Errorf("postgres rows error: %v", err)
	}
	return addrports, nil
}
