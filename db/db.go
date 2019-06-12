//go:generate go-bindata -o ../data/bindata.go -pkg data ../data/schema/
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq" // database/sql driver
	"github.com/pkg/errors"
	"github.com/yuuki/lstf/tcpflow"
	"github.com/yuuki/ttracer/data"
)

const (
	DefaultDBName     = "ttracer"
	DefaultDBUserName = "ttracer"
	DefaultDBHostname = "localhost"
	DefaultDBPort     = "5432"
	ConnectTimeout    = 5
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
		return nil, errors.Wrap(err, "postgres open error")
	}
	if err = db.Ping(); err != nil {
		return nil, errors.Wrap(err, "postgres ping error")
	}
	return &DB{db}, nil
}

// CreateSchema creates the table schemas defined by the paths including Schemas.
func (db *DB) CreateSchema() error {
	for _, schema := range schemas {
		sql, err := data.Asset(schema)
		if err != nil {
			return errors.Wrapf(err, "get schema error: %v", schema)
		}
		_, err = db.Exec(fmt.Sprintf("%s", sql))
		if err != nil {
			return errors.Wrapf(err, "exec schema error: %s", sql)
		}
	}
	return nil
}

const (
	InsertOrUpdateTimeoutSec = 10
)

// InsertOrUpdateHostFlows insert host flows or update it if the same flow exists.
func (db *DB) InsertOrUpdateHostFlows(flows tcpflow.HostFlows) error {
	ctx, cancel := context.WithTimeout(context.Background(), InsertOrUpdateTimeoutSec*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "begin transaction error")
	}
	q1 := `
	INSERT INTO nodes (ipv4, port) VALUES ($1, $2)
	ON CONFLICT (ipv4, port) DO NOTHING
	RETURNING node_id
`
	stmt1, err := tx.PrepareContext(ctx, q1)
	if err != nil {
		return errors.Wrapf(err, "query prepare error: %s", q1)
	}
	stmtFindNodeID, err := tx.PrepareContext(ctx, `
	SELECT node_id FROM nodes WHERE ipv4 = $1 AND port = $2
`)
	if err != nil {
		return errors.Wrap(err, "query prepare error")
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
		return errors.Wrapf(err, "query prepare error: %s", q2)
	}

	for _, flow := range flows {
		if flow.Local.Addr == "127.0.0.1" || flow.Local.Addr == "::1" || flow.Peer.Addr == "127.0.0.1" || flow.Peer.Addr == "::1" {
			continue
		}
		var localNodeid, peerNodeid int64
		err := stmt1.QueryRowContext(ctx, flow.Local.Addr, flow.Local.PortInt()).Scan(&localNodeid)
		if err == sql.ErrNoRows {
			err = stmtFindNodeID.QueryRowContext(ctx, flow.Local.Addr, flow.Local.PortInt()).Scan(&localNodeid)
		}
		if err != nil {
			return errors.Wrapf(err, "query error")
		}
		err = stmt1.QueryRowContext(ctx, flow.Peer.Addr, flow.Peer.PortInt()).Scan(&peerNodeid)
		if err == sql.ErrNoRows {
			err = stmtFindNodeID.QueryRowContext(ctx, flow.Peer.Addr, flow.Peer.PortInt()).Scan(&peerNodeid)
		}
		if err != nil {
			return errors.Wrapf(err, "query error")
		}
		if flow.Direction == tcpflow.FlowActive {
			_, err = stmt2.ExecContext(ctx, flow.Direction.String(), localNodeid, peerNodeid, flow.Connections)
		} else if flow.Direction == tcpflow.FlowPassive {
			_, err = stmt2.ExecContext(ctx, flow.Direction.String(), peerNodeid, localNodeid, flow.Connections)
		}
		if err != nil {
			return errors.Wrapf(err, "query error")
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "transaction commit error")
	}
	return nil
}

// AddrPort are IP addr and port.
type AddrPort struct {
	IPAddr      net.IP
	Port        int16
	Connections int
}

func (a *AddrPort) String() string {
	port := fmt.Sprintf("%d", a.Port)
	if a.Port == 0 {
		port = "many"
	}
	return fmt.Sprintf("%s:%s (connections:%d)", a.IPAddr, port, a.Connections)
}

// FindListeningPortsByAddrs find listening ports for multiple `addrs`.
func (db *DB) FindListeningPortsByAddrs(addrs []net.IP) (map[string][]int16, error) {
	ipv4s := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ipv4s = append(ipv4s, addr.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := db.QueryContext(ctx, `
	SELECT ipv4, port FROM nodes WHERE nodes.ipv4 = ANY($1)
`, pq.Array(ipv4s))
	if err == sql.ErrNoRows {
		return map[string][]int16{}, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "query error")
	}
	defer rows.Close()

	portsbyaddr := map[string][]int16{}
	for rows.Next() {
		var (
			addr string
			port int16
		)
		if err := rows.Scan(&addr, &port); err != nil {
			return nil, errors.Wrap(err, "postgres query error")
		}
		if port == 0 { // port == 0 means 'many'
			continue
		}
		portsbyaddr[addr] = append(portsbyaddr[addr], port)
	}
	return portsbyaddr, nil
}

// FindSourceByDestAddrAndPort find source nodes.
func (db *DB) FindSourceByDestAddrAndPort(addr net.IP, port int16) ([]*AddrPort, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := db.QueryContext(ctx, `
	SELECT
		connections, updated, source_nodes.ipv4 AS source_ipv4, source_nodes.port AS source_port 
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
			sport       int16
		)
		if err := rows.Scan(&connections, &updated, &sipv4, &sport); err != nil {
			return nil, errors.Wrap(err, "postgres query error")
		}
		addrports = append(addrports, &AddrPort{
			IPAddr:      net.ParseIP(sipv4),
			Port:        sport,
			Connections: connections,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "postgres rows error")
	}
	return addrports, nil
}
