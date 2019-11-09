package db

import (
	"database/sql"
	"log"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lib/pq"
	"github.com/yuuki/lstf/tcpflow"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCreateSchema(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS").WillReturnResult(sqlmock.NewResult(1, 1))

	err := db.CreateSchema()
	if err != nil {
		t.Fatal(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestInsertOrUpdateHostFlows_empty(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	flows := []*tcpflow.HostFlow{}

	mock.ExpectBegin()
	mock.ExpectPrepare("SELECT flows.source_node_id FROM flows")
	mock.ExpectPrepare("SELECT node_id FROM passive_nodes")
	mock.ExpectPrepare("INSERT INTO processes")
	mock.ExpectPrepare("INSERT INTO active_nodes")
	mock.ExpectPrepare("INSERT INTO passive_nodes")
	mock.ExpectPrepare("SELECT node_id FROM active_nodes")
	mock.ExpectPrepare("SELECT node_id FROM passive_nodes")
	mock.ExpectPrepare("INSERT INTO flows")
	mock.ExpectCommit() // executed only prepare statement

	err := db.InsertOrUpdateHostFlows(flows)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestInsertOrUpdateHostFlows(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	flows := []*tcpflow.HostFlow{
		{
			Direction:   tcpflow.FlowActive,
			Local:       &tcpflow.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &tcpflow.AddrPort{Addr: "10.0.10.2", Port: "5432"},
			Process:     &tcpflow.Process{Pgid: 1001, Name: "python"},
			Connections: 10,
		},
		{
			Direction:   tcpflow.FlowPassive,
			Local:       &tcpflow.AddrPort{Addr: "10.0.10.1", Port: "80"},
			Peer:        &tcpflow.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &tcpflow.Process{Pgid: 1002, Name: "nginx"},
			Connections: 12,
		},
	}

	mock.ExpectBegin()
	stmtFindActiveNodes := mock.ExpectPrepare("SELECT flows.source_node_id FROM flows")
	stmtFindPassiveNodes := mock.ExpectPrepare("SELECT node_id FROM passive_nodes WHERE process_id IN (.+)")
	stmtInsertProcesses := mock.ExpectPrepare("INSERT INTO processes")
	stmtInsertActiveNodes := mock.ExpectPrepare("INSERT INTO active_nodes")
	stmtInsertPassiveNodes := mock.ExpectPrepare("INSERT INTO passive_nodes")
	stmtFindActiveNodesByProcess := mock.ExpectPrepare("SELECT node_id FROM active_nodes")
	stmtFindPassiveNodesByProcess := mock.ExpectPrepare("SELECT node_id FROM passive_nodes WHERE process_id = (.+) AND port = (.+)")
	stmtInsertFlows := mock.ExpectPrepare("INSERT INTO flows")

	// first loop
	{
		localProcessID, peerProcessID, localNodeID, peerNodeID := 101, 301, 501, 701

		stmtInsertProcesses.ExpectQuery().WithArgs(
			flows[0].Local.Addr, flows[0].Process.Pgid, flows[0].Process.Name,
		).WillReturnRows(
			sqlmock.NewRows([]string{"process_id"}).AddRow(localProcessID),
		)

		stmtInsertActiveNodes.ExpectQuery().WithArgs(localProcessID).WillReturnError(
			sql.ErrNoRows,
		) // conflict when inserting
		stmtFindActiveNodesByProcess.ExpectQuery().WithArgs(localProcessID).WillReturnRows(
			sqlmock.NewRows([]string{"node_id"}).AddRow(localNodeID),
		)

		stmtFindPassiveNodes.ExpectQuery().WithArgs(
			flows[0].Peer.Addr, flows[0].Peer.Port,
		).WillReturnError(sql.ErrNoRows) // return empty
		stmtInsertProcesses.ExpectQuery().WithArgs(
			flows[0].Peer.Addr, 0, "",
		).WillReturnRows(
			sqlmock.NewRows([]string{"process_id"}).AddRow(peerProcessID),
		)
		stmtInsertPassiveNodes.ExpectQuery().WithArgs(
			peerProcessID, flows[0].Peer.Port,
		).WillReturnRows(
			sqlmock.NewRows([]string{"node_id"}).AddRow(peerNodeID),
		)

		stmtInsertFlows.ExpectExec().WithArgs(
			localNodeID, peerNodeID, flows[0].Connections,
		).WillReturnResult(sqlmock.NewResult(0, 1))
	}

	// second loop
	{
		localProcessID, peerProcessID, localNodeID, peerNodeID := 102, 302, 502, 702

		stmtInsertProcesses.ExpectQuery().WithArgs(
			flows[1].Local.Addr, flows[1].Process.Pgid, flows[1].Process.Name,
		).WillReturnRows(
			sqlmock.NewRows([]string{"process_id"}).AddRow(localProcessID),
		)

		stmtInsertPassiveNodes.ExpectQuery().WithArgs(
			localProcessID, flows[1].Local.Port,
		).WillReturnError(sql.ErrNoRows)
		stmtFindPassiveNodesByProcess.ExpectQuery().WithArgs(
			localProcessID, flows[1].Local.Port,
		).WillReturnRows(
			sqlmock.NewRows([]string{"node_id"}).AddRow(localNodeID),
		)

		stmtFindActiveNodes.ExpectQuery().WithArgs(
			flows[1].Local.Port, flows[1].Peer.Addr,
		).WillReturnError(sql.ErrNoRows)
		stmtInsertProcesses.ExpectQuery().WithArgs(
			flows[1].Peer.Addr, 0, "",
		).WillReturnRows(
			sqlmock.NewRows([]string{"process_id"}).AddRow(peerProcessID),
		)
		stmtInsertActiveNodes.ExpectQuery().WithArgs(
			peerProcessID,
		).WillReturnRows(
			sqlmock.NewRows([]string{"node_id"}).AddRow(peerNodeID),
		)

		stmtInsertFlows.ExpectExec().WithArgs(
			peerNodeID, localNodeID, flows[1].Connections,
		).WillReturnResult(sqlmock.NewResult(0, 1))
	}

	mock.ExpectCommit()

	err := db.InsertOrUpdateHostFlows(flows)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestInsertOrUpdateHostFlows_empty_process(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	flows := []*tcpflow.HostFlow{
		{
			Direction:   tcpflow.FlowActive,
			Local:       &tcpflow.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &tcpflow.AddrPort{Addr: "10.0.10.2", Port: "5432"},
			Process:     nil,
			Connections: 10,
		},
	}

	mock.ExpectBegin()
	mock.ExpectPrepare("SELECT flows.source_node_id FROM flows")
	mock.ExpectPrepare("SELECT node_id FROM passive_nodes")
	mock.ExpectPrepare("INSERT INTO processes")
	mock.ExpectPrepare("INSERT INTO active_nodes")
	mock.ExpectPrepare("INSERT INTO passive_nodes")
	mock.ExpectPrepare("SELECT node_id FROM active_nodes")
	mock.ExpectPrepare("INSERT INTO flows")

	stmt2 := mock.ExpectPrepare("INSERT INTO nodes")
	mock.ExpectPrepare("SELECT node_id FROM nodes")
	stmt3 := mock.ExpectPrepare("INSERT INTO flows")

	// first loop
	stmt2.ExpectQuery().WithArgs("10.0.10.1", 0, 0, "").WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(1))
	stmt2.ExpectQuery().WithArgs("10.0.10.2", 5432, 0, "").WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(2))
	stmt3.ExpectExec().WithArgs("active", 1, 2, 10).WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err := db.InsertOrUpdateHostFlows(flows)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestFindListeningPortsByAddrs(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	straddrs := pq.Array([]string{"192.0.2.1", "192.0.2.2"})
	columns := sqlmock.NewRows([]string{"ipv4", "port", "pgid", "pname"})
	mock.ExpectQuery("SELECT (.+) FROM passive_nodes").WithArgs(straddrs).WillReturnRows(
		columns.AddRow("192.0.2.1", 80, 833, "nginx").AddRow("192.0.2.2", 443, 1001, "nginx"),
	)

	addrs := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
	}
	portsbyaddr, err := db.FindListeningPortsByAddrs(addrs)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if len(portsbyaddr) != 2 {
		t.Errorf("portsbyaddr should be 2, but %v", len(portsbyaddr))
	}
	if ports, ok := portsbyaddr[addrs[0].String()]; !ok || ports[0].Port != 80 {
		log.Println(ports)
		t.Errorf("portsbyaddr should have '192.0.2.1' as key. value should be 80: %v", ports)
	}
	if ports, ok := portsbyaddr[addrs[1].String()]; !ok || ports[0].Port != 443 {
		t.Errorf("portsbyaddr should have '192.0.2.2' as key. value should be 443: %v", ports)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestFindSourceByDestAddrAndPort(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	addr, port := net.ParseIP("192.0.10.1"), 0
	pgid, pname := 3008, "nginx"
	connections := 10

	columns := sqlmock.NewRows([]string{"connections", "updated", "source_ipv4", "source_port", "source_pgid", "source_pname"})
	mock.ExpectQuery("SELECT (.+) FROM flows").WithArgs(addr.String(), port).WillReturnRows(
		columns.AddRow(connections, time.Now(), addr.String(), port, pgid, pname),
	)

	addrports, err := db.FindSourceByDestAddrAndPort(addr, port)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if len(addrports) != 1 {
		t.Errorf("addrports should be 1, but %v", len(addrports))
	}

	want := []*AddrPort{
		{
			IPAddr:      addr,
			Port:        port,
			Pgid:        pgid,
			Pname:       pname,
			Connections: connections,
		},
	}
	if diff := cmp.Diff(want, addrports); diff != "" {
		t.Errorf("FindSourceByDestAddrAndPort() mismatch (-want +got):\n%s", diff)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
