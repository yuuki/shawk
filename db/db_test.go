package db

import (
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/lib/pq"

	"github.com/yuuki/shawk/probe"
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

	flows := []*probe.HostFlow{}

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

	flows := []*probe.HostFlow{
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "5432"},
			Process:     &probe.Process{Pgid: 1001, Name: "python"},
			Connections: 10,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "80"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &probe.Process{Pgid: 1002, Name: "nginx"},
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

	flows := []*probe.HostFlow{
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "5432"},
			Connections: 10,
		},
	}

	mock.ExpectBegin()

	mock.ExpectPrepare("SELECT flows.source_node_id FROM flows")
	stmtFindPassiveNodes := mock.ExpectPrepare("SELECT node_id FROM passive_nodes WHERE process_id IN (.+)")
	stmtInsertProcesses := mock.ExpectPrepare("INSERT INTO processes")
	stmtInsertActiveNodes := mock.ExpectPrepare("INSERT INTO active_nodes")
	stmtInsertPassiveNodes := mock.ExpectPrepare("INSERT INTO passive_nodes")
	stmtFindActiveNodesByProcess := mock.ExpectPrepare("SELECT node_id FROM active_nodes")
	mock.ExpectPrepare("SELECT node_id FROM passive_nodes WHERE process_id = (.+) AND port = (.+)")
	stmtInsertFlows := mock.ExpectPrepare("INSERT INTO flows")

	// first loop
	localProcessID, peerProcessID, localNodeID, peerNodeID := 101, 301, 501, 701

	stmtInsertProcesses.ExpectQuery().WithArgs(
		flows[0].Local.Addr, 0, "",
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

	mock.ExpectCommit()

	err := db.InsertOrUpdateHostFlows(flows)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestFindPassiveFlows(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	paddrs := []net.IP{net.ParseIP("192.168.3.1"), net.ParseIP("192.168.3.2")}

	columns := sqlmock.NewRows([]string{
		"pipv4",
		"ppname",
		"pport",
		"ppgid",
		"aipv4",
		"apname",
		"apgid",
		"connections",
		"updated",
	})

	// flow1
	pipv4, ppname, ppgid, pport := "192.168.3.1", "unicorn", 10021, 8000
	aipv4, apname, apgid := "192.168.2.1", "nginx", 4123
	connections := 10
	columns.AddRow(pipv4, ppname, pport, ppgid, aipv4, apname, apgid, connections, time.Now())

	// flow2
	pipv4, ppname, ppgid, pport = "192.168.3.1", "unicorn", 10021, 8000
	aipv4, apname, apgid = "192.168.5.1", "varnish", 13456
	connections = 20
	columns.AddRow(pipv4, ppname, pport, ppgid, aipv4, apname, apgid, connections, time.Now())

	until := time.Now()

	mock.ExpectQuery("SELECT (.+) FROM flows").WithArgs(
		pq.Array([]string{"192.168.3.1", "192.168.3.2"}),
		pq.FormatTimestamp(time.Time{}),
		pq.FormatTimestamp(until),
	).WillReturnRows(columns)

	flows, err := db.FindPassiveFlows(&FindFlowsCond{
		Addrs: paddrs,
		Until: until,
	})
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if len(flows) != 1 {
		t.Errorf("flows should be 2, but %v", len(flows))
	}

	want := Flows{
		"192.168.3.1-unicorn": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("192.168.2.1"),
					Port:   0,
					Pgid:   4123,
					Pname:  "nginx",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("192.168.3.1"),
					Port:   8000,
					Pgid:   10021,
					Pname:  "unicorn",
				},
				Connections: 10,
			},
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("192.168.5.1"),
					Port:   0,
					Pgid:   13456,
					Pname:  "varnish",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("192.168.3.1"),
					Port:   8000,
					Pgid:   10021,
					Pname:  "unicorn",
				},
				Connections: 20,
			},
		},
	}
	if diff := cmp.Diff(want, flows); diff != "" {
		t.Errorf("FindDestNodes() mismatch (-want +got):\n%s", diff)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestFindActiveFlows(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	aaddrs := []net.IP{net.ParseIP("192.168.2.1"), net.ParseIP("192.168.2.2")}

	columns := sqlmock.NewRows([]string{
		"aipv4",
		"apname",
		"pport",
		"apgid",
		"pipv4",
		"ppname",
		"ppgid",
		"connections",
		"updated",
	})

	// flow1
	aipv4, apname, apgid := "192.168.2.1", "unicorn", 4123
	pipv4, ppname, ppgid, pport := "192.168.3.1", "mysqld", 10021, 3306
	connections := 10
	columns.AddRow(aipv4, apname, pport, apgid, pipv4, ppname, ppgid, connections, time.Now())

	// flow2
	aipv4, apname, apgid = "192.168.2.1", "unicorn", 4123
	pipv4, ppname, ppgid, pport = "192.168.4.1", "memcached", 21199, 11211
	connections = 20
	columns.AddRow(aipv4, apname, pport, apgid, pipv4, ppname, ppgid, connections, time.Now())

	until := time.Now()

	mock.ExpectQuery("SELECT (.+) FROM flows").WithArgs(
		pq.Array([]string{"192.168.2.1", "192.168.2.2"}),
		pq.FormatTimestamp(time.Time{}),
		pq.FormatTimestamp(until),
	).WillReturnRows(columns)

	flows, err := db.FindActiveFlows(&FindFlowsCond{
		Addrs: aaddrs,
		Until: until,
	})
	if err != nil {
		t.Fatalf("%+v", err)
	}

	if len(flows) != 1 {
		t.Errorf("flows should be 2, but %v", len(flows))
	}

	want := Flows{
		"192.168.2.1-unicorn": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("192.168.2.1"),
					Port:   0,
					Pgid:   4123,
					Pname:  "unicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("192.168.3.1"),
					Port:   3306,
					Pgid:   10021,
					Pname:  "mysqld",
				},
				Connections: 10,
			},
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("192.168.2.1"),
					Port:   0,
					Pgid:   4123,
					Pname:  "unicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("192.168.4.1"),
					Port:   11211,
					Pgid:   21199,
					Pname:  "memcached",
				},
				Connections: 20,
			},
		},
	}
	if diff := cmp.Diff(want, flows); diff != "" {
		t.Errorf("FindDestNodes() mismatch (-want +got):\n%s", diff)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
