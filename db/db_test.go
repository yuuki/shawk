package db

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/yuuki/lstf/tcpflow"
)

func TestCreateSchema(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	mock.ExpectExec("CREATE TYPE (.+)").WillReturnResult(sqlmock.NewResult(1, 1))

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

	flows := tcpflow.HostFlows{}

	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO nodes")
	mock.ExpectPrepare("SELECT node_id FROM nodes")
	mock.ExpectPrepare("INSERT INTO flows")
	mock.ExpectCommit()

	err := db.InsertOrUpdateHostFlows(flows)
	if err != nil {
		t.Fatal(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestInsertOrUpdateHostFlows(t *testing.T) {
	db, mock := NewTestDB()
	defer db.Close()

	flow1 := &tcpflow.HostFlow{
		Direction:   tcpflow.FlowActive,
		Local:       &tcpflow.AddrPort{Addr: "10.0.10.1", Port: "many"},
		Peer:        &tcpflow.AddrPort{Addr: "10.0.10.2", Port: "5432"},
		Connections: 10,
	}
	flow2 := &tcpflow.HostFlow{
		Direction:   tcpflow.FlowPassive,
		Local:       &tcpflow.AddrPort{Addr: "10.0.10.1", Port: "80"},
		Peer:        &tcpflow.AddrPort{Addr: "10.0.10.2", Port: "many"},
		Connections: 12,
	}
	flows := tcpflow.HostFlows{
		flow1.UniqKey(): flow1,
		flow2.UniqKey(): flow2,
	}

	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO nodes")
	mock.ExpectPrepare("SELECT node_id FROM nodes")
	mock.ExpectPrepare("INSERT INTO flows")

	// first loop
	mock.ExpectQuery("INSERT INTO nodes").WithArgs("10.0.10.1", 0).WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(1))
	mock.ExpectQuery("INSERT INTO nodes").WithArgs("10.0.10.2", 5432).WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(2))
	mock.ExpectExec("INSERT INTO flows").WithArgs("active", 1, 2, 10).WillReturnResult(sqlmock.NewResult(1, 1))

	// second loop
	mock.ExpectQuery("INSERT INTO nodes").WithArgs("10.0.10.1", 80).WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(3))
	mock.ExpectQuery("INSERT INTO nodes").WithArgs("10.0.10.2", 0).WillReturnRows(sqlmock.NewRows([]string{"node_id"}).AddRow(4))
	mock.ExpectExec("INSERT INTO flows").WithArgs("passive", 4, 3, 12).WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err := db.InsertOrUpdateHostFlows(flows)
	if err != nil {
		t.Fatal(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
