package db

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/yuuki/shawk/probe"
)

var (
	testdb *TestDB
)

func TestMain(m *testing.M) {
	code := 0
	defer func() {
		os.Exit(code)
	}()

	testdb = NewTestDB()
	defer testdb.Purge()

	code = m.Run()
}

func TestCreateSchema(t *testing.T) {
	db, err := New(testdb.GetURL().String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Shutdown()

	if err = db.CreateSchema(); err != nil {
		t.Fatal(err)
	}
}

func setupTestCase(t *testing.T) (*DB, func(t *testing.T)) {
	// setup
	db, err := New(testdb.GetURL().String())
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CreateSchema(); err != nil {
		t.Fatal(err)
	}

	return db, func(t *testing.T) {
		// teardown
		db.Exec(
			context.Background(),
			"drop schema public cascade; create schema public",
		)
		db.Shutdown()
	}
}

func TestInsertOrUpdateHostFlows_empty(t *testing.T) {
	db, teardown := setupTestCase(t)
	defer teardown(t)

	flows := []*probe.HostFlow{}

	if err := db.InsertOrUpdateHostFlows(flows); err != nil {
		t.Fatalf("%+v", err)
	}

	ctx := context.Background()
	rows, err := db.Query(ctx, "SELECT * FROM flows")
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer rows.Close()

	vals, err := rows.Values()
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(vals) > 0 {
		t.Errorf("flows table should be empty")
	}
}

func TestInsertOrUpdateHostFlows(t *testing.T) {
	db, teardown := setupTestCase(t)
	defer teardown(t)

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

	if err := db.InsertOrUpdateHostFlows(flows); err != nil {
		t.Fatal(err)
	}

	{
		rows, err := db.Query(context.Background(), "SELECT pname from processes ORDER BY created")
		if err != nil {
			t.Fatalf("%+v", err)
		}
		defer rows.Close()
		names := []string{}
		for rows.Next() {
			var pname string
			if err := rows.Scan(&pname); err != nil {
				t.Fatal(err)
			}
			names = append(names, pname)
		}
		// Empty process on "10.0.10.2" exists.
		want := []string{"python", "nginx", ""}
		if diff := cmp.Diff(names, want); diff != "" {
			t.Errorf("InsertUpdateHostFlows() mismatch (-want +got):\n%s", diff)
		}
	}

	{
		rows, err := db.Query(context.Background(), "SELECT * from active_nodes")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		ids := []int64{}
		for rows.Next() {
			var id, pid int64
			if err := rows.Scan(&id, &pid); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		// Empty active_nodes on "10.0.10.2" exists.
		if size := len(ids); size != 2 {
			t.Errorf("size of active_nodes should be 1, not %d", size)
		}
	}

	{
		rows, err := db.Query(context.Background(), "SELECT node_id from passive_nodes")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		ids := []int64{}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		// Empty passive_nodes on "10.0.10.2" exists.
		if size := len(ids); size != 2 {
			t.Errorf("size of passive_nodes should be 2, not %d", size)
		}
	}

	{
		rows, err := db.Query(
			context.Background(),
			"SELECT source_node_id, destination_node_id FROM flows ORDER BY created",
		)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		sids, dids := []int64{}, []int64{}
		for rows.Next() {
			var sid, did int64
			if err := rows.Scan(&sid, &did); err != nil {
				t.Fatal(err)
			}
			sids = append(sids, sid)
			dids = append(dids, did)
		}
		want := []int64{1, 2}
		if diff := cmp.Diff(sids, want); diff != "" {
			t.Errorf("InsertUpdateHostFlows() mismatch (-want +got):\n%s", diff)
		}
		want = []int64{1, 2}
		if diff := cmp.Diff(dids, want); diff != "" {
			t.Errorf("InsertUpdateHostFlows() mismatch (-want +got):\n%s", diff)
		}
		if size := len(sids); size != len(flows) {
			t.Errorf("size of flows should be %d, not %d", len(flows), size)
		}
	}
}

func TestInsertOrUpdateHostFlows_empty_process(t *testing.T) {
	db, teardown := setupTestCase(t)
	defer teardown(t)

	flows := []*probe.HostFlow{
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "5432"},
			Connections: 10,
		},
	}

	if err := db.InsertOrUpdateHostFlows(flows); err != nil {
		t.Fatal(err)
	}

	{
		rows, err := db.Query(
			context.Background(),
			"SELECT source_node_id, destination_node_id FROM flows ORDER BY created",
		)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		sids, dids := []int64{}, []int64{}
		for rows.Next() {
			var sid, did int64
			if err := rows.Scan(&sid, &did); err != nil {
				t.Fatal(err)
			}
			sids = append(sids, sid)
			dids = append(dids, did)
		}
		want := []int64{1, 2}
		if diff := cmp.Diff(sids, want); diff != "" {
			t.Errorf("InsertUpdateHostFlows() mismatch (-want +got):\n%s", diff)
		}
		want = []int64{1, 2}
		if diff := cmp.Diff(dids, want); diff != "" {
			t.Errorf("InsertUpdateHostFlows() mismatch (-want +got):\n%s", diff)
		}
		if size := len(sids); size != len(flows) {
			t.Errorf("size of flows should be %d, not %d", len(flows), size)
		}
	}
}

func TestFindPassiveFlows(t *testing.T) {
	db, teardown := setupTestCase(t)
	defer teardown(t)

	input := []*probe.HostFlow{
		// haproxy(10.0.10.1:80) -> nginx(10.0.10.2:80) -> python(10.0.10.2:8000)
		//                                              |-> postgres(10.0.10.3:5432)
		//                                              |-> redis(10.0.10.4:6379)
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "80"},
			Process:     &probe.Process{Pgid: 1001, Name: "haproxy"},
			Connections: 100,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "80"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Process:     &probe.Process{Pgid: 2001, Name: "nginx"},
			Connections: 12,
		},
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "8000"},
			Process:     &probe.Process{Pgid: 2002, Name: "gunicorn"},
			Connections: 18,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "8000"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &probe.Process{Pgid: 2002, Name: "gunicorn"},
			Connections: 10,
		},
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.3", Port: "5432"},
			Process:     &probe.Process{Pgid: 2002, Name: "gunicorn"},
			Connections: 21,
		},
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.4", Port: "6379"},
			Process:     &probe.Process{Pgid: 2002, Name: "gunicorn"},
			Connections: 14,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.3", Port: "5432"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &probe.Process{Pgid: 3001, Name: "postgres"},
			Connections: 20,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.4", Port: "6379"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &probe.Process{Pgid: 4001, Name: "redis"},
			Connections: 19,
		},
	}

	if err := db.InsertOrUpdateHostFlows(input); err != nil {
		t.Fatal(err)
	}

	got, err := db.FindPassiveFlows(&FindFlowsCond{
		Addrs: []net.IP{
			net.ParseIP("10.0.10.1"),
			net.ParseIP("10.0.10.2"),
			net.ParseIP("10.0.10.3"),
			net.ParseIP("10.0.10.4"),
		},
	})
	if err != nil {
		t.Fatalf("%+v", err)
	}

	want := Flows{
		"10.0.10.2-": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.1"),
					Port:   0,
					Pgid:   1001,
					Pname:  "haproxy",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   80,
				},
				Connections: 100,
			},
		},
		"10.0.10.2-nginx": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.1"),
					Port:   0,
					Pgid:   1001,
					Pname:  "haproxy",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   80,
					Pgid:   2001,
					Pname:  "nginx",
				},
				Connections: 12,
			},
		},
		"10.0.10.2-gunicorn": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   0,
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   8000,
					Pgid:   2002,
					Pname:  "gunicorn",
				},
				Connections: 10,
			},
		},
		"10.0.10.3-": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   0,
					Pgid:   2002,
					Pname:  "gunicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.3"),
					Port:   5432,
				},
				Connections: 21,
			},
		},
		"10.0.10.3-postgres": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   0,
					Pgid:   2002,
					Pname:  "gunicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.3"),
					Port:   5432,
					Pgid:   3001,
					Pname:  "postgres",
				},
				Connections: 20,
			},
		},
		"10.0.10.4-": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   0,
					Pgid:   2002,
					Pname:  "gunicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.4"),
					Port:   6379,
				},
				Connections: 14,
			},
		},
		"10.0.10.4-redis": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   0,
					Pgid:   2002,
					Pname:  "gunicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.4"),
					Port:   6379,
					Pgid:   4001,
					Pname:  "redis",
				},
				Connections: 19,
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("FindPassiveFlows() mismatch (-want +got):\n%s", diff)
	}
}

func TestFindActiveFlows(t *testing.T) {
	db, teardown := setupTestCase(t)
	defer teardown(t)

	input := []*probe.HostFlow{
		// nginx(10.0.10.1:80) ->  python(10.0.10.2:8000)
		//                          |-> postgres(10.0.10.3:5432)
		//                          |-> redis(10.0.10.4:6379)
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "80"},
			Process:     &probe.Process{Pgid: 1001, Name: "nginx"},
			Connections: 100,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "8000"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.1", Port: "many"},
			Process:     &probe.Process{Pgid: 2001, Name: "gunicorn"},
			Connections: 10,
		},
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.3", Port: "5432"},
			Process:     &probe.Process{Pgid: 2001, Name: "gunicorn"},
			Connections: 21,
		},
		{
			Direction:   probe.FlowActive,
			Local:       &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.4", Port: "6379"},
			Process:     &probe.Process{Pgid: 2001, Name: "gunicorn"},
			Connections: 14,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.3", Port: "5432"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &probe.Process{Pgid: 3001, Name: "postgres"},
			Connections: 20,
		},
		{
			Direction:   probe.FlowPassive,
			Local:       &probe.AddrPort{Addr: "10.0.10.4", Port: "6379"},
			Peer:        &probe.AddrPort{Addr: "10.0.10.2", Port: "many"},
			Process:     &probe.Process{Pgid: 4001, Name: "redis"},
			Connections: 19,
		},
	}

	if err := db.InsertOrUpdateHostFlows(input); err != nil {
		t.Fatal(err)
	}

	got, err := db.FindActiveFlows(&FindFlowsCond{
		Addrs: []net.IP{
			net.ParseIP("10.0.10.1"),
			net.ParseIP("10.0.10.2"),
			net.ParseIP("10.0.10.3"),
			net.ParseIP("10.0.10.4"),
		},
	})
	if err != nil {
		t.Fatalf("%+v", err)
	}

	want := Flows{
		"10.0.10.1-": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.1"),
					Port:   0,
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   8000,
					Pgid:   2001,
					Pname:  "gunicorn",
				},
				Connections: 10,
			},
		},
		"10.0.10.1-nginx": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.1"),
					Port:   0,
					Pgid:   1001,
					Pname:  "nginx",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   80,
				},
				Connections: 100,
			},
		},
		"10.0.10.2-gunicorn": []*Flow{
			{
				ActiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.2"),
					Port:   0,
					Pgid:   2001,
					Pname:  "gunicorn",
				},
				PassiveNode: &Node{
					IPAddr: net.ParseIP("10.0.10.3"),
					Port:   5432,
				},
				Connections: 21,
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("FindActiveFlows() mismatch (-want +got):\n%s", diff)
	}
}
