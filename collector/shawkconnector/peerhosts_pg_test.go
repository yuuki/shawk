package shawkconnector

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestPGFormerHolders: the latest host that held an address names it if no
// other host held it meanwhile; an address several hosts held at once, a
// loopback address, and one held only before the window name none.
func TestPGFormerHolders(t *testing.T) {
	dsn, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('n3','m','node-03','k','v',now()-interval '60 days',now()-interval '2 days'),
		  ('n4','m','node-04','k','v',now()-interval '60 days',now()-interval '40 days'),
		  ('old','m','old-01','k','v',now()-interval '60 days',now()-interval '20 days'),
		  ('new','m','new-01','k','v',now()-interval '20 days',now()),
		  ('a','m','a','k','v',now()-interval '9 days',now()-interval '1 day'),
		  ('b','m','b','k','v',now()-interval '9 days',now()-interval '1 day')`,
		`INSERT INTO shawk.host_addrs VALUES
		  ('n3','10.0.2.3',now()-interval '60 days',now()-interval '2 days'),
		  ('n3','127.0.0.1',now()-interval '60 days',now()-interval '2 days'),
		  ('n4','10.0.2.4',now()-interval '60 days',now()-interval '40 days'),
		  ('old','10.0.2.5',now()-interval '60 days',now()-interval '20 days 1 minute'),
		  ('new','10.0.2.5',now()-interval '20 days',now()-interval '1 hour'),
		  ('new','10.0.2.5',now()-interval '30 minutes',now()),
		  ('a','172.17.0.1',now()-interval '9 days',now()-interval '1 day'),
		  ('b','172.17.0.1',now()-interval '9 days',now()-interval '1 day 1 minute')`)
	st, err := newPGStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	rows, err := st.peers(context.Background(), time.Hour, formerHolderWindow)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range rows.former {
		got = append(got, f.addr.String()+" "+f.host+" "+f.name)
	}
	slices.Sort(got)
	if want := []string{"10.0.2.3 n3 node-03", "10.0.2.5 new new-01"}; !slices.Equal(got, want) {
		t.Errorf("former holders = %v, want %v", got, want)
	}
	rows, err = st.peers(context.Background(), time.Hour, 0)
	if err != nil || rows.former != nil {
		t.Errorf("without peer_hosts: %v, %v", rows.former, err)
	}
}
