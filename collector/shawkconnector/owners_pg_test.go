package shawkconnector

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestPGListenerOwners: a listener that changes hands keeps a row per owner
// in listener_owners, so its history is kept (#98), while listeners keeps
// one row per listener with its latest known owner, which service_endpoints
// names. The tables have a replica identity, so that they can be published
// for logical replication.
func TestPGListenerOwners(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	execAll(t, conn, `CREATE PUBLICATION shawk_test FOR TABLE shawk.listeners, shawk.listener_owners`)
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	write := func(port uint16, pk procKey, first, last time.Time) {
		t.Helper()
		h := newHostChanges("h")
		h.setHost("m", "app-01", "k", "v", last)
		h.addAddr(addrOf("10.0.0.5"), span{first, last})
		if pk != (procKey{}) {
			h.addProcess(pk, "", span{first, last})
		}
		h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: port, netns: 1, procKey: pk}, span{first, last})
		if err := st.write(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	old := procKey{"app.service", "puma", "app"}
	replacement := procKey{"app.service", "unicorn", "app2"}
	write(8080, old, now.Add(-2*time.Hour), now.Add(-30*time.Minute))
	// The owner is unknown for a moment, then the port changes hands.
	write(8080, procKey{}, now.Add(-29*time.Minute), now.Add(-29*time.Minute))
	write(8080, replacement, now.Add(-29*time.Minute), now.Add(-time.Minute))
	// Replays update the rows.
	write(8080, replacement, now.Add(-time.Minute), now)
	write(8080, old, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	// A listener whose owner became unknown keeps its last known owner.
	write(9090, old, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	write(9090, procKey{}, now.Add(-time.Hour), now)

	age := func(t string) string {
		return `to_char(now() - ` + t + `.first_seen, 'HH24:MI') || '-' || to_char(now() - ` + t + `.last_seen, 'HH24:MI')`
	}
	got := queryStrings(t, conn, `
SELECT o.port, p.comm, `+age("o")+` FROM shawk.listener_owners o JOIN shawk.processes p ON p.id = o.process_id`)
	want := []string{"8080 puma 03:00-00:30", "8080 unicorn 00:29-00:00", "9090 puma 03:00-02:00"}
	if !slices.Equal(got, want) {
		t.Errorf("listener_owners = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `
SELECT l.port, coalesce(p.comm, '-'), `+age("l")+` FROM shawk.listeners l LEFT JOIN shawk.processes p ON p.id = l.process_id`)
	want = []string{"8080 unicorn 03:00-00:00", "9090 puma 03:00-00:00"}
	if !slices.Equal(got, want) {
		t.Errorf("listeners = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `SELECT port, host(addr), service FROM shawk_v1.service_endpoints`)
	want = []string{"8080 10.0.0.5 app2", "9090 10.0.0.5 app"}
	if !slices.Equal(got, want) {
		t.Errorf("service_endpoints = %q, want %q", got, want)
	}

	// The owners go with the retention, and so do processes nothing
	// refers to any more.
	if _, err := conn.Exec(ctx, `SELECT shawk.prune(now() - interval '90 minutes')`); err != nil {
		t.Fatal(err)
	}
	got = queryStrings(t, conn, `SELECT o.port, p.comm FROM shawk.listener_owners o JOIN shawk.processes p ON p.id = o.process_id`)
	if !slices.Equal(got, []string{"8080 puma", "8080 unicorn"}) {
		t.Errorf("listener_owners after prune = %q", got)
	}
}

// TestPGListenerOwnersBatch: several owners of a listener in one write,
// the latest of which is unknown.
func TestPGListenerOwnersBatch(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	h := newHostChanges("h")
	h.setHost("m", "app-01", "k", "v", now)
	a := procKey{"a.service", "a", "a"}
	b := procKey{"b.service", "b", "b"}
	for _, o := range []struct {
		pk          procKey
		first, last time.Time
	}{
		{a, now.Add(-3 * time.Minute), now.Add(-2 * time.Minute)},
		{b, now.Add(-2 * time.Minute), now.Add(-time.Minute)},
		{procKey{}, now, now},
	} {
		if o.pk != (procKey{}) {
			h.addProcess(o.pk, "", span{o.first, o.last})
		}
		h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.5"), port: 80, netns: 1, procKey: o.pk}, span{o.first, o.last})
	}
	if err := st.write(ctx, h); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, conn, `
SELECT coalesce(p.comm, '-'), to_char(now() - l.first_seen, 'MI'), to_char(now() - l.last_seen, 'MI')
FROM shawk.listeners l LEFT JOIN shawk.processes p ON p.id = l.process_id`)
	if !slices.Equal(got, []string{"b 03 00"}) {
		t.Errorf("listeners = %q, want the latest known owner over the whole span", got)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.listener_owners`); !slices.Equal(got, []string{"2"}) {
		t.Errorf("listener_owners = %q rows", got)
	}
}
