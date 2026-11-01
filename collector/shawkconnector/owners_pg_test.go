package shawkconnector

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestPGListenerOwners: a listener that changes hands keeps a row per owner,
// so its history is kept (#98); service_endpoints names its latest owner.
func TestPGListenerOwners(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	write := func(pk procKey, first, last time.Time) {
		t.Helper()
		h := newHostChanges("h")
		h.setHost("m", "app-01", "k", "v", last)
		h.addAddr(addrOf("10.0.0.5"), span{first, last})
		k := listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: 8080, netns: 1, procKey: pk}
		if pk != (procKey{}) {
			h.addProcess(pk, "", span{first, last})
		}
		h.addListener(k, span{first, last})
		if err := st.write(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	old := procKey{"app.service", "puma", "app"}
	replacement := procKey{"app.service", "unicorn", "app2"}
	write(old, now.Add(-2*time.Hour), now.Add(-30*time.Minute))
	// The owner is unknown for a moment, then the port changes hands.
	write(procKey{}, now.Add(-29*time.Minute), now.Add(-29*time.Minute))
	write(replacement, now.Add(-29*time.Minute), now.Add(-time.Minute))
	// Replays of the same owner update its row.
	write(replacement, now.Add(-time.Minute), now)
	write(old, now.Add(-3*time.Hour), now.Add(-2*time.Hour))

	got := queryStrings(t, conn, `
SELECT coalesce(p.comm, '-'), to_char(now() - l.first_seen, 'HH24:MI'), to_char(now() - l.last_seen, 'HH24:MI')
FROM shawk.listeners l LEFT JOIN shawk.processes p ON p.id = l.process_id`)
	want := []string{"- 00:29 00:29", "puma 03:00 00:30", "unicorn 00:29 00:00"}
	if !slices.Equal(got, want) {
		t.Errorf("listeners = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `SELECT host(addr), service FROM shawk_v1.service_endpoints WHERE port = 8080`)
	if !slices.Equal(got, []string{"10.0.0.5 app2"}) {
		t.Errorf("service_endpoints = %q", got)
	}
}
