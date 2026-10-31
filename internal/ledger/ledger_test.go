package ledger

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuuki/shawk/internal/api"
)

func openTest(t *testing.T) *Ledger {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "ledger.db"), DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func clientRecord() Record {
	return Record{
		Direction: "out", Proto: "tcp", LocalAddr: "10.0.0.2", RemoteAddr: "10.0.0.10", Port: 5432,
		NetNS: 1, Unit: "app.service", Comm: "puma", Exe: "/usr/bin/ruby", PID: 100,
		Conns: 3, BytesSent: 300, BytesRecv: 900, OpenConns: 2, RTTSumUs: 300, RTTCount: 3,
	}
}

func TestWriteAndQuery(t *testing.T) {
	ctx := context.Background()
	l := openTest(t)
	now := time.Now().Truncate(time.Second)

	r := clientRecord()
	if err := l.Write(ctx, now.Add(-2*time.Minute), []Record{r}, nil); err != nil {
		t.Fatal(err)
	}
	r.Conns, r.OpenConns, r.PID, r.Exe = 1, 5, 101, ""
	if err := l.Write(ctx, now, []Record{r}, nil); err != nil {
		t.Fatal(err)
	}
	other := clientRecord()
	other.Direction, other.Port, other.Unit, other.Comm = "in", 8080, "app.service", "puma"
	if err := l.Write(ctx, now, []Record{other}, nil); err != nil {
		t.Fatal(err)
	}

	edges, err := l.Edges(ctx, api.EdgeQuery{Direction: "out", Port: 5432, Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.Stats.Conns != 4 || e.Stats.BytesSent != 600 || e.Stats.MaxOpenConns != 5 || e.Stats.RTTAvgUs != 100 {
		t.Errorf("stats = %+v", e.Stats)
	}
	if e.PID != 101 || e.Exe != "/usr/bin/ruby" {
		t.Errorf("pid/exe = %d/%q", e.PID, e.Exe)
	}
	if !e.FirstSeen.Equal(now.Add(-2*time.Minute)) || !e.LastSeen.Equal(now) {
		t.Errorf("first/last = %v/%v", e.FirstSeen, e.LastSeen)
	}

	// The window excludes the first interval.
	edges, err = l.Edges(ctx, api.EdgeQuery{Direction: "out", Since: now.Add(-30 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].Stats.Conns != 1 {
		t.Errorf("windowed edges = %+v", edges)
	}

	// Older windows are answered from hourly and daily buckets.
	for _, since := range []time.Time{now.Add(-72 * time.Hour), now.Add(-365 * 24 * time.Hour)} {
		edges, err = l.Edges(ctx, api.EdgeQuery{Direction: "out", Since: since})
		if err != nil {
			t.Fatal(err)
		}
		if len(edges) != 1 || edges[0].Stats.Conns != 4 {
			t.Errorf("edges since %v = %+v", since, edges)
		}
	}

	// Edges not active in the window are excluded.
	edges, err = l.Edges(ctx, api.EdgeQuery{Until: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 0 {
		t.Errorf("edges before the first record = %+v", edges)
	}

	since, err := l.Since(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !since.Equal(now.Add(-2 * time.Minute)) {
		t.Errorf("Since = %v", since)
	}
}

func TestListeners(t *testing.T) {
	ctx := context.Background()
	l := openTest(t)
	now := time.Now().Truncate(time.Second)
	ls := ListenerRecord{Proto: "tcp", Addr: "0.0.0.0", Port: 80, NetNS: 1, Unit: "nginx.service", Comm: "nginx", PID: 10}
	if err := l.Write(ctx, now.Add(-time.Minute), nil, []ListenerRecord{ls}); err != nil {
		t.Fatal(err)
	}
	// An owner that could not be resolved does not overwrite the known one.
	ls.Unit, ls.Comm, ls.PID = "", "", 0
	if err := l.Write(ctx, now, nil, []ListenerRecord{ls}); err != nil {
		t.Fatal(err)
	}
	got, err := l.Listeners(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Comm != "nginx" || got[0].PID != 10 || !got[0].LastSeen.Equal(now) {
		t.Errorf("listeners = %+v", got)
	}
}

func TestPrune(t *testing.T) {
	ctx := context.Background()
	l := openTest(t)
	now := time.Now().Truncate(time.Second)
	old := clientRecord()
	old.RemoteAddr = "10.0.0.99"
	if err := l.Write(ctx, now.Add(-4*365*24*time.Hour), []Record{old}, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(ctx, now.Add(-3*24*time.Hour), []Record{clientRecord()}, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Prune(ctx, now); err != nil {
		t.Fatal(err)
	}
	edges, err := l.Edges(ctx, api.EdgeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].RemoteAddr != "10.0.0.10" {
		t.Fatalf("edges after prune = %+v", edges)
	}
	var minutes int
	if err := l.db.QueryRow(`SELECT count(*) FROM activity WHERE res = 60`).Scan(&minutes); err != nil {
		t.Fatal(err)
	}
	if minutes != 0 {
		t.Errorf("minute buckets older than the retention remain: %d", minutes)
	}
}

func TestUnresolvedCgroupKeepsPath(t *testing.T) {
	ctx := context.Background()
	l := openTest(t)
	now := time.Now().Truncate(time.Second)
	r := clientRecord()
	r.Cgroup = "/system.slice/app.service"
	if err := l.Write(ctx, now.Add(-time.Minute), []Record{r}, nil); err != nil {
		t.Fatal(err)
	}
	r.Cgroup = ""
	if err := l.Write(ctx, now, []Record{r}, nil); err != nil {
		t.Fatal(err)
	}
	edges, err := l.Edges(ctx, api.EdgeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].Cgroup != "/system.slice/app.service" {
		t.Errorf("edges = %+v", edges)
	}
}
