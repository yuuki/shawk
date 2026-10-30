package api

import (
	"testing"
	"time"
)

func TestEdgeQueryRoundTrip(t *testing.T) {
	q := EdgeQuery{
		Direction: "in", Proto: "tcp", LocalAddr: "10.0.0.1", RemoteAddr: "10.0.0.2", Port: 5432,
		Unit: "postgresql.service", Comm: "postgres",
		Since: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Until: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
	}
	got, err := ParseEdgeQuery(q.Values())
	if err != nil {
		t.Fatal(err)
	}
	if got != q {
		t.Errorf("round trip = %+v, want %+v", got, q)
	}
	if _, err := ParseEdgeQuery(map[string][]string{"port": {"70000"}}); err == nil {
		t.Error("invalid port accepted")
	}
}
