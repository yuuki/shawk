package shawkconnector

import (
	"context"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
)

// TestPGEndpointAtAddressOfAnotherHost: a listener and a server edge that
// an agent reports at the address of another host, with a time far in the
// future, are written no later than maxClockAhead ahead, and a connector
// that reads the endpoints from PostgreSQL names the peers at the address
// after the host that holds it.
func TestPGEndpointAtAddressOfAnotherHost(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	consume(t, c, sink, tAgent{host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.5"}, time: now,
		segment:   now.Add(-time.Hour),
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", comm: "postgres"}}})
	consume(t, c, sink, tAgent{host: "evil-01", machineID: "m-evil", addrs: []string{"10.0.0.66"}, time: now,
		segment:   now.Add(-time.Hour),
		listeners: []tListener{{proto: "tcp", addr: "10.0.0.5", port: 5432, svc: "evil", comm: "evil", last: farFuture}},
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.5", peer: "10.0.0.11", port: 5432, svc: "evil",
			comm: "evil", opened: 1, last: farFuture}}})
	c.flush(ctx)

	got := queryStrings(t, conn, `SELECT t, max(last_seen) <= now() + interval '2 minutes 5 seconds' FROM (
	    SELECT 'edges' AS t, last_seen FROM shawk.edges UNION ALL
	    SELECT 'listeners', last_seen FROM shawk.listeners UNION ALL
	    SELECT 'processes', last_seen FROM shawk.processes UNION ALL
	    SELECT 'service_endpoints', last_seen FROM shawk_v1.service_endpoints) x GROUP BY t`)
	if want := []string{"edges true", "listeners true", "processes true", "service_endpoints true"}; !slices.Equal(got, want) {
		t.Errorf("times written = %v, want %v", got, want)
	}

	// A connector that has seen neither host reads them from PostgreSQL.
	cfg := *c.cfg
	cfg.Postgres.Migrate = false
	sink2 := new(consumertest.MetricsSink)
	c2, err := newConnector(connectortest.NewNopSettings(Type), &cfg, sink2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c2.Shutdown(ctx) })
	out := consume(t, c2, sink2, tAgent{host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11"}, time: now,
		segment: now.Add(-time.Hour),
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.5", port: 5432, svc: "app",
			comm: "app", opened: 1}}})
	if s := find(out, metricConnOpened, "app", "postgres", roleClient, ""); len(s) != 1 || !s[0].agent {
		t.Errorf("client series = %+v, want postgres with an agent", find(out, metricConnOpened, "app", "*", roleClient, ""))
	}
}
