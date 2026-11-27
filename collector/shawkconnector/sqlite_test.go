package shawkconnector

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func openTestSQLite(t *testing.T, path string, now time.Time) *sqliteStore {
	t.Helper()
	ctx := context.Background()
	st, err := newSQLiteStore(ctx, SQLiteConfig{Path: path}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st.now = func() time.Time { return now }
	t.Cleanup(st.close)
	if _, err := st.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestSQLiteMigrateAndLock(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "shawk.db")

	st, err := newSQLiteStore(ctx, SQLiteConfig{Path: dbPath}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := st.migrate(ctx)
	if err != nil {
		st.close()
		t.Fatal(err)
	}
	if len(applied) != 1 {
		st.close()
		t.Fatalf("applied = %v, want 1 migration", applied)
	}
	// Second migrate is a no-op.
	if applied2, err := st.migrate(ctx); err != nil || len(applied2) != 0 {
		st.close()
		t.Fatalf("second migrate = %v, %v", applied2, err)
	}

	// A second connector opening the same database file must fail immediately.
	if st2, err := newSQLiteStore(ctx, SQLiteConfig{Path: dbPath}, 15*time.Minute); err == nil {
		st2.close()
		st.close()
		t.Fatal("second process opened locked SQLite database")
	} else if !strings.Contains(err.Error(), "locked") {
		st.close()
		t.Fatalf("unexpected lock error: %v", err)
	}

	// Schema newer than this connector is refused.
	if _, err := st.db.ExecContext(ctx, `PRAGMA user_version = 99`); err != nil {
		st.close()
		t.Fatal(err)
	}
	if _, err := st.migrate(ctx); err == nil {
		st.close()
		t.Fatal("newer schema version was accepted")
	}
	if _, err := st.db.ExecContext(ctx, `PRAGMA user_version = 1`); err != nil {
		st.close()
		t.Fatal(err)
	}
	st.close()

	// After close, another opener acquires the lock cleanly.
	st3, err := newSQLiteStore(ctx, SQLiteConfig{Path: dbPath}, 15*time.Minute)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	defer st3.close()
	if v, err := st3.schemaVersion(ctx); err != nil || v != sqliteSchemaVersion {
		t.Fatalf("schemaVersion = %d, %v", v, err)
	}
}

func TestSQLitePeers(t *testing.T) {
	ctx := context.Background()
	now := t0
	st := openTestSQLite(t, filepath.Join(t.TempDir(), "shawk.db"), now)

	// Host db-01: alive, holds IPv4 + IPv6 + loopback, listens on 0.0.0.0:5432
	// (IPv4-only expansion) and :::8080 (both IPv4 & IPv6), plus a Unix socket
	// and a listener-less UDP server edge, plus a moved IP 10.0.0.50 held earlier.
	hDB := newHostChanges("db-id")
	hDB.setHost("m-db", "db-01", "5.14", "test", now.Add(-time.Minute))
	hDB.addSession(now.Add(-time.Hour), sessionRow{
		lastHeartbeat: now.Add(-time.Minute),
		udpTraced:     true,
		netnsScope:    "all",
		peerFold:      foldIn,
		peerInternal:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	hDB.addAddr(addrOf("10.0.0.10"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hDB.addAddr(addrOf("fd00::10"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hDB.addAddr(addrOf("127.0.0.1"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	// Former IP that moved to another host later.
	hDB.addAddr(addrOf("10.0.0.50"), span{now.Add(-3 * time.Hour), now.Add(-2 * time.Hour)})
	// Shared container bridge IP also held by app-01.
	hDB.addAddr(addrOf("172.17.0.1"), span{now.Add(-time.Hour), now.Add(-time.Minute)})

	hDB.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: 5432, netns: 1,
		procKey: procKey{unit: "postgresql.service", comm: "postgres", service: "postgres"}}, span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hDB.addListener(listenerRowKey{proto: "tcp", addr: addrOf("::"), port: 8080, netns: 1,
		procKey: procKey{unit: "api.service", comm: "api", service: "api"}}, span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hDB.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.50"), port: 9000, netns: 1,
		procKey: procKey{unit: "old.service", comm: "old", service: "old"}}, span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hDB.addListener(listenerRowKey{proto: "tcp", addr: addrOf("127.0.0.1"), port: 9100, netns: 1,
		procKey: procKey{unit: "local.service", comm: "local", service: "local"}}, span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hDB.addListener(listenerRowKey{proto: transportUnix, path: "/run/pg.sock", netns: 1,
		procKey: procKey{unit: "postgresql.service", comm: "postgres", service: "postgres"}}, span{now.Add(-time.Hour), now.Add(-time.Minute)})
	// Listener-less UDP server edge 3 days ago.
	hDB.addEdge(edgeRowKey{role: roleServer, proto: "udp", local: addrOf("10.0.0.10"), peer: addrOf("10.0.0.11"), port: 53, netns: 1,
		procKey: procKey{unit: "named.service", comm: "named", service: "dns"}}, span{now.Add(-3 * 24 * time.Hour), now.Add(-3 * 24 * time.Hour)})
	if err := st.write(ctx, hDB); err != nil {
		t.Fatal(err)
	}

	// Host app-01: alive, took over 10.0.0.50 at now-1h, also holds shared 172.17.0.1,
	// has a Slurm job client edge, a folded edge (must be ignored), and a learned translation.
	hApp := newHostChanges("app-id")
	hApp.setHost("m-app", "app-01", "5.14", "test", now.Add(-time.Minute))
	hApp.addSession(now.Add(-time.Hour), sessionRow{lastHeartbeat: now.Add(-time.Minute), netnsScope: "all"})
	hApp.addAddr(addrOf("10.0.0.11"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hApp.addAddr(addrOf("10.0.0.50"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hApp.addAddr(addrOf("172.17.0.1"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hApp.addAddr(addrOf("127.0.0.1"), span{now.Add(-time.Hour), now.Add(-time.Minute)})
	hApp.addEdge(edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.10"), port: 5432, netns: 1,
		procKey: procKey{unit: "slurm/batch", comm: "a.out", service: "a.out"}}, span{now.Add(-10 * time.Minute), now.Add(-time.Minute)})
	hApp.addEdge(edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("0.0.0.0"), folded: true, port: 443, netns: 1,
		procKey: procKey{unit: "curl.service", comm: "curl", service: "curl"}}, span{now.Add(-10 * time.Minute), now.Add(-time.Minute)})
	hApp.addTranslation(translationID{
		proto: "tcp", netns: 1,
		client: addrOf("10.0.0.11"), virtual: addrOf("10.96.0.1"), vport: 80,
		source: addrOf("10.0.0.11"), backend: addrOf("10.0.0.10"), bport: 8080,
	}, span{now.Add(-5 * time.Minute), now.Add(-time.Minute)})
	if err := st.write(ctx, hApp); err != nil {
		t.Fatal(err)
	}

	// Dead host dead-01: stopped 2 days ago, held 10.0.0.99 alone (must appear in formerHolders).
	hDead := newHostChanges("dead-id")
	hDead.setHost("m-dead", "dead-01", "5.14", "test", now.Add(-2*24*time.Hour))
	hDead.addSession(now.Add(-3*24*time.Hour), sessionRow{lastHeartbeat: now.Add(-2 * 24 * time.Hour), netnsScope: "all"})
	hDead.addAddr(addrOf("10.0.0.99"), span{now.Add(-3 * 24 * time.Hour), now.Add(-2 * 24 * time.Hour)})
	if err := st.write(ctx, hDead); err != nil {
		t.Fatal(err)
	}

	rows, err := st.peers(ctx, 15*time.Minute, formerHolderWindow)
	if err != nil {
		t.Fatal(err)
	}

	// Verify service_endpoints.
	hasEP := func(addr string, port uint16, proto, svc string, exact bool) bool {
		a := addrOf(addr)
		for _, e := range rows.endpoints {
			if e.key.addr == a && e.key.port == port && e.key.proto == proto && e.service == svc && e.exact == exact {
				return true
			}
		}
		return false
	}
	if !hasEP("10.0.0.10", 5432, "tcp", "postgres", false) {
		t.Errorf("missing expanded IPv4 listener 10.0.0.10:5432 in %+v", rows.endpoints)
	}
	if hasEP("fd00::10", 5432, "tcp", "postgres", false) {
		t.Errorf("0.0.0.0 listener must not expand to IPv6")
	}
	if !hasEP("10.0.0.10", 8080, "tcp", "api", false) || !hasEP("fd00::10", 8080, "tcp", "api", false) {
		t.Errorf(":: listener must expand to both IPv4 and IPv6: %+v", rows.endpoints)
	}
	if hasEP("10.0.0.50", 9000, "tcp", "old", true) {
		t.Errorf("moved IP 10.0.0.50 should be excluded from db-01 endpoints")
	}
	if !hasEP("127.0.0.1", 9100, "tcp", "local", true) {
		t.Errorf("loopback listener should never be marked moved")
	}
	if !hasEP("10.0.0.10", 53, "udp", "dns", true) {
		t.Errorf("listener-less UDP server endpoint missing")
	}

	// Verify client_endpoints: Slurm job renamed to slurm-job, folded edge omitted.
	if len(rows.clients) != 1 || rows.clients[0].service != slurmJobService || rows.clients[0].key.server != addrOf("10.0.0.10") {
		t.Errorf("clients = %+v", rows.clients)
	}

	// Verify unix_endpoints.
	if len(rows.unix) != 1 || rows.unix[0].key.path != "/run/pg.sock" || rows.unix[0].service != "postgres" {
		t.Errorf("unix = %+v", rows.unix)
	}

	// Verify learned_translations.
	if len(rows.learned) != 1 || rows.learned[0].id.virtual != addrOf("10.96.0.1") || rows.learned[0].id.backend != addrOf("10.0.0.10") {
		t.Errorf("learned = %+v", rows.learned)
	}

	// Verify agent_addrs: dead-01 is not alive; db-01 carries udpTraced, fold and internal prefixes.
	var dbAgent *agentAddrRow
	for i := range rows.agents {
		if rows.agents[i].host == "dead-id" {
			t.Errorf("dead host in agent_addrs: %+v", rows.agents[i])
		}
		if rows.agents[i].host == "db-id" && rows.agents[i].addr == addrOf("10.0.0.10") {
			dbAgent = &rows.agents[i]
		}
	}
	if dbAgent == nil || !dbAgent.agent.udpTraced || dbAgent.agent.fold != foldIn || len(dbAgent.agent.internal) != 1 {
		t.Errorf("db agent addr = %+v", dbAgent)
	}

	// Verify formerHolders: dead-01 (10.0.0.99) and app-01 (10.0.0.50) included,
	// shared 172.17.0.1 and loopback 127.0.0.1 excluded.
	formerByAddr := map[netip.Addr]string{}
	for _, f := range rows.former {
		formerByAddr[f.addr] = f.name
	}
	if formerByAddr[addrOf("10.0.0.99")] != "dead-01" {
		t.Errorf("former 10.0.0.99 = %q, want dead-01", formerByAddr[addrOf("10.0.0.99")])
	}
	if formerByAddr[addrOf("10.0.0.50")] != "app-01" {
		t.Errorf("former 10.0.0.50 = %q, want app-01", formerByAddr[addrOf("10.0.0.50")])
	}
	if _, ok := formerByAddr[addrOf("172.17.0.1")]; ok {
		t.Errorf("shared address 172.17.0.1 must not be in formerHolders")
	}
	if _, ok := formerByAddr[addrOf("127.0.0.1")]; ok {
		t.Errorf("loopback address must not be in formerHolders")
	}
}

func TestSQLiteConnectorRestartAndResolution(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "shawk.db")
	now := t0

	startConn := func() (*shawkConnector, *consumertest.MetricsSink) {
		cfg := createDefaultConfig()
		cfg.SQLite.Path = dbPath
		cfg.PeerHosts = true
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		sink := &consumertest.MetricsSink{}
		c, err := newConnector(connectortest.NewNopSettings(Type), cfg, sink)
		if err != nil {
			t.Fatal(err)
		}
		c.now = func() time.Time { return now }
		c.agg.started = now.Add(-time.Minute)
		if err := c.Start(ctx, nil); err != nil {
			t.Fatal(err)
		}
		return c, sink
	}

	// First connector observes db-01 listening on 0.0.0.0:5432, flushes to SQLite, and stops.
	c1, sink1 := startConn()
	consume(t, c1, sink1, tAgent{
		host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.10"}, time: now, segment: now.Add(-time.Hour),
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", comm: "postgres", unit: "postgresql.service"}},
	})
	if err := c1.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// Advance 10 minutes: db-01 is now down (> aliveWindow). Start a fresh connector
	// on the same SQLite file and send a failed connect from app-01 to 10.0.0.10:5432.
	now = now.Add(10 * time.Minute)
	c2, sink2 := startConn()
	defer func() {
		if err := c2.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()

	consume(t, c2, sink2, tAgent{
		host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11"}, time: now, segment: now.Add(-time.Hour),
		edges: []tEdge{{
			role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
			svc: "web", comm: "web", unit: "web.service", failed: 2,
			reasons: map[string]tReason{"refused": {value: 2, start: now.Add(-15 * time.Second)}},
		}},
	})

	// Check that connector #2 resolved service.peer.name, shawk.peer.host, and
	// shawk.peer.agent=false from SQLite on the very first interval after restart.
	var foundPeer, foundHost bool
	for _, md := range sink2.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					m := ms.At(k)
					if m.Type() != pmetric.MetricTypeSum {
						continue
					}
					dps := m.Sum().DataPoints()
					for l := range dps.Len() {
						a := dps.At(l).Attributes()
						peerSvc, _ := a.Get(attrPeerService)
						peerAgent, _ := a.Get(attrPeerAgent)
						if m.Name() == metricConnFailed && peerSvc.Str() == "postgres" && !peerAgent.Bool() {
							foundPeer = true
						}
						if m.Name() == metricHostConnFailedByReason {
							peerHost, _ := a.Get(attrPeerHost)
							if peerSvc.Str() == "postgres" && peerHost.Str() == "db-01" && !peerAgent.Bool() {
								foundHost = true
							}
						}
					}
				}
			}
		}
	}
	if !foundPeer {
		t.Error("restarted SQLite connector did not resolve service.peer.name=postgres with shawk.peer.agent=false")
	}
	if !foundHost {
		t.Error("restarted SQLite connector did not resolve shawk.peer.host=db-01 for dead host")
	}
}

func TestSQLitePrune(t *testing.T) {
	ctx := context.Background()
	now := t0
	st := openTestSQLite(t, filepath.Join(t.TempDir(), "shawk.db"), now)

	// Old host (40d ago): everything should be pruned.
	oldT := now.Add(-40 * 24 * time.Hour)
	hOld := newHostChanges("old-id")
	hOld.setHost("m-old", "old-01", "5.14", "test", oldT)
	hOld.addSession(oldT, sessionRow{lastHeartbeat: oldT, netnsScope: "all"})
	hOld.addAddr(addrOf("10.0.0.1"), span{oldT, oldT})
	hOld.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.1"), port: 80, netns: 1,
		procKey: procKey{unit: "old.service", comm: "old", service: "old"}}, span{oldT, oldT})
	hOld.addListener(listenerRowKey{proto: transportUnix, path: "/run/old.sock", netns: 1,
		procKey: procKey{unit: "old.service", comm: "old", service: "old"}}, span{oldT, oldT})
	if err := st.write(ctx, hOld); err != nil {
		t.Fatal(err)
	}

	// Active host with stale client_endpoints (3h), stale server_endpoints (10d),
	// stale learned_translation (2h), and fresh rows.
	hNew := newHostChanges("new-id")
	hNew.setHost("m-new", "new-01", "5.14", "test", now)
	hNew.addSession(now.Add(-time.Hour), sessionRow{lastHeartbeat: now, netnsScope: "all"})
	hNew.addAddr(addrOf("10.0.0.2"), span{now, now})
	hNew.addEdge(edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.2"), peer: addrOf("10.0.0.3"), port: 80, netns: 1,
		procKey: procKey{unit: "a.service", comm: "a", service: "a"}}, span{now.Add(-3 * time.Hour), now.Add(-3 * time.Hour)})
	hNew.addEdge(edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.2"), peer: addrOf("10.0.0.4"), port: 80, netns: 1,
		procKey: procKey{unit: "a.service", comm: "a", service: "a"}}, span{now.Add(-5 * time.Minute), now.Add(-5 * time.Minute)})
	hNew.addEdge(edgeRowKey{role: roleServer, proto: "udp", local: addrOf("10.0.0.2"), peer: addrOf("10.0.0.3"), port: 53, netns: 1,
		procKey: procKey{unit: "dns.service", comm: "dns", service: "dns"}}, span{now.Add(-10 * 24 * time.Hour), now.Add(-10 * 24 * time.Hour)})
	hNew.addEdge(edgeRowKey{role: roleServer, proto: "udp", local: addrOf("10.0.0.2"), peer: addrOf("10.0.0.3"), port: 123, netns: 1,
		procKey: procKey{unit: "ntp.service", comm: "ntp", service: "ntp"}}, span{now.Add(-2 * 24 * time.Hour), now.Add(-2 * 24 * time.Hour)})
	hNew.addTranslation(translationID{
		proto: "tcp", netns: 1,
		client: addrOf("10.0.0.2"), virtual: addrOf("10.96.0.1"), vport: 80,
		source: addrOf("10.0.0.2"), backend: addrOf("10.0.0.3"), bport: 8080,
	}, span{now.Add(-2 * time.Hour), now.Add(-2 * time.Hour)})
	if err := st.write(ctx, hNew); err != nil {
		t.Fatal(err)
	}

	deleted, err := st.prune(ctx, 0, pruneBatch)
	if err != nil {
		t.Fatal(err)
	}
	if deleted == 0 {
		t.Fatal("prune deleted 0 rows")
	}
	if again, err := st.prune(ctx, 0, pruneBatch); err != nil || again != 0 {
		t.Fatalf("second prune = %d, %v; want 0", again, err)
	}

	rows, err := st.peers(ctx, 15*time.Minute, formerHolderWindow)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.clients) != 1 || rows.clients[0].key.server != addrOf("10.0.0.4") {
		t.Errorf("clients after prune = %+v", rows.clients)
	}
	if len(rows.endpoints) != 1 || rows.endpoints[0].key.port != 123 {
		t.Errorf("endpoints after prune = %+v", rows.endpoints)
	}
	if len(rows.learned) != 0 {
		t.Errorf("learned after prune = %+v", rows.learned)
	}
}

func TestSQLiteInventory(t *testing.T) {
	ctx := context.Background()
	st := openTestSQLite(t, ":memory:", t0)

	if inv, err := st.inventory(ctx); err != nil || inv != nil {
		t.Fatalf("empty inventory = %+v, %v", inv, err)
	}
	inv, err := parseInventory([]byte(testInventory))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.syncInventory(ctx, inv, t0); err != nil {
		t.Fatal(err)
	}
	// Failure records the error without clearing the stored inventory.
	if err := st.inventoryFailed(ctx, t0.Add(time.Minute), "bad yaml"); err != nil {
		t.Fatal(err)
	}
	got, err := st.inventory(ctx)
	if err != nil || got == nil {
		t.Fatalf("inventory = %+v, %v", got, err)
	}
	if got.digest != inv.digest || len(got.hosts) != len(inv.hosts) {
		t.Errorf("digest/hosts mismatch: got %d (%s), want %d (%s)", len(got.hosts), got.digest, len(inv.hosts), inv.digest)
	}
	for i := range inv.hosts {
		if got.hosts[i].name != inv.hosts[i].name || got.hosts[i].slurmNode != inv.hosts[i].slurmNode ||
			got.hosts[i].agent != inv.hosts[i].agent || !slices.Equal(got.hosts[i].roles, inv.hosts[i].roles) ||
			!slices.Equal(got.hosts[i].addrs, inv.hosts[i].addrs) {
			t.Errorf("host[%d] = %+v, want %+v", i, got.hosts[i], inv.hosts[i])
		}
	}
}

func TestSQLitePragmasSurviveReconnect(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "shawk.db")
	st := openTestSQLite(t, dbPath, t0)

	checkPragmas := func(stage string) {
		t.Helper()
		var fk, busy, temp int
		if err := st.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("%s: foreign_keys: %v", stage, err)
		}
		if err := st.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
			t.Fatalf("%s: busy_timeout: %v", stage, err)
		}
		if err := st.db.QueryRowContext(ctx, `PRAGMA temp_store`).Scan(&temp); err != nil {
			t.Fatalf("%s: temp_store: %v", stage, err)
		}
		if fk != 1 || busy != int(defaultSQLiteBusyTimeout.Milliseconds()) || temp != 2 {
			t.Fatalf("%s: pragmas fk=%d busy=%d temp=%d, want 1/%d/2", stage, fk, busy, temp, defaultSQLiteBusyTimeout.Milliseconds())
		}
	}

	checkPragmas("initial")
	// Force database/sql to close the idle physical connection and open a fresh one.
	st.db.SetMaxIdleConns(0)
	st.db.SetMaxIdleConns(1)
	checkPragmas("after reconnect")
}

func TestSQLiteStartFailsFastAndReleasesLock(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "shawk.db")

	st, err := newSQLiteStore(ctx, SQLiteConfig{Path: dbPath}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `PRAGMA user_version = 99`); err != nil {
		st.close()
		t.Fatal(err)
	}
	st.close()

	cfg := createDefaultConfig()
	cfg.SQLite.Path = dbPath
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, &consumertest.MetricsSink{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, nil); err == nil {
		_ = c.Shutdown(ctx)
		t.Fatal("Start() succeeded on newer SQLite schema version")
	}

	// Lock must have been released so another process can open the database.
	st2, err := newSQLiteStore(ctx, SQLiteConfig{Path: dbPath}, 15*time.Minute)
	if err != nil {
		t.Fatalf("lock was not released after failed Start(): %v", err)
	}
	st2.close()
}

func TestSQLiteDeadHostServerEndpointsAndBoundedPrune(t *testing.T) {
	ctx := context.Background()
	now := t0
	st := openTestSQLite(t, filepath.Join(t.TempDir(), "shawk.db"), now)

	// Dead host stopped 12 days ago with a listener-less UDP server endpoint:
	// must survive prune() and stay visible in peers() for up to 30 days.
	deadT := now.Add(-12 * 24 * time.Hour)
	hDead := newHostChanges("dead-srv")
	hDead.setHost("m-dead", "dead-dns", "5.14", "test", deadT)
	hDead.addSession(deadT, sessionRow{lastHeartbeat: deadT, netnsScope: "all"})
	hDead.addAddr(addrOf("10.0.0.53"), span{deadT, deadT})
	hDead.addEdge(edgeRowKey{role: roleServer, proto: "udp", local: addrOf("10.0.0.53"), peer: addrOf("10.0.0.1"), port: 53, netns: 1,
		procKey: procKey{unit: "named.service", comm: "named", service: "dns"}}, span{deadT, deadT})
	if err := st.write(ctx, hDead); err != nil {
		t.Fatal(err)
	}

	// Expired host (40 days ago) with 5 server_endpoints rows to test bounded prune
	// without ON DELETE CASCADE bypassing maxRows.
	oldT := now.Add(-40 * 24 * time.Hour)
	hOld := newHostChanges("expired-many")
	hOld.setHost("m-old", "old-many", "5.14", "test", oldT)
	hOld.addSession(oldT, sessionRow{lastHeartbeat: oldT, netnsScope: "all"})
	for p := uint16(8000); p < 8005; p++ {
		hOld.addEdge(edgeRowKey{role: roleServer, proto: "tcp", local: addrOf("10.0.0.88"), peer: addrOf("10.0.0.1"), port: p, netns: 1,
			procKey: procKey{unit: "svc.service", comm: "svc", service: "svc"}}, span{oldT, oldT})
	}
	if err := st.write(ctx, hOld); err != nil {
		t.Fatal(err)
	}

	// First batch with maxRows=2 must delete only 2 child rows and keep the parent host
	// row until all child rows are drained.
	n1, err := st.prune(ctx, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != 2 {
		t.Fatalf("batch 1 deleted %d rows, want 2 (no cascade bypass)", n1)
	}
	var oldHostCount int
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE id = 'expired-many'`).Scan(&oldHostCount); err != nil {
		t.Fatal(err)
	}
	if oldHostCount != 1 {
		t.Fatalf("parent host row was prematurely deleted via cascade")
	}

	// Drain remaining batches.
	for range 10 {
		n, err := st.prune(ctx, 0, 2)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE id = 'expired-many'`).Scan(&oldHostCount); err != nil {
		t.Fatal(err)
	}
	if oldHostCount != 0 {
		t.Fatalf("expired host still present after full drain")
	}

	// Dead host's server_endpoint from 12 days ago must still resolve.
	rows, err := st.peers(ctx, 15*time.Minute, formerHolderWindow)
	if err != nil {
		t.Fatal(err)
	}
	foundDeadDNS := false
	for _, ep := range rows.endpoints {
		if ep.host == "dead-srv" && ep.key.addr == addrOf("10.0.0.53") && ep.key.port == 53 && ep.service == "dns" {
			foundDeadDNS = true
		}
	}
	if !foundDeadDNS {
		t.Errorf("dead host server_endpoint from 12d ago was pruned or missing: %+v", rows.endpoints)
	}
}

func TestSQLiteUnknownOwnerListenerAndAddrPeriods(t *testing.T) {
	ctx := context.Background()
	now := t0
	st := openTestSQLite(t, ":memory:", now)

	// Host reports owned listener :80 and addr 10.0.0.10 at now-3h.
	t1 := now.Add(-3 * time.Hour)
	h1 := newHostChanges("h1")
	h1.setHost("m1", "node-01", "5.14", "test", t1)
	h1.addSession(t1, sessionRow{lastHeartbeat: t1, netnsScope: "all"})
	h1.addAddr(addrOf("10.0.0.10"), span{t1, t1})
	h1.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.10"), port: 80, netns: 1,
		procKey: procKey{unit: "nginx.service", comm: "nginx", service: "nginx"}}, span{t1, t1})
	h1.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.10"), port: 443, netns: 1,
		procKey: procKey{unit: "nginx.service", comm: "nginx", service: "nginx"}}, span{t1, t1})
	if err := st.write(ctx, h1); err != nil {
		t.Fatal(err)
	}

	// Within aliveWindow (2m later): addr period should continue (still 1 row in host_addrs).
	t2 := t1.Add(2 * time.Minute)
	h2 := newHostChanges("h1")
	h2.setHost("m1", "node-01", "5.14", "test", t2)
	h2.addAddr(addrOf("10.0.0.10"), span{t2, t2})
	if err := st.write(ctx, h2); err != nil {
		t.Fatal(err)
	}
	var periodCount int
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM host_addrs WHERE host_id = 'h1'`).Scan(&periodCount); err != nil {
		t.Fatal(err)
	}
	if periodCount != 1 {
		t.Fatalf("addr periods within aliveWindow = %d, want 1", periodCount)
	}

	// 3 hours later (> aliveWindow): new addr period row; :443 gets an unknown-owner
	// refresh (must preserve nginx owner) and :9999 is a brand-new unknown-owner
	// listener (must advance listened[h1] so stopped :80 expires after 1h).
	h3 := newHostChanges("h1")
	h3.setHost("m1", "node-01", "5.14", "test", now)
	h3.addSession(now, sessionRow{lastHeartbeat: now, netnsScope: "all"})
	h3.addAddr(addrOf("10.0.0.10"), span{now, now})
	h3.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.10"), port: 443, netns: 1}, span{now, now})
	h3.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.10"), port: 9999, netns: 1}, span{now, now})
	if err := st.write(ctx, h3); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM host_addrs WHERE host_id = 'h1'`).Scan(&periodCount); err != nil {
		t.Fatal(err)
	}
	if periodCount != 2 {
		t.Fatalf("addr periods after gap > aliveWindow = %d, want 2", periodCount)
	}

	rows, err := st.peers(ctx, 15*time.Minute, formerHolderWindow)
	if err != nil {
		t.Fatal(err)
	}
	ports := map[uint16]string{}
	for _, ep := range rows.endpoints {
		ports[ep.key.port] = ep.service
	}
	if ports[443] != "nginx" {
		t.Errorf("port 443 owner = %q, want nginx (preserved across unknown-owner refresh)", ports[443])
	}
	if _, ok := ports[80]; ok {
		t.Errorf("stopped port 80 should have expired once listened[h1] advanced to now")
	}
	if _, ok := ports[9999]; ok {
		t.Errorf("unknown-owner port 9999 must not emit a service endpoint")
	}
}
