package shawkconnector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
)

// withCertificate returns the context of a gRPC call whose client presented
// cert, verified by the receiver unless unverified. A cert without DER bytes
// gets its names as such, so that certificates with other names have other
// ids (certificateID).
func withCertificate(cert *x509.Certificate, verified bool) context.Context {
	if cert.Raw == nil {
		cert.Raw = []byte(strings.Join(certificateNames(cert), "\n"))
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{cert}}
	}
	return grpcpeer.NewContext(context.Background(), &grpcpeer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

func TestCertifiedHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		host string
		ok   bool
	}{
		{"DNS name", &x509.Certificate{DNSNames: []string{"app-01.example", "app-01"}}, "app-01", true},
		{"case and final dot", &x509.Certificate{DNSNames: []string{"App-01.Example."}}, "app-01.example", true},
		{"common name without DNS names", &x509.Certificate{Subject: pkix.Name{CommonName: "app-01"}}, "app-01", true},
		{"common name ignored with DNS names", &x509.Certificate{DNSNames: []string{"app-02"},
			Subject: pkix.Name{CommonName: "app-01"}}, "app-01", false},
		{"another host", &x509.Certificate{DNSNames: []string{"app-02"}}, "app-01", false},
		{"short name of another domain", &x509.Certificate{DNSNames: []string{"app-01.a.example"}}, "app-01", false},
		{"wildcard", &x509.Certificate{DNSNames: []string{"*.example"}}, "app-01.example", false},
		{"no name", &x509.Certificate{}, "", false},
	} {
		if err := certifiedHost(tc.cert, tc.host); (err == nil) != tc.ok {
			t.Errorf("%s: certifiedHost = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// With host_identity: certificate, an agent writes only as the host its
// certificate names.
func TestHostIdentityCertificate(t *testing.T) {
	c, _, _, _ := testConnector(t, func(cfg *Config) { cfg.HostIdentity = hostIdentityCertificate })
	edge := tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
		svc: "app", comm: "app", opened: 1, last: t0}
	ta := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: t0, edges: []tEdge{edge}}
	key := hostKey("", "app-01")

	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"no certificate (HTTP, or no TLS)", context.Background()},
		{"certificate of another host", withCertificate(&x509.Certificate{DNSNames: []string{"db-01"}}, true)},
		{"unverified certificate", withCertificate(&x509.Certificate{DNSNames: []string{"app-01"}}, false)},
	} {
		err := c.ConsumeMetrics(tc.ctx, ta.metrics())
		if err == nil || !consumererror.IsPermanent(err) {
			t.Errorf("%s: ConsumeMetrics = %v, want a permanent error", tc.name, err)
		}
		if _, ok := c.changes.pending[key]; ok {
			t.Errorf("%s: the metrics of app-01 were accepted", tc.name)
		}
	}

	if err := c.ConsumeMetrics(withCertificate(&x509.Certificate{DNSNames: []string{"app-01"}}, true), ta.metrics()); err != nil {
		t.Fatalf("ConsumeMetrics with the certificate of app-01: %v", err)
	}
	if _, ok := c.changes.pending[key]; !ok {
		t.Error("the metrics of app-01 were not accepted with its certificate")
	}
}

// TestMaxHostsPerCertificate: with host_identity: certificate, the
// certificate names the host.name but neither its host.id nor how it is
// spelt, which make other hosts; the connector holds at most
// maxHostsPerCertificate hosts of a certificate, whatever names it has
// (#145, finding 6). A further one is refused with an error that is not
// permanent and nothing of it is kept, the hosts held are not evicted, and
// one is taken again once a host of the certificate expired. Another
// certificate that names the same host, as of a machine of another cluster
// with the same name, has its own hosts.
func TestMaxHostsPerCertificate(t *testing.T) {
	c, _, _, now := testConnector(t, func(cfg *Config) { cfg.HostIdentity = hostIdentityCertificate })
	logs := observe(c)
	ctx := withCertificate(&x509.Certificate{DNSNames: []string{"app-01", "app-01.example"}}, true)
	agent := func(host, machineID string) tAgent {
		return tAgent{host: host, machineID: machineID, addrs: []string{"10.0.0.11"}, time: *now,
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
				svc: "app", comm: "app", opened: 1}}}
	}
	send := func(ctx context.Context, host, machineID string) error {
		t.Helper()
		return c.ConsumeMetrics(ctx, agent(host, machineID).metrics())
	}
	held := func(host, machineID string) bool {
		_, ok := c.changes.pending[hostKey(machineID, host)]
		return ok
	}
	refused := func(ctx context.Context, host, machineID string) {
		t.Helper()
		err := send(ctx, host, machineID)
		if err == nil || consumererror.IsPermanent(err) {
			t.Errorf("%s %s: ConsumeMetrics = %v, want an error that is not permanent", host, machineID, err)
		}
		key := hostKey(machineID, host)
		_, agentKnown := c.resolver.localAgents[key]
		if held(host, machineID) || agentKnown || c.agg.hosts[key] != nil {
			t.Errorf("%s %s: the state of a refused host is kept", host, machineID)
		}
	}

	// The host and those it was before its machine id changed, under both
	// names of the certificate.
	for i := range maxHostsPerCertificate {
		host := []string{"app-01", "app-01.example"}[i%2]
		if id := fmt.Sprintf("m%d", i+1); send(ctx, host, id) != nil {
			t.Fatalf("%s %s refused", host, id)
		}
	}
	// Another host.id, under either name, and another spelling of a name,
	// are refused.
	refused(ctx, "app-01", "new")
	refused(ctx, "app-01.example", "new")
	refused(ctx, "APP-01.", "m1")
	// Logged at most once a minute.
	if got := logs.FilterMessageSnippet("has the most hosts held").All(); len(got) != 1 ||
		got[0].ContextMap()["certificate_sha256"] != certificateID(&x509.Certificate{Raw: []byte("app-01\napp-01.example")}) {
		t.Errorf("warnings = %v, want one about the certificate of app-01", got)
	}
	// The hosts held stay. Another certificate of the same name, and that of
	// another host, are not bounded by the first.
	if err := send(ctx, "app-01", "m1"); err != nil {
		t.Errorf("a host held is refused: %v", err)
	}
	other := withCertificate(&x509.Certificate{DNSNames: []string{"app-01"}, Raw: []byte("another cluster")}, true)
	if err := send(other, "app-01", "other"); err != nil {
		t.Errorf("another certificate of app-01 is refused: %v", err)
	}
	if err := send(withCertificate(&x509.Certificate{DNSNames: []string{"app-02"}}, true), "app-02", "new"); err != nil {
		t.Errorf("the certificate of another host is refused: %v", err)
	}

	// All but m1 stop; once they have not sent for the idle TTL, new
	// host.id values are taken up to the bound again.
	*now = now.Add(time.Minute)
	if err := send(ctx, "app-01", "m1"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(c.cfg.IdleTTL)
	c.expire(*now)
	if err := send(ctx, "app-01", "m1"); err != nil {
		t.Fatal(err)
	}
	for i := range maxHostsPerCertificate - 1 {
		if id := fmt.Sprintf("new%d", i+1); send(ctx, "app-01", id) != nil || !held("app-01", id) {
			t.Errorf("app-01 %s is refused after hosts of the certificate expired", id)
		}
	}
	*now = now.Add(time.Minute)
	refused(ctx, "app-01", "more")

	// Once every host of a certificate has expired, nothing of it is held.
	*now = now.Add(c.cfg.IdleTTL + time.Minute)
	c.expire(*now)
	if len(c.limits.hosts) != 0 || len(c.limits.certificates) != 0 {
		t.Errorf("held after every host expired: %d hosts, certificates %v", len(c.limits.hosts), c.limits.certificates)
	}
}

// TestLimitsCertificates: a new host is refused by max_hosts before the
// bound of its certificate is looked at, a host held is taken whatever its
// certificate holds, and hosts without a certificate are not counted.
func TestLimitsCertificates(t *testing.T) {
	l := newLimits(maxHostsPerCertificate+2, 100, time.Minute)
	admit := func(key, cert string) admission {
		got, _ := l.admit(&hostBatch{key: key, certificate: cert}, t0)
		return got
	}
	for i := range maxHostsPerCertificate {
		if got := admit(fmt.Sprintf("a%d", i), "A"); got != admitted {
			t.Fatalf("host %d of A: %v", i, got)
		}
	}
	if got := admit("a-more", "A"); got != certificateFull {
		t.Errorf("one more host of A: %v, want certificateFull", got)
	}
	if got := admit("a0", "A"); got != admitted {
		t.Errorf("a host held of A: %v", got)
	}
	if got := admit("none", ""); got != admitted {
		t.Errorf("a host without a certificate: %v", got)
	}
	if got := admit("b0", "B"); got != admitted {
		t.Errorf("the host of B: %v", got)
	}
	// max_hosts hosts are held: max_hosts is told first.
	if got := admit("a-more", "A"); got != hostsFull {
		t.Errorf("one more host of A at max_hosts: %v, want hostsFull", got)
	}
	if l.certificates["A"] != maxHostsPerCertificate || l.certificates["B"] != 1 || len(l.certificates) != 2 {
		t.Errorf("certificates = %v", l.certificates)
	}
}

// Without host_identity, requests without a certificate are accepted, as
// before.
func TestHostIdentityNone(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second)})
	if _, ok := c.changes.pending[hostKey("", "app-01")]; !ok {
		t.Error("the metrics of app-01 were not accepted")
	}
	// Without identities, only max_hosts bounds the hosts of a name.
	for i := range maxHostsPerCertificate + 1 {
		id := fmt.Sprintf("m%d", i+1)
		consume(t, c, sink, tAgent{host: "app-01", machineID: id, addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second)})
		if _, ok := c.changes.pending[hostKey(id, "app-01")]; !ok {
			t.Errorf("the metrics of app-01 with host.id %s were not accepted", id)
		}
	}
}

func TestHostIdentityValidate(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	cfg.HostIdentity = "cert"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "host_identity") {
		t.Errorf("Validate = %v", err)
	}
}

// Strings PostgreSQL refuses are cleaned when they are read, so that they
// do not make it drop the changes of the host.
func TestStringsCleaned(t *testing.T) {
	m := pcommon.NewMap()
	m.PutStr("a", "ok")
	m.PutStr("b", "a\x00b")
	m.PutStr("c", "x\xffy")
	for k, want := range map[string]string{"a": "ok", "b": "a�b", "c": "x�y"} {
		if got := getString(m, k); got != want {
			t.Errorf("getString(%s) = %q, want %q", k, got, want)
		}
	}
}
