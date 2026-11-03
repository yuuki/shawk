package shawkconnector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
)

// withCertificate returns the context of a gRPC call whose client presented
// cert, verified by the receiver unless unverified.
func withCertificate(cert *x509.Certificate, verified bool) context.Context {
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

// Without host_identity, requests without a certificate are accepted, as
// before.
func TestHostIdentityNone(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second)})
	if _, ok := c.changes.pending[hostKey("", "app-01")]; !ok {
		t.Error("the metrics of app-01 were not accepted")
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
