package otlp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// testCert issues a certificate for hosts, IP addresses or DNS names
// (127.0.0.1 if none), signed by parent (self-signed if nil) and writes it
// and its key as PEM files.
func testCert(t *testing.T, dir, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, hosts ...string) (*x509.Certificate, *ecdsa.PrivateKey, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         isCA, BasicConstraintsValid: true,
	}
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1"}
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	certFile, keyFile := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, key, certFile, keyFile
}

// TestMutualTLS sends to a collector that requires a client certificate.
func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, caFile, _ := testCert(t, dir, "ca", nil, nil, true)
	_, _, srvCert, srvKey := testCert(t, dir, "server", ca, caKey, false)
	_, _, cliCert, cliKey := testCert(t, dir, "client", ca, caKey, false)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cert, err := tls.LoadX509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	defer srv.Close()

	req := testRequest()
	without, err := NewExporter(ExporterConfig{Endpoint: srv.URL, Protocol: ProtocolHTTP, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := without.Export(context.Background(), req); err == nil {
		t.Error("sent without a client certificate")
	}
	with, err := NewExporter(ExporterConfig{Endpoint: srv.URL, Protocol: ProtocolHTTP, CAFile: caFile,
		CertFile: cliCert, KeyFile: cliKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := with.Export(context.Background(), req); err != nil {
		t.Errorf("with a client certificate: %v", err)
	}
}

// serverTLS returns the TLS configuration of a test collector with the
// certificate of certFile and keyFile, which stores the server name that
// each client asks for (SNI) in sni.
func serverTLS(t *testing.T, certFile, keyFile string, sni *atomic.Value) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni.Store(h.ServerName)
			return nil, nil
		}}
}

// authServer is a collector of gRPC that stores the authorization of each
// request.
type authServer struct {
	colmetricspb.UnimplementedMetricsServiceServer
	auth *atomic.Value
}

func (s *authServer) Export(ctx context.Context, _ *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.auth.Store(strings.Join(md.Get("authorization"), ","))
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

// startTLSCollector starts a collector of the protocol over TLS at
// 127.0.0.1, which stores the Authorization of each request in auth, and
// returns its endpoint.
func startTLSCollector(t *testing.T, protocol string, conf *tls.Config, auth *atomic.Value) string {
	t.Helper()
	if protocol == ProtocolHTTP {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth.Store(r.Header.Get("Authorization"))
		}))
		srv.TLS = conf
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv.URL
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(conf)))
	colmetricspb.RegisterMetricsServiceServer(srv, &authServer{auth: auth})
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return "https://" + ln.Addr().String()
}

// export sends a request with a new exporter of cfg.
func export(t *testing.T, cfg ExporterConfig) error {
	t.Helper()
	exp, err := NewExporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exp.Export(ctx, testRequest())
}

// TestServerName sends to a collector at 127.0.0.1 whose certificate names
// collector.example only: with ServerName the agent asks for that name and
// verifies the certificate by it; without, the certificate is refused.
func TestServerName(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, caFile, _ := testCert(t, dir, "ca", nil, nil, true)
	_, _, srvCert, srvKey := testCert(t, dir, "server", ca, caKey, false, "collector.example")
	for _, protocol := range []string{ProtocolGRPC, ProtocolHTTP} {
		t.Run(protocol, func(t *testing.T) {
			var sni, auth atomic.Value
			ep := startTLSCollector(t, protocol, serverTLS(t, srvCert, srvKey, &sni), &auth)
			cfg := ExporterConfig{Endpoint: ep, Protocol: protocol, CAFile: caFile}
			// Verified for 127.0.0.1, which it does not name.
			if err := export(t, cfg); err == nil || !strings.Contains(err.Error(), "IP SANs") {
				t.Errorf("without a server name: %v, want a certificate that does not name 127.0.0.1", err)
			}
			cfg.ServerName = "collector.example"
			if err := export(t, cfg); err != nil {
				t.Fatalf("with the server name: %v", err)
			}
			if got, _ := sni.Load().(string); got != "collector.example" {
				t.Errorf("SNI %q, want collector.example", got)
			}
		})
	}
}

// TestBearerToken checks that the token of BearerTokenFile goes with the
// requests, in the metadata of gRPC and the headers of HTTP, and nothing
// without one.
func TestBearerToken(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, caFile, _ := testCert(t, dir, "ca", nil, nil, true)
	_, _, srvCert, srvKey := testCert(t, dir, "server", ca, caKey, false)
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("s3cr3t-T0ken.~+/=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{ProtocolGRPC, ProtocolHTTP} {
		t.Run(protocol, func(t *testing.T) {
			var sni, auth atomic.Value
			ep := startTLSCollector(t, protocol, serverTLS(t, srvCert, srvKey, &sni), &auth)
			cfg := ExporterConfig{Endpoint: ep, Protocol: protocol, CAFile: caFile}
			if err := export(t, cfg); err != nil {
				t.Fatal(err)
			}
			if got, _ := auth.Load().(string); got != "" {
				t.Errorf("authorization %q without a token", got)
			}
			cfg.BearerTokenFile = tokenFile
			if err := export(t, cfg); err != nil {
				t.Fatal(err)
			}
			if got, _ := auth.Load().(string); got != "Bearer s3cr3t-T0ken.~+/=" {
				t.Errorf("authorization %q", got)
			}
		})
	}
}
