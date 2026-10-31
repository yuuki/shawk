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
	"testing"
	"time"
)

// testCert issues a certificate signed by parent (self-signed if nil) and
// writes it and its key as PEM files.
func testCert(t *testing.T, dir, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, string, string) {
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
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
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
