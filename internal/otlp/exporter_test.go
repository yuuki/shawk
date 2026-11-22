package otlp

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func testRequest() *colmetricspb.ExportMetricsServiceRequest {
	s := NewState(time.Minute)
	s.AddEdge(clientEdge(), EdgeStats{Conns: 1}, t0, t0)
	return s.Request(Resource{Hostname: "h"}, AgentStatus{}, t0)
}

func TestHTTPExporter(t *testing.T) {
	var got colmetricspb.ExportMetricsServiceRequest
	reject := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/metrics" || r.Header.Get("Content-Type") != "application/x-protobuf" ||
			r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(zr)
		if err := proto.Unmarshal(body, &got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := &colmetricspb.ExportMetricsServiceResponse{}
		if reject {
			resp.PartialSuccess = &colmetricspb.ExportMetricsPartialSuccess{RejectedDataPoints: 2, ErrorMessage: "bad"}
		}
		b, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(b)
	}))
	defer srv.Close()

	exp, err := NewExporter(ExporterConfig{Endpoint: srv.URL, Protocol: ProtocolHTTP})
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	req := testRequest()
	if err := exp.Export(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&got, req) {
		t.Error("the collector received a different request")
	}
	reject = true
	if err := exp.Export(context.Background(), req); !errors.Is(err, ErrRejected) {
		t.Errorf("partial success: %v", err)
	}

	// The endpoint is a base URL, as OTEL_EXPORTER_OTLP_ENDPOINT.
	bad, _ := NewExporter(ExporterConfig{Endpoint: srv.URL + "/wrong", Protocol: ProtocolHTTP})
	if err := bad.Export(context.Background(), req); err == nil {
		t.Error("an HTTP error was not reported")
	}
	for _, ep := range []string{srv.URL + "/", srv.URL + "/v1/metrics"} {
		e, err := NewExporter(ExporterConfig{Endpoint: ep, Protocol: ProtocolHTTP})
		if err != nil {
			t.Fatal(err)
		}
		reject = false
		if err := e.Export(context.Background(), req); err != nil {
			t.Errorf("%s: %v", ep, err)
		}
	}
}

// TestHTTPExporterRedirect checks that a redirect does not send the request
// elsewhere and fails the export.
func TestHTTPExporterRedirect(t *testing.T) {
	var delivered atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
	}))
	defer other.Close()
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/v1/metrics", code)
		}))
		exp, err := NewExporter(ExporterConfig{Endpoint: srv.URL, Protocol: ProtocolHTTP})
		if err != nil {
			t.Fatal(err)
		}
		err = exp.Export(context.Background(), testRequest())
		if err == nil || !strings.Contains(err.Error(), strconv.Itoa(code)) || !strings.Contains(err.Error(), other.URL) {
			t.Errorf("%d: %v", code, err)
		}
		exp.Close()
		srv.Close()
	}
	if n := delivered.Load(); n != 0 {
		t.Errorf("%d requests were redirected", n)
	}
}

type metricsServer struct {
	colmetricspb.UnimplementedMetricsServiceServer
	got chan *colmetricspb.ExportMetricsServiceRequest
}

func (s *metricsServer) Export(_ context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	s.got <- req
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func TestGRPCExporter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	ms := &metricsServer{got: make(chan *colmetricspb.ExportMetricsServiceRequest, 1)}
	colmetricspb.RegisterMetricsServiceServer(srv, ms)
	go srv.Serve(ln)
	defer srv.Stop()

	exp, err := NewExporter(ExporterConfig{Endpoint: "http://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := testRequest()
	if err := exp.Export(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := <-ms.got; !proto.Equal(got, req) {
		t.Error("the collector received a different request")
	}
}

func TestNewExporterErrors(t *testing.T) {
	dir := t.TempDir()
	tokenFile, emptyFile := filepath.Join(dir, "token"), filepath.Join(dir, "empty")
	if err := os.WriteFile(tokenFile, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []ExporterConfig{
		{Endpoint: "localhost:4317"},
		{Endpoint: "ftp://localhost:4317"},
		{Endpoint: "http://localhost:4317", Protocol: "http/json"},
		{Endpoint: "https://localhost:4317", CAFile: "/nonexistent"},
		// TLS settings with a plaintext endpoint would be silently ignored.
		{Endpoint: "http://localhost:4317", CAFile: "/etc/ssl/ca.pem"},
		{Endpoint: "http://localhost:4317", CertFile: "/c.pem", KeyFile: "/k.pem"},
		{Endpoint: "http://localhost:4317", ServerName: "collector.example"},
		{Endpoint: "https://localhost:4317", CertFile: "/c.pem"},
		{Endpoint: "https://localhost:4317", CertFile: "/nonexistent", KeyFile: "/nonexistent"},
		// A token is never sent in the clear, not even to loopback.
		{Endpoint: "http://localhost:4317", BearerTokenFile: tokenFile},
		{Endpoint: "http://10.0.0.1:4318", Protocol: ProtocolHTTP, BearerTokenFile: tokenFile},
		{Endpoint: "https://localhost:4317", BearerTokenFile: "/nonexistent"},
		{Endpoint: "https://localhost:4317", BearerTokenFile: emptyFile},
	} {
		if _, err := NewExporter(cfg); err == nil {
			t.Errorf("NewExporter(%+v) succeeded", cfg)
		}
	}
}

// TestBearerTokenFile checks how a token is read: one word of visible
// ASCII without the white space around it, in errors that never hold it.
func TestBearerTokenFile(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("s3cr3t", maxBearerTokenFile/6)
	for _, tc := range []struct {
		content, want string // want "" for an error
	}{
		{"s3cr3t\n", "Bearer s3cr3t"},
		{" \t s3cr3t \r\n\n", "Bearer s3cr3t"},
		{long, "Bearer " + long},
		{"", ""},
		{" \n\t\n", ""},
		{"s3cr3t # comment\n", ""},
		{"s3cr3t\nanother\n", ""},
		{"s3cr3t\x00", ""},
		{"s3cr3té", ""},
		{long + strings.Repeat(" ", maxBearerTokenFile+1-len(long)), ""},
	} {
		f := filepath.Join(dir, "token")
		if err := os.WriteFile(f, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ExporterConfig{BearerTokenFile: f}.authorization()
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("%.40q: %.40q, %v; want %.40q", tc.content, got, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%.40q: the error holds the token: %v", tc.content, err)
		}
	}
	if _, err := (ExporterConfig{BearerTokenFile: dir}).authorization(); err == nil {
		t.Error("a directory was read as a token")
	}
	// A FIFO that nothing writes is empty, rather than blocking the start.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ExporterConfig{BearerTokenFile: fifo}.authorization()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO without a writer was read as a token")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO without a writer blocks")
	}
}

func TestCleartextRemote(t *testing.T) {
	for ep, want := range map[string]bool{
		"http://10.0.0.1:4327":           true,
		"http://collector.example:4327":  true,
		"http://[2001:db8::1]:4327":      true,
		"http://localhost:4327":          false,
		"http://LOCALHOST.:4327":         false,
		"http://127.0.0.1:4327":          false,
		"http://127.0.0.2:4327":          false,
		"http://[::1]:4327":              false,
		"https://10.0.0.1:4327":          false,
		"https://collector.example:4327": false,
		"collector.example:4327":         false, // invalid
	} {
		if got := (ExporterConfig{Endpoint: ep}).CleartextRemote(); got != want {
			t.Errorf("%s: %v, want %v", ep, got, want)
		}
	}
}

func TestDefaultEndpoint(t *testing.T) {
	if DefaultEndpoint(ProtocolGRPC) != "http://localhost:4327" || DefaultEndpoint(ProtocolHTTP) != "http://localhost:4328" {
		t.Error("default endpoints")
	}
}
