package otlp

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	for _, cfg := range []ExporterConfig{
		{Endpoint: "localhost:4317"},
		{Endpoint: "ftp://localhost:4317"},
		{Endpoint: "http://localhost:4317", Protocol: "http/json"},
		{Endpoint: "https://localhost:4317", CAFile: "/nonexistent"},
		// TLS settings with a plaintext endpoint would be silently ignored.
		{Endpoint: "http://localhost:4317", CAFile: "/etc/ssl/ca.pem"},
		{Endpoint: "http://localhost:4317", CertFile: "/c.pem", KeyFile: "/k.pem"},
		{Endpoint: "https://localhost:4317", CertFile: "/c.pem"},
		{Endpoint: "https://localhost:4317", CertFile: "/nonexistent", KeyFile: "/nonexistent"},
	} {
		if _, err := NewExporter(cfg); err == nil {
			t.Errorf("NewExporter(%+v) succeeded", cfg)
		}
	}
}

func TestDefaultEndpoint(t *testing.T) {
	if DefaultEndpoint(ProtocolGRPC) != "http://localhost:4327" || DefaultEndpoint(ProtocolHTTP) != "http://localhost:4328" {
		t.Error("default endpoints")
	}
}
