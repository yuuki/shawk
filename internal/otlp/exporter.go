package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/protobuf/proto"
)

// Protocols of OTLP.
const (
	ProtocolGRPC = "grpc"
	ProtocolHTTP = "http/protobuf"
)

// ExporterConfig configures an Exporter.
type ExporterConfig struct {
	// Endpoint is a URL. The scheme http disables TLS. With http/protobuf,
	// /v1/metrics is appended to an endpoint without a path.
	Endpoint string
	Protocol string // ProtocolGRPC or ProtocolHTTP
	// CAFile is a PEM file of the CAs that verify the collector, instead of
	// the system roots.
	CAFile string
}

// Exporter sends requests to a collector.
type Exporter interface {
	// Export sends a request. A partially rejected request is an error.
	Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error
	Close() error
}

// NewExporter returns an exporter. It does not connect yet.
func NewExporter(cfg ExporterConfig) (Exporter, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid OTLP endpoint %q: want http://HOST:PORT or https://HOST:PORT", cfg.Endpoint)
	}
	var tlsConf *tls.Config
	if u.Scheme == "https" {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates in %s", cfg.CAFile)
			}
			tlsConf.RootCAs = pool
		}
	}
	switch cfg.Protocol {
	case "", ProtocolGRPC:
		creds := insecure.NewCredentials()
		if tlsConf != nil {
			creds = credentials.NewTLS(tlsConf)
		}
		conn, err := grpc.NewClient(u.Host, grpc.WithTransportCredentials(creds),
			grpc.WithDefaultCallOptions(grpc.UseCompressor(grpcgzip.Name)))
		if err != nil {
			return nil, err
		}
		return &grpcExporter{conn: conn, client: colmetricspb.NewMetricsServiceClient(conn)}, nil
	case ProtocolHTTP:
		if u.Path == "" || u.Path == "/" {
			u.Path = "/v1/metrics"
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConf
		return &httpExporter{url: u.String(), client: &http.Client{Transport: tr}}, nil
	}
	return nil, fmt.Errorf("invalid OTLP protocol %q: want %s or %s", cfg.Protocol, ProtocolGRPC, ProtocolHTTP)
}

type grpcExporter struct {
	conn   *grpc.ClientConn
	client colmetricspb.MetricsServiceClient
}

func (e *grpcExporter) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	resp, err := e.client.Export(ctx, req)
	if err != nil {
		return err
	}
	return partialSuccess(resp)
}

func (e *grpcExporter) Close() error { return e.conn.Close() }

type httpExporter struct {
	url    string
	client *http.Client
}

func (e *httpExporter) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body)
	if err := zw.Close(); err != nil {
		return err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, &buf)
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/x-protobuf")
	hreq.Header.Set("Content-Encoding", "gzip")
	resp, err := e.client.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%s: %s %s", e.url, resp.Status, msg)
	}
	var r colmetricspb.ExportMetricsServiceResponse
	if resp.Header.Get("Content-Type") == "application/x-protobuf" && len(data) > 0 {
		if err := proto.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("decoding the response: %w", err)
		}
	}
	return partialSuccess(&r)
}

func (e *httpExporter) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

// ErrRejected is returned when the collector rejects some data points.
var ErrRejected = errors.New("data points rejected")

func partialSuccess(resp *colmetricspb.ExportMetricsServiceResponse) error {
	ps := resp.GetPartialSuccess()
	if ps.GetRejectedDataPoints() == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d: %s", ErrRejected, ps.GetRejectedDataPoints(), ps.GetErrorMessage())
}
