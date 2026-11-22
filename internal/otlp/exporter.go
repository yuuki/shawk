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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"

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
	// Endpoint is a URL. The scheme http disables TLS. With http/protobuf it
	// is a base URL to which /v1/metrics is appended, as with
	// OTEL_EXPORTER_OTLP_ENDPOINT, unless the path already ends with it.
	Endpoint string
	Protocol string // ProtocolGRPC or ProtocolHTTP
	// CAFile is a PEM file of the CAs that verify the collector, instead of
	// the system roots.
	CAFile string
	// CertFile and KeyFile are a client certificate and its key, presented
	// to a collector that requires them (mutual TLS).
	CertFile string
	KeyFile  string
	// ServerName is the name that the certificate of the collector must
	// hold, sent in SNI, instead of the host of the endpoint: e.g. for an
	// endpoint given by its IP address. Over gRPC it is also the authority
	// of the requests.
	ServerName string
	// BearerTokenFile is a file of a token sent with every request as
	// "Authorization: Bearer TOKEN", for a collector that authenticates
	// agents by tokens rather than client certificates. NewExporter reads
	// it once; the white space around the token is left out.
	BearerTokenFile string
}

// maxBearerTokenFile bounds the file of a bearer token, far above the
// tokens of collectors: a larger file is another file given by mistake.
const maxBearerTokenFile = 4096

// DefaultEndpoint returns the endpoint of a collector on the local host for
// a protocol: the ports of the otlp/shawk receiver in the examples.
func DefaultEndpoint(protocol string) string {
	if protocol == ProtocolHTTP {
		return "http://localhost:4328"
	}
	return "http://localhost:4327"
}

// Exporter sends requests to a collector.
type Exporter interface {
	// Export sends a request. A partially rejected request is an error.
	Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error
	Close() error
}

// Validate checks the configuration without reading its files.
func (cfg ExporterConfig) Validate() error {
	_, err := cfg.endpoint()
	return err
}

// endpoint validates the configuration and returns the parsed endpoint.
func (cfg ExporterConfig) endpoint() (*url.URL, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid OTLP endpoint %q: want http://HOST:PORT or https://HOST:PORT", cfg.Endpoint)
	}
	// A token is refused over http:// also to a loopback address: while the
	// collector is down, any user of the host can listen on its port and
	// take the token, whereas TLS verifies the collector.
	if u.Scheme == "http" && cfg.BearerTokenFile != "" {
		return nil, fmt.Errorf("a bearer token is set but the OTLP endpoint %s does not use TLS, which would send it in the clear; use https://", cfg.Endpoint)
	}
	if u.Scheme == "http" && (cfg.CAFile != "" || cfg.CertFile != "" || cfg.ServerName != "") {
		return nil, fmt.Errorf("a CA, client certificate or server name is set but the OTLP endpoint %s does not use TLS; use https://", cfg.Endpoint)
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("set both or neither of the client certificate and its key")
	}
	switch cfg.Protocol {
	case "", ProtocolGRPC, ProtocolHTTP:
	default:
		return nil, fmt.Errorf("invalid OTLP protocol %q: want %s or %s", cfg.Protocol, ProtocolGRPC, ProtocolHTTP)
	}
	return u, nil
}

// CleartextRemote reports whether a valid configuration sends to another
// host without TLS: the endpoint uses http:// and its host is neither
// localhost nor a loopback address.
func (cfg ExporterConfig) CleartextRemote() bool {
	u, err := cfg.endpoint()
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// tlsConfig returns the TLS configuration of an https:// endpoint, with
// the client certificate and the CA of the configuration, if any, read
// from their files.
func (cfg ExporterConfig) tlsConfig() (*tls.Config, error) {
	// An empty ServerName is the host of the endpoint, for gRPC as for HTTP.
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading the client certificate: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}
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
	return tlsConf, nil
}

// authorization returns the value of the Authorization header of the
// requests, read from BearerTokenFile: "Bearer " and the token, or ""
// without a file. Its errors hold the path of the file, never its content.
func (cfg ExporterConfig) authorization() (string, error) {
	if cfg.BearerTokenFile == "" {
		return "", nil
	}
	// Without O_NONBLOCK, opening a FIFO that nothing writes would block the
	// start until systemd gives up waiting for READY=1; with it, the FIFO
	// reads as empty. It changes nothing for a regular file.
	f, err := os.OpenFile(cfg.BearerTokenFile, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("reading the bearer token: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBearerTokenFile+1))
	if err != nil {
		return "", fmt.Errorf("reading the bearer token: %w", err)
	}
	if len(b) > maxBearerTokenFile {
		return "", fmt.Errorf("the bearer token file %s is larger than %d bytes", cfg.BearerTokenFile, maxBearerTokenFile)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("the bearer token file %s is empty", cfg.BearerTokenFile)
	}
	// A token is one word of visible ASCII, as gRPC metadata and the
	// tokens of bearertokenauth are.
	for i := range len(token) {
		if c := token[i]; c <= ' ' || c > '~' {
			return "", fmt.Errorf("the bearer token in %s holds white space, a control character or a byte that is not ASCII", cfg.BearerTokenFile)
		}
	}
	return "Bearer " + token, nil
}

// NewExporter returns an exporter. It does not connect yet.
func NewExporter(cfg ExporterConfig) (Exporter, error) {
	u, err := cfg.endpoint()
	if err != nil {
		return nil, err
	}
	var tlsConf *tls.Config
	if u.Scheme == "https" {
		if tlsConf, err = cfg.tlsConfig(); err != nil {
			return nil, err
		}
	}
	auth, err := cfg.authorization()
	if err != nil {
		return nil, err
	}
	switch cfg.Protocol {
	case "", ProtocolGRPC:
		creds := insecure.NewCredentials()
		if tlsConf != nil {
			creds = credentials.NewTLS(tlsConf)
		}
		opts := []grpc.DialOption{grpc.WithTransportCredentials(creds),
			grpc.WithDefaultCallOptions(grpc.UseCompressor(grpcgzip.Name))}
		if auth != "" {
			opts = append(opts, grpc.WithPerRPCCredentials(bearerToken(auth)))
		}
		conn, err := grpc.NewClient(u.Host, opts...)
		if err != nil {
			return nil, err
		}
		return &grpcExporter{conn: conn, client: colmetricspb.NewMetricsServiceClient(conn)}, nil
	case ProtocolHTTP:
		if !strings.HasSuffix(u.Path, "/v1/metrics") {
			u.Path = strings.TrimSuffix(u.Path, "/") + "/v1/metrics"
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConf
		// Redirects are not followed: a 307 or 308 would send the request,
		// with its body, to another address, maybe without TLS.
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		return &httpExporter{url: u.String(), client: client, authorization: auth}, nil
	}
	panic("unreachable: the protocol was validated")
}

// bearerToken is the credentials of gRPC that send the Authorization of a
// bearer token ("Bearer " and the token) in the metadata of every request.
type bearerToken string

func (t bearerToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": string(t)}, nil
}

// RequireTransportSecurity makes gRPC refuse to send the token without TLS.
func (bearerToken) RequireTransportSecurity() bool { return true }

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
	// authorization is the value of the Authorization header, if any.
	authorization string
}

func (e *httpExporter) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(body) //nolint:errcheck // a gzip.Writer keeps the error of a write, which Close returns
	if err := zw.Close(); err != nil {
		return err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, &buf)
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/x-protobuf")
	hreq.Header.Set("Content-Encoding", "gzip")
	if e.authorization != "" {
		hreq.Header.Set("Authorization", e.authorization)
	}
	resp, err := e.client.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 == 3 {
		return fmt.Errorf("%s: %s to %q: redirects are not followed", e.url, resp.Status, clip(resp.Header.Get("Location")))
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s %s", e.url, resp.Status, clip(strings.TrimSpace(string(data))))
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

// clip bounds a string from the collector in an error.
func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
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
