package agent

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"

	"github.com/yuuki/shawk/internal/otlp"
)

type collector struct {
	colmetricspb.UnimplementedMetricsServiceServer
	got chan *colmetricspb.ExportMetricsServiceRequest
}

func (c *collector) Export(_ context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	select {
	case c.got <- req:
	default:
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func attrs(kvs []*commonpb.KeyValue) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		switch v := kv.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			m[kv.Key] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			m[kv.Key] = strconv.FormatInt(v.IntValue, 10)
		}
	}
	return m
}

// TestRun runs the agent with the BPF programs and a fake collector, and
// checks that a connection made by the test reaches the collector.
func TestRun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	col := &collector{got: make(chan *colmetricspb.ExportMetricsServiceRequest, 1)}
	colmetricspb.RegisterMetricsServiceServer(srv, col)
	go srv.Serve(ln)
	defer srv.Stop()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	echoPort := strconv.Itoa(echo.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Exporter:  otlp.ExporterConfig{Endpoint: "http://" + ln.Addr().String()},
			Interval:  500 * time.Millisecond,
			IdleTTL:   2 * time.Minute,
			traceSelf: true,
		})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	deadline := time.After(20 * time.Second)
	for {
		if c, err := net.Dial("tcp", echo.Addr().String()); err == nil {
			c.Close()
		}
		select {
		case err := <-done:
			t.Fatalf("Run: %v", err)
		case <-deadline:
			t.Fatal("no request with the test connection")
		case req := <-col.got:
			res := attrs(req.ResourceMetrics[0].Resource.Attributes)
			if res["service.name"] != "shawk-agent" || res["host.name"] == "" {
				t.Fatalf("resource = %v", res)
			}
			client, server, up := false, false, false
			for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
				switch m.Name {
				case otlp.MetricConnOpened:
					for _, p := range m.GetSum().DataPoints {
						a := attrs(p.Attributes)
						if a["server.port"] != echoPort || p.GetAsInt() == 0 {
							continue
						}
						if netip.MustParseAddr(a["network.peer.address"]).IsLoopback() && a["service.name"] != "" {
							client = client || a["shawk.role"] == "client"
							server = server || a["shawk.role"] == "server"
						}
					}
				case otlp.MetricAgentUp:
					up = true
				}
			}
			if client && server && up {
				return
			}
		}
	}
}

// The connector judges liveness and shared addresses within windows of a
// few minutes, which a longer interval would exceed.
func TestRunRejectsLongInterval(t *testing.T) {
	err := Run(context.Background(), Config{Interval: 2 * time.Minute, IdleTTL: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("Run with a 2m interval: %v", err)
	}
}
