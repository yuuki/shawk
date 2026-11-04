package main

import (
	"context"
	"flag"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/protobuf/proto"
)

// sinkOut is what sink prints for an interval of a host: the requests of
// one export of the agent.
type sinkOut struct {
	Label    string `json:"label,omitempty"`
	Host     string `json:"host"`
	Requests int    `json:"requests"`
	Bytes    int    `json:"bytes"` // uncompressed
	Points   int    `json:"points"`
	Edges    int    `json:"edges"`         // series of edges (points of shawk.edge.last_seen)
	Dropped  int64  `json:"flows_dropped"` // -1 until the metrics of the agent arrive
	// Complete tells that the metrics of the agent arrived: they are in the
	// last request of an interval, which the agent sends only when all the
	// others succeeded.
	Complete bool    `json:"complete"`
	Span     float64 `json:"span_ms"` // from the first request to the end of the last
}

// runSink receives OTLP over gRPC and prints, per host and interval, the
// requests of the interval. Requests of a host closer than -gap belong to
// one interval.
func runSink(args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	var (
		addr  = fs.String("listen", "127.0.0.1:4327", "address to listen on")
		gap   = fs.Duration("gap", 2*time.Second, "pause that ends the requests of an interval")
		label = fs.String("label", "", "label of the output lines")
	)
	fs.Parse(args)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	s := &sink{gap: *gap, label: *label, open: map[string]*pending{}}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(16 << 20))
	colmetricspb.RegisterMetricsServiceServer(srv, s)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		srv.Stop()
	}()
	go s.flushLoop(ctx)
	err = srv.Serve(ln)
	// The intervals still open, e.g. the last one of an agent that stopped.
	s.mu.Lock()
	for h, p := range s.open {
		s.print(p)
		delete(s.open, h)
	}
	s.mu.Unlock()
	return err
}

type pending struct {
	out         sinkOut
	first, last time.Time
}

type sink struct {
	colmetricspb.UnimplementedMetricsServiceServer
	gap   time.Duration
	label string
	mu    sync.Mutex
	open  map[string]*pending
}

func (s *sink) Export(_ context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	arrived := time.Now()
	size := proto.Size(req)
	for _, rm := range req.ResourceMetrics {
		host := ""
		for _, kv := range rm.GetResource().GetAttributes() {
			if kv.Key == "host.name" {
				host = kv.GetValue().GetStringValue()
			}
		}
		points, edges, dropped := 0, 0, int64(-1)
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				n := countPoints(m)
				points += n
				switch m.Name {
				case "shawk.edge.last_seen":
					edges += n
				case "shawk.agent.flows.dropped":
					for _, p := range m.GetSum().GetDataPoints() {
						dropped = p.GetAsInt()
					}
				}
			}
		}
		s.mu.Lock()
		p := s.open[host]
		if p != nil && arrived.Sub(p.last) > s.gap {
			s.print(p)
			p = nil
		}
		if p == nil {
			p = &pending{out: sinkOut{Label: s.label, Host: host, Dropped: -1}, first: arrived}
			s.open[host] = p
		}
		p.out.Requests++
		p.out.Bytes += size
		p.out.Points += points
		p.out.Edges += edges
		if dropped >= 0 {
			p.out.Dropped = dropped
			p.out.Complete = true
		}
		p.last = time.Now()
		s.mu.Unlock()
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func (s *sink) print(p *pending) {
	p.out.Span = ms(p.last.Sub(p.first))
	emit(p.out)
}

// flushLoop prints the intervals that ended.
func (s *sink) flushLoop(ctx context.Context) {
	t := time.NewTicker(s.gap / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for h, p := range s.open {
				if now.Sub(p.last) > s.gap {
					s.print(p)
					delete(s.open, h)
				}
			}
			s.mu.Unlock()
		}
	}
}

func countPoints(m *metricspb.Metric) int {
	switch d := m.Data.(type) {
	case *metricspb.Metric_Sum:
		return len(d.Sum.DataPoints)
	case *metricspb.Metric_Gauge:
		return len(d.Gauge.DataPoints)
	case *metricspb.Metric_Histogram:
		return len(d.Histogram.DataPoints)
	}
	return 0
}
