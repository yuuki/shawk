package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/yuuki/shawk/internal/otlp"
	"github.com/yuuki/shawk/internal/procinfo"
	"github.com/yuuki/shawk/internal/tracer"
)

// fakeSource returns its snapshots one after the other, then empty ones.
type fakeSource struct {
	snaps []*tracer.Snapshot
	err   error
}

func (f *fakeSource) Collect() (*tracer.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(f.snaps) == 0 {
		return &tracer.Snapshot{}, nil
	}
	s := f.snaps[0]
	f.snaps = f.snaps[1:]
	return s, nil
}

func (f *fakeSource) UDPEnabled() bool                            { return true }
func (f *fakeSource) ProgramStats() ([]tracer.ProgramStat, error) { return nil, nil }

// fakeExporter records the requests and fails the next fail ones.
type fakeExporter struct {
	fail  int
	calls int
	sent  []*colmetricspb.ExportMetricsServiceRequest
}

func (e *fakeExporter) Export(_ context.Context, req *colmetricspb.ExportMetricsServiceRequest) error {
	e.calls++
	if e.fail > 0 {
		e.fail--
		return errors.New("unavailable")
	}
	e.sent = append(e.sent, req)
	return nil
}

func (e *fakeExporter) Close() error { return nil }

func newTestAgent(src source, exp otlp.Exporter, maxSeries int) *Agent {
	cfg := Config{
		Interval:            15 * time.Second,
		IdleTTL:             15 * time.Minute,
		MaxSeriesPerRequest: maxSeries,
		Logger:              slog.New(slog.DiscardHandler),
	}
	return newAgent(cfg, src, exp, procinfo.NewResolver(), otlp.Resource{Hostname: "h"}, time.Now())
}

// sumOf returns the sum of the points of a counter in requests, for the
// server port given, by role.
func sumOf(reqs []*colmetricspb.ExportMetricsServiceRequest, metric string, port uint16) map[string]int64 {
	out := map[string]int64{}
	for _, req := range reqs {
		for _, rm := range req.ResourceMetrics {
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					if m.Name != metric {
						continue
					}
					for _, p := range m.GetSum().GetDataPoints() {
						if a := attrs(p.Attributes); a["server.port"] == strconv.Itoa(int(port)) || port == 0 {
							out[a["shawk.role"]] += p.GetAsInt()
						}
					}
				}
			}
		}
	}
	return out
}

func flow(dir tracer.Direction, port uint16, cgroup uint64, conns uint64) tracer.Flow {
	return tracer.Flow{
		FlowKey: tracer.FlowKey{
			Direction:  dir,
			Proto:      tracer.ProtoTCP,
			LocalAddr:  netip.MustParseAddr("10.0.0.1"),
			RemoteAddr: netip.MustParseAddr("10.0.0.2"),
			Port:       port,
			NetNS:      1,
			CgroupID:   cgroup,
			Comm:       "batch",
		},
		FlowStats: tracer.FlowStats{Conns: conns, BytesSent: 10 * conns},
	}
}

// TestTickMergesFlows checks that flows the kernel keeps apart, here by
// cgroups whose paths are not known, are sent as one series when they
// resolve to the same process.
func TestTickMergesFlows(t *testing.T) {
	src := &fakeSource{snaps: []*tracer.Snapshot{{Flows: []tracer.Flow{
		flow(tracer.DirOut, 5432, 101, 2),
		flow(tracer.DirOut, 5432, 102, 3),
		flow(tracer.DirIn, 5432, 101, 1),
	}}}}
	exp := &fakeExporter{}
	a := newTestAgent(src, exp, 0)
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sumOf(exp.sent, otlp.MetricConnOpened, 5432); got["client"] != 5 || got["server"] != 1 {
		t.Errorf("connections = %v", got)
	}
	var series int
	for _, m := range exp.sent[0].ResourceMetrics[0].ScopeMetrics[0].Metrics {
		if m.Name == otlp.MetricConnOpened {
			series = len(m.GetSum().DataPoints)
		}
	}
	if series != 2 {
		t.Errorf("%d series of %s, want one per role", series, otlp.MetricConnOpened)
	}
}

// TestTickAfterFailedExport checks that an interval whose request failed is
// made up for by the next one: the counters are cumulative, the failures are
// counted, and the observation segment keeps its start.
func TestTickAfterFailedExport(t *testing.T) {
	src := &fakeSource{snaps: []*tracer.Snapshot{
		{Flows: []tracer.Flow{flow(tracer.DirOut, 5432, 101, 2), flow(tracer.DirOut, 6379, 101, 1)}},
		{Flows: []tracer.Flow{flow(tracer.DirOut, 5432, 101, 3)}},
	}}
	// One series per request: the interval spans several requests, and the
	// rest of it is not sent after the first fails.
	exp := &fakeExporter{fail: 1}
	a := newTestAgent(src, exp, 1)
	if err := a.tick(context.Background()); err == nil {
		t.Fatal("tick succeeded with a failing exporter")
	}
	if exp.calls != 1 {
		t.Errorf("%d requests after the first failed, want none", exp.calls-1)
	}
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sumOf(exp.sent, otlp.MetricConnOpened, 5432); got["client"] != 5 {
		t.Errorf("connections to 5432 = %v, want the 2 of the failed interval and 3", got)
	}
	if got := sumOf(exp.sent, otlp.MetricConnOpened, 6379); got["client"] != 1 {
		t.Errorf("connections to 6379 = %v", got)
	}
	if got := sumOf(exp.sent, otlp.MetricAgentExportFailures, 0); got[""] != 1 {
		t.Errorf("export failures = %v", got)
	}
	var start int64
	for _, req := range exp.sent {
		for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
			if m.Name == otlp.MetricAgentSegmentStart {
				start = m.GetGauge().DataPoints[0].GetAsInt()
			}
		}
	}
	if want := a.started.Unix(); start < want-1 || start > want+1 {
		t.Errorf("segment start = %d, want the start of the agent %d", start, want)
	}
}

// TestTickCollectError checks that nothing is sent when the tracer fails.
func TestTickCollectError(t *testing.T) {
	exp := &fakeExporter{}
	a := newTestAgent(&fakeSource{err: errors.New("iterator")}, exp, 0)
	if err := a.tick(context.Background()); err == nil {
		t.Fatal("tick succeeded")
	}
	if exp.calls != 0 {
		t.Errorf("%d requests sent", exp.calls)
	}
}
