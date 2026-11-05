package agent

import (
	"context"
	"errors"
	"log/slog"
	"maps"
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
func (f *fakeSource) TranslationsTraced() bool                    { return true }
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

// newTestAgent returns an agent started at the time given.
func newTestAgent(src source, exp otlp.Exporter, maxSeries int, started time.Time) *Agent {
	cfg := Config{
		Interval:            15 * time.Second,
		IdleTTL:             15 * time.Minute,
		MaxSeriesPerRequest: maxSeries,
		Logger:              slog.New(slog.DiscardHandler),
	}
	return newAgent(cfg, src, exp, procinfo.NewResolver(), otlp.Resource{Hostname: "h"}, started)
}

// Cgroup ids are inode numbers; these are no cgroup of the host running the
// tests, whose paths would give the flows different units.
const unknownCgroup = 1 << 62

// lastSum returns the values of a counter for the server port given (all
// ports for 0), by role, in the last request that carries each: the
// counters are cumulative.
func lastSum(reqs []*colmetricspb.ExportMetricsServiceRequest, metric string, port uint16) map[string]int64 {
	out := map[string]int64{}
	for _, req := range reqs {
		got := map[string]int64{}
		for _, rm := range req.ResourceMetrics {
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					if m.Name != metric {
						continue
					}
					for _, p := range m.GetSum().GetDataPoints() {
						if a := attrs(p.Attributes); a["server.port"] == strconv.Itoa(int(port)) || port == 0 {
							got[a["shawk.role"]] += p.GetAsInt()
						}
					}
				}
			}
		}
		for role, v := range got {
			out[role] = v
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
		flow(tracer.DirOut, 5432, unknownCgroup, 2),
		flow(tracer.DirOut, 5432, unknownCgroup+1, 3),
		flow(tracer.DirIn, 5432, unknownCgroup, 1),
	}}}}
	exp := &fakeExporter{}
	a := newTestAgent(src, exp, 0, time.Now())
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := lastSum(exp.sent, otlp.MetricConnOpened, 5432); got["client"] != 5 || got["server"] != 1 {
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

// TestTickKernelSockets checks that flows and listeners of the kernel are
// named after their port and side, whatever process the kernel used.
func TestTickKernelSockets(t *testing.T) {
	kernel := func(dir tracer.Direction, port uint16) tracer.Flow {
		f := flow(dir, port, 0, 1)
		f.Comm = tracer.KernelComm
		return f
	}
	src := &fakeSource{snaps: []*tracer.Snapshot{{
		Flows: []tracer.Flow{kernel(tracer.DirOut, 2049), kernel(tracer.DirIn, 2049), kernel(tracer.DirOut, 40000)},
		Listeners: []tracer.Listener{{Proto: tracer.ProtoTCP, Addr: netip.IPv4Unspecified(), Port: 2049, NetNS: 1,
			Comm: tracer.KernelComm}},
	}}}
	a := newTestAgent(src, &fakeExporter{}, 0, time.Now())
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The service of each side of each port.
	services := map[string]string{}
	for k := range a.state.Edges() {
		services[k.Role+"/"+strconv.Itoa(int(k.Port))] = k.Service
		if k.Unit != "" || k.Exe != "" || k.Comm != tracer.KernelComm {
			t.Errorf("edge to %d: process %+v", k.Port, k.Process)
		}
	}
	for k := range a.state.Listeners() {
		services["listener/"+strconv.Itoa(int(k.Port))] = k.Service
	}
	want := map[string]string{
		"client/2049":   "~kernel:nfs",
		"server/2049":   "~kernel:nfsd",
		"listener/2049": "~kernel:nfsd",
		"client/40000":  "~kernel",
	}
	if len(services) != len(want) {
		t.Errorf("services = %v, want %v", services, want)
	}
	for side, w := range want {
		if got := services[side]; got != w {
			t.Errorf("service of %s = %q, want %q", side, got, w)
		}
	}
}

// TestTickListenerKernelChosen checks that a listener tells whether the
// kernel chose its port, as lockd's does unless its port is set.
func TestTickListenerKernelChosen(t *testing.T) {
	src := &fakeSource{snaps: []*tracer.Snapshot{{
		Listeners: []tracer.Listener{
			{Proto: tracer.ProtoTCP, Addr: netip.IPv4Unspecified(), Port: 2049, NetNS: 1, Comm: tracer.KernelComm},
			{Proto: tracer.ProtoTCP, Addr: netip.IPv4Unspecified(), Port: 39917, NetNS: 1, Comm: tracer.KernelComm,
				KernelChosen: true},
		},
	}}}
	a := newTestAgent(src, &fakeExporter{}, 0, time.Now())
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := map[uint16]bool{}
	for k := range a.state.Listeners() {
		got[k.Port] = k.KernelChosen
	}
	if want := map[uint16]bool{2049: false, 39917: true}; !maps.Equal(got, want) {
		t.Errorf("kernel-chosen ports = %v, want %v", got, want)
	}
}

// TestTickAfterFailedExport checks that an interval whose request failed is
// made up for by the next one: the counters are cumulative since the start,
// not since the last request that succeeded, the failures are counted, and
// the observation segment keeps its start.
func TestTickAfterFailedExport(t *testing.T) {
	src := &fakeSource{snaps: []*tracer.Snapshot{
		{Flows: []tracer.Flow{flow(tracer.DirOut, 5432, unknownCgroup, 1)}},
		{Flows: []tracer.Flow{flow(tracer.DirOut, 5432, unknownCgroup, 2), flow(tracer.DirOut, 6379, unknownCgroup, 1)}},
		{Flows: []tracer.Flow{flow(tracer.DirOut, 5432, unknownCgroup, 3)}},
	}}
	exp := &fakeExporter{}
	// One series per request: the interval spans several requests, and the
	// rest of it is not sent after the first fails. The agent started a few
	// minutes ago, so that a segment started anew would show.
	started := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	a := newTestAgent(src, exp, 1, started)
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	exp.fail, exp.calls = 1, 0
	if err := a.tick(context.Background()); err == nil {
		t.Fatal("tick succeeded with a failing exporter")
	}
	if exp.calls != 1 {
		t.Errorf("%d requests after the first failed, want none", exp.calls-1)
	}
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := lastSum(exp.sent, otlp.MetricConnOpened, 5432); got["client"] != 6 {
		t.Errorf("connections to 5432 = %v, want 1+2+3", got)
	}
	if got := lastSum(exp.sent, otlp.MetricConnOpened, 6379); got["client"] != 1 {
		t.Errorf("connections to 6379 = %v", got)
	}
	if got := lastSum(exp.sent, otlp.MetricAgentExportFailures, 0); got[""] != 1 {
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
	// The start is expressed by the current clock, within a second; a
	// segment started anew would be minutes later.
	if want := started.Unix(); start < want-1 || start > want+1 {
		t.Errorf("segment start = %d, want the start of the agent %d", start, want)
	}
}

// TestTickCollectError checks that nothing is sent when the tracer fails.
func TestTickCollectError(t *testing.T) {
	exp := &fakeExporter{}
	a := newTestAgent(&fakeSource{err: errors.New("iterator")}, exp, 0, time.Now())
	if err := a.tick(context.Background()); err == nil {
		t.Fatal("tick succeeded")
	}
	if exp.calls != 0 {
		t.Errorf("%d requests sent", exp.calls)
	}
}

// localSource is a fakeSource that folds peers and records the addresses of
// the host it is given.
type localSource struct {
	fakeSource
	local [][]netip.Addr
}

func (s *localSource) SetLocalAddrs(addrs []netip.Addr) error {
	s.local = append(s.local, addrs)
	return nil
}

// TestTickFolded checks that a folded flow is sent as an edge with
// shawk.peer.folded and the unspecified address, apart from an edge to the
// same port with an exact peer, and that the addresses of the host are
// given to a source that folds peers.
func TestTickFolded(t *testing.T) {
	folded := flow(tracer.DirIn, 443, unknownCgroup, 5)
	folded.RemoteAddr = netip.IPv4Unspecified()
	folded.Folded = true
	src := &localSource{fakeSource: fakeSource{snaps: []*tracer.Snapshot{{
		Flows: []tracer.Flow{folded, flow(tracer.DirIn, 443, unknownCgroup, 1)},
	}}}}
	exp := &fakeExporter{}
	a := newTestAgent(src, exp, 0, time.Now())
	a.cfg.Fold = tracer.FoldIn
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(src.local) != 1 {
		t.Errorf("the addresses of the host were given %d times, want once", len(src.local))
	}
	var foldedEdges, exactEdges int
	for k := range a.state.Edges() {
		switch {
		case k.PeerFolded && k.PeerAddr == netip.IPv4Unspecified():
			foldedEdges++
		case !k.PeerFolded:
			exactEdges++
		}
	}
	if foldedEdges != 1 || exactEdges != 1 {
		t.Errorf("%d folded and %d exact edges, want 1 and 1", foldedEdges, exactEdges)
	}
	var marked int
	for _, req := range exp.sent {
		for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
			if m.Name != otlp.MetricConnOpened {
				continue
			}
			for _, dp := range m.GetSum().DataPoints {
				for _, kv := range dp.Attributes {
					if kv.Key == otlp.AttrPeerFolded && kv.Value.GetBoolValue() {
						marked++
					}
				}
			}
		}
	}
	if marked != 1 {
		t.Errorf("%d data points of %s marked %s, want 1", marked, otlp.MetricConnOpened, otlp.AttrPeerFolded)
	}

	// Without folding, the addresses of the host are not needed.
	src.local = nil
	a.cfg.Fold = tracer.FoldNone
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(src.local) != 0 {
		t.Errorf("the addresses of the host were given without folding")
	}
}

// TestTickTranslations checks that the translations of a snapshot are sent
// with their attributes, and with the drops and whether they are traced in
// the metrics of the agent.
func TestTickTranslations(t *testing.T) {
	x := tracer.Translation{Proto: tracer.ProtoTCP, NetNS: 7, Client: netip.MustParseAddr("10.0.0.1"),
		Virtual: netip.MustParseAddr("10.96.0.10"), VirtualPort: 5432, Source: netip.MustParseAddr("10.0.0.1"),
		Backend: netip.MustParseAddr("10.244.0.5"), BackendPort: 6432}
	src := &fakeSource{snaps: []*tracer.Snapshot{{Translations: []tracer.Translation{x}, TranslationDrops: 3}}}
	exp := &fakeExporter{}
	a := newTestAgent(src, exp, 0, time.Now())
	if err := a.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	var traced, dropped int64 = -1, -1
	for _, m := range exp.sent[0].ResourceMetrics[0].ScopeMetrics[0].Metrics {
		switch m.Name {
		case otlp.MetricTranslationLast:
			got = attrs(m.GetGauge().DataPoints[0].Attributes)
		case otlp.MetricAgentTranslationsTraced:
			traced = m.GetGauge().DataPoints[0].GetAsInt()
		case otlp.MetricAgentTranslationsDropped:
			dropped = m.GetSum().DataPoints[0].GetAsInt()
		}
	}
	want := map[string]string{"network.transport": "tcp", "shawk.netns": "7",
		"shawk.translation.client.address": "10.0.0.1", "shawk.translation.virtual.address": "10.96.0.10",
		"shawk.translation.virtual.port": "5432", "shawk.translation.source.address": "10.0.0.1",
		"shawk.translation.backend.address": "10.244.0.5", "shawk.translation.backend.port": "6432"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (%v)", k, got[k], v, got)
		}
	}
	if traced != 1 || dropped != 3 {
		t.Errorf("traced = %d, dropped = %d", traced, dropped)
	}
}
