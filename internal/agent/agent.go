// Package agent runs the per-host daemon: it collects bundled flows from the
// tracer and sends them as OTLP metrics to the shawk connector of an
// OpenTelemetry Collector. It keeps no database of its own.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"golang.org/x/sys/unix"

	"github.com/yuuki/shawk/internal/otlp"
	"github.com/yuuki/shawk/internal/procinfo"
	"github.com/yuuki/shawk/internal/tracer"
	"github.com/yuuki/shawk/internal/version"
)

// Config configures an agent.
type Config struct {
	Exporter otlp.ExporterConfig
	Interval time.Duration
	// IdleTTL is how long a series is sent after its last activity.
	IdleTTL  time.Duration
	NetNS    uint32 // 0 traces all network namespaces
	MaxFlows uint32
	// MaxSeriesPerRequest bounds the edges and listeners in one request;
	// a host with more sends several requests per interval.
	MaxSeriesPerRequest int
	ServiceFallback     procinfo.Fallback
	BPFStats            bool // enable and send the run time statistics of the BPF programs
	Logger              *slog.Logger

	traceSelf bool // trace the agent's own flows; for tests
}

// Agent is a running agent.
type Agent struct {
	cfg      Config
	log      *slog.Logger
	tracer   *tracer.Tracer
	exporter otlp.Exporter
	cgroups  *procinfo.Resolver
	state    *otlp.State
	segment  *otlp.Segment
	idents   *identities
	started  time.Time
	res      otlp.Resource

	lastCollect time.Time
	failures    uint64
	drops       uint64
}

// Run starts the agent and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 15 * time.Minute
	}
	if cfg.IdleTTL < 2*time.Minute || cfg.IdleTTL < 4*cfg.Interval {
		return fmt.Errorf("the idle TTL %s must be at least 2m and 4 intervals", cfg.IdleTTL)
	}
	exp, err := otlp.NewExporter(cfg.Exporter)
	if err != nil {
		return err
	}
	defer exp.Close()

	cgroups := procinfo.NewResolver()
	tr, err := tracer.New(tracer.Options{
		NetNS:     cfg.NetNS,
		MaxFlows:  cfg.MaxFlows,
		OnCgroup:  cgroups.Learn,
		TraceSelf: cfg.traceSelf,
		Logger:    cfg.Logger,
	})
	if err != nil {
		return fmt.Errorf("starting tracer: %w", err)
	}
	defer tr.Close()
	if cfg.BPFStats {
		if err := tr.EnableStats(); err != nil {
			cfg.Logger.Warn("enabling BPF run time statistics", "error", err)
		}
	}
	if tr.SelfPID() != uint32(os.Getpid()) {
		cfg.Logger.Warn("the agent runs in a PID namespace; owners of sockets of processes outside it are not resolved, run it in the host PID namespace",
			"pid", os.Getpid(), "host_pid", tr.SelfPID())
	}
	if !tr.UDPEnabled() {
		cfg.Logger.Warn("UDP is not traced; see the error above (UDP tracing needs BPF trampolines, fentry)")
	}

	hostname, _ := os.Hostname()
	machineID := procinfo.MachineID()
	if machineID == "" {
		cfg.Logger.Warn("the host has no machine id (/etc/machine-id); it is identified by its name only")
	}
	now := time.Now()
	a := &Agent{
		cfg:      cfg,
		log:      cfg.Logger,
		tracer:   tr,
		exporter: exp,
		cgroups:  cgroups,
		state:    otlp.NewState(cfg.IdleTTL),
		segment:  otlp.NewSegment(now, cfg.IdleTTL),
		idents:   newIdentities(cfg.ServiceFallback, cfg.IdleTTL),
		started:  now,
		res: otlp.Resource{
			MachineID:    machineID,
			Hostname:     hostname,
			Kernel:       kernelRelease(),
			AgentVersion: version.Version,
		},
		// Flows are traced from here on.
		lastCollect: now,
	}
	a.log.Info("agent started", "endpoint", cfg.Exporter.Endpoint, "protocol", cfg.Exporter.Protocol,
		"interval", cfg.Interval, "idle_ttl", cfg.IdleTTL, "udp", tr.UDPEnabled())

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Send the last partial interval.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.tick(shutdownCtx); err != nil {
				a.log.Error("sending the last interval", "error", err)
			}
			return nil
		case <-ticker.C:
			tickCtx, cancel := context.WithTimeout(ctx, a.exportTimeout())
			if err := a.tick(tickCtx); err != nil {
				a.log.Error("collecting and sending flows", "error", err)
			}
			cancel()
		}
	}
}

// exportTimeout keeps an export from delaying the next collection.
func (a *Agent) exportTimeout() time.Duration {
	return max(a.cfg.Interval*2/3, time.Second)
}

// tick closes an interval of the tracer and sends all live series. A failed
// request is made up for by the next one, since the series are cumulative.
func (a *Agent) tick(ctx context.Context) error {
	snap, err := a.tracer.Collect()
	if err != nil {
		return err
	}
	now := time.Now()
	a.observe(snap, a.lastCollect, now)
	a.lastCollect = now
	a.state.Expire(now)
	a.idents.expire(now)

	reqs, segStart := a.request(now)
	// The last request carries the metrics of the agent and closes the
	// interval; after a failure the rest is not sent, and the next interval
	// makes up for it since the series are cumulative.
	for i, req := range reqs {
		if err := a.exporter.Export(ctx, req); err != nil {
			a.failures++
			return fmt.Errorf("sending request %d of %d to %s: %w", i+1, len(reqs), a.cfg.Exporter.Endpoint, err)
		}
	}
	a.segment.Succeeded(segStart, now)
	return nil
}

// observe accounts a snapshot of the interval (start, end] to the series.
func (a *Agent) observe(snap *tracer.Snapshot, start, end time.Time) {
	a.drops = snap.Drops
	a.idents.beginInterval()
	a.state.BeginInterval()
	for i := range snap.Flows {
		f := &snap.Flows[i]
		role := otlp.RoleClient
		if f.Direction == tracer.DirIn {
			role = otlp.RoleServer
		}
		k := otlp.EdgeKey{
			Role:      role,
			Proto:     f.Proto.String(),
			LocalAddr: f.LocalAddr,
			PeerAddr:  f.RemoteAddr,
			Port:      f.Port,
			NetNS:     f.NetNS,
			Process:   a.idents.resolve(f.PID, f.Comm, procinfo.Unit(a.cgroups.CgroupPath(f.CgroupID)), end),
		}
		a.state.AddEdge(k, otlp.EdgeStats{
			Conns:      f.Conns,
			ConnFails:  f.ConnFails,
			OpenConns:  f.OpenConns,
			BytesSent:  f.BytesSent,
			BytesRecv:  f.BytesRecv,
			MsgsSent:   f.MsgsSent,
			MsgsRecv:   f.MsgsRecv,
			Retrans:    f.Retrans,
			RTTSumUs:   f.RTTSumUs,
			RTTSamples: f.RTTSamples,
		}, start, end)
	}
	for _, l := range snap.Listeners {
		a.state.AddListener(otlp.ListenerKey{
			Proto:   l.Proto.String(),
			Addr:    l.Addr,
			Port:    l.Port,
			NetNS:   l.NetNS,
			Process: a.idents.resolve(l.PID, l.Comm, procinfo.Unit(a.cgroups.CgroupPath(l.CgroupID)), end),
		}, end)
	}
}

// request builds the requests of the live series at now, and returns the
// start of the observation segment they carry.
func (a *Agent) request(now time.Time) ([]*colmetricspb.ExportMetricsServiceRequest, time.Time) {
	res := a.res
	res.Addrs = hostAddrs()
	// Addresses of containers in other network namespaces.
	for _, addr := range a.state.LocalAddrs() {
		if !slices.Contains(res.Addrs, addr) {
			res.Addrs = append(res.Addrs, addr)
		}
	}
	segStart := a.segment.Start(now)
	st := otlp.AgentStatus{
		Started:        a.started,
		SegmentStart:   segStart,
		NetNSScope:     a.netnsScope(),
		UDPTraced:      a.tracer.UDPEnabled(),
		FlowsDropped:   a.drops,
		ExportFailures: a.failures,
	}
	if a.cfg.BPFStats {
		if stats, err := a.tracer.ProgramStats(); err == nil {
			for _, s := range stats {
				st.BPFPrograms = append(st.BPFPrograms, otlp.BPFProgram{Name: s.Name, RunCount: s.RunCount, RunTime: s.Runtime})
			}
		}
	}
	return a.state.Requests(res, st, now, a.cfg.MaxSeriesPerRequest), segStart
}

func (a *Agent) netnsScope() string {
	if a.cfg.NetNS == 0 {
		return "all"
	}
	return strconv.FormatUint(uint64(a.cfg.NetNS), 10)
}

func kernelRelease() string {
	var uts unix.Utsname
	if unix.Uname(&uts) != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// hostAddrs returns the addresses of the interfaces of the host.
func hostAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// ParseNetNS parses the --netns flag: "all", "self" or an inode number.
func ParseNetNS(s string) (uint32, error) {
	switch s {
	case "", "all":
		return 0, nil
	case "self":
		ns := procinfo.NetNS()
		if ns == 0 {
			return 0, errors.New("cannot determine the network namespace")
		}
		return ns, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid network namespace %q", s)
	}
	return uint32(v), nil
}
