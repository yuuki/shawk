// Package agent runs the per-host daemon: it collects bundled flows from the
// tracer, records them in the ledger and serves them to clients.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/yuuki/shawk/internal/api"
	"github.com/yuuki/shawk/internal/ledger"
	"github.com/yuuki/shawk/internal/procinfo"
	"github.com/yuuki/shawk/internal/tracer"
	"github.com/yuuki/shawk/internal/version"
)

// Config configures an agent.
type Config struct {
	Listen    string // address of the API server
	DBPath    string
	Interval  time.Duration
	NetNS     uint32 // 0 traces all network namespaces
	MaxFlows  uint32
	Retention ledger.Retention
	Token     string // bearer token required by the API; empty disables auth
	BPFStats  bool   // enable the kernel's run time accounting of BPF programs
	Logger    *slog.Logger
}

// Agent is a running agent.
type Agent struct {
	cfg      Config
	log      *slog.Logger
	tracer   *tracer.Tracer
	ledger   *ledger.Ledger
	cgroups  *procinfo.Resolver
	apiPort  uint16
	started  time.Time
	hostname string

	mu       sync.Mutex
	drops    uint64
	lastErr  error
	lastTick time.Time
}

// Run starts the agent and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	lg, err := ledger.Open(cfg.DBPath, cfg.Retention)
	if err != nil {
		return fmt.Errorf("opening ledger %s: %w", cfg.DBPath, err)
	}
	defer lg.Close()

	tr, err := tracer.New(tracer.Options{NetNS: cfg.NetNS, MaxFlows: cfg.MaxFlows, Logger: cfg.Logger})
	if err != nil {
		return fmt.Errorf("starting tracer: %w", err)
	}
	defer tr.Close()
	if cfg.BPFStats {
		if err := tr.EnableStats(); err != nil {
			cfg.Logger.Warn("enabling BPF run time statistics", "error", err)
		}
	}
	if !tr.UDPEnabled() {
		cfg.Logger.Warn("UDP is not traced: this kernel does not support BPF trampolines (fentry)")
	}

	hostname, _ := os.Hostname()
	a := &Agent{
		cfg:      cfg,
		log:      cfg.Logger,
		tracer:   tr,
		ledger:   lg,
		cgroups:  procinfo.NewResolver(),
		apiPort:  uint16(ln.Addr().(*net.TCPAddr).Port),
		started:  time.Now(),
		hostname: hostname,
	}

	srv := &http.Server{Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	a.log.Info("agent started", "listen", ln.Addr().String(), "db", cfg.DBPath, "interval", cfg.Interval, "udp", tr.UDPEnabled())

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx)
			// Record the last partial interval.
			if err := a.collect(context.Background()); err != nil {
				a.log.Error("collecting flows", "error", err)
			}
			return nil
		case err := <-errc:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			if err := a.collect(ctx); err != nil {
				a.log.Error("collecting flows", "error", err)
			}
			if time.Since(lastPrune) > time.Hour {
				if err := lg.Prune(ctx, time.Now()); err != nil {
					a.log.Error("pruning ledger", "error", err)
				}
				lastPrune = time.Now()
			}
		}
	}
}

type recordKey struct {
	dir, proto, laddr, raddr string
	port                     uint16
	netns                    uint32
	unit, comm               string
}

// collect closes an interval of the tracer and records it.
func (a *Agent) collect(ctx context.Context) error {
	snap, err := a.tracer.Collect()
	now := time.Now()
	a.mu.Lock()
	a.lastErr = err
	a.lastTick = now
	if snap != nil {
		a.drops = snap.Drops
	}
	a.mu.Unlock()
	if err != nil {
		return err
	}

	exes := map[uint32]string{}
	exe := func(pid uint32) string {
		if s, ok := exes[pid]; ok {
			return s
		}
		s := procinfo.Exe(pid)
		exes[pid] = s
		return s
	}

	index := make(map[recordKey]int, len(snap.Flows))
	recs := make([]ledger.Record, 0, len(snap.Flows))
	for i := range snap.Flows {
		f := &snap.Flows[i]
		// Queries of shawk clients to this agent.
		if f.Direction == tracer.DirOut && f.Port == a.apiPort && f.Comm == "shawk" {
			continue
		}
		cg := a.cgroups.CgroupPath(f.CgroupID)
		r := ledger.Record{
			Direction:  f.Direction.String(),
			Proto:      f.Proto.String(),
			LocalAddr:  f.LocalAddr.String(),
			RemoteAddr: f.RemoteAddr.String(),
			Port:       f.Port,
			NetNS:      f.NetNS,
			Unit:       procinfo.Unit(cg),
			Comm:       f.Comm,
			Cgroup:     cg,
			Exe:        exe(f.PID),
			PID:        f.PID,
			Conns:      f.Conns,
			ConnFails:  f.ConnFails,
			OpenConns:  f.OpenConns,
			BytesSent:  f.BytesSent,
			BytesRecv:  f.BytesRecv,
			MsgsSent:   f.MsgsSent,
			MsgsRecv:   f.MsgsRecv,
			Retrans:    f.Retrans,
			RTTSumUs:   f.RTTSumUs,
			RTTCount:   f.RTTSamples,
		}
		// Different cgroups may map to the same unit, e.g. login sessions.
		k := recordKey{r.Direction, r.Proto, r.LocalAddr, r.RemoteAddr, r.Port, r.NetNS, r.Unit, r.Comm}
		if j, ok := index[k]; ok {
			mergeRecord(&recs[j], &r)
			continue
		}
		index[k] = len(recs)
		recs = append(recs, r)
	}

	listeners := make([]ledger.ListenerRecord, 0, len(snap.Listeners))
	for _, l := range snap.Listeners {
		if l.Proto == tracer.ProtoTCP && l.Port == a.apiPort && l.PID == uint32(os.Getpid()) {
			continue
		}
		cg := a.cgroups.CgroupPath(l.CgroupID)
		listeners = append(listeners, ledger.ListenerRecord{
			Proto:  l.Proto.String(),
			Addr:   l.Addr.String(),
			Port:   l.Port,
			NetNS:  l.NetNS,
			Unit:   procinfo.Unit(cg),
			Comm:   l.Comm,
			Cgroup: cg,
			Exe:    exe(l.PID),
			PID:    l.PID,
		})
	}
	return a.ledger.Write(ctx, now, recs, listeners)
}

func mergeRecord(dst, src *ledger.Record) {
	dst.Conns += src.Conns
	dst.ConnFails += src.ConnFails
	dst.OpenConns += src.OpenConns
	dst.BytesSent += src.BytesSent
	dst.BytesRecv += src.BytesRecv
	dst.MsgsSent += src.MsgsSent
	dst.MsgsRecv += src.MsgsRecv
	dst.Retrans += src.Retrans
	dst.RTTSumUs += src.RTTSumUs
	dst.RTTCount += src.RTTCount
	if src.PID != 0 {
		dst.PID, dst.Exe, dst.Cgroup = src.PID, src.Exe, src.Cgroup
	}
}

func (a *Agent) info(ctx context.Context) (*api.Info, error) {
	since, err := a.ledger.Since(ctx)
	if err != nil {
		return nil, err
	}
	var uts unix.Utsname
	kernel := ""
	if unix.Uname(&uts) == nil {
		kernel = unix.ByteSliceToString(uts.Release[:])
	}
	a.mu.Lock()
	drops := a.drops
	a.mu.Unlock()
	return &api.Info{
		Hostname:    a.hostname,
		Version:     version.Version,
		Kernel:      kernel,
		Addrs:       hostAddrs(),
		StartedAt:   a.started,
		LedgerSince: since,
		Interval:    a.cfg.Interval.String(),
		UDP:         a.tracer.UDPEnabled(),
		Drops:       drops,
	}, nil
}

// hostAddrs returns the addresses of the interfaces of the host.
func hostAddrs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// ProgramStats is a run time statistic of a BPF program.
type ProgramStats struct {
	Name      string  `json:"name"`
	RunCount  uint64  `json:"run_count"`
	RuntimeNs int64   `json:"runtime_ns"`
	AvgNs     float64 `json:"avg_ns"`
}

func (a *Agent) programStats() ([]ProgramStats, error) {
	stats, err := a.tracer.ProgramStats()
	if err != nil {
		return nil, err
	}
	out := make([]ProgramStats, 0, len(stats))
	for _, s := range stats {
		ps := ProgramStats{Name: s.Name, RunCount: s.RunCount, RuntimeNs: s.Runtime.Nanoseconds()}
		if s.RunCount > 0 {
			ps.AvgNs = float64(s.Runtime.Nanoseconds()) / float64(s.RunCount)
		}
		out = append(out, ps)
	}
	return out, nil
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
