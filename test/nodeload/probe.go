//go:build linux

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/yuuki/shawk/internal/agent"
	"github.com/yuuki/shawk/internal/procinfo"
	"github.com/yuuki/shawk/internal/tracer"
)

// runProbe loads the tracer of shawk with the options of the agent and
// collects it every interval, as the agent does, without exporting.
func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	var (
		netns    = fs.String("netns", "", "path of the network namespace to trace, e.g. /run/netns/node; empty traces all")
		maxFlows = fs.Uint("max-flows", 16384, "-max-flows of the agent")
		interval = fs.Duration("interval", 15*time.Second, "collection interval")
		count    = fs.Int("count", 8, "intervals")
		expect   = fs.Int("expect", 0, "distinct flows the workload makes, for the coverage")
		label    = fs.String("label", "", "label of the output lines")
		comm     = fs.String("comm", "", "count the flows of this command only (drops and memory stay those of all)")
	)
	fs.Parse(args)
	var ns uint32
	if *netns != "" {
		var st unix.Stat_t
		if err := unix.Stat(*netns, &st); err != nil {
			return err
		}
		ns = uint32(st.Ino)
	}
	internal, err := agent.ParseInternalPeers("private")
	if err != nil {
		return err
	}
	tr, err := tracer.New(tracer.Options{
		NetNS:             ns,
		MaxFlows:          uint32(*maxFlows),
		Fold:              tracer.FoldIn,
		InternalPeers:     internal,
		LearnTranslations: true,
		// As the agent: the paths of new cgroups are learned from events.
		OnCgroup: procinfo.NewResolver().Learn,
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return err
	}
	defer tr.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var uname unix.Utsname
	unix.Uname(&uname)
	seen := map[tracer.FlowKey]bool{}
	var lastDrops, lastBusy, lastCgroups uint64
	lastCPU := cpuTime()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for i := 0; i <= *count; i++ {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		start := time.Now()
		snap, err := tr.Collect()
		took := time.Since(start)
		if err != nil {
			return err
		}
		o := probeOut{Label: *label, MaxFlows: uint32(*maxFlows), Interval: i, Flows: len(snap.Flows),
			Drops: snap.Drops - lastDrops, Busy: snap.Contended - lastBusy, Expected: *expect,
			Collect: ms(took), Kernel: unix.ByteSliceToString(uname.Release[:])}
		o.Cgroups = snap.CgroupEventDrops - lastCgroups
		lastDrops, lastBusy, lastCgroups = snap.Drops, snap.Contended, snap.CgroupEventDrops
		o.Flows = 0
		for _, f := range snap.Flows {
			if *comm != "" && f.Comm != *comm {
				continue
			}
			o.Flows++
			if f.Direction == tracer.DirOut {
				o.Out++
			}
			o.Open += f.OpenConns
			seen[f.FlowKey] = true
		}
		o.Seen = len(seen)
		cpu := cpuTime()
		o.CPU = ms(cpu - lastCPU)
		lastCPU = cpu
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		o.Heap = float64(m.HeapAlloc) / (1 << 20)
		o.RSS = rssMiB(os.Getpid())
		o.Maps = mapsMiB(os.Getpid())
		// The first interval holds the connections adopted at start.
		if i > 0 {
			emit(o)
		}
	}
	return nil
}

// cpuTime is the CPU time of this process.
func cpuTime() time.Duration {
	var ru unix.Rusage
	unix.Getrusage(unix.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// rssMiB reads VmRSS of a process.
func rssMiB(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	return statusKiB(b, "VmRSS:") / 1024
}

// mapsMiB sums the memory the kernel charges for the BPF maps a process
// holds (memlock in the fdinfo of the maps).
func mapsMiB(pid int) float64 {
	paths, _ := filepath.Glob(fmt.Sprintf("/proc/%d/fdinfo/*", pid))
	var kib float64
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Contains(b, []byte("map_type:")) {
			continue
		}
		kib += statusKiB(b, "memlock:") / 1024
	}
	return kib / 1024
}
