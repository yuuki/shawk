package tracer

import (
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// ProgramStat is the cumulative run time of a BPF program.
type ProgramStat struct {
	Name     string
	RunCount uint64
	Runtime  time.Duration
}

// EnableStats turns on the kernel's run time accounting of BPF programs,
// which has a small overhead of its own.
func (t *Tracer) EnableStats() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.statsCloser != nil {
		return nil
	}
	c, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return err
	}
	t.statsCloser = c
	return nil
}

// ProgramStats returns the run time statistics of the attached programs.
func (t *Tracer) ProgramStats() ([]ProgramStat, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ProgramStat
	for name, prog := range t.progs {
		s, err := prog.Stats()
		if err != nil {
			return nil, err
		}
		out = append(out, ProgramStat{Name: name, RunCount: s.RunCount, Runtime: s.Runtime})
	}
	return out, nil
}
