package agent

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rdmaClass is where the kernel lists the RDMA devices (InfiniBand, RoCE).
const rdmaClass = "/sys/class/infiniband"

// rdmaCounters sums the data the RDMA ports of the host sent and received
// since the agent started, from their port counters. It is a hint only: the
// counters of a port cover all its traffic (IPoIB included), so they tell
// neither which hosts or processes used RDMA nor that shawk missed none of
// its dependencies.
type rdmaCounters struct {
	root  string            // rdmaClass, or a directory of tests
	last  map[string]uint64 // the last value of every counter read
	bytes uint64

	mu     sync.Mutex
	result uint64 // bytes at the last read that completed
	found  bool
}

func newRDMACounters(root string) *rdmaCounters {
	return &rdmaCounters{root: root, last: map[string]uint64{}}
}

// run reads the counters every interval until ctx is done. A read of a
// counter may query the device (a MAD to its performance management
// agent), so the reads are kept off the collection of flows: a device that
// does not answer stops only the hint, at its last value.
func (r *rdmaCounters) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		n, ok := r.read()
		r.mu.Lock()
		r.result, r.found = n, ok
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// latest returns the bytes at the last read that completed, and whether
// the host had readable port counters then.
func (r *rdmaCounters) latest() (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result, r.found
}

// read adds the increase of the counters since the last read, and returns
// the bytes since the first, and whether a counter was read. The first
// value of a counter is its base; a counter that went down was reset, and
// counts from zero. A counter no longer listed is forgotten, so that a
// device that comes back under its name starts at a new base.
func (r *rdmaCounters) read() (uint64, bool) {
	// port_xmit_data and port_rcv_data count octets divided by 4. Without
	// extended counters they have 32 bits and stop at their maximum.
	paths, err := filepath.Glob(filepath.Join(r.root, "*", "ports", "*", "counters", "port_*_data"))
	if err != nil {
		return r.bytes, false
	}
	listed := make(map[string]bool, len(paths))
	found := false
	for _, p := range paths {
		if base := filepath.Base(p); base != "port_xmit_data" && base != "port_rcv_data" {
			continue
		}
		listed[p] = true
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			continue
		}
		found = true
		last, seen := r.last[p]
		r.last[p] = v
		switch {
		case !seen:
		case v >= last:
			r.bytes += 4 * (v - last)
		default:
			r.bytes += 4 * v
		}
	}
	for p := range r.last {
		if !listed[p] {
			delete(r.last, p)
		}
	}
	return r.bytes, found
}
