package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
}

func newRDMACounters(root string) *rdmaCounters {
	return &rdmaCounters{root: root, last: map[string]uint64{}}
}

// read adds the increase of the counters since the last read, and returns
// the bytes since the first, and whether the host has RDMA ports. The first
// value of a counter is its base; a counter that went down was reset, and
// counts from zero.
func (r *rdmaCounters) read() (uint64, bool) {
	// port_xmit_data and port_rcv_data count octets divided by 4. Without
	// extended counters they have 32 bits and stop at their maximum.
	paths, _ := filepath.Glob(filepath.Join(r.root, "*", "ports", "*", "counters", "port_*_data"))
	found := false
	for _, p := range paths {
		if base := filepath.Base(p); base != "port_xmit_data" && base != "port_rcv_data" {
			continue
		}
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
	return r.bytes, found
}
