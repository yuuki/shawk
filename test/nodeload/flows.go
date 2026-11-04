package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// probeOut is what probe prints for an interval.
type probeOut struct {
	Label    string  `json:"label,omitempty"`
	MaxFlows uint32  `json:"max_flows"`
	Interval int     `json:"interval"`
	Flows    int     `json:"flows"`        // flows collected
	Out      int     `json:"out"`          // of which outgoing
	Open     uint64  `json:"open"`         // connections open at the end of the interval
	Drops    uint64  `json:"drops"`        // flow updates dropped in the interval
	Busy     uint64  `json:"busy"`         // of which refused with -EBUSY
	Cgroups  uint64  `json:"cgroup_drops"` // events of new cgroups dropped in the interval
	Seen     int     `json:"seen"`         // distinct flows collected so far
	Expected int     `json:"expected"`     // distinct flows of the workload (-expect)
	Collect  float64 `json:"collect_ms"`
	CPU      float64 `json:"cpu_ms"` // CPU time of the probe in the interval
	RSS      float64 `json:"rss_mib"`
	Heap     float64 `json:"heap_mib"`
	Maps     float64 `json:"bpf_maps_mib"` // memlock of the BPF maps of the probe
	Kernel   string  `json:"kernel"`
}

// runFlows prints a table of the output of probe, a row per label and
// -max-flows: the medians of the intervals, the largest collection time,
// and the distinct flows seen by the last interval against those expected.
func runFlows(files []string) error {
	type group struct {
		label    string
		maxFlows uint32
		rows     []probeOut
	}
	var groups []*group
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var o probeOut
			if err := json.Unmarshal(sc.Bytes(), &o); err != nil || o.MaxFlows == 0 {
				continue
			}
			i := slices.IndexFunc(groups, func(g *group) bool { return g.label == o.Label && g.maxFlows == o.MaxFlows })
			if i < 0 {
				groups = append(groups, &group{label: o.Label, maxFlows: o.MaxFlows})
				i = len(groups) - 1
			}
			groups[i].rows = append(groups[i].rows, o)
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return err
		}
	}
	fmt.Println("| workload | -max-flows | intervals | flows | open conns | drops per interval | seen / expected | collect ms (median, max) | probe CPU ms | RSS MiB | BPF maps MiB |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|---|")
	for _, g := range groups {
		med := func(f func(o probeOut) float64) float64 {
			v := make([]float64, len(g.rows))
			for i, o := range g.rows {
				v[i] = f(o)
			}
			slices.Sort(v)
			return v[len(v)/2]
		}
		var maxCollect, rss, maps float64
		for _, o := range g.rows {
			maxCollect = max(maxCollect, o.Collect)
			rss = max(rss, o.RSS)
			maps = max(maps, o.Maps)
		}
		last := g.rows[len(g.rows)-1]
		cover := fmt.Sprint(last.Seen)
		if last.Expected > 0 {
			cover = fmt.Sprintf("%d / %d (%.0f %%)", last.Seen, last.Expected, 100*float64(last.Seen)/float64(last.Expected))
		}
		fmt.Printf("| %s | %d | %d | %.0f | %.0f | %.0f | %s | %.1f, %.1f | %.0f | %.0f | %.0f |\n",
			g.label, g.maxFlows, len(g.rows), med(func(o probeOut) float64 { return float64(o.Flows) }),
			med(func(o probeOut) float64 { return float64(o.Open) }),
			med(func(o probeOut) float64 { return float64(o.Drops) }), cover,
			med(func(o probeOut) float64 { return o.Collect }), maxCollect,
			med(func(o probeOut) float64 { return o.CPU }), rss, maps)
	}
	return nil
}
