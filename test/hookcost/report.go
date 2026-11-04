package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
)

// runReport prints, for every kernel and workload, the median CPU time per
// transaction of each variant over its runs without -stats, its difference
// to the runs without hooks ("none"), and, from the runs with -stats, how
// often its programs ran per transaction and how long a run took. The
// difference divided by the runs is the cost of an event: hook and work.
func runReport(files []string) error {
	type group struct {
		cpu, rate []float64
		runs, ns  float64 // per transaction and per run, from -stats
		statOps   float64
		errs      []string
		fails     []result
	}
	groups := map[string]*group{}
	key := func(r *result, variant string) string {
		return fmt.Sprintf("%s\t%s\t%s\t%d\t%d\t%s", r.Kernel, r.Arch, r.Mode, r.Pairs, r.Size, variant)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var r result
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				continue
			}
			k := key(&r, r.Variant)
			g := groups[k]
			if g == nil {
				g = &group{}
				groups[k] = g
			}
			switch {
			case r.Error != "":
				g.errs = append(g.errs, r.Error)
			case r.Mode == "fail":
				g.fails = append(g.fails, r)
			case r.Stats:
				var runs, ns uint64
				for _, p := range r.Progs {
					runs += p.Runs
					ns += p.Ns
				}
				g.runs += float64(runs)
				g.ns += float64(ns)
				g.statOps += float64(r.Ops)
			default:
				// A USER_HZ tick is 10 ms.
				g.cpu = append(g.cpu, float64(r.Busy)*1e7/float64(r.Ops))
				g.rate = append(g.rate, float64(r.Ops)/r.Secs)
			}
		}
		f.Close()
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("| kernel | mode | pairs | variant | n | transactions/s | CPU µs/transaction | Δ CPU ns/transaction (range) | runs/transaction | ns/run (bpf_stats) | Δ CPU ns/run |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|---|")
	for _, k := range keys {
		g := groups[k]
		f := strings.Split(k, "\t")
		kernel, mode, pairs, variant := f[0]+" "+f[1], f[2], f[3], f[5]
		if mode == "fail" {
			continue
		}
		if len(g.cpu) == 0 {
			if len(g.errs) > 0 {
				fmt.Printf("| %s | %s | %s | %s | 0 | unavailable: %s |||||||\n", kernel, mode, pairs, variant, short(g.errs[0]))
			}
			continue
		}
		base := groups[strings.Join(append(f[:5:5], "none"), "\t")]
		cpu := median(g.cpu)
		row := fmt.Sprintf("| %s | %s | %s | %s | %d | %.0f | %.2f |", kernel, mode, pairs, variant, len(g.cpu), median(g.rate), cpu/1000)
		var delta float64
		if base != nil && len(base.cpu) > 0 && variant != "none" {
			delta = cpu - median(base.cpu)
			lo, hi := slices.Min(g.cpu)-median(base.cpu), slices.Max(g.cpu)-median(base.cpu)
			row += fmt.Sprintf(" %+.0f (%+.0f…%+.0f) |", delta, lo, hi)
		} else {
			row += " |"
		}
		if g.statOps > 0 && g.runs > 0 {
			perOp := g.runs / g.statOps
			row += fmt.Sprintf(" %.2f | %.0f |", perOp, g.ns/g.runs)
			if delta != 0 {
				row += fmt.Sprintf(" %+.0f |", delta/perOp)
			} else {
				row += " |"
			}
		} else {
			row += " | | |"
		}
		fmt.Println(row)
	}

	fmt.Println()
	for _, k := range keys {
		g := groups[k]
		for _, r := range g.fails {
			fmt.Printf("fail %s %s target=%s wait=%s attempts=%d secs=%.1f errnos=%v shawk=%v errobs=%v\n",
				r.Kernel, r.Arch, r.Target, r.Wait, r.Ops, r.Secs, r.Errnos, r.Shawk, r.ErrObs)
		}
	}
	return nil
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func short(s string) string {
	s = strings.ReplaceAll(s, "|", "/")
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
