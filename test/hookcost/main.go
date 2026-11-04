// Command hookcost measures what the hooks compared in
// docs/research/kernel-hooks/kernel_hooks.md (#165) cost on the running
// kernel.
//
//	hookcost [flags]           attach variants, run a workload, print JSON
//	hookcost report FILE...    summarize the JSON lines
//	hookcost netbench [flags]  the workload, which the first form runs
//
// A variant is a set of BPF programs of hookcost.bpf.c attached to their
// hooks, "none", or "shawk", the tracer of shawk itself. The workload runs
// in a process of its own, so that the tracer does not take it for its own
// traffic. The CPU time of the host is read from /proc/stat around it, so
// that the cost of a hook shows as CPU time per transaction, whichever task
// or softirq pays it. With -stats, the kernel also counts the runs of each
// program.
//
// It needs CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN (cgroup_skb), CAP_SYS_ADMIN
// (-stats, and the namespaces the tracer of shawk walks), CAP_SYS_PTRACE
// and CAP_DAC_READ_SEARCH, or root: a binary with these file capabilities
// runs as an ordinary user. run.sh runs the measurements of the note.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/yuuki/shawk/internal/tracer"
)

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v3" -target bpfel hookcost bpf/hookcost.bpf.c -- -I../../internal/tracer/bpf/include

// hook attaches the first of progs that loads.
type hook struct {
	kind     string // kprobe, kretprobe, kmulti, tracing, egress, ingress
	progs    []string
	target   string // the function of a kprobe
	optional bool   // skipped where the kernel cannot attach it
}

func kp(prog, fn string) hook       { return hook{kind: "kprobe", progs: []string{prog}, target: fn} }
func krp(prog, fn string) hook      { return hook{kind: "kretprobe", progs: []string{prog}, target: fn} }
func kmp(prog, fn string) hook      { return hook{kind: "kmulti", progs: []string{prog}, target: fn} }
func tr(progs ...string) hook       { return hook{kind: "tracing", progs: progs} }
func cgroup(kind, prog string) hook { return hook{kind: kind, progs: []string{prog}} }

func optional(h hook) hook {
	h.optional = true
	return h
}

// The variants of the note: hooks on TCP messages (option c), on accept
// (option b), on UDP datagrams (item 2), and where the errors of failed
// active opens can be seen (errobs).
var variants = map[string][]hook{
	"none":     nil,
	"tp-empty": {tr("tp_empty")},

	"tcpmsg-kprobe-empty": {kp("k_empty", "tcp_sendmsg"), kp("k_empty", "tcp_cleanup_rbuf")},
	"tcpmsg-kprobe":       {kp("k_tcp_sendmsg", "tcp_sendmsg"), kp("k_tcp_cleanup_rbuf", "tcp_cleanup_rbuf")},
	"tcpmsg-kmulti":       {kmp("km_tcp_sendmsg", "tcp_sendmsg"), kmp("km_tcp_cleanup_rbuf", "tcp_cleanup_rbuf")},
	"tcpmsg-fentry-empty": {tr("f_empty_tcp_sendmsg"), tr("f_empty_tcp_cleanup_rbuf")},
	"tcpmsg-fentry":       {tr("f_tcp_sendmsg"), tr("f_tcp_cleanup_rbuf")},

	"accept-kretprobe-empty": {krp("kr_empty", "inet_csk_accept")},
	"accept-kretprobe":       {krp("kr_inet_csk_accept", "inet_csk_accept")},
	"accept-fexit":           {tr("fx_inet_csk_accept", "fx_inet_csk_accept_arg")},

	"udp-kprobe-empty": {kp("k_empty", "ip_send_skb"), kp("k_empty", "skb_consume_udp")},
	"udp-kprobe": {kp("k_ip_send_skb", "ip_send_skb"), kp("k_ip6_send_skb", "ip6_send_skb"),
		kp("k_skb_consume_udp", "skb_consume_udp")},
	"udp-fentry-empty": {tr("f_empty_ip_send_skb"), tr("f_empty_skb_consume_udp")},
	"udp-fentry":       {tr("f_ip_send_skb"), tr("f_ip6_send_skb"), tr("f_skb_consume_udp")},
	"cgskb-empty":      {cgroup("egress", "cg_empty_egress"), cgroup("ingress", "cg_empty_ingress")},
	"cgskb":            {cgroup("egress", "cg_udp_egress"), cgroup("ingress", "cg_udp_ingress")},

	// The kprobe on tcp_done_with_error() where the kernel has it.
	"errobs": {kp("k_sk_error_report", "sk_error_report"), optional(kp("k_tcp_done_with_error", "tcp_done_with_error")),
		tr("tp_inet_sk_error_report"), tr("tp_tcp_receive_reset"), kp("k_ip_icmp_error", "ip_icmp_error"),
		kp("k_ipv6_icmp_error", "ipv6_icmp_error"), tr("tp_fail_state")},
}

type progStat struct {
	Name string `json:"name"`
	Runs uint64 `json:"runs"`
	Ns   uint64 `json:"ns"`
}

type result struct {
	Kernel   string            `json:"kernel"`
	Arch     string            `json:"arch"`
	CPUs     int               `json:"cpus"`
	Variant  string            `json:"variant"`
	Mode     string            `json:"mode"`
	Pairs    int               `json:"pairs"`
	Size     int               `json:"size"`
	Target   string            `json:"target,omitempty"`
	Wait     string            `json:"wait,omitempty"`
	Stats    bool              `json:"stats"`
	Error    string            `json:"error,omitempty"`
	Ops      uint64            `json:"ops"`
	Secs     float64           `json:"secs"`
	Busy     uint64            `json:"busy_ticks"`
	Total    uint64            `json:"total_ticks"`
	Progs    []progStat        `json:"progs,omitempty"`
	Errnos   map[string]uint64 `json:"errnos,omitempty"`
	Shawk    map[string]uint64 `json:"shawk_fails,omitempty"`
	ErrObs   map[string]uint64 `json:"errobs,omitempty"`
	Attached []string          `json:"attached,omitempty"`
}

func main() {
	cmd, args := "", os.Args[1:]
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "netbench":
		exit(runNetbench(args[1:]))
	case "report":
		exit(runReport(args[1:]))
	default:
		exit(measure(args))
	}
}

func exit(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "hookcost:", err)
		os.Exit(1)
	}
}

func measure(args []string) error {
	fs := flag.NewFlagSet("hookcost", flag.ExitOnError)
	variant := fs.String("variant", "none", "variants to attach, separated by commas")
	stats := fs.Bool("stats", false, "count the runs of the programs (adds a cost of its own)")
	var w workload
	w.flags(fs)
	fs.Parse(args)

	var uts unix.Utsname
	unix.Uname(&uts)
	r := result{
		Kernel:  unix.ByteSliceToString(uts.Release[:]),
		Arch:    unix.ByteSliceToString(uts.Machine[:]),
		CPUs:    cpus(),
		Variant: *variant,
		Mode:    w.mode,
		Pairs:   w.pairs,
		Size:    w.size,
		Stats:   *stats,
	}
	if w.mode == "fail" {
		r.Target, r.Wait = w.target, w.wait
	}
	err := run(&r, strings.Split(*variant, ","), *stats, &w)
	if err != nil {
		r.Error = err.Error()
	}
	return json.NewEncoder(os.Stdout).Encode(&r)
}

func run(r *result, names []string, stats bool, w *workload) error {
	if stats {
		c, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		if err != nil {
			return fmt.Errorf("enabling statistics: %w", err)
		}
		defer c.Close()
	}
	var (
		progs  = map[string]*ebpf.Program{}
		links  []link.Link
		shawk  *tracer.Tracer
		mcoll  *ebpf.Collection
		loaded = map[string]*ebpf.Program{}
	)
	defer func() {
		for _, l := range links {
			l.Close()
		}
		for _, p := range loaded {
			p.Close()
		}
		if mcoll != nil {
			mcoll.Close()
		}
		if shawk != nil {
			shawk.Close()
		}
	}()

	spec, err := loadHookcost()
	if err != nil {
		return err
	}
	// The maps are created once and shared by the programs, which are
	// loaded one by one so that one the kernel refuses names itself.
	maps := spec.Copy()
	maps.Programs = map[string]*ebpf.ProgramSpec{}
	if mcoll, err = ebpf.NewCollection(maps); err != nil {
		return fmt.Errorf("creating maps: %w", err)
	}
	load := func(name string) (*ebpf.Program, error) {
		if p, ok := loaded[name]; ok {
			return p, nil
		}
		s := spec.Copy()
		ps, ok := s.Programs[name]
		if !ok {
			return nil, fmt.Errorf("no program %s", name)
		}
		s.Programs = map[string]*ebpf.ProgramSpec{name: ps}
		c, err := ebpf.NewCollectionWithOptions(s, ebpf.CollectionOptions{MapReplacements: mcoll.Maps})
		if err != nil {
			return nil, err
		}
		p := c.DetachProgram(name)
		c.Close()
		loaded[name] = p
		return p, nil
	}

	for _, name := range names {
		if name == "shawk" {
			if shawk, err = tracer.New(tracer.Options{}); err != nil {
				return fmt.Errorf("shawk: %w", err)
			}
			if !shawk.UDPEnabled() {
				r.Attached = append(r.Attached, "shawk (UDP not traced)")
			} else {
				r.Attached = append(r.Attached, "shawk")
			}
			if stats {
				if err := shawk.EnableStats(); err != nil {
					return err
				}
			}
			continue
		}
		hooks, ok := variants[name]
		if !ok {
			return fmt.Errorf("unknown variant %s", name)
		}
		for _, h := range hooks {
			l, pname, err := attach(h, load)
			if err != nil && h.optional {
				r.Attached = append(r.Attached, fmt.Sprintf("not %s: %v", h.target, err))
				continue
			}
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			links = append(links, l)
			progs[pname] = loaded[pname]
			r.Attached = append(r.Attached, pname+"@"+h.kind+":"+h.target)
		}
	}

	before, err := progStats(progs, shawk)
	if err != nil {
		return err
	}
	busy0, total0, err := cpuTicks()
	if err != nil {
		return err
	}
	out, err := w.exec()
	busy1, total1, _ := cpuTicks()
	if err != nil {
		return err
	}
	r.Busy, r.Total = busy1-busy0, total1-total0
	r.Ops, r.Secs, r.Errnos = out.Ops, out.Secs, out.Errnos
	after, err := progStats(progs, shawk)
	if err != nil {
		return err
	}
	for name, a := range after {
		b := before[name]
		r.Progs = append(r.Progs, progStat{Name: name, Runs: a.Runs - b.Runs, Ns: a.Ns - b.Ns})
	}

	if shawk != nil && strings.HasPrefix(w.mode, "fail") {
		if r.Shawk, err = shawkFails(shawk, w.target); err != nil {
			return err
		}
	}
	if v := mcoll.Variables["fails"]; v != nil && loaded["tp_fail_state"] != nil {
		r.ErrObs = map[string]uint64{}
		for _, n := range []string{"fails", "fails_err_close", "fails_err_kprobe", "fails_err_tp", "fails_err_early"} {
			var x uint64
			if err := mcoll.Variables[n].Get(&x); err != nil {
				return err
			}
			r.ErrObs[n] = x
		}
	}
	return nil
}

// attach loads the first program of h that the kernel accepts and attaches
// it. It returns the name of the program.
func attach(h hook, load func(string) (*ebpf.Program, error)) (link.Link, string, error) {
	var errs []error
	for _, name := range h.progs {
		p, err := load(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("loading %s: %w", name, err))
			continue
		}
		var l link.Link
		switch h.kind {
		case "kprobe":
			l, err = link.Kprobe(h.target, p, nil)
		case "kretprobe":
			l, err = link.Kretprobe(h.target, p, nil)
		case "kmulti":
			l, err = link.KprobeMulti(p, link.KprobeMultiOptions{Symbols: []string{h.target}})
		case "tracing":
			l, err = link.AttachTracing(link.TracingOptions{Program: p})
		case "egress", "ingress":
			typ := ebpf.AttachCGroupInetEgress
			if h.kind == "ingress" {
				typ = ebpf.AttachCGroupInetIngress
			}
			l, err = link.AttachCgroup(link.CgroupOptions{Path: "/sys/fs/cgroup", Attach: typ, Program: p})
		default:
			err = fmt.Errorf("unknown kind %s", h.kind)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("attaching %s: %w", name, err))
			continue
		}
		return l, name, nil
	}
	return nil, "", errors.Join(errs...)
}

func progStats(progs map[string]*ebpf.Program, shawk *tracer.Tracer) (map[string]progStat, error) {
	out := map[string]progStat{}
	for name, p := range progs {
		s, err := p.Stats()
		if err != nil {
			return nil, err
		}
		out[name] = progStat{Name: name, Runs: s.RunCount, Ns: uint64(s.Runtime)}
	}
	if shawk != nil {
		st, err := shawk.ProgramStats()
		if err != nil {
			return nil, err
		}
		for _, s := range st {
			out[s.Name] = progStat{Name: s.Name, Runs: s.RunCount, Ns: uint64(s.Runtime)}
		}
	}
	return out, nil
}

// shawkFails returns the failed active opens to the target that the tracer
// of shawk counted, by reason.
func shawkFails(t *tracer.Tracer, target string) (map[string]uint64, error) {
	snap, err := t.Collect()
	if err != nil {
		return nil, err
	}
	host := target
	if i := strings.LastIndex(target, ":"); i >= 0 {
		host = target[:i]
	}
	out := map[string]uint64{"drops": snap.Drops, "contended": snap.Contended}
	for _, f := range snap.Flows {
		if f.Proto != tracer.ProtoTCP || f.Direction != tracer.DirOut || f.RemoteAddr.Unmap().String() != host {
			continue
		}
		out["conn_fails"] += f.ConnFails
		for i, n := range f.Fails {
			out[tracer.FailReason(i).String()] += n
		}
		out["other"] += f.OtherFails()
	}
	return out, nil
}

// cpuTicks returns the busy and total CPU time of the host from /proc/stat,
// in USER_HZ ticks.
func cpuTicks() (busy, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	fields := strings.Fields(sc.Text())
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("unexpected /proc/stat: %q", sc.Text())
	}
	for i, s := range fields[1:9] {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, err
		}
		total += v
		// idle and iowait
		if i != 3 && i != 4 {
			busy += v
		}
	}
	return busy, total, nil
}

func cpus() int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return 0
	}
	return set.Count()
}

// exec runs the workload in a process of its own.
func (w *workload) exec() (*benchOut, error) {
	cmd := exec.Command("/proc/self/exe", append([]string{"netbench"}, w.args()...)...)
	cmd.Stderr = os.Stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netbench: %w", err)
	}
	var out benchOut
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("netbench: %w: %q", err, b)
	}
	if out.Ops == 0 {
		return nil, fmt.Errorf("netbench made no transaction")
	}
	return &out, nil
}
