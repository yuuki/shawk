package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/yuuki/shawk/internal/query"
)

func runWhoUses(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("who-uses", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "30d")
	depth := fs.Int("depth", 1, "levels of clients to follow upstream")
	rest, err := parseFlags(fs, args, "1")
	if err != nil {
		return err
	}
	t, err := target(rest[0])
	if err != nil {
		return err
	}
	q, err := f.querier()
	if err != nil {
		return err
	}
	roots, err := q.WhoUses(ctx, t.Host, t.Port, t.Unit, t.Comm, *depth)
	if err != nil {
		return err
	}
	if f.json {
		return writeJSON(w, roots)
	}
	if len(roots) == 0 {
		fmt.Fprintf(w, "No clients of %s since %s.\n", rest[0], q.Since.Format(time.DateTime))
		return nil
	}
	for _, r := range roots {
		printTree(w, r, "", "", true)
	}
	return nil
}

func runDeps(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("deps", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "30d")
	depth := fs.Int("depth", 1, "levels of services to follow downstream")
	rest, err := parseFlags(fs, args, "1")
	if err != nil {
		return err
	}
	t, err := target(rest[0])
	if err != nil {
		return err
	}
	q, err := f.querier()
	if err != nil {
		return err
	}
	roots, err := q.Deps(ctx, t.Host, t.Unit, t.Comm, *depth)
	if err != nil {
		return err
	}
	if t.Port != 0 {
		// Narrow to dependencies on the given service port.
		for _, r := range roots {
			var kept []*query.Node
			for _, c := range r.Children {
				if c.Port == t.Port {
					kept = append(kept, c)
				}
			}
			r.Children = kept
		}
	}
	if f.json {
		return writeJSON(w, roots)
	}
	if len(roots) == 0 {
		fmt.Fprintf(w, "No dependencies of %s since %s.\n", rest[0], q.Since.Format(time.DateTime))
		return nil
	}
	for _, r := range roots {
		printTree(w, r, "", "", true)
	}
	return nil
}

func runCanIRemove(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("can-i-remove", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "30d")
	rest, err := parseFlags(fs, args, "1")
	if err != nil {
		return err
	}
	t, err := target(rest[0])
	if err != nil {
		return err
	}
	q, err := f.querier()
	if err != nil {
		return err
	}
	r, err := q.CanIRemove(ctx, t.Host, t.Port)
	if err != nil {
		return err
	}
	if f.json {
		if err := writeJSON(w, map[string]any{"safe": r.Safe(), "result": r, "since": q.Since}); err != nil {
			return err
		}
	} else {
		if r.Coverage.After(q.Since) {
			fmt.Fprintf(w, "warning: the ledger of %s starts at %s; dependencies before it are unknown.\n",
				r.Host, r.Coverage.Format(time.DateTime))
		}
		if r.Safe() {
			fmt.Fprintf(w, "OK: no remote process used %s since %s.\n", rest[0], q.Since.Format(time.DateTime))
			return nil
		}
		fmt.Fprintf(w, "NO: %s is still used by remote processes since %s:\n", rest[0], q.Since.Format(time.DateTime))
		for _, svc := range r.Clients {
			printTree(w, svc, "", "", true)
		}
	}
	if !r.Safe() {
		return ErrFound
	}
	return nil
}

func runUnused(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("unused", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "30d")
	rest, err := parseFlags(fs, args, "0..1")
	if err != nil {
		return err
	}
	t, err := target(rest[0])
	if err != nil {
		return err
	}
	q, err := f.querier()
	if err != nil {
		return err
	}
	ls, err := q.Unused(ctx, t.Host)
	if err != nil {
		return err
	}
	if f.json {
		return writeJSON(w, ls)
	}
	if len(ls) == 0 {
		fmt.Fprintf(w, "Every service on %s was used since %s.\n", t.Host, q.Since.Format(time.DateTime))
		return nil
	}
	fmt.Fprintf(w, "Services on %s that nobody used since %s:\n", t.Host, q.Since.Format(time.DateTime))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROTO\tADDRESS\tPORT\tPROCESS\tLISTENING SINCE")
	for _, l := range ls {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", l.Proto, l.Addr, l.Port, l.Process(), l.FirstSeen.Format(time.DateTime))
	}
	return tw.Flush()
}

func runDiff(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "24h")
	baseline := fs.String("baseline", "7d", "how far back the baseline window starts")
	rest, err := parseFlags(fs, args, "0..1")
	if err != nil {
		return err
	}
	t, err := target(rest[0])
	if err != nil {
		return err
	}
	q, err := f.querier()
	if err != nil {
		return err
	}
	bd, err := ParseDuration(*baseline)
	if err != nil {
		return fmt.Errorf("%w: -baseline: %v", errUsage, err)
	}
	changes, err := q.Diff(ctx, t.Host, q.Until.Add(-bd))
	if err != nil {
		return err
	}
	if f.json {
		return writeJSON(w, changes)
	}
	if len(changes) == 0 {
		fmt.Fprintf(w, "No changes in the dependencies of %s since %s.\n", t.Host, q.Since.Format(time.DateTime))
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range changes {
		e := c.Edge
		sign, when := "+", "first seen "+e.FirstSeen.Format(time.DateTime)
		if !c.Added {
			sign, when = "-", "last seen "+e.LastSeen.Format(time.DateTime)
		}
		peer := fmt.Sprintf("-> %s:%d/%s", e.RemoteAddr, e.Port, e.Proto)
		if e.Direction == "in" {
			peer = fmt.Sprintf("<- %s (port %d/%s)", e.RemoteAddr, e.Port, e.Proto)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", sign, e.Process(), peer, when)
	}
	return tw.Flush()
}

func runGraph(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "7d")
	depth := fs.Int("depth", 2, "hops to follow from the TARGETs")
	format := fs.String("format", "mermaid", "output format: mermaid, dot or json")
	rest, err := parseFlags(fs, args, "1..")
	if err != nil {
		return err
	}
	var hosts []string
	for _, s := range rest {
		t, err := target(s)
		if err != nil {
			return err
		}
		hosts = append(hosts, t.Host)
	}
	q, err := f.querier()
	if err != nil {
		return err
	}
	g, err := q.Graph(ctx, hosts, *depth)
	if err != nil {
		return err
	}
	if f.json {
		*format = "json"
	}
	switch *format {
	case "mermaid":
		return g.WriteMermaid(w)
	case "dot":
		return g.WriteDOT(w)
	case "json":
		return writeJSON(w, g)
	}
	return fmt.Errorf("%w: unknown format %q", errUsage, *format)
}

func runStatus(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var f queryFlags
	f.register(fs, "30d")
	rest, err := parseFlags(fs, args, "0..1")
	if err != nil {
		return err
	}
	t, err := target(rest[0])
	if err != nil {
		return err
	}
	c, err := f.client()
	if err != nil {
		return err
	}
	info, err := c.Info(ctx, t.Host)
	if err != nil {
		return err
	}
	progs, _ := c.Programs(ctx, t.Host)
	if f.json {
		return writeJSON(w, map[string]any{"info": info, "programs": progs})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "host\t%s\n", info.Hostname)
	fmt.Fprintf(tw, "version\t%s\n", info.Version)
	fmt.Fprintf(tw, "kernel\t%s\n", info.Kernel)
	fmt.Fprintf(tw, "addresses\t%s\n", strings.Join(info.Addrs, ", "))
	fmt.Fprintf(tw, "started\t%s\n", info.StartedAt.Format(time.DateTime))
	fmt.Fprintf(tw, "ledger since\t%s\n", info.LedgerSince.Format(time.DateTime))
	fmt.Fprintf(tw, "interval\t%s\n", info.Interval)
	fmt.Fprintf(tw, "udp traced\t%v\n", info.UDP)
	fmt.Fprintf(tw, "dropped flow updates\t%d\n", info.Drops)
	for _, p := range progs {
		if runs, _ := p["run_count"].(float64); runs > 0 {
			fmt.Fprintf(tw, "bpf %v\t%.0f runs, %.0f ns/run\n", p["name"], runs, p["avg_ns"])
		}
	}
	return tw.Flush()
}

// printTree renders a dependency tree.
func printTree(w io.Writer, n *query.Node, prefix, branch string, root bool) {
	fmt.Fprintf(w, "%s%s%s\n", prefix, branch, nodeLine(n, root))
	childPrefix := prefix
	if !root {
		if branch == "└── " {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
	}
	for i, c := range n.Children {
		b := "├── "
		if i == len(n.Children)-1 {
			b = "└── "
		}
		printTree(w, c, childPrefix, b, false)
	}
}

func nodeLine(n *query.Node, root bool) string {
	var b strings.Builder
	b.WriteString(n.Host)
	if n.Port != 0 {
		fmt.Fprintf(&b, ":%d/%s", n.Port, n.Proto)
	}
	if n.Agent && n.Addr != "" && n.Addr != n.Host {
		fmt.Fprintf(&b, " (%s)", n.Addr)
	}
	b.WriteString("  ")
	b.WriteString(n.Process())
	if n.Cycle {
		b.WriteString("  (cycle)")
	}
	if !n.LastSeen.IsZero() {
		b.WriteString("  ")
		b.WriteString(statsSummary(n))
	}
	return b.String()
}

func statsSummary(n *query.Node) string {
	s := n.Stats
	var parts []string
	if s.Conns > 0 {
		parts = append(parts, fmt.Sprintf("conns=%s", humanCount(s.Conns)))
	}
	if s.MaxOpenConns > 0 {
		parts = append(parts, fmt.Sprintf("open=%s", humanCount(s.MaxOpenConns)))
	}
	if s.ConnFails > 0 {
		parts = append(parts, fmt.Sprintf("fails=%s", humanCount(s.ConnFails)))
	}
	if s.MsgsSent+s.MsgsRecv > 0 {
		parts = append(parts, fmt.Sprintf("msgs=%s", humanCount(s.MsgsSent+s.MsgsRecv)))
	}
	if s.BytesSent+s.BytesRecv > 0 {
		parts = append(parts, fmt.Sprintf("bytes=%s/%s", humanBytes(s.BytesSent), humanBytes(s.BytesRecv)))
	}
	parts = append(parts, "last="+ago(n.LastSeen))
	return strings.Join(parts, " ")
}

func humanCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.Format(time.DateOnly)
}
