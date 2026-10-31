// Package cli implements the shawk command line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/yuuki/shawk/internal/agent"
	"github.com/yuuki/shawk/internal/api"
	"github.com/yuuki/shawk/internal/client"
	"github.com/yuuki/shawk/internal/ledger"
	"github.com/yuuki/shawk/internal/query"
	"github.com/yuuki/shawk/internal/tracer"
	"github.com/yuuki/shawk/internal/version"

	"log/slog"
)

const usage = `shawk discovers network dependencies among processes with eBPF and keeps
them in a ledger on every host, so that you can ask who depends on what.

Usage:
  shawk <command> [flags] [arguments]

Agent:
  agent          run the agent that records dependencies on this host
  flows          show bundled flows on this host live (no agent needed)

Queries (ask the agents; TARGET is HOST[:PORT][/UNIT|/@COMM]):
  who-uses       show the processes that use services on TARGET (upstream)
  deps           show the services that processes on TARGET use (downstream)
  can-i-remove   check whether remote processes still use TARGET
  unused         show services on TARGET that nobody used
  diff           show dependencies of TARGET that appeared or disappeared
  graph          export the dependency graph around TARGETs (dot, mermaid, json)
  status         show the status of the agent on TARGET

Other:
  version        print the version

Run 'shawk <command> -h' for the flags of a command.
`

// Exit statuses of can-i-remove besides 0 (safe to remove). Errors exit
// with status 2.
var (
	// ErrFound means remote processes used the target (status 1).
	ErrFound = errors.New("dependencies found")
	// ErrUnknown means none were seen but the record is incomplete (status 3).
	ErrUnknown = errors.New("dependencies unknown")
)

// Main runs the command line and returns the exit status.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmds := map[string]func(context.Context, []string, io.Writer) error{
		"agent":        runAgent,
		"flows":        runFlows,
		"who-uses":     runWhoUses,
		"deps":         runDeps,
		"can-i-remove": runCanIRemove,
		"unused":       runUnused,
		"diff":         runDiff,
		"graph":        runGraph,
		"status":       runStatus,
		"version": func(context.Context, []string, io.Writer) error {
			fmt.Fprintln(stdout, "shawk", version.Version)
			return nil
		},
	}
	name := args[0]
	if name == "-h" || name == "--help" || name == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmd, ok := cmds[name]
	if !ok {
		fmt.Fprintf(stderr, "shawk: unknown command %q\n\n%s", name, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := cmd(ctx, args[1:], stdout)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, ErrFound):
		return 1
	case errors.Is(err, ErrUnknown):
		return 3
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "shawk %s: %v\n", name, err)
		return 2
	}
	fmt.Fprintf(stderr, "shawk %s: %v\n", name, err)
	return 2
}

var errUsage = errors.New("usage error")

// queryFlags are the flags common to the query commands.
type queryFlags struct {
	port      int
	tokenFile string
	timeout   time.Duration
	json      bool
	since     string
}

func (f *queryFlags) register(fs *flag.FlagSet, since string) {
	fs.IntVar(&f.port, "port", api.DefaultPort, "TCP port of the agent API")
	fs.StringVar(&f.tokenFile, "token-file", os.Getenv("SHAWK_TOKEN_FILE"), "file containing the bearer token of the agent API")
	fs.DurationVar(&f.timeout, "timeout", 5*time.Second, "timeout of each request to an agent")
	fs.BoolVar(&f.json, "json", false, "output JSON")
	fs.StringVar(&f.since, "since", since, "time window to look back, e.g. 30d, 12h")
}

func (f *queryFlags) client() (*client.Client, error) {
	token, err := readToken(f.tokenFile)
	if err != nil {
		return nil, err
	}
	return client.New(f.port, token, f.timeout), nil
}

func (f *queryFlags) querier() (*query.Querier, error) {
	c, err := f.client()
	if err != nil {
		return nil, err
	}
	d, err := ParseDuration(f.since)
	if err != nil {
		return nil, fmt.Errorf("%w: -since: %v", errUsage, err)
	}
	now := time.Now()
	return query.New(c, now.Add(-d), now), nil
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func parseFlags(fs *flag.FlagSet, args []string, nargs string) ([]string, error) {
	fs.SetOutput(os.Stderr)
	// Allow flags after positional arguments, e.g. "who-uses db-01 -depth 2".
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
	switch nargs {
	case "1":
		if len(rest) != 1 {
			return nil, fmt.Errorf("%w: expected one TARGET", errUsage)
		}
	case "0..1":
		if len(rest) > 1 {
			return nil, fmt.Errorf("%w: expected at most one TARGET", errUsage)
		}
		if len(rest) == 0 {
			rest = []string{"localhost"}
		}
	case "1..":
		if len(rest) == 0 {
			return nil, fmt.Errorf("%w: expected TARGETs", errUsage)
		}
	}
	return rest, nil
}

func target(s string) (query.Target, error) {
	t, err := query.ParseTarget(s)
	if err != nil {
		return t, fmt.Errorf("%w: %v", errUsage, err)
	}
	return t, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ParseDuration parses a positive duration that may use the units d (days)
// and w (weeks) in addition to those of time.ParseDuration.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	unit := s[len(s)-1]
	if unit != 'd' && unit != 'w' {
		d, err := time.ParseDuration(s)
		if err == nil && d <= 0 {
			err = fmt.Errorf("duration %q is not positive", s)
		}
		return d, err
	}
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if unit == 'w' {
		n *= 7
	}
	// Up to 100 years; time.Duration overflows at about 292.
	if err != nil || !(n > 0) || n > 100*365 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return time.Duration(n * float64(24*time.Hour)), nil
}

func runAgent(ctx context.Context, args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	var (
		listen    = fs.String("listen", fmt.Sprintf(":%d", api.DefaultPort), "address of the API server")
		db        = fs.String("db", "/var/lib/shawk/ledger.db", "path of the ledger database")
		interval  = fs.Duration("interval", 15*time.Second, "collection interval")
		netns     = fs.String("netns", "all", `network namespaces to trace: "all", "self" or an inode number`)
		maxFlows  = fs.Uint("max-flows", 16384, "capacity of the in-kernel flow table per interval")
		retMinute = fs.String("retention-minute", "2d", "retention of per-minute activity")
		retHour   = fs.String("retention-hour", "90d", "retention of per-hour activity")
		retDay    = fs.String("retention-day", "1095d", "retention of per-day activity and of dependencies")
		tokenFile = fs.String("token-file", os.Getenv("SHAWK_TOKEN_FILE"), "file containing a bearer token required by the API")
		bpfStats  = fs.Bool("bpf-stats", false, "enable run time statistics of the BPF programs (small overhead)")
		logLevel  = fs.String("log-level", "info", "log level: debug, info, warn or error")
	)
	if _, err := parseFlags(fs, args, "0"); err != nil {
		return err
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("%w: -log-level: %v", errUsage, err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	ns, err := agent.ParseNetNS(*netns)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	var ret ledger.Retention
	for _, r := range []struct {
		s   string
		dst *time.Duration
	}{{*retMinute, &ret.Minute}, {*retHour, &ret.Hour}, {*retDay, &ret.Day}} {
		if *r.dst, err = ParseDuration(r.s); err != nil {
			return fmt.Errorf("%w: retention: %v", errUsage, err)
		}
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(*db), 0o755); err != nil {
		return err
	}
	return agent.Run(ctx, agent.Config{
		Listen: *listen, DBPath: *db, Interval: *interval, NetNS: ns, MaxFlows: uint32(*maxFlows),
		Retention: ret, Token: token, BPFStats: *bpfStats, Logger: logger,
	})
}

func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}

func runFlows(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("flows", flag.ContinueOnError)
	var (
		interval = fs.Duration("interval", 2*time.Second, "refresh interval")
		count    = fs.Int("count", 0, "number of intervals to show; 0 means forever")
		netns    = fs.String("netns", "all", `network namespaces to trace: "all", "self" or an inode number`)
		asJSON   = fs.Bool("json", false, "output JSON lines")
	)
	if _, err := parseFlags(fs, args, "0"); err != nil {
		return err
	}
	ns, err := agent.ParseNetNS(*netns)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	tr, err := tracer.New(tracer.Options{NetNS: ns, OwnerScanInterval: *interval})
	if err != nil {
		return err
	}
	defer tr.Close()
	if !tr.UDPEnabled() {
		fmt.Fprintln(os.Stderr, "warning: UDP is not traced: this kernel does not support BPF trampolines (fentry)")
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for i := 0; *count == 0 || i < *count; i++ {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		snap, err := tr.Collect()
		if err != nil {
			return err
		}
		if *asJSON {
			if err := json.NewEncoder(w).Encode(map[string]any{"time": time.Now(), "flows": snap.Flows, "drops": snap.Drops}); err != nil {
				return err
			}
			continue
		}
		printFlows(w, snap.Flows)
	}
	return nil
}

func printFlows(w io.Writer, flows []tracer.Flow) {
	sort.Slice(flows, func(i, j int) bool {
		a, b := flows[i], flows[j]
		if a.Direction != b.Direction {
			return a.Direction > b.Direction
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.RemoteAddr.Less(b.RemoteAddr)
	})
	fmt.Fprintf(w, "--- %s\n", time.Now().Format(time.TimeOnly))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DIR\tPROTO\tLOCAL\tREMOTE\tPORT\tPROCESS\tPID\tCONNS\tOPEN\tSENT\tRECV")
	for _, f := range flows {
		local, remote := f.LocalAddr.String(), f.RemoteAddr.String()
		arrow := "-->"
		if f.Direction == tracer.DirIn {
			arrow = "<--"
		}
		conns := strconv.FormatUint(f.Conns, 10)
		if f.Proto == tracer.ProtoUDP {
			conns = fmt.Sprintf("%dmsg", f.MsgsSent+f.MsgsRecv)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\t%s\n", arrow, f.Proto, local, remote, f.Port, f.Comm,
			f.PID, conns, f.OpenConns, humanBytes(f.BytesSent), humanBytes(f.BytesRecv))
	}
	tw.Flush()
}
