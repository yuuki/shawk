// Package cli implements the shawk command line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/yuuki/shawk/internal/agent"
	"github.com/yuuki/shawk/internal/otlp"
	"github.com/yuuki/shawk/internal/procinfo"
	"github.com/yuuki/shawk/internal/tracer"
	"github.com/yuuki/shawk/internal/version"
)

const usage = `shawk traces the network dependencies of the processes on a host with eBPF
and sends them to the shawk connector of an OpenTelemetry Collector, which
keeps them in PostgreSQL and Prometheus for Grafana.

Usage:
  shawk <command> [flags]

Commands:
  agent          run the agent that traces dependencies on this host
  flows          show bundled flows on this host live (no collector needed)
  version        print the version

Run 'shawk <command> -h' for the flags of a command.
`

// Main runs the command line and returns the exit status.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmds := map[string]func(context.Context, []string, io.Writer) error{
		"agent": runAgent,
		"flows": runFlows,
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
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "shawk %s: %v\n", name, err)
		return 2
	}
	fmt.Fprintf(stderr, "shawk %s: %v\n", name, err)
	return 2
}

var errUsage = errors.New("usage error")

func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	return nil
}

func runAgent(ctx context.Context, args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	var (
		endpoint = fs.String("otlp-endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
			"URL of the otlp/shawk receiver of the collector; http:// disables TLS (default http://localhost:4327 for grpc, :4328 for http/protobuf)")
		protocol = fs.String("otlp-protocol", envOr("OTEL_EXPORTER_OTLP_PROTOCOL", otlp.ProtocolGRPC),
			"OTLP protocol: grpc or http/protobuf")
		caFile   = fs.String("otlp-ca-file", "", "PEM file of the CAs that verify the collector (default: system roots)")
		certFile = fs.String("otlp-cert-file", "", "PEM client certificate for a collector that requires one (mutual TLS)")
		keyFile  = fs.String("otlp-key-file", "", "PEM key of -otlp-cert-file")
		perReq   = fs.Int("max-series-per-request", 1000, "dependencies and listeners per OTLP request; more are sent in several requests")
		interval = fs.Duration("interval", 15*time.Second, "collection and export interval")
		idleTTL  = fs.Duration("idle-ttl", 15*time.Minute, "how long a dependency is sent after its last activity")
		netns    = fs.String("netns", "all", `network namespaces to trace: "all", "self" or an inode number`)
		maxFlows = fs.Uint("max-flows", 16384, "capacity of the in-kernel flow table per interval")
		fallback = fs.String("service-name-fallback", "exe",
			`name of a service without OTEL_SERVICE_NAME: "exe" (executable name) or "unit" (systemd unit)`)
		bpfStats = fs.Bool("bpf-stats", false, "enable and send run time statistics of the BPF programs (small overhead)")
		logLevel = fs.String("log-level", "info", "log level: debug, info, warn or error")
	)
	if err := parseFlags(fs, args); err != nil {
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
	fb, err := procinfo.ParseFallback(*fallback)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if *endpoint == "" {
		*endpoint = otlp.DefaultEndpoint(*protocol)
	}
	if *perReq < 1 {
		return fmt.Errorf("%w: -max-series-per-request must be positive", errUsage)
	}
	return agent.Run(ctx, agent.Config{
		Exporter: otlp.ExporterConfig{Endpoint: *endpoint, Protocol: *protocol, CAFile: *caFile,
			CertFile: *certFile, KeyFile: *keyFile},
		MaxSeriesPerRequest: *perReq,
		Interval:            *interval,
		IdleTTL:             *idleTTL,
		NetNS:               ns,
		MaxFlows:            uint32(*maxFlows),
		ServiceFallback:     fb,
		BPFStats:            *bpfStats,
		Logger:              logger,
	})
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func runFlows(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("flows", flag.ContinueOnError)
	var (
		interval = fs.Duration("interval", 2*time.Second, "refresh interval")
		count    = fs.Int("count", 0, "number of intervals to show; 0 means forever")
		netns    = fs.String("netns", "all", `network namespaces to trace: "all", "self" or an inode number`)
		asJSON   = fs.Bool("json", false, "output JSON lines")
	)
	if err := parseFlags(fs, args); err != nil {
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
		fmt.Fprintln(os.Stderr, "warning: UDP is not traced: its programs could not be loaded (they need BPF trampolines, fentry)")
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
