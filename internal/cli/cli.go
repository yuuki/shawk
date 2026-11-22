// Package cli implements the shawk command line interface.
package cli

import (
	"cmp"
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
	"strings"
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

// Exit statuses of Main.
const (
	exitOK    = 0
	exitError = 1 // the command failed
	exitUsage = 2 // the command line is invalid
)

// command runs a command with its arguments.
type command func(ctx context.Context, args []string, stdout, stderr io.Writer) error

var commands = map[string]command{
	"agent": runAgent,
	"flows": runFlows,
	"version": func(_ context.Context, args []string, stdout, stderr io.Writer) error {
		fs := flag.NewFlagSet("version", flag.ContinueOnError)
		fs.Usage = func() { fmt.Fprintln(stderr, "Usage: shawk version") }
		if err := parseFlags(fs, args, stderr); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "shawk", version.Version)
		return nil
	},
}

// Main runs the command line and returns the exit status: 0 on success, 1
// when the command fails and 2 when the command line is invalid.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	name := args[0]
	if name == "-h" || name == "--help" || name == "help" {
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "shawk: unknown command %q\n\n%s", name, usage)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := cmd(ctx, args[1:], stdout, stderr)
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errFlags):
		// The flag package has already reported the error with the usage.
		return exitUsage
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "shawk %s: %v\n", name, err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "shawk %s: %v\n", name, err)
	return exitError
}

var (
	// errUsage is wrapped by the errors of invalid values of flags and
	// arguments.
	errUsage = errors.New("usage error")
	// errFlags is returned for flags that cannot be parsed, which the flag
	// package reports itself.
	errFlags = errors.New("invalid flags")
)

// parseFlags parses the flags of a command, which takes no arguments.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %w", errFlags, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	return nil
}

func runAgent(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	var (
		endpoint = fs.String("otlp-endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
			"URL of the otlp/shawk receiver of the collector; http:// disables TLS (default http://localhost:4327 for grpc, :4328 for http/protobuf)")
		protocol = fs.String("otlp-protocol", envOr("OTEL_EXPORTER_OTLP_PROTOCOL", otlp.ProtocolGRPC),
			"OTLP protocol: grpc or http/protobuf")
		caFile   = fs.String("otlp-ca-file", "", "PEM file of the CAs that verify the collector (default: system roots)")
		certFile = fs.String("otlp-cert-file", "", "PEM client certificate for a collector that requires one (mutual TLS)")
		keyFile  = fs.String("otlp-key-file", "", "PEM key of -otlp-cert-file")
		srvName  = fs.String("otlp-server-name", "",
			"name that the certificate of the collector must hold, sent in SNI, if not the host of -otlp-endpoint (e.g. an IP address); https:// only")
		tokenFile = fs.String("otlp-bearer-token-file", "",
			"file of a token sent with every request (Authorization: Bearer), for a collector that authenticates agents by tokens; read at start; https:// only")
		perReq   = fs.Int("max-series-per-request", 1000, "dependencies, listeners and translations per OTLP request, which also stays below 3 MiB; more are sent in several requests")
		interval = fs.Duration("interval", 15*time.Second, "collection and export interval, at most 1m")
		idleTTL  = fs.Duration("idle-ttl", 15*time.Minute, "how long a dependency is sent after its last activity")
		netns    = fs.String("netns", "all", `network namespaces to trace: "all", "self" or an inode number`)
		maxFlows = fs.Uint("max-flows", 16384, "capacity of the in-kernel flow table per interval; also sizes the tables of listening ports (8192 to 65536) and those of Unix sockets: a quarter of it for their flows, a half for their open connections (at least 1024 each)")
		fold     = fs.String("fold-external", "in",
			`fold the peers outside -internal-peers into one dependency per local endpoint: "in" (the clients of local servers), "all" (also the servers of local clients) or "none"`)
		internal = fs.String("internal-peers", "private",
			`comma-separated address ranges whose peers are kept exact; "private" stands for the ranges not routed on the Internet (RFC 1918, CGNAT, loopback, link-local, ULA)`)
		fallback = fs.String("service-name-fallback", "exe",
			`name of a service without OTEL_SERVICE_NAME: "exe" (executable name) or "unit" (systemd unit)`)
		bpfStats = fs.Bool("bpf-stats", false, "enable and send run time statistics of the BPF programs (small overhead)")
		learn    = fs.Bool("learn-translations", true,
			"learn the translations of addresses the host makes (DNAT, SNAT, IPVS) from conntrack, so that dependencies through them are matched")
		jobUsers = fs.Bool("job-users", false,
			"send the user ids of the processes of Slurm jobs (process.user.id), which PostgreSQL keeps with job_users of the connector; for administrators only")
		classify = fs.Bool("classify-protocols", false,
			"classify the wire protocol of new TCP connections (TLS version, HTTP, SSH, PostgreSQL, ...) from the first payload each side sends, kept in PostgreSQL; needs BPF trampolines, and adds a hook to every TCP send (design §3.9)")
		logLevel = fs.String("log-level", "info", "log level: debug, info, warn or error")
	)
	if err := parseFlags(fs, args, stderr); err != nil {
		return err
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("%w: -log-level: %w", errUsage, err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: lvl}))
	ns, err := agent.ParseNetNS(*netns)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	fb, err := procinfo.ParseFallback(*fallback)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	foldMode, err := tracer.ParseFoldMode(*fold)
	if err != nil {
		return fmt.Errorf("%w: -fold-external: %w", errUsage, err)
	}
	internalPeers, err := agent.ParseInternalPeers(*internal)
	if err != nil {
		return fmt.Errorf("%w: -internal-peers: %w", errUsage, err)
	}
	if *endpoint == "" {
		*endpoint = otlp.DefaultEndpoint(*protocol)
	}
	if *perReq < 1 {
		return fmt.Errorf("%w: -max-series-per-request must be positive", errUsage)
	}
	cfg := agent.Config{
		Exporter: otlp.ExporterConfig{Endpoint: *endpoint, Protocol: *protocol, CAFile: *caFile,
			CertFile: *certFile, KeyFile: *keyFile, ServerName: *srvName, BearerTokenFile: *tokenFile},
		MaxSeriesPerRequest: *perReq,
		Interval:            *interval,
		IdleTTL:             *idleTTL,
		NetNS:               ns,
		MaxFlows:            uint32(*maxFlows),
		Fold:                foldMode,
		InternalPeers:       internalPeers,
		ServiceFallback:     fb,
		BPFStats:            *bpfStats,
		LearnTranslations:   *learn,
		JobUsers:            *jobUsers,
		ClassifyProtocols:   *classify,
		Logger:              logger,
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	return agent.Run(ctx, cfg)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func runFlows(ctx context.Context, args []string, w, stderr io.Writer) error {
	fs := flag.NewFlagSet("flows", flag.ContinueOnError)
	var (
		interval = fs.Duration("interval", 2*time.Second, "refresh interval")
		count    = fs.Int("count", 0, "number of intervals to show; 0 means forever")
		netns    = fs.String("netns", "all", `network namespaces to trace: "all", "self" or an inode number`)
		asJSON   = fs.Bool("json", false, "output JSON lines")
		classify = fs.Bool("classify-protocols", false,
			"classify the wire protocol of new TCP connections from the first payload each side sends (column WIRE)")
	)
	if err := parseFlags(fs, args, stderr); err != nil {
		return err
	}
	if *interval <= 0 {
		return fmt.Errorf("%w: -interval must be positive", errUsage)
	}
	if *count < 0 {
		return fmt.Errorf("%w: -count must not be negative", errUsage)
	}
	ns, err := agent.ParseNetNS(*netns)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	tr, err := tracer.New(tracer.Options{NetNS: ns, OwnerScanInterval: *interval, ClassifyProtocols: *classify})
	if err != nil {
		return err
	}
	defer tr.Close()
	if *classify && !tr.ProtocolsEnabled() {
		fmt.Fprintln(stderr, "warning: wire protocols are not classified: their program could not be loaded (it needs BPF trampolines, fentry)")
	}
	if !tr.UDPEnabled() {
		fmt.Fprintln(stderr, "warning: UDP is not traced: its programs could not be loaded (they need BPF trampolines, fentry)")
	}
	if !tr.UnixEnabled() {
		fmt.Fprintln(stderr, "warning: Unix sockets are not traced: trampolines and fallback kprobes could not be attached")
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
		printFlows(w, snap.Flows, *classify)
	}
	return nil
}

func printFlows(w io.Writer, flows []tracer.Flow, wire bool) {
	sort.Slice(flows, func(i, j int) bool { return flowLess(&flows[i], &flows[j]) })
	fmt.Fprintf(w, "--- %s\n", time.Now().Format(time.TimeOnly))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "DIR\tPROTO\tLOCAL\tREMOTE\tPORT\tPROCESS\tPID\tCONNS\tFAILED\tHANDSHAKE\tSYN-RETRANS\tOPEN\tSENT\tRECV"
	if wire {
		header += "\tWIRE"
	}
	fmt.Fprintln(tw, header)
	for i := range flows {
		printFlow(tw, &flows[i], wire)
	}
	tw.Flush()
}

// flowLess orders the flows of the table: the incoming ones first, then by
// transport, port, name of the Unix socket and remote address.
func flowLess(a, b *tracer.Flow) bool {
	return cmp.Or(
		cmp.Compare(b.Direction, a.Direction),
		cmp.Compare(a.Proto, b.Proto),
		cmp.Compare(a.Port, b.Port),
		strings.Compare(a.Path, b.Path),
		a.RemoteAddr.Compare(b.RemoteAddr),
	) < 0
}

// printFlow writes the row of a flow, with its wire protocols if wire.
func printFlow(w io.Writer, f *tracer.Flow, wire bool) {
	local, remote := f.LocalAddr.String(), f.RemoteAddr.String()
	port := strconv.FormatUint(uint64(f.Port), 10)
	if f.Proto == tracer.ProtoUnix {
		// The name of the socket of the server, which has no address.
		local, remote, port = "-", f.Path, "-"
	}
	arrow := "-->"
	if f.Direction == tracer.DirIn {
		arrow = "<--"
	}
	conns := strconv.FormatUint(f.Conns, 10)
	if f.Proto == tracer.ProtoUDP {
		conns = fmt.Sprintf("%dmsg", f.MsgsSent+f.MsgsRecv)
	}
	// Only active opens of TCP have handshakes, and they and the
	// connects of Unix sockets failures; Unix sockets count no bytes.
	failed, handshake, synRetrans := "-", "-", "-"
	sent, recv := humanBytes(f.BytesSent), humanBytes(f.BytesRecv)
	switch {
	case f.Proto == tracer.ProtoTCP && f.Direction == tracer.DirOut:
		failed, handshake, synRetrans = failures(&f.FlowStats), meanHandshake(&f.FlowStats), strconv.FormatUint(f.SynRetrans, 10)
	case f.Proto == tracer.ProtoUnix:
		failed, sent, recv = failures(&f.FlowStats), "-", "-"
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s", arrow, f.Proto, local, remote, port, f.Comm,
		f.PID, conns, failed, handshake, synRetrans, f.OpenConns, sent, recv)
	if wire {
		// The protocols of the connections whose first payload was
		// sent in the interval.
		protocols := f.Protocols.String()
		if protocols == "" {
			protocols = "-"
		}
		fmt.Fprintf(w, "\t%s", protocols)
	}
	fmt.Fprintln(w)
}

// failures formats the failed active opens of a flow with their reasons,
// e.g. "3 (timeout:2 refused:1)".
func failures(s *tracer.FlowStats) string {
	if s.ConnFails == 0 {
		return "0"
	}
	var reasons []string
	for r := range tracer.FailReason(tracer.NumFailReasons) {
		if n := s.Fails[r]; n > 0 {
			reasons = append(reasons, fmt.Sprintf("%s:%d", r, n))
		}
	}
	if n := s.OtherFails(); n > 0 {
		reasons = append(reasons, fmt.Sprintf("other:%d", n))
	}
	return fmt.Sprintf("%d (%s)", s.ConnFails, strings.Join(reasons, " "))
}

// meanHandshake formats the mean duration of the handshakes of a flow.
func meanHandshake(s *tracer.FlowStats) string {
	n := s.HandshakeCount()
	if n == 0 {
		return "-"
	}
	return (time.Duration(s.HandshakeSumUs/n) * time.Microsecond).String()
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
