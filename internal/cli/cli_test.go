package cli

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuuki/shawk/internal/tracer"
)

func TestHumanBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0B", 1023: "1023B", 1024: "1.0KiB", 1536: "1.5KiB", 5 << 30: "5.0GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Main(nil, &out, &errOut); code != 2 {
		t.Errorf("exit code without arguments = %d", code)
	}
	if code := Main([]string{"nope"}, &out, &errOut); code != 2 {
		t.Errorf("exit code of an unknown command = %d", code)
	}
	if code := Main([]string{"version", "extra"}, &out, &errOut); code != 2 {
		t.Errorf("exit code of version with an argument = %d", code)
	}
	if code := Main([]string{"version"}, &out, &errOut); code != 0 {
		t.Errorf("exit code of version = %d", code)
	}
	if code := Main([]string{"help"}, &out, &errOut); code != 0 {
		t.Errorf("exit code of help = %d", code)
	}
}

func TestAgentFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{
		{"agent", "-service-name-fallback", "comm"},
		{"agent", "-netns", "nope"},
		{"agent", "-log-level", "loud"},
		{"agent", "extra"},
		{"agent", "-no-such-flag"},
		{"agent", "-interval", "2m"},
		{"agent", "-idle-ttl", "1m"},
		{"agent", "-otlp-endpoint", "localhost:4327"},
		{"agent", "-otlp-protocol", "carrier-pigeon"},
		{"agent", "-otlp-cert-file", "client.crt", "-otlp-key-file", "client.key"}, // without https://
		{"agent", "-otlp-endpoint", "http://localhost:4327", "-otlp-server-name", "collector.example"},
		// A token is never sent in the clear, not even to loopback.
		{"agent", "-otlp-endpoint", "http://localhost:4327", "-otlp-bearer-token-file", "token"},
		{"flows", "extra"},
		{"flows", "-interval", "0"},
		{"flows", "-count", "-1"},
	} {
		if code := Main(args, &out, &errOut); code != 2 {
			t.Errorf("exit code of %v = %d", args, code)
		}
	}
	// A valid command line whose command fails is not a usage error: the CA
	// file is read when the agent starts.
	if code := Main([]string{"agent", "-otlp-endpoint", "https://localhost:4327", "-otlp-ca-file", "/nonexistent/ca.pem"},
		&out, &errOut); code != 1 {
		t.Errorf("exit code of an agent whose CA file is missing = %d", code)
	}
	// So is the token, which the agent refuses empty.
	empty := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"/nonexistent/token", empty} {
		if code := Main([]string{"agent", "-otlp-endpoint", "https://localhost:4327", "-otlp-bearer-token-file", file},
			&out, &errOut); code != 1 {
			t.Errorf("exit code of an agent with the token file %s = %d", file, code)
		}
	}
}

func TestFlowColumns(t *testing.T) {
	var s tracer.FlowStats
	if got := failures(&s); got != "0" {
		t.Errorf("failures without any = %q", got)
	}
	if got := meanHandshake(&s); got != "-" {
		t.Errorf("mean handshake without any = %q", got)
	}
	s.ConnFails = 4
	s.Fails[tracer.FailTimeout] = 2
	s.Fails[tracer.FailRefused] = 1
	if got, want := failures(&s), "4 (refused:1 timeout:2 other:1)"; got != want {
		t.Errorf("failures = %q, want %q", got, want)
	}
	s.Handshakes[0], s.Handshakes[9] = 1, 1
	s.HandshakeSumUs = 1_000_200
	if got, want := meanHandshake(&s), "500.1ms"; got != want {
		t.Errorf("mean handshake = %q, want %q", got, want)
	}
}

func TestPrintUnixFlows(t *testing.T) {
	var out bytes.Buffer
	printFlows(&out, []tracer.Flow{{
		FlowKey: tracer.FlowKey{Direction: tracer.DirOut, Proto: tracer.ProtoUnix, Path: "/run/docker.sock",
			Comm: "docker"},
		FlowStats: tracer.FlowStats{Conns: 2, ConnFails: 1, OpenConns: 1, PID: 42,
			Fails: [tracer.NumFailReasons]uint64{tracer.FailRefused: 1}},
	}}, false)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("output = %q", out.String())
	}
	got := strings.Fields(lines[2])
	want := []string{"-->", "unix", "-", "/run/docker.sock", "-", "docker", "42", "2", "1", "(refused:1)", "-", "-", "1", "-", "-"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("row = %q, want %q", got, want)
	}
}

func TestPrintWireProtocols(t *testing.T) {
	var out bytes.Buffer
	flows := []tracer.Flow{
		{FlowKey: tracer.FlowKey{Direction: tracer.DirOut, Proto: tracer.ProtoTCP, LocalAddr: netip.MustParseAddr("10.0.0.1"),
			RemoteAddr: netip.MustParseAddr("10.0.0.2"), Port: 5432, Comm: "psql"},
			FlowStats: tracer.FlowStats{Conns: 2, PID: 7, Protocols: 1<<tracer.WirePostgres | 1<<tracer.WireTLS13}},
		{FlowKey: tracer.FlowKey{Direction: tracer.DirIn, Proto: tracer.ProtoTCP, LocalAddr: netip.MustParseAddr("10.0.0.1"),
			RemoteAddr: netip.MustParseAddr("10.0.0.3"), Port: 22, Comm: "sshd"},
			FlowStats: tracer.FlowStats{Conns: 1, PID: 8}},
	}
	printFlows(&out, flows, true)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !strings.HasSuffix(strings.TrimSpace(lines[1]), "WIRE") {
		t.Fatalf("output = %q", out.String())
	}
	for _, want := range []string{"tls_1_3,postgres", "-"} {
		found := false
		for _, l := range lines[2:] {
			f := strings.Fields(l)
			found = found || f[len(f)-1] == want
		}
		if !found {
			t.Errorf("no row ends with %q in %q", want, out.String())
		}
	}
}
