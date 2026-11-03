package cli

import (
	"bytes"
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
	// The query commands were removed with the ledger.
	if code := Main([]string{"who-uses", "db-01"}, &out, &errOut); code != 2 {
		t.Errorf("exit code of who-uses = %d", code)
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
		{"flows", "extra"},
	} {
		if code := Main(args, &out, &errOut); code != 2 {
			t.Errorf("exit code of %v = %d", args, code)
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
