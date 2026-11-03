package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/shawk/internal/otlp"
	"github.com/yuuki/shawk/internal/procinfo"
)

func TestIdentities(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	exes := map[uint32]string{100: "/usr/bin/ruby", 200: "/usr/sbin/nginx"}
	envs := map[uint32]map[string]string{100: {"OTEL_SERVICE_NAME": "billing"}}
	reads := 0
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute)
	r.exe = func(pid uint32) string { reads++; return exes[pid] }
	r.comm = func(uint32) string { return "" }
	stuck := map[uint32]bool{}
	r.env = func(pid uint32) (map[string]string, bool) { return envs[pid], !stuck[pid] }

	r.beginInterval()
	got := r.resolve(100, "ruby", "billing.service", nil, now)
	want := otlp.Process{Unit: "billing.service", Comm: "ruby", Exe: "/usr/bin/ruby", Service: "billing"}
	if got != want {
		t.Errorf("resolve = %+v, want %+v", got, want)
	}
	r.resolve(100, "ruby", "billing.service", nil, now)
	if reads != 1 {
		t.Errorf("/proc read %d times in an interval", reads)
	}
	if got := r.resolve(200, "nginx", "nginx.service", nil, now); got.Service != "nginx" || got.Exe != "/usr/sbin/nginx" {
		t.Errorf("resolve nginx = %+v", got)
	}

	// The process exited: the latest identity of the unit and comm is used.
	delete(exes, 100)
	r.beginInterval()
	if got := r.resolve(100, "ruby", "billing.service", nil, now.Add(time.Minute)); got != want {
		t.Errorf("resolve after exit = %+v, want %+v", got, want)
	}
	// Unknown processes are named after comm, then the unit.
	if got := r.resolve(0, "kworker", "", nil, now); got != (otlp.Process{Comm: "kworker", Service: "kworker"}) {
		t.Errorf("resolve without a process = %+v", got)
	}
	if got := r.resolve(0, "", "nfs-server.service", nil, now); got.Service != "nfs-server.service" {
		t.Errorf("resolve without comm = %+v", got)
	}
	if got := r.resolve(0, "", "", nil, now); got.Service != procinfo.UnknownService {
		t.Errorf("resolve without anything = %+v", got)
	}

	// The environment of a stuck process cannot be read in time: its latest
	// identity is used rather than a name without OTEL_SERVICE_NAME.
	exes[100] = "/usr/bin/ruby"
	stuck[100] = true
	r.beginInterval()
	if got := r.resolve(100, "ruby", "billing.service", nil, now.Add(2*time.Minute)); got != want {
		t.Errorf("resolve of a stuck process = %+v, want %+v", got, want)
	}

	r.expire(now.Add(16 * time.Minute))
	if _, ok := r.latest[unitComm{"billing.service", "ruby"}]; !ok {
		t.Error("an identity used recently expired")
	}
	r.expire(now.Add(30 * time.Minute))
	if len(r.latest) != 0 {
		t.Errorf("identities not expired: %v", r.latest)
	}
}

// Reads of /proc run several at once within a budget, so that stuck
// processes do not hold up the export; those not read in time keep their
// latest identity.
func TestPrefetchBudget(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute)
	r.budget = 300 * time.Millisecond
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	r.exe = func(pid uint32) string { return "/usr/bin/app" }
	r.comm = func(uint32) string { return "" }
	r.env = func(pid uint32) (map[string]string, bool) {
		if pid >= 1000 {
			<-block // a process stuck for longer than the budget
		}
		return map[string]string{"OTEL_SERVICE_NAME": "svc"}, true
	}
	// An earlier interval left an identity for one of the stuck ones.
	r.beginInterval()
	r.byPID[1000] = procRead{exe: "/usr/bin/app", env: map[string]string{"OTEL_SERVICE_NAME": "known"}, complete: true}
	r.resolve(1000, "app", "known.service", nil, now)

	r.beginInterval()
	pids := []uint32{1, 2, 3}
	for pid := uint32(1000); pid < 1100; pid++ {
		pids = append(pids, pid)
	}
	start := time.Now()
	r.prefetch(pids)
	if d := time.Since(start); d > time.Second {
		t.Errorf("prefetch took %s with a budget of %s", d, r.budget)
	}
	if got := r.resolve(2, "app", "", nil, now); got.Service != "svc" {
		t.Errorf("a process read in time = %+v", got)
	}
	if got := r.resolve(1000, "app", "known.service", nil, now); got.Service != "known" {
		t.Errorf("a stuck process with an earlier identity = %+v", got)
	}
	// One without an earlier identity is named without its environment, and
	// /proc is not read again in the interval.
	if got := r.resolve(1050, "worker", "", nil, now); got.Service != "worker" {
		t.Errorf("a stuck process without an earlier identity = %+v", got)
	}
}

// A PID reused by another process since the flow was seen is not trusted:
// the command name of /proc must match that of the flow.
func TestReusedPID(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute)
	r.exe = func(uint32) string { return "/usr/bin/python3" }
	r.comm = func(uint32) string { return "python3" }
	r.env = func(uint32) (map[string]string, bool) { return map[string]string{"OTEL_SERVICE_NAME": "billing"}, true }
	r.beginInterval()
	if got := r.resolve(100, "python3", "billing.service", nil, now); got.Service != "billing" {
		t.Errorf("resolve = %+v", got)
	}
	// The flow of a curl that exited; its PID now runs python3.
	if got := r.resolve(100, "curl", "billing.service", nil, now); got.Service != "curl" || got.Exe != "" {
		t.Errorf("resolve of a reused PID = %+v", got)
	}
}

// The latest identity of a unit shared by containers, such as replicas or a
// container and the one that replaced it, keeps the container of the flow
// (#104).
func TestLatestIdentityOfContainers(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute)
	exes := map[uint32]string{100: "/usr/bin/node"}
	r.exe = func(pid uint32) string { return exes[pid] }
	r.comm = func(uint32) string { return "" }
	r.env = func(uint32) (map[string]string, bool) { return nil, true }
	a := &procinfo.Container{Runtime: procinfo.RuntimeDocker, ID: "aaaa", Name: "web"}
	b := &procinfo.Container{Runtime: procinfo.RuntimeDocker, ID: "bbbb", Name: "web"}
	r.beginInterval()
	if got := r.resolve(100, "node", "docker/web", a, now); got.ContainerID != "aaaa" || got.Exe != "/usr/bin/node" {
		t.Errorf("resolve of a = %+v", got)
	}
	// A short-lived process of b exited before /proc was read.
	got := r.resolve(200, "node", "docker/web", b, now)
	if got.ContainerID != "bbbb" || got.Exe != "/usr/bin/node" || got.Service != "node" {
		t.Errorf("resolve of b from the latest identity = %+v", got)
	}
	if got := r.resolve(300, "node", "docker/web", nil, now); got.ContainerID != "" {
		t.Errorf("resolve without a container = %+v", got)
	}
}

// The reads of environments that hang are logged at most every
// stuckLogEvery, with the reads skipped since the last line.
func TestLogStuckReads(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	a := newTestAgent(&fakeSource{}, &fakeExporter{}, 0, now)
	var buf bytes.Buffer
	a.log = slog.New(slog.NewTextHandler(&buf, nil))
	var stuck procinfo.EnvironReads
	a.idents.stuck = func() procinfo.EnvironReads { return stuck }
	lines := func() []string { return strings.Split(strings.TrimSpace(buf.String()), "\n") }

	a.logStuckReads(now)
	if buf.Len() != 0 {
		t.Errorf("logged without reads that hang: %s", buf.String())
	}
	stuck = procinfo.EnvironReads{Stuck: 3}
	a.logStuckReads(now)
	if l := lines(); len(l) != 1 || !strings.Contains(l[0], "stuck=3 slots=32 skipped=0") {
		t.Errorf("first line: %q", l)
	}
	stuck = procinfo.EnvironReads{Stuck: procinfo.MaxEnvironReads, Skipped: 100}
	a.logStuckReads(now.Add(time.Minute))
	if l := lines(); len(l) != 1 {
		t.Errorf("logged again within %s: %q", stuckLogEvery, l)
	}
	a.logStuckReads(now.Add(stuckLogEvery))
	if l := lines(); len(l) != 2 || !strings.Contains(l[1], "stuck=32 slots=32 skipped=100") {
		t.Errorf("second line: %q", l)
	}
	stuck.Skipped = 150
	a.logStuckReads(now.Add(2 * stuckLogEvery))
	if l := lines(); len(l) != 3 || !strings.Contains(l[2], "skipped=50") {
		t.Errorf("third line: %q", l)
	}
}
