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
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute, nil)
	r.exe = func(pid uint32) string { reads++; return exes[pid] }
	r.comm = func(uint32) string { return "" }
	stuck := map[uint32]bool{}
	r.env = func(pid uint32) (map[string]string, bool) { return envs[pid], !stuck[pid] }

	r.beginInterval()
	got := r.resolve(100, "ruby", 0, "billing.service", nil, now)
	want := otlp.Process{Unit: "billing.service", Comm: "ruby", Exe: "/usr/bin/ruby", Service: "billing"}
	if got != want {
		t.Errorf("resolve = %+v, want %+v", got, want)
	}
	r.resolve(100, "ruby", 0, "billing.service", nil, now)
	if reads != 1 {
		t.Errorf("/proc read %d times in an interval", reads)
	}
	if got := r.resolve(200, "nginx", 0, "nginx.service", nil, now); got.Service != "nginx" || got.Exe != "/usr/sbin/nginx" {
		t.Errorf("resolve nginx = %+v", got)
	}

	// The process exited: the latest identity of the unit and comm is used.
	delete(exes, 100)
	r.beginInterval()
	if got := r.resolve(100, "ruby", 0, "billing.service", nil, now.Add(time.Minute)); got != want {
		t.Errorf("resolve after exit = %+v, want %+v", got, want)
	}
	// Unknown processes are named after comm, then the unit.
	if got := r.resolve(0, "kworker", 0, "", nil, now); got != (otlp.Process{Comm: "kworker", Service: "kworker"}) {
		t.Errorf("resolve without a process = %+v", got)
	}
	if got := r.resolve(0, "", 0, "nfs-server.service", nil, now); got.Service != "nfs-server.service" {
		t.Errorf("resolve without comm = %+v", got)
	}
	if got := r.resolve(0, "", 0, "", nil, now); got.Service != procinfo.UnknownService {
		t.Errorf("resolve without anything = %+v", got)
	}

	// The environment of a stuck process cannot be read in time: its latest
	// identity is used rather than a name without OTEL_SERVICE_NAME.
	exes[100] = "/usr/bin/ruby"
	stuck[100] = true
	r.beginInterval()
	if got := r.resolve(100, "ruby", 0, "billing.service", nil, now.Add(2*time.Minute)); got != want {
		t.Errorf("resolve of a stuck process = %+v, want %+v", got, want)
	}

	r.expire(now.Add(16 * time.Minute))
	if _, ok := r.latest[identityKey{unit: "billing.service", comm: "ruby"}]; !ok {
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
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute, nil)
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
	r.resolve(1000, "app", 0, "known.service", nil, now)

	r.beginInterval()
	reqs := []procRequest{{1, true}, {2, true}, {3, true}}
	for pid := uint32(1000); pid < 1100; pid++ {
		reqs = append(reqs, procRequest{pid, true})
	}
	start := time.Now()
	r.prefetch(reqs)
	if d := time.Since(start); d > time.Second {
		t.Errorf("prefetch took %s with a budget of %s", d, r.budget)
	}
	if got := r.resolve(2, "app", 0, "", nil, now); got.Service != "svc" {
		t.Errorf("a process read in time = %+v", got)
	}
	if got := r.resolve(1000, "app", 0, "known.service", nil, now); got.Service != "known" {
		t.Errorf("a stuck process with an earlier identity = %+v", got)
	}
	// One without an earlier identity is named without its environment, and
	// /proc is not read again in the interval.
	if got := r.resolve(1050, "worker", 0, "", nil, now); got.Service != "worker" {
		t.Errorf("a stuck process without an earlier identity = %+v", got)
	}
}

// A PID reused by another process since the flow was seen is not trusted:
// the command name of /proc must match that of the flow.
func TestReusedPID(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute, nil)
	r.exe = func(uint32) string { return "/usr/bin/python3" }
	r.comm = func(uint32) string { return "python3" }
	r.env = func(uint32) (map[string]string, bool) { return map[string]string{"OTEL_SERVICE_NAME": "billing"}, true }
	r.beginInterval()
	if got := r.resolve(100, "python3", 0, "billing.service", nil, now); got.Service != "billing" {
		t.Errorf("resolve = %+v", got)
	}
	// The flow of a curl that exited; its PID now runs python3.
	if got := r.resolve(100, "curl", 0, "billing.service", nil, now); got.Service != "curl" || got.Exe != "" {
		t.Errorf("resolve of a reused PID = %+v", got)
	}
}

// The latest identity of a unit shared by containers, such as replicas or a
// container and the one that replaced it, keeps the container of the flow
// (#104).
func TestLatestIdentityOfContainers(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute, nil)
	exes := map[uint32]string{100: "/usr/bin/node"}
	r.exe = func(pid uint32) string { return exes[pid] }
	r.comm = func(uint32) string { return "" }
	r.env = func(uint32) (map[string]string, bool) { return nil, true }
	a := &procinfo.Container{Runtime: procinfo.RuntimeDocker, ID: "aaaa", Name: "web"}
	b := &procinfo.Container{Runtime: procinfo.RuntimeDocker, ID: "bbbb", Name: "web"}
	r.beginInterval()
	if got := r.resolve(100, "node", 0, "docker/web", a, now); got.ContainerID != "aaaa" || got.Exe != "/usr/bin/node" {
		t.Errorf("resolve of a = %+v", got)
	}
	// A short-lived process of b exited before /proc was read.
	got := r.resolve(200, "node", 0, "docker/web", b, now)
	if got.ContainerID != "bbbb" || got.Exe != "/usr/bin/node" || got.Service != "node" {
		t.Errorf("resolve of b from the latest identity = %+v", got)
	}
	if got := r.resolve(300, "node", 0, "docker/web", nil, now); got.ContainerID != "" {
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

// The processes of Slurm jobs are not named by their environment, which
// their users set, and are not given the identity of a process of another
// job: their unit is shared by every job, so the latest identities are
// kept per cgroup (#173).
func TestIdentitiesOfSlurmJobs(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute, nil)
	exes := map[uint32]string{100: "/home/alice/bin/a.out", 200: "/home/bob/bin/a.out", 300: "/usr/sbin/slurmstepd"}
	r.exe = func(pid uint32) string { return exes[pid] }
	r.comm = func(uint32) string { return "" }
	envReads := map[uint32]int{}
	r.env = func(pid uint32) (map[string]string, bool) {
		envReads[pid]++
		return map[string]string{"OTEL_SERVICE_NAME": "slurmctld"}, true
	}
	const step1, step2, stepd = 11, 22, 33

	r.beginInterval()
	r.prefetch([]procRequest{{100, false}, {200, false}, {300, true}})
	alice := r.resolve(100, "a.out", step1, "slurm/step", nil, now)
	want := otlp.Process{Unit: "slurm/step", Comm: "a.out", Exe: "/home/alice/bin/a.out", Service: "a.out"}
	if alice != want {
		t.Errorf("resolve of a job = %+v, want %+v", alice, want)
	}
	if got := r.resolve(200, "a.out", step2, "slurm/step", nil, now); got.Exe != "/home/bob/bin/a.out" || got.Service != "a.out" {
		t.Errorf("resolve of another job = %+v", got)
	}
	if envReads[100] != 0 || envReads[200] != 0 {
		t.Errorf("environments of jobs read: %v", envReads)
	}
	// slurmstepd is not a process of the job, and keeps its environment.
	if got := r.resolve(300, "slurmstepd", stepd, procinfo.SlurmStepd, nil, now); got.Service != "slurmctld" {
		t.Errorf("resolve of slurmstepd = %+v", got)
	}

	// Both processes exited: each step keeps its own latest identity, and
	// a new step has none.
	clear(exes)
	r.beginInterval()
	if got := r.resolve(100, "a.out", step1, "slurm/step", nil, now.Add(time.Minute)); got != alice {
		t.Errorf("resolve after exit = %+v, want %+v", got, alice)
	}
	if got := r.resolve(200, "a.out", step2, "slurm/step", nil, now.Add(time.Minute)); got.Exe != "/home/bob/bin/a.out" {
		t.Errorf("resolve of the other job after exit = %+v", got)
	}
	if got := r.resolve(400, "a.out", 44, "slurm/step", nil, now.Add(time.Minute)); got.Exe != "" || got.Service != "a.out" {
		t.Errorf("resolve in a new step = %+v", got)
	}
	// Other units are still keyed by unit and comm only.
	exes[500] = "/usr/sbin/nginx"
	r.resolve(500, "nginx", 55, "nginx.service", nil, now)
	delete(exes, 500)
	r.beginInterval()
	if got := r.resolve(501, "nginx", 66, "nginx.service", nil, now); got.Exe != "/usr/sbin/nginx" {
		t.Errorf("resolve in another cgroup of a unit = %+v", got)
	}
}

// A PID asked for with and without its environment, e.g. a process that
// pam_slurm_adopt moved into a job with sockets opened before, is read
// with it.
func TestPrefetchEnvironment(t *testing.T) {
	r := newIdentities(procinfo.FallbackExe, 15*time.Minute, nil)
	r.exe = func(uint32) string { return "/usr/sbin/sshd" }
	r.comm = func(uint32) string { return "sshd" }
	reads := 0
	r.env = func(uint32) (map[string]string, bool) {
		reads++
		return map[string]string{"OTEL_SERVICE_NAME": "ssh"}, true
	}
	r.beginInterval()
	r.prefetch([]procRequest{{100, false}, {100, true}, {200, false}})
	if reads != 1 || r.byPID[100].noEnv || !r.byPID[200].noEnv {
		t.Errorf("prefetch read %d environments: %+v", reads, r.byPID)
	}
	// A process read without its environment is read again with it.
	if got := r.read(200, true); got.noEnv || got.env["OTEL_SERVICE_NAME"] != "ssh" || reads != 2 {
		t.Errorf("read with the environment = %+v after %d reads", got, reads)
	}
}

// With users, a process of a Slurm job carries the user id read in the
// interval in the cgroup of the flow; one that could not be read is
// unknown, never that of the latest identity, and so is the user of a
// process that took the PID of the flow in another cgroup, even with the
// same comm. Other processes carry no user.
func TestIdentitiesUsers(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	const step, other = 11, 12
	exes := map[uint32]string{100: "/home/alice/a.out", 200: "/usr/sbin/slurmstepd"}
	uids := map[uint32]uint32{100: 1001, 200: 0}
	cgroups := map[uint32]uint64{100: step, 200: 22}
	comms := map[uint32]string{100: "a.out", 200: "slurmstepd"}
	uidReads := map[uint32]int{}
	users := func(pid uint32) (uint32, uint64, bool) {
		uidReads[pid]++
		u, ok := uids[pid]
		return u, cgroups[pid], ok && exes[pid] != ""
	}
	newResolver := func(users func(uint32) (uint32, uint64, bool)) *identities {
		r := newIdentities(procinfo.FallbackExe, 15*time.Minute, users)
		r.exe = func(pid uint32) string { return exes[pid] }
		r.comm = func(pid uint32) string { return comms[pid] }
		r.env = func(uint32) (map[string]string, bool) { return nil, true }
		return r
	}

	r := newResolver(users)
	r.beginInterval()
	r.prefetch([]procRequest{{100, false}, {200, true}})
	got := r.resolve(100, "a.out", step, "slurm/batch", nil, now)
	if !got.HasUserID || got.UserID != 1001 {
		t.Errorf("job process = %+v, want user 1001", got)
	}
	// slurmstepd is not a process of the job.
	if got := r.resolve(200, "slurmstepd", 22, procinfo.SlurmStepd, nil, now); got.HasUserID {
		t.Errorf("slurmstepd = %+v, want no user", got)
	}
	if uidReads[100] != 1 {
		t.Errorf("user ids read %v, want once per process", uidReads)
	}
	// A process asked for with its environment too, as one that
	// pam_slurm_adopt moved into a job, carries its user on the flows of
	// the job, not on those it opened before.
	exes[300], uids[300], cgroups[300], comms[300] = "/usr/bin/bash", 1001, 33, "bash"
	r.prefetch([]procRequest{{300, true}, {300, false}})
	if got := r.resolve(300, "bash", 33, "slurm/extern", nil, now); !got.HasUserID || got.UserID != 1001 {
		t.Errorf("adopted process = %+v, want user 1001", got)
	}

	// The process exited and another one of another job, with the same
	// comm, took its PID: its user is not that of the flow.
	uids[100], cgroups[100], exes[100] = 1002, other, "/home/bob/a.out"
	r.beginInterval()
	if got := r.resolve(100, "a.out", step, "slurm/batch", nil, now.Add(time.Minute)); got.HasUserID {
		t.Errorf("PID taken in another cgroup = %+v, want no user", got)
	}
	// The process exited: the identity is the latest of the step, without
	// its user.
	delete(exes, 100)
	r.beginInterval()
	got = r.resolve(100, "a.out", step, "slurm/batch", nil, now.Add(2*time.Minute))
	if got.HasUserID || got.Exe != "/home/alice/a.out" {
		t.Errorf("exited job process = %+v, want the latest identity without a user", got)
	}
	// The user id cannot be read.
	exes[100], cgroups[100] = "/home/alice/a.out", step
	delete(uids, 100)
	r.beginInterval()
	if got := r.resolve(100, "a.out", step, "slurm/batch", nil, now.Add(3*time.Minute)); got.HasUserID || got.Exe == "" {
		t.Errorf("job process without a readable user = %+v", got)
	}
	// The PID belongs to a process with another comm.
	uids[100] = 1001
	comms[100] = "other"
	r.beginInterval()
	if got := r.resolve(100, "a.out", step, "slurm/batch", nil, now.Add(4*time.Minute)); got.HasUserID {
		t.Errorf("reused PID = %+v, want no user", got)
	}

	// Without users, no user id is read.
	comms[100] = "a.out"
	clear(uidReads)
	r = newResolver(nil)
	r.beginInterval()
	r.prefetch([]procRequest{{100, false}})
	if got := r.resolve(100, "a.out", step, "slurm/batch", nil, now); got.HasUserID || len(uidReads) != 0 {
		t.Errorf("job process without users = %+v, user ids read %v", got, uidReads)
	}
}
