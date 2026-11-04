package procinfo

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnit(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"", ""},
		{"/", ""},
		{"/system.slice/nginx.service", "nginx.service"},
		{"/system.slice/postgresql-16.service", "postgresql-16.service"},
		{"/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope", "docker-0123456789ab"},
		{"/machine.slice/libpod-0123456789abcdef0123.scope/container", "podman-0123456789ab"},
		{"/kubepods.slice/kubepods-pod1.slice/cri-containerd-0123456789abcdef0123.scope", "containerd-0123456789ab"},
		{"/kubepods.slice/kubepods-pod1.slice/crio-0123456789abcdef0123.scope", "crio-0123456789ab"},
		{"/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "docker-0123456789ab"},
		{"/kubepods/burstable/pod1/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "container-0123456789ab"},
		{"/user.slice/user-1000.slice/session-3.scope", "user-1000.slice/session.scope"},
		{"/user.slice/user-1000.slice/session-c12.scope", "user-1000.slice/session.scope"},
		{"/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service", "user@1000.service/foo.service"},
		{"/user.slice/user-1000.slice/user@1000.service/init.scope", "user@1000.service"},
		{"/user.slice/user-1000.slice/user@1000.service", "user@1000.service"},
		{"/system.slice/run-r0a1b2c3d4e5f60718293a4b5c6d7e8f9.scope", "run.scope"},
		{"/system.slice/run-u12.service", "run.service"},
		{"/system.slice/run-p4242-i4243.service", "run.service"},
		{"/system.slice/run-u12-s1.service", "run.service"},
		{"/system.slice/run-4242.scope", "run.scope"},
		{"/system.slice/run-backup.service", "run-backup.service"},
		{"/system.slice/run-postgresql.service", "run-postgresql.service"},
		{"/system.slice/run-r0a1b2.scope", "run-r0a1b2.scope"},
		{"/init.scope", "init.scope"},
		{"/system.slice/crond.service", "crond.service"},

		// Slurm, with the job directory named after the job id (before
		// 26.05, or CgroupJobIdPaths=yes) or its SLUID.
		{"/system.slice/slurmstepd.scope/job_42/step_batch/user/task_0", "slurm/batch"},
		{"/system.slice/slurmstepd.scope/job_42/step_0/user/task_0", "slurm/step"},
		{"/system.slice/slurmstepd.scope/job_42/step_12/user/task_3", "slurm/step"},
		{"/system.slice/slurmstepd.scope/job_42/step_1.2/user/task_0", "slurm/step"},
		{"/system.slice/slurmstepd.scope/job_42/step_extern/user/task_0", "slurm/extern"},
		{"/system.slice/slurmstepd.scope/job_42/step_extern/user/task_special", "slurm/extern"},
		{"/system.slice/slurmstepd.scope/job_42/step_interactive/user/task_0", "slurm/interactive"},
		{"/system.slice/slurmstepd.scope/job_42/step_0/slurm", "slurmstepd"},
		{"/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_batch/user/task_0", "slurm/batch"},
		{"/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_0/user/task_1", "slurm/step"},
		{"/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_extern/user/task_special", "slurm/extern"},
		{"/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_interactive/user/task_0", "slurm/interactive"},
		{"/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_extern/slurm", "slurmstepd"},
		{"/system.slice/slurmstepd.scope/s5K1KKYAYG5D00/step_0/slurm_processes", "slurmstepd"},
		{"/system.slice/node1_slurmstepd.scope/job_42/step_0/user/task_0", "slurm/step"},
		{"/system.slice/node1_slurmstepd.scope/s5K1KKYAYG5D00/step_0/slurm", "slurmstepd"},
		{"/system.slice/slurmstepd_node1.scope/job_42/step_0/user/task_0", "slurm/step"},
		{"/system.slice/node1_slurmstepd.scope/system", "slurmstepd"},
		{"/system.slice/slurmstepd-x.scope/job_42/step_0/user/task_0", "task_0"},
		{"/system.slice/slurmstepd.scope/system", "slurmstepd"},
		// Other hierarchies keep the names they had.
		{"/system.slice/slurmstepd.scope", "slurmstepd.scope"},
		{"/system.slice/slurmstepd.scope/job_42", "job_42"},
		{"/system.slice/slurmstepd.scope/job_42/step_0", "step_0"},
		{"/system.slice/slurmstepd.scope/job_42/step_0/user", "user"},
		{"/system.slice/slurmstepd.scope/job_42/step_0/user/task_0/sub", "sub"},
		{"/system.slice/slurmstepd.scope/job_42/step_x/user/task_0", "task_0"},
		{"/system.slice/slurmstepd.scope/system/step_0/user/task_0", "task_0"},
		{"/system.slice/slurmd.service", "slurmd.service"},
		{"/user.slice/user-1000.slice/user@1000.service/system.slice/slurmstepd.scope/job_42/step_0/user/task_0",
			"user@1000.service"},
		{"/slurm/uid_1000/job_42/step_0/task_0", "task_0"},
	} {
		if got := Unit(tc.path); got != tc.want {
			t.Errorf("Unit(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestSlurmJob(t *testing.T) {
	for unit, want := range map[string]bool{
		"slurm/batch": true, "slurm/step": true, "slurm/extern": true, "slurm/interactive": true,
		"slurmstepd": false, "slurmd.service": false, "task_0": false, "": false,
	} {
		if got := SlurmJob(unit); got != want {
			t.Errorf("SlurmJob(%q) = %v, want %v", unit, got, want)
		}
	}
}

func TestParseProcCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/slurmstepd.scope/job_42/step_0/user/task_0\n": "/system.slice/slurmstepd.scope/job_42/step_0/user/task_0",
		"12:memory:/user.slice\n0::/system.slice/nginx.service\n":       "/system.slice/nginx.service",
		"12:memory:/user.slice\n":                                       "",
		"0::/../../system.slice/nginx.service\n":                        "",
		"":                                                              "",
	} {
		if got := parseProcCgroup([]byte(in)); got != want {
			t.Errorf("parseProcCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCgroup2Mount(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mountinfo")
	data := "25 1 0:23 / /sys rw - sysfs sysfs rw\n" +
		"35 25 0:30 / /sys/fs/cgroup/unified rw,nosuid - cgroup2 cgroup2 rw\n"
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := cgroup2Mount(p); got != "/sys/fs/cgroup/unified" {
		t.Errorf("cgroup2Mount = %q", got)
	}
}

func TestResolverSelf(t *testing.T) {
	r := NewResolver()
	if r.root == "" {
		t.Skip("cgroup v2 is not mounted")
	}
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip(err)
	}
	// "0::/path" is the cgroup v2 entry.
	var want string
	for _, line := range splitLines(string(b)) {
		if len(line) > 3 && line[:3] == "0::" {
			want = line[3:]
		}
	}
	st, err := os.Stat(filepath.Join(r.root, want))
	if err != nil {
		t.Skip(err)
	}
	id := statIno(t, st)
	if got := r.CgroupPath(id); got != want {
		t.Errorf("CgroupPath(%d) = %q, want %q", id, got, want)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func statIno(t *testing.T, fi os.FileInfo) uint64 {
	t.Helper()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no inode")
	}
	return st.Ino
}

func TestLearn(t *testing.T) {
	r := &Resolver{paths: map[uint64]string{}, learned: map[uint64]learnedPath{}}
	r.Learn(42, "/system.slice/monthly-report.service")
	if got := r.CgroupPath(42); got != "/system.slice/monthly-report.service" {
		t.Errorf("CgroupPath(42) = %q", got)
	}
	if got := r.CgroupPath(43); got != "" {
		t.Errorf("CgroupPath(43) = %q", got)
	}
}
