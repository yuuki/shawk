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
		{"/user.slice/user-1000.slice/session-3.scope", "user-1000.slice/session.scope"},
		{"/user.slice/user-1000.slice/session-c12.scope", "user-1000.slice/session.scope"},
		{"/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service", "user@1000.service/foo.service"},
		{"/user.slice/user-1000.slice/user@1000.service/init.scope", "user@1000.service"},
		{"/user.slice/user-1000.slice/user@1000.service", "user@1000.service"},
		{"/system.slice/run-r0a1b2c3d4.scope", "run.scope"},
		{"/system.slice/run-u12.service", "run.service"},
		{"/init.scope", "init.scope"},
		{"/system.slice/crond.service", "crond.service"},
	} {
		if got := Unit(tc.path); got != tc.want {
			t.Errorf("Unit(%q) = %q, want %q", tc.path, got, tc.want)
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
