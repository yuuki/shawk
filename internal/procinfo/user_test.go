package procinfo

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStatusUID(t *testing.T) {
	for _, tc := range []struct {
		status string
		uid    uint32
		ok     bool
	}{
		{"Name:\tsrun\nUmask:\t0022\nUid:\t1000\t1001\t1000\t1000\nGid:\t100\t100\t100\t100\n", 1001, true},
		{"Uid:\t0\t0\t0\t0\n", 0, true},
		{"Uid:\t4294967294\t4294967294\t4294967294\t4294967294", 4294967294, true},
		{"Name:\tsrun\n", 0, false},
		{"Uid:\t1000\n", 0, false},
		{"Uid:\t1000\t-1\t1000\t1000\n", 0, false},
		{"Uid:\t1000\t4294967296\t1000\t1000\n", 0, false},
		{"", 0, false},
	} {
		uid, ok := statusUID(tc.status)
		if uid != tc.uid || ok != tc.ok {
			t.Errorf("statusUID(%q) = %d, %v; want %d, %v", tc.status, uid, ok, tc.uid, tc.ok)
		}
	}
}

// User reads the user id and the cgroup of a process, which is that of the
// test: its id is the inode of its directory in the hierarchy.
func TestUser(t *testing.T) {
	r := NewResolver()
	b, err := os.ReadFile("/proc/self/cgroup")
	path := parseProcCgroup(b)
	if err != nil || path == "" || r.root == "" {
		t.Skip("no cgroup v2")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(r.root, path), &st); err != nil {
		t.Skip(err)
	}
	uid, cg, ok := r.User(uint32(os.Getpid()))
	if !ok || uid != uint32(os.Geteuid()) || cg != st.Ino {
		t.Errorf("User(self) = %d, %d, %v; want %d, %d", uid, cg, ok, os.Geteuid(), st.Ino)
	}
	if _, _, ok := r.User(0); ok {
		t.Error("User(0) is known")
	}
	if _, _, ok := (&Resolver{}).User(uint32(os.Getpid())); ok {
		t.Error("User without a cgroup v2 hierarchy is known")
	}
}
