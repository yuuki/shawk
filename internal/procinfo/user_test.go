package procinfo

import (
	"os"
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

func TestUserID(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc")
	}
	uid, ok := UserID(uint32(os.Getpid()))
	if !ok || uid != uint32(os.Geteuid()) {
		t.Errorf("UserID(self) = %d, %v; want %d", uid, ok, os.Geteuid())
	}
	if _, ok := UserID(0); ok {
		t.Error("UserID(0) is known")
	}
}
