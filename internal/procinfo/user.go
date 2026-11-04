package procinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// User returns the effective user id of a process (process.user.id) and
// the id of the cgroup it is in, or false if they cannot be read, as when
// the process is gone or its cgroup is not in the hierarchy.
//
// Both are of one process: /proc/PID is opened once and its files are read
// through it, which fails once the process has exited, rather than reading
// a process that took the PID in between. The cgroup tells the caller
// whether the process is still that of a flow, whose PID may have been
// taken since the flow was seen by a process with the same command name.
func (r *Resolver) User(pid uint32) (uid uint32, cgroupID uint64, ok bool) {
	if pid == 0 || r.root == "" {
		return 0, 0, false
	}
	proc, err := os.OpenRoot("/proc/" + strconv.FormatUint(uint64(pid), 10))
	if err != nil {
		return 0, 0, false
	}
	defer proc.Close()
	status, err := proc.ReadFile("status")
	if err != nil {
		return 0, 0, false
	}
	cgroup, err := proc.ReadFile("cgroup")
	if err != nil {
		return 0, 0, false
	}
	uid, ok = statusUID(string(status))
	path := parseProcCgroup(cgroup)
	if !ok || path == "" {
		return 0, 0, false
	}
	// On cgroup v2 the id of a cgroup is the inode number of its directory.
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(r.root, path), &st); err != nil {
		return 0, 0, false
	}
	return uid, st.Ino, true
}

// statusUID returns the effective user id of the content of
// /proc/PID/status, whose line Uid holds the real, effective, saved and
// file system user ids.
func statusUID(status string) (uint32, bool) {
	for line := range strings.Lines(status) {
		v, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) < 2 {
			return 0, false
		}
		uid, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(uid), true
	}
	return 0, false
}
