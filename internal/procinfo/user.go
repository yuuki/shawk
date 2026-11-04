package procinfo

import (
	"os"
	"strconv"
	"strings"
)

// UserID returns the effective user id of a process (process.user.id), and
// false if it cannot be read, as when the process is gone.
func UserID(pid uint32) (uint32, bool) {
	if pid == 0 {
		return 0, false
	}
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status")
	if err != nil {
		return 0, false
	}
	return statusUID(string(b))
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
