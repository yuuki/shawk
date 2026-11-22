package procinfo

import (
	"os"
	"strconv"
	"strings"
)

// Proc is the directory of a process in /proc, opened once. Its files are
// read through it, so that they are all of that process: the reads fail once
// the process has exited, rather than read a process that took its PID in
// between.
type Proc struct {
	dir *os.Root
}

// OpenProc opens the directory of a process in /proc. It fails if the
// process is gone.
func OpenProc(pid uint32) (*Proc, error) {
	if pid == 0 {
		return nil, os.ErrNotExist
	}
	dir, err := os.OpenRoot("/proc/" + strconv.FormatUint(uint64(pid), 10))
	if err != nil {
		return nil, err
	}
	return &Proc{dir: dir}, nil
}

// Exe returns the path of the executable of the process, as Exe does, or ""
// if the process has exited or is not accessible.
func (p *Proc) Exe() string {
	s, err := p.dir.Readlink("exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(s, " (deleted)")
}

// Comm returns the command name of the process (of its main thread), or
// false if the process has exited.
func (p *Proc) Comm() (string, bool) {
	b, err := p.dir.ReadFile("comm")
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(string(b), "\n"), true
}

// Cgroup returns the path of the cgroup v2 of the process, as CgroupOf does:
// "" if it has none in the hierarchy of the agent. It returns false if the
// process has exited.
func (p *Proc) Cgroup() (string, bool) {
	b, err := p.dir.ReadFile("cgroup")
	if err != nil {
		return "", false
	}
	return parseProcCgroup(b), true
}

// Close closes the directory.
func (p *Proc) Close() error { return p.dir.Close() }
