// Package procinfo resolves the identity of processes observed by the
// tracer: cgroup paths, systemd unit names and executables.
package procinfo

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// rescanInterval limits how often the cgroup hierarchy is walked when an
	// unknown cgroup id is looked up.
	rescanInterval = 5 * time.Second
	// learnedTTL is how long a learned path is kept; flows of a removed
	// cgroup are resolved at the end of their interval at the latest.
	learnedTTL = time.Hour
	maxLearned = 100000
)

// Resolver maps cgroup ids to cgroup paths.
type Resolver struct {
	root string // mount point of the cgroup v2 hierarchy

	mu       sync.Mutex
	paths    map[uint64]string
	learned  map[uint64]learnedPath
	lastScan time.Time
}

type learnedPath struct {
	path string
	at   time.Time
}

// NewResolver finds the cgroup v2 hierarchy. Without it, only learned paths
// are resolved.
func NewResolver() *Resolver {
	return &Resolver{
		root:    cgroup2Mount("/proc/self/mountinfo"),
		paths:   map[uint64]string{},
		learned: map[uint64]learnedPath{},
	}
}

// Learn records the path of a cgroup reported when it was created, so that
// it can be resolved after the cgroup is removed.
func (r *Resolver) Learn(id uint64, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.learned) >= maxLearned {
		r.expire(time.Now())
		if len(r.learned) >= maxLearned {
			clear(r.learned)
		}
	}
	r.learned[id] = learnedPath{path: path, at: time.Now()}
}

func (r *Resolver) expire(now time.Time) {
	for id, l := range r.learned {
		if now.Sub(l.at) > learnedTTL {
			delete(r.learned, id)
		}
	}
}

// CgroupPath returns the path of a cgroup relative to the hierarchy root,
// such as "/system.slice/nginx.service", or "" if it is unknown.
func (r *Resolver) CgroupPath(id uint64) string {
	if id == 0 {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.paths[id]; ok {
		return p
	}
	if l, ok := r.learned[id]; ok {
		return l.path
	}
	if r.root == "" || time.Since(r.lastScan) < rescanInterval {
		return ""
	}
	r.scan()
	return r.paths[id]
}

// scan walks the cgroup hierarchy. On cgroup v2 the id of a cgroup is the
// inode number of its directory.
func (r *Resolver) scan() {
	paths := make(map[uint64]string, len(r.paths))
	filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		rel := strings.TrimPrefix(path, r.root)
		if rel == "" {
			rel = "/"
		}
		paths[st.Ino] = rel
		return nil
	})
	r.paths = paths
	r.lastScan = time.Now()
	r.expire(r.lastScan)
}

func cgroup2Mount(mountinfo string) string {
	f, err := os.Open(mountinfo)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// 36 25 0:31 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		if fields := strings.Fields(right); len(fields) > 0 && fields[0] == "cgroup2" {
			if f := strings.Fields(left); len(f) >= 5 {
				return unescapeMount(f[4])
			}
		}
	}
	return ""
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var (
	containerScope = regexp.MustCompile(`^(docker|libpod|cri-containerd|crio)-([0-9a-f]{12})[0-9a-f]*\.scope$`)
	sessionScope   = regexp.MustCompile(`^session-[^.]+\.scope$`)
	runScope       = regexp.MustCompile(`^run-[^.]+\.(scope|service)$`)
	userService    = regexp.MustCompile(`^user@\d+\.service$`)
)

// Unit derives a stable name of the service a process belongs to from its
// cgroup path. Names that change at every run, such as login sessions and
// transient units, are normalized so that dependencies of the same service
// accumulate under one name.
//
//	/system.slice/nginx.service                      -> nginx.service
//	/system.slice/docker-0123456789ab....scope       -> docker-0123456789ab
//	/user.slice/user-1000.slice/session-3.scope      -> user-1000.slice/session.scope
//	/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service
//	                                                 -> user@1000.service/foo.service
//	/system.slice/run-r1234.scope                    -> run.scope
func Unit(cgroupPath string) string {
	parts := strings.FieldsFunc(cgroupPath, func(r rune) bool { return r == '/' })
	if len(parts) == 0 {
		return ""
	}
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if m := containerScope.FindStringSubmatch(p); m != nil {
			kind := m[1]
			if kind == "libpod" {
				kind = "podman"
			}
			return kind + "-" + m[2]
		}
		if runScope.MatchString(p) {
			return "run." + p[strings.LastIndexByte(p, '.')+1:]
		}
		if sessionScope.MatchString(p) {
			if i > 0 {
				return parts[i-1] + "/session.scope"
			}
			return "session.scope"
		}
		if strings.HasSuffix(p, ".service") {
			if !userService.MatchString(p) {
				for j := i - 1; j >= 0; j-- {
					if userService.MatchString(parts[j]) {
						return parts[j] + "/" + p
					}
				}
			}
			return p
		}
	}
	return parts[len(parts)-1]
}

// Comm returns the command name of a process (of its main thread), or "" if
// the process is gone.
func Comm(pid uint32) string {
	if pid == 0 {
		return ""
	}
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(string(b), "\n")
}

// Exe returns the path of the executable of a process, or "" if the process
// is gone or not accessible.
func Exe(pid uint32) string {
	if pid == 0 {
		return ""
	}
	p, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(p, " (deleted)")
}

// NetNS returns the inode number of the network namespace of the current
// process.
func NetNS() uint32 { return netNS("/proc/self/ns/net") }

// NetNSOf returns the inode of the network namespace of a process, or 0 if
// it cannot be read.
func NetNSOf(pid uint32) uint32 {
	return netNS("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/ns/net")
}

func netNS(path string) uint32 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return uint32(st.Ino)
}
