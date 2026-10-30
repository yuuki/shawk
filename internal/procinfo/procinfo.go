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

// rescanInterval limits how often the cgroup hierarchy is walked when an
// unknown cgroup id is looked up.
const rescanInterval = 5 * time.Second

// Resolver maps cgroup ids to cgroup paths.
type Resolver struct {
	root string // mount point of the cgroup v2 hierarchy

	mu       sync.Mutex
	paths    map[uint64]string
	lastScan time.Time
}

// NewResolver finds the cgroup v2 hierarchy. Cgroup paths are not resolved
// when it is not mounted.
func NewResolver() *Resolver {
	return &Resolver{root: cgroup2Mount("/proc/self/mountinfo"), paths: map[uint64]string{}}
}

// CgroupPath returns the path of a cgroup relative to the hierarchy root,
// such as "/system.slice/nginx.service", or "" if it is unknown.
func (r *Resolver) CgroupPath(id uint64) string {
	if r.root == "" || id == 0 {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.paths[id]; ok {
		return p
	}
	if time.Since(r.lastScan) < rescanInterval {
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
func NetNS() uint32 {
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		return 0
	}
	return uint32(st.Ino)
}
