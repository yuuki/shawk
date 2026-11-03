// Package procinfo resolves the identity of processes observed by the
// tracer: cgroup paths, systemd unit names, containers and executables.
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
	"sync/atomic"
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
	// maxPendingReads bounds the containers of new cgroups waiting to have
	// their state read (see Learn).
	maxPendingReads = 4096
)

// Resolver maps cgroup ids to cgroup paths and units.
type Resolver struct {
	root       string // mount point of the cgroup v2 hierarchy
	containers *Containers

	mu       sync.Mutex
	paths    map[uint64]string
	learned  map[uint64]learnedPath
	lastScan time.Time

	// The paths of new cgroups of containers whose state a worker reads.
	readerOnce sync.Once
	pending    chan string
	reads      sync.WaitGroup // queued reads, waited for in tests
	dropped    atomic.Uint64  // reads not queued because the queue was full
}

type learnedPath struct {
	path string
	at   time.Time
}

// NewResolver finds the cgroup v2 hierarchy. Without it, only learned paths
// are resolved.
func NewResolver() *Resolver {
	return &Resolver{
		root:       cgroup2Mount("/proc/self/mountinfo"),
		containers: NewContainers(),
		paths:      map[uint64]string{},
		learned:    map[uint64]learnedPath{},
	}
}

// Learn records the path of a cgroup reported when it was created, so that
// it can be resolved after the cgroup is removed. The state of the
// container of the cgroup is read soon after too, while the runtime still
// has it: a container removed within an interval keeps its name.
//
// Learn is called on the goroutine that drains the events of the kernel,
// which drops new ones while it waits, so it does not read files: a worker
// reads the state of the container (#126). When too many reads are queued,
// as when a node starts many pods at once, the new ones are not queued;
// such a container is read when its flows are exported, and loses its
// name only if it is removed before.
func (r *Resolver) Learn(id uint64, path string) {
	r.mu.Lock()
	if len(r.learned) >= maxLearned {
		r.expire(time.Now())
		if len(r.learned) >= maxLearned {
			clear(r.learned)
		}
	}
	r.learned[id] = learnedPath{path: path, at: time.Now()}
	r.mu.Unlock()
	if r.containers != nil && len(cgroupContainers(path)) > 0 {
		r.queueRead(path)
	}
}

// queueRead queues the read of the state of the containers of a cgroup
// path, unless the queue is full.
func (r *Resolver) queueRead(path string) {
	r.readerOnce.Do(func() {
		r.pending = make(chan string, maxPendingReads)
		go r.readQueued()
	})
	r.reads.Add(1)
	select {
	case r.pending <- path:
	default:
		r.dropped.Add(1)
		r.reads.Done()
	}
}

// readQueued reads the state of the containers of the queued paths.
func (r *Resolver) readQueued() {
	for p := range r.pending {
		r.unit(p)
		r.reads.Done()
	}
}

// ReadsDropped returns how many reads of the state of containers of new
// cgroups were not queued because the queue was full (cumulative).
func (r *Resolver) ReadsDropped() uint64 { return r.dropped.Load() }

// Unit returns the unit of the cgroup id (see Unit), and its container if
// it is one. The unit of a container is named after its state, which the
// runtime keeps on disk (see Container.Unit).
func (r *Resolver) Unit(id uint64) (string, *Container) {
	return r.unit(r.CgroupPath(id))
}

// unit names the innermost container of a cgroup path whose state the
// runtime has. A container in a container, e.g. with Docker in Docker,
// keeps its state in the outer one, out of reach, and is named after the
// outer container. Without any state, the outermost container names it by
// id, as Unit does.
func (r *Resolver) unit(path string) (string, *Container) {
	refs := cgroupContainers(path)
	if len(refs) == 0 || r.containers == nil {
		return Unit(path), nil
	}
	var ctr *Container
	for _, ref := range refs {
		var found bool
		if ctr, found = r.containers.Lookup(ref.runtime, ref.id); found {
			break
		}
	}
	return ctr.Unit(), ctr
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
	if r.containers != nil {
		r.containers.expire(r.lastScan)
	}
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
	sessionScope = regexp.MustCompile(`^session-[^.]+\.scope$`)
	// Names systemd-run gives transient units without --unit:
	//   run-<pid>                   systemd 228 and earlier
	//   run-u<n>, run-u<n>-s<m>     after the D-Bus connection (229-256;
	//                               -s<m> after soft reboots, 256)
	//   run-p<pid>-i<pidfd id>      systemd 257 and later
	//   run-r<random 128-bit id>    when none of the above is available
	// Units named by the user, such as run-backup.service, are kept.
	runScope    = regexp.MustCompile(`^run-([0-9]+|u[0-9]+(-s[0-9]+)?|r[0-9a-f]{32}|p[0-9]+-i[0-9]+)\.(scope|service)$`)
	userService = regexp.MustCompile(`^user@\d+\.service$`)
)

// Unit derives a stable name of the service a process belongs to from its
// cgroup path. Names that change at every run, such as login sessions and
// transient units, are normalized so that dependencies of the same service
// accumulate under one name. A container is named after its runtime and
// abbreviated id, which Resolver.Unit replaces with a stable name when the
// runtime has its state.
//
//	/system.slice/nginx.service                      -> nginx.service
//	/system.slice/docker-0123456789ab....scope       -> docker-0123456789ab
//	/kubepods/burstable/pod<uid>/0123456789ab...     -> container-0123456789ab
//	/system.slice/docker-<outer>.scope/docker/<inner> -> docker-<outer 12 hex>
//	/user.slice/user-1000.slice/session-3.scope      -> user-1000.slice/session.scope
//	/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service
//	                                                 -> user@1000.service/foo.service
//	/system.slice/run-u1234.scope                    -> run.scope
func Unit(cgroupPath string) string {
	parts := strings.FieldsFunc(cgroupPath, func(r rune) bool { return r == '/' })
	if len(parts) == 0 {
		return ""
	}
	if refs := cgroupContainers(cgroupPath); len(refs) > 0 {
		outer := refs[len(refs)-1]
		return (&Container{Runtime: runtimeOrAny(outer.runtime), ID: outer.id}).Unit()
	}
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
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

// containerRef identifies a container by the cgroup the runtime made for
// it; runtime is "" when the cgroup does not tell it.
type containerRef struct{ runtime, id string }

// cgroupContainers finds the containers of a cgroup path, innermost first:
// several when containers run in a container. It finds none when a unit of
// systemd is deeper than the innermost container, e.g. a service of
// systemd in a container, which then names the process, as in Unit; it
// stops at a unit above the containers, such as user@1000.service above
// the containers of a rootless runtime.
func cgroupContainers(cgroupPath string) []containerRef {
	parts := strings.FieldsFunc(cgroupPath, func(r rune) bool { return r == '/' })
	var refs []containerRef
	for i := len(parts) - 1; i >= 0; i-- {
		if runtime, id, ok := containerOf(parts, i); ok {
			refs = append(refs, containerRef{runtime, id})
			continue
		}
		p := parts[i]
		if runScope.MatchString(p) || sessionScope.MatchString(p) || strings.HasSuffix(p, ".service") {
			break
		}
	}
	return refs
}

func runtimeOrAny(runtime string) string {
	if runtime == "" {
		return "container"
	}
	return runtime
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
