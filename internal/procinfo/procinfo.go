// Package procinfo resolves the identity of processes observed by the
// tracer: cgroup paths, systemd unit names, containers and executables.
package procinfo

import (
	"io/fs"
	"os"
	"path/filepath"
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
	if refs, under := cgroupContainers(path); r.containers != nil && len(refs) > 0 && under == "" {
		r.queueRead(path)
	}
}

// LearnOf records path as the path of the cgroup id if the directory of
// path in the hierarchy is that cgroup, such as the cgroup a process of a
// flow is in when the path of the cgroup of the flow is not known. It
// reports whether it did.
func (r *Resolver) LearnOf(id uint64, path string) bool {
	if id == 0 || r.root == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "/..") {
		return false
	}
	var st syscall.Stat_t
	if syscall.Stat(r.root+path, &st) != nil || st.Ino != id {
		return false
	}
	r.Learn(id, path)
	return true
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

// unit names the outermost container of a cgroup path after the state its
// runtime keeps. A container in a container, e.g. with Docker in Docker or
// kind, keeps its state in the outer one, out of reach, and is named after
// the outer container; so is a cgroup that a container allowed to write its
// cgroups made in its own with the name of another container of the host.
// A container in the cgroup of a unit (see cgroupContainers) is named by
// id, after the unit. Without any state, the outermost container names it
// by id, as Unit does.
func (r *Resolver) unit(path string) (string, *Container) {
	refs, under := cgroupContainers(path)
	if len(refs) == 0 || r.containers == nil {
		return Unit(path), nil
	}
	outer := refs[len(refs)-1]
	if under != "" {
		ctr := &Container{Runtime: runtimeOrAny(outer.runtime), ID: outer.id, Under: under}
		return ctr.Unit(), ctr
	}
	ctr, _ := r.containers.Lookup(outer.runtime, outer.id)
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
	//nolint:errcheck // the function skips what cannot be read and returns no error, so neither does WalkDir
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

// CgroupOf returns the path of the cgroup v2 of a process, relative to the
// root of the hierarchy as CgroupPath, or "" if it cannot be read or is
// outside the cgroup namespace of the agent ("/../...").
func CgroupOf(pid uint32) string {
	if pid == 0 {
		return ""
	}
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup")
	if err != nil {
		return ""
	}
	return parseProcCgroup(b)
}

// parseProcCgroup returns the path of the line of cgroup v2 ("0::<path>")
// of /proc/PID/cgroup.
func parseProcCgroup(b []byte) string {
	for line := range strings.SplitSeq(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			if strings.HasPrefix(p, "/..") {
				return ""
			}
			return p
		}
	}
	return ""
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
