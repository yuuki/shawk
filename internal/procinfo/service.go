package procinfo

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Fallback selects the name of a process that does not name its service in
// its environment.
type Fallback int

const (
	// FallbackExe names the service after the executable, as OBI does.
	FallbackExe Fallback = iota
	// FallbackUnit names the service after the systemd unit.
	FallbackUnit
)

// ParseFallback parses the -service-name-fallback flag: "exe" or "unit".
func ParseFallback(s string) (Fallback, error) {
	switch s {
	case "", "exe":
		return FallbackExe, nil
	case "unit":
		return FallbackUnit, nil
	}
	return 0, fmt.Errorf("invalid service name fallback %q", s)
}

func (f Fallback) String() string {
	if f == FallbackUnit {
		return "unit"
	}
	return "exe"
}

// Service is the name of the service a process belongs to, in the sense of
// the OpenTelemetry resource attributes service.name and service.namespace.
type Service struct {
	Name      string
	Namespace string
}

// Job returns the name Prometheus gives to the service in the job label:
// "namespace/name", or "name" without a namespace.
func (s Service) Job() string {
	if s.Namespace == "" {
		return s.Name
	}
	return s.Namespace + "/" + s.Name
}

// maxEnviron bounds how much of the environment of a process is read.
const maxEnviron = 1 << 20

// environTimeout bounds the wait for a read of /proc/PID/environ, which
// takes the lock of the memory map of the process and can block while the
// process is stuck: for a while on a hung network file system, or for good
// on a FUSE file system that its user stalls.
const environTimeout = 200 * time.Millisecond

// environBackoff is how long the environment of a process whose read timed
// out is not read again after that read returned: a process slow to
// answer once is likely slow again.
const environBackoff = 5 * time.Minute

// MaxEnvironReads bounds the reads of environments outstanding at once.
// A read that hangs holds a goroutine and a file descriptor until it
// returns, which may be never, and a user can make one hang per process
// it starts. Once this many are outstanding, no read starts: the
// processes are not read in time, as if their read had timed out. A read
// returns within microseconds unless it hangs, so the slots are held by
// reads that hang; the agent reads 8 processes at once, so 24 reads may
// hang before one of its readers finds no slot. 32 goroutines and file
// descriptors cost little, and more processes hanging at once point to a
// stall of the host, e.g. of a file system that many processes map, which
// reading more processes would only add readers to.
const MaxEnvironReads = 32

// maxSlowEnviron bounds the PIDs that back off. The agent can time out 40
// reads in an interval (8 readers for a second, 200 ms each), 800 in the
// 5 minutes of a backoff with intervals of 15 s, more with shorter ones. A
// read that returns while this many PIDs back off does not back off.
const maxSlowEnviron = 4096

// environReads tracks the reads of environments.
var environReads = struct {
	sync.Mutex
	// running counts the reads started that have not returned, and stuck
	// those of them that timed out.
	running, stuck int
	// skipped counts the reads not started because MaxEnvironReads were
	// running.
	skipped uint64
	// slow holds the PIDs whose environment is not read: the zero time
	// while a read that timed out is running, then the time until which
	// the process backs off.
	slow map[uint32]time.Time
}{slow: map[uint32]time.Time{}}

// EnvironReads tells how many reads of environments hang.
type EnvironReads struct {
	// Stuck counts the reads that timed out and have not returned.
	Stuck int
	// Skipped counts the reads not started, since the agent started,
	// because MaxEnvironReads were outstanding.
	Skipped uint64
}

// StuckEnvironReads returns how many reads of environments hang.
func StuckEnvironReads() EnvironReads {
	e := &environReads
	e.Lock()
	defer e.Unlock()
	return EnvironReads{Stuck: e.stuck, Skipped: e.skipped}
}

// OTelEnv returns the variables of the environment of a process whose names
// start with OTEL_. Other variables, which may hold secrets, are discarded
// as soon as they are read. ok is false if the environment could not be
// read in time; env is nil if the process has none or cannot be read.
func OTelEnv(pid uint32) (env map[string]string, ok bool) {
	if pid == 0 {
		return nil, true
	}
	r := startEnvironRead(pid)
	if r == nil {
		return nil, false
	}
	go r.run()
	timeout := time.NewTimer(environTimeout)
	defer timeout.Stop()
	select {
	case env := <-r.done:
		return env, true
	case <-timeout.C:
	}
	if !r.abandon() {
		// The read returned as it timed out.
		return <-r.done, true
	}
	return nil, false
}

// environRead is a read of the environment of a process, which holds one
// of MaxEnvironReads until it returns.
type environRead struct {
	pid uint32
	// done receives the environment, unless the read was abandoned.
	done chan map[string]string
	// Guarded by environReads.
	returned, abandoned bool
}

// startEnvironRead returns a read of the environment of pid, or nil if the
// process backs off or MaxEnvironReads are outstanding.
func startEnvironRead(pid uint32) *environRead {
	e := &environReads
	e.Lock()
	defer e.Unlock()
	if t, slow := e.slow[pid]; slow {
		if t.IsZero() || time.Now().Before(t) {
			return nil
		}
		delete(e.slow, pid)
	}
	if e.running >= MaxEnvironReads {
		e.skipped++
		return nil
	}
	e.running++
	return &environRead{pid: pid, done: make(chan map[string]string, 1)}
}

// run reads the environment, then releases the slot of the read. The
// process of a read that was abandoned backs off.
func (r *environRead) run() {
	env := readEnviron(r.pid)
	e := &environReads
	e.Lock()
	defer e.Unlock()
	e.running--
	r.returned = true
	if !r.abandoned {
		r.done <- env
		return
	}
	e.stuck--
	now := time.Now()
	// Forget the PIDs whose backoff ended, which may have exited.
	for pid, t := range e.slow {
		if !t.IsZero() && now.After(t) {
			delete(e.slow, pid)
		}
	}
	// At most maxSlowEnviron PIDs back off, and at most MaxEnvironReads
	// more wait for their read.
	if len(e.slow) < maxSlowEnviron {
		e.slow[r.pid] = now.Add(environBackoff)
	} else {
		delete(e.slow, r.pid)
	}
}

// abandon stops waiting for the read, unless it has returned: the process
// is not read again while the read runs. It reports whether the read was
// abandoned.
func (r *environRead) abandon() bool {
	e := &environReads
	e.Lock()
	defer e.Unlock()
	if r.returned {
		return false
	}
	r.abandoned = true
	e.stuck++
	e.slow[r.pid] = time.Time{}
	return true
}

// readEnviron reads the OTEL_ variables of a process; replaced in tests.
var readEnviron = readOTelEnv

func readOTelEnv(pid uint32) map[string]string {
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/environ")
	if err != nil {
		return nil
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, maxEnviron))
	return parseOTelEnv(data)
}

// parseOTelEnv extracts the OTEL_ variables from the contents of
// /proc/PID/environ, a sequence of NUL-terminated NAME=value strings.
func parseOTelEnv(data []byte) map[string]string {
	var env map[string]string
	for len(data) > 0 {
		var kv []byte
		kv, data, _ = bytes.Cut(data, []byte{0})
		if !bytes.HasPrefix(kv, []byte("OTEL_")) {
			continue
		}
		k, v, ok := bytes.Cut(kv, []byte{'='})
		if !ok {
			continue
		}
		if env == nil {
			env = map[string]string{}
		}
		env[string(k)] = string(v)
	}
	return env
}

// ResourceAttributes parses the value of OTEL_RESOURCE_ATTRIBUTES: a
// comma-separated list of key=value pairs whose values may be
// percent-encoded. Malformed pairs are skipped.
func ResourceAttributes(s string) map[string]string {
	attrs := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		if u, err := url.PathUnescape(strings.TrimSpace(v)); err == nil {
			attrs[k] = u
		}
	}
	return attrs
}

// ServiceName names the service of a process. The first of these is used:
//
//  1. OTEL_SERVICE_NAME in the environment of the process,
//  2. service.name in OTEL_RESOURCE_ATTRIBUTES,
//  3. the service of the pod of Kubernetes of the process, from its
//     annotations, its labels, then its owner (Container.Workload),
//  4. the base name of the executable, or the unit with FallbackUnit,
//  5. comm,
//  6. the unit, then UnknownService, for sockets whose owner is unknown.
//
// service.namespace in OTEL_RESOURCE_ATTRIBUTES gives the namespace, else
// the namespace of the service of the pod. Both are cut to 255 bytes. The
// order follows OBI, so that both name a service the same way: OBI names
// the processes of a pod from its metadata, and those of other containers
// after their executable. Containers apart from Kubernetes are told apart
// by their unit, or named after it with FallbackUnit.
func ServiceName(env map[string]string, exe, comm, unit string, workload Service, fb Fallback) Service {
	var s Service
	attrs := ResourceAttributes(env["OTEL_RESOURCE_ATTRIBUTES"])
	s.Namespace = attrs["service.namespace"]
	if s.Namespace == "" {
		s.Namespace = workload.Namespace
	}
	s.Name = strings.TrimSpace(env["OTEL_SERVICE_NAME"])
	if s.Name == "" {
		s.Name = attrs["service.name"]
	}
	if s.Name == "" {
		s.Name = workload.Name
	}
	if s.Name == "" && fb == FallbackUnit {
		s.Name = unit
	}
	if s.Name == "" && exe != "" {
		s.Name = path.Base(exe)
	}
	if s.Name == "" {
		s.Name = comm
	}
	if s.Name == "" {
		s.Name = unit
	}
	if s.Name == "" {
		s.Name = UnknownService
	}
	s.Name, s.Namespace = truncateName(s.Name), truncateName(s.Namespace)
	return s
}

// maxServiceName bounds the length of the name and namespace of a service.
// They come from the environment of the process, which any user sets: one
// of 128 KiB, repeated in every data point of the series of the process,
// would make a request too large for the collector, and stop the export of
// the host.
const maxServiceName = 255

// truncateName cuts a name to maxServiceName bytes, at the start of a
// character.
func truncateName(s string) string {
	if len(s) <= maxServiceName {
		return s
	}
	n := maxServiceName
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// UnknownService names the service of a socket whose process and unit are
// unknown, e.g. a connection accepted on a listener closed within an
// interval.
const UnknownService = "~unknown"

// KernelService is the service.name of sockets that belong to the kernel
// rather than to a process (see KernelServiceName).
const KernelService = "~kernel"

// kernelPorts names the subsystems of the kernel that use sockets, by
// their usual service port. Only sockets of the kernel are named by port:
// an application on one of these ports keeps its own name.
var kernelPorts = map[uint16]string{
	111:   KernelService + ":rpcbind", // the portmapper, e.g. for NFSv3 and lockd
	139:   KernelService + ":smb",
	445:   KernelService + ":smb", // the CIFS/SMB client
	2049:  KernelService + ":nfs", // the NFS client
	3260:  KernelService + ":iscsi",
	3300:  KernelService + ":ceph", // monitors (msgr2)
	4420:  KernelService + ":nvme-tcp",
	6789:  KernelService + ":ceph", // monitors (msgr1)
	7777:  KernelService + ":ocfs2",
	8009:  KernelService + ":nvme-tcp", // discovery
	16385: KernelService + ":rds",
	21064: KernelService + ":dlm",
}

// kernelServers names the servers of the kernel apart from its clients on
// the same port, so that a dependency of a client on a server of the
// kernel has two ends. The subsystems not listed here are clients only
// (Ceph) or peers of one another (DRBD, OCFS2, DLM), and have one name.
var kernelServers = map[uint16]string{
	445:  KernelService + ":ksmbd",
	2049: KernelService + ":nfsd",
	3260: KernelService + ":iscsi-target", // LIO
	4420: KernelService + ":nvmet-tcp",
	8009: KernelService + ":nvmet-tcp", // discovery
}

// KernelServiceName names the service of a socket of the kernel after its
// service port and its side: ~kernel:nfs for the client side of 2049,
// ~kernel:nfsd for its server side, ~kernel for a port of no known
// subsystem. The kernel opens a socket in a kernel worker or in whatever
// process triggers it (e.g. mount), so neither the command name nor the
// cgroup is stable; the port is. The name starts with ~, like the other
// names shawk makes up (~unknown, ~unresolved), which peer_cidrs cannot
// take, and has no /, which separates the namespace in the Prometheus job.
// Ceph also uses 6800-7300 for its daemons, and DRBD usually 7788-7799.
func KernelServiceName(port uint16, server bool) string {
	if name, ok := kernelServers[port]; ok && server {
		return name
	}
	if name, ok := kernelPorts[port]; ok {
		return name
	}
	switch {
	case port >= 6800 && port <= 7300:
		return KernelService + ":ceph"
	case port >= 7788 && port <= 7799:
		return KernelService + ":drbd"
	}
	return KernelService
}

// machineIDPaths are where the machine id is looked up, in order.
var machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// MachineID returns the machine id of the host from /etc/machine-id or
// /var/lib/dbus/machine-id, or "" if neither has one.
func MachineID() string { return machineID(machineIDPaths...) }

func machineID(paths ...string) string {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	return ""
}
