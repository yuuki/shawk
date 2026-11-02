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

// environTimeout bounds a read of /proc/PID/environ, which takes the lock
// of the memory map of the process and can block while the process is
// stuck, e.g. on a hung network file system.
const environTimeout = 200 * time.Millisecond

// environBackoff is how long the environment of a process whose read timed
// out is not read again after that read returned: a process slow to
// answer once is likely slow again.
const environBackoff = 5 * time.Minute

// slowEnviron are the PIDs whose environment is not read: the zero time
// while a read that timed out is still running, then the time until which
// it backs off.
var slowEnviron sync.Map

// OTelEnv returns the variables of the environment of a process whose names
// start with OTEL_. Other variables, which may hold secrets, are discarded
// as soon as they are read. ok is false if the environment could not be
// read in time; env is nil if the process has none or cannot be read.
func OTelEnv(pid uint32) (env map[string]string, ok bool) {
	if pid == 0 {
		return nil, true
	}
	if v, slow := slowEnviron.Load(pid); slow {
		if t := v.(time.Time); t.IsZero() || time.Now().Before(t) {
			return nil, false
		}
		slowEnviron.Delete(pid)
	}
	done := make(chan map[string]string, 1)
	go func() {
		done <- readEnviron(pid)
	}()
	select {
	case env := <-done:
		return env, true
	case <-time.After(environTimeout):
		slowEnviron.Store(pid, time.Time{})
		go func() {
			<-done
			now := time.Now()
			slowEnviron.Store(pid, now.Add(environBackoff))
			// Forget the PIDs whose backoff ended, which may have exited.
			slowEnviron.Range(func(k, v any) bool {
				if t := v.(time.Time); !t.IsZero() && now.After(t) {
					slowEnviron.Delete(k)
				}
				return true
			})
		}()
		return nil, false
	}
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
//  3. the base name of the executable, or the unit with FallbackUnit,
//  4. comm,
//  5. the unit, then UnknownService, for sockets whose owner is unknown.
//
// service.namespace in OTEL_RESOURCE_ATTRIBUTES gives the namespace. The
// order follows OBI, so that both name a service the same way.
func ServiceName(env map[string]string, exe, comm, unit string, fb Fallback) Service {
	var s Service
	attrs := ResourceAttributes(env["OTEL_RESOURCE_ATTRIBUTES"])
	s.Namespace = attrs["service.namespace"]
	s.Name = strings.TrimSpace(env["OTEL_SERVICE_NAME"])
	if s.Name == "" {
		s.Name = attrs["service.name"]
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
	return s
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
