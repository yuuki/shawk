package procinfo

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
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

// OTelEnv returns the variables of the environment of a process whose names
// start with OTEL_. Other variables, which may hold secrets, are discarded
// as soon as they are read. It returns nil if the environment cannot be read.
func OTelEnv(pid uint32) map[string]string {
	if pid == 0 {
		return nil
	}
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/environ")
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, maxEnviron)
	n, _ := readFull(f, buf)
	return parseOTelEnv(buf[:n])
}

func readFull(f *os.File, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			return n, err
		}
	}
	return n, nil
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
//  4. comm.
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
	return s
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
