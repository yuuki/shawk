package procinfo

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
)

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
