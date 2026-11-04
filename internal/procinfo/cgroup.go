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
	// The scope slurmd makes for slurmstepd, with the name of the node
	// when Slurm is built with --enable-multiple-slurmd: <node>_slurmstepd.scope
	// (the documentation also writes slurmstepd_<node>.scope), and the
	// directories of the steps of a job in it: step_<id>,
	// step_<id>.<component> for a component of a heterogeneous job,
	// step_batch, step_extern and step_interactive.
	slurmScope = regexp.MustCompile(`^(.+_)?slurmstepd(_.+)?\.scope$`)
	slurmStep  = regexp.MustCompile(`^step_(batch|extern|interactive|[0-9]+(\.[0-9]+)?)$`)
)

// SlurmStepd is the unit of slurmstepd, and SlurmJobPrefix the prefix of
// the units of the processes of Slurm jobs (see Unit).
const (
	SlurmStepd     = "slurmstepd"
	SlurmJobPrefix = "slurm/"
)

// SlurmJob reports whether unit is that of the processes of a Slurm job,
// which the users of the cluster run and name as they like (see Unit).
func SlurmJob(unit string) bool { return strings.HasPrefix(unit, SlurmJobPrefix) }

// slurmUnit names the cgroups slurmstepd makes on cgroup v2. Every job has
// a directory in the scope, named job_<id> before Slurm 26.05 or with
// CgroupJobIdPaths=yes, and otherwise its SLUID; it is recognized by the
// structure under it, whatever its name:
//
//	<scope>/<job>/<step>/user/task_<n>   the tasks of a step  -> slurm/<kind>
//	<scope>/<job>/<step>/slurm           slurmstepd of a step -> slurmstepd
//	<scope>/system                       slurmstepd waiting   -> slurmstepd
//
// task_special holds the processes that pam_slurm_adopt moves into the
// extern step. slurmstepd moves itself into slurm_processes in later
// releases. The kind of a step is batch, extern, interactive, or step for
// those srun starts. The scope is in system.slice at the root, where users
// cannot make cgroups; other paths are not recognized (ok is false), nor
// is cgroup v1.
func slurmUnit(parts []string) (unit string, ok bool) {
	if len(parts) < 3 || parts[0] != "system.slice" || !slurmScope.MatchString(parts[1]) {
		return "", false
	}
	switch rest := parts[2:]; {
	case len(rest) == 1 && rest[0] == "system":
		return SlurmStepd, true
	case len(rest) < 3 || rest[0] == "system":
		return "", false
	case !slurmStep.MatchString(rest[1]):
		return "", false
	case len(rest) == 3 && (rest[2] == "slurm" || rest[2] == "slurm_processes"):
		return SlurmStepd, true
	case len(rest) == 4 && rest[2] == "user" && strings.HasPrefix(rest[3], "task_"):
		kind := strings.TrimPrefix(rest[1], "step_")
		if kind[0] >= '0' && kind[0] <= '9' {
			kind = "step"
		}
		return SlurmJobPrefix + kind, true
	}
	return "", false
}

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
//	/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-0123456789ab....scope
//	                                                 -> user@1000.service/podman-0123456789ab
//	/user.slice/user-1000.slice/session-3.scope      -> user-1000.slice/session.scope
//	/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service
//	                                                 -> user@1000.service/foo.service
//	/system.slice/run-u1234.scope                    -> run.scope
//	/system.slice/slurmstepd.scope/job_42/step_0/user/task_0
//	                                                 -> slurm/step
//	/system.slice/slurmstepd.scope/job_42/step_0/slurm
//	                                                 -> slurmstepd
//
// The processes of Slurm jobs are named after the kind of their step (see
// slurmUnit): slurm/batch, slurm/step, slurm/extern or slurm/interactive.
func Unit(cgroupPath string) string {
	parts := strings.FieldsFunc(cgroupPath, func(r rune) bool { return r == '/' })
	if len(parts) == 0 {
		return ""
	}
	if u, ok := slurmUnit(parts); ok {
		return u
	}
	if refs, under := cgroupContainers(cgroupPath); len(refs) > 0 {
		outer := refs[len(refs)-1]
		return (&Container{Runtime: runtimeOrAny(outer.runtime), ID: outer.id, Under: under}).Unit()
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
// the containers of a rootless runtime, and returns that unit as under.
//
// The runtimes of the host make the cgroups of their containers in slices
// or at the root of the hierarchy, never in a unit: a unit above the
// containers delegates its cgroups to a user (user@1000.service, or a
// service with Delegate=yes and User=), who may name them after any
// container of the host. Their state is not read (see Resolver.unit).
func cgroupContainers(cgroupPath string) (refs []containerRef, under string) {
	parts := strings.FieldsFunc(cgroupPath, func(r rune) bool { return r == '/' })
	for i := len(parts) - 1; i >= 0; i-- {
		if runtime, id, ok := containerOf(parts, i); ok {
			refs = append(refs, containerRef{runtime, id})
			continue
		}
		p := parts[i]
		if runScope.MatchString(p) || sessionScope.MatchString(p) || strings.HasSuffix(p, ".service") {
			if len(refs) > 0 {
				under = Unit("/" + strings.Join(parts[:i+1], "/"))
			}
			break
		}
	}
	return refs, under
}

func runtimeOrAny(runtime string) string {
	if runtime == "" {
		return "container"
	}
	return runtime
}
