package procinfo

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// slurmUnits are the units of the processes of Slurm jobs (see slurmUnit).
var slurmUnits = map[string]bool{"slurm/batch": true, "slurm/step": true, "slurm/extern": true, "slurm/interactive": true}

// FuzzUnit checks the unit of a cgroup path, whose names users choose in
// the cgroups delegated to them: it depends on the components of the path
// only, as the cgroups of /proc/PID/cgroup give it, and only the
// structure of slurmstepd names a process of a Slurm job.
func FuzzUnit(f *testing.F) {
	for _, p := range []string{
		"/system.slice/nginx.service",
		"/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope",
		"/kubepods/burstable/pod1/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-0123456789abcdef0123.scope",
		"/user.slice/user-1000.slice/session-3.scope",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service",
		"/system.slice/run-p4242-i4243.service",
		"/system.slice/slurmstepd.scope/job_42/step_0/user/task_0",
		"/hpc.slice/hpc-slurm.slice/node1_slurmstepd.scope/s5K1KKYAYG5D00/step_1+2/user/task_3",
		"/system.slice/slurmstepd.scope/job_42/step_extern/slurm",
		"/user.slice/user-1000.slice/user@1000.service/system.slice/slurmstepd.scope/job_42/step_0/user/task_0",
		"", "/", "//a//b/", "/../x", "/caf\xc3\xa9.service", "/\xff.scope",
	} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		u := Unit(p)
		if (u == "") != (strings.Trim(p, "/") == "") {
			t.Fatalf("Unit(%q) = %q", p, u)
		}
		// Slashes around and between the components do not matter.
		for _, q := range []string{"/" + p, p + "/", strings.ReplaceAll(p, "/", "//")} {
			if v := Unit(q); v != u {
				t.Fatalf("Unit(%q) = %q, but Unit(%q) = %q", p, u, q, v)
			}
		}
		if utf8.ValidString(p) && !utf8.ValidString(u) {
			t.Fatalf("Unit(%q) = %q, not valid UTF-8", p, u)
		}
		// A user cannot make the cgroup of a process look like that of a
		// task of a Slurm job: only slurmstepd makes the structure under a
		// scope in slices, where users make no cgroups.
		if slurmUnits[u] {
			parts := strings.FieldsFunc(p, func(r rune) bool { return r == '/' })
			if s, ok := slurmUnit(parts); !ok || s != u {
				t.Fatalf("Unit(%q) = %q, but the path is not one of slurmstepd", p, u)
			}
		}
		// The path read from /proc/PID/cgroup is the line of cgroup v2.
		if !strings.Contains(p, "\n") && !strings.HasPrefix(p, "/..") {
			if got := parseProcCgroup([]byte("1:name=systemd:/x\n0::" + p + "\n")); got != p {
				t.Fatalf("parseProcCgroup of %q = %q", p, got)
			}
		}
	})
}

// escapeMount escapes a path as the kernel writes it in mountinfo
// (mangle() of fs/proc_namespace.c with " \t\n\\").
func escapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\\':
			fmt.Fprintf(&b, `\%03o`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// FuzzUnescapeMount checks that the mount point of the cgroup2 hierarchy is
// read back as the kernel escaped it.
func FuzzUnescapeMount(f *testing.F) {
	for _, s := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified", "/mnt/with space", `/back\slash`, `\040`, "/tab\t", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e := escapeMount(s)
		if got := unescapeMount(e); got != s {
			t.Fatalf("unescapeMount(%q) = %q, want %q", e, got, s)
		}
		if !strings.Contains(s, `\`) && unescapeMount(s) != s {
			t.Fatalf("unescapeMount(%q) = %q changed a path without escapes", s, unescapeMount(s))
		}
	})
}

// FuzzServiceName checks the names that the environment of a process, which
// any user sets, gives its service: only OTEL_ variables are kept, and the
// name and namespace are never empty or longer than maxServiceName bytes.
func FuzzServiceName(f *testing.F) {
	f.Add([]byte("PATH=/usr/bin\x00OTEL_SERVICE_NAME=billing\x00DB_PASSWORD=s3cret\x00"+
		"OTEL_RESOURCE_ATTRIBUTES=service.namespace=shop,deployment.environment=prod\x00OTEL_BROKEN\x00"),
		"/usr/bin/ruby", "ruby", "billing.service", "", "", false)
	f.Add([]byte("OTEL_RESOURCE_ATTRIBUTES= service.name = cart , service.namespace=shop%2Feu,bad,=x,k=%zz\x00"),
		"/usr/bin/java", "java", "k8s/shop/cart/app", "cart", "shop", true)
	f.Add([]byte("OTEL_SERVICE_NAME="+strings.Repeat("a", 254)+"é"+strings.Repeat("b", 300)+"\x00"),
		"", "", "", "", "", false)
	f.Add([]byte("OTEL_SERVICE_NAME= \x00"), "", "", "", "", "", true)
	f.Fuzz(func(t *testing.T, environ []byte, exe, comm, unit, workload, workloadNS string, byUnit bool) {
		env := parseOTelEnv(environ)
		for k, v := range env {
			if !strings.HasPrefix(k, "OTEL_") || strings.ContainsAny(k, "=\x00") || strings.Contains(v, "\x00") {
				t.Fatalf("parseOTelEnv(%q) kept %q=%q", environ, k, v)
			}
		}
		for k := range ResourceAttributes(env["OTEL_RESOURCE_ATTRIBUTES"]) {
			if k == "" || k != strings.TrimSpace(k) || strings.ContainsAny(k, ",=") {
				t.Fatalf("ResourceAttributes(%q) has the key %q", env["OTEL_RESOURCE_ATTRIBUTES"], k)
			}
		}
		fb := FallbackExe
		if byUnit {
			fb = FallbackUnit
		}
		s := ServiceName(env, exe, comm, unit, Service{Name: workload, Namespace: workloadNS}, fb)
		if s.Name == "" || len(s.Name) > maxServiceName || len(s.Namespace) > maxServiceName {
			t.Fatalf("ServiceName = %q (%d bytes), namespace of %d bytes", s.Name, len(s.Name), len(s.Namespace))
		}
		// OTEL_SERVICE_NAME comes first, cut at the start of a character.
		if want := strings.TrimSpace(env["OTEL_SERVICE_NAME"]); want != "" {
			if !strings.HasPrefix(want, s.Name) || (utf8.ValidString(want) && !utf8.ValidString(s.Name)) {
				t.Fatalf("ServiceName = %q for OTEL_SERVICE_NAME %q", s.Name, want)
			}
		}
	})
}
