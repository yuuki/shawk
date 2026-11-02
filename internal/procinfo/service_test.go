package procinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseOTelEnv(t *testing.T) {
	data := "PATH=/usr/bin\x00OTEL_SERVICE_NAME=billing\x00DB_PASSWORD=s3cret\x00" +
		"OTEL_RESOURCE_ATTRIBUTES=service.namespace=shop,deployment.environment=prod\x00OTEL_BROKEN\x00" +
		"HOME=/root\x00OTEL_EMPTY=\x00"
	got := parseOTelEnv([]byte(data))
	want := map[string]string{
		"OTEL_SERVICE_NAME":        "billing",
		"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=shop,deployment.environment=prod",
		"OTEL_EMPTY":               "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseOTelEnv = %v, want %v", got, want)
	}
	if got := parseOTelEnv([]byte("PATH=/bin\x00HOME=/\x00")); got != nil {
		t.Errorf("parseOTelEnv without OTEL_ variables = %v", got)
	}
}

func TestOTelEnvSelf(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "shawk-test")
	t.Setenv("SHAWK_SECRET", "x")
	// /proc/self/environ holds the environment at exec; check the parser on
	// a process started with a known environment instead.
	if env, ok := OTelEnv(0); env != nil || !ok {
		t.Errorf("OTelEnv(0) = %v, %v", env, ok)
	}
	// The environment of this process: at exec it had no OTEL_ variables
	// beyond those the test runner passed; only OTEL_ ones come back.
	env, ok := OTelEnv(uint32(os.Getpid()))
	if !ok {
		t.Error("reading the own environment timed out")
	}
	for k := range env {
		if !strings.HasPrefix(k, "OTEL_") {
			t.Errorf("non-OTEL variable %q kept", k)
		}
	}
	b, err := os.ReadFile("/proc/self/environ")
	if err != nil {
		t.Skip(err)
	}
	for k := range parseOTelEnv(b) {
		if !strings.HasPrefix(k, "OTEL_") {
			t.Errorf("non-OTEL variable %q kept", k)
		}
	}
}

func TestResourceAttributes(t *testing.T) {
	got := ResourceAttributes(" service.name = cart , service.namespace=shop%2Feu,bad,=x,k=%zz")
	want := map[string]string{"service.name": "cart", "service.namespace": "shop/eu"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResourceAttributes = %v, want %v", got, want)
	}
}

func TestServiceName(t *testing.T) {
	for _, tc := range []struct {
		name            string
		env             map[string]string
		exe, comm, unit string
		fb              Fallback
		want            Service
	}{
		{"service name variable", map[string]string{
			"OTEL_SERVICE_NAME":        "billing",
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=ignored,service.namespace=shop",
		}, "/usr/bin/ruby", "ruby", "billing.service", FallbackExe, Service{"billing", "shop"}},
		{"resource attributes", map[string]string{
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=cart",
		}, "/usr/bin/java", "java", "cart.service", FallbackExe, Service{"cart", ""}},
		{"blank service name", map[string]string{"OTEL_SERVICE_NAME": " "},
			"/usr/sbin/nginx", "nginx", "nginx.service", FallbackExe, Service{"nginx", ""}},
		{"executable", nil, "/usr/lib/postgresql/16/bin/postgres", "postgres", "postgresql.service", FallbackExe, Service{"postgres", ""}},
		{"comm without executable", nil, "", "kworker", "", FallbackExe, Service{"kworker", ""}},
		{"unit without process", nil, "", "", "nfs-server.service", FallbackExe, Service{"nfs-server.service", ""}},
		{"nothing known", nil, "", "", "", FallbackExe, Service{UnknownService, ""}},
		{"unit", nil, "/usr/bin/ruby", "ruby", "billing.service", FallbackUnit, Service{"billing.service", ""}},
		{"unit unknown", nil, "/usr/bin/ruby", "ruby", "", FallbackUnit, Service{"ruby", ""}},
		{"environment wins over unit", map[string]string{"OTEL_SERVICE_NAME": "billing"},
			"/usr/bin/ruby", "ruby", "billing-v2.service", FallbackUnit, Service{"billing", ""}},
		{"namespace without name", map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=shop"},
			"/usr/bin/php-fpm", "php-fpm", "", FallbackExe, Service{"php-fpm", "shop"}},
	} {
		if got := ServiceName(tc.env, tc.exe, tc.comm, tc.unit, tc.fb); got != tc.want {
			t.Errorf("%s: ServiceName = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestKernelServiceName(t *testing.T) {
	// The client and the server side; one name when they are the same.
	for port, want := range map[uint16][2]string{
		2049:  {"~kernel:nfs", "~kernel:nfsd"},
		445:   {"~kernel:smb", "~kernel:ksmbd"},
		139:   {"~kernel:smb", "~kernel:smb"},
		3260:  {"~kernel:iscsi", "~kernel:iscsi-target"},
		4420:  {"~kernel:nvme-tcp", "~kernel:nvmet-tcp"},
		6789:  {"~kernel:ceph", "~kernel:ceph"},
		6800:  {"~kernel:ceph", "~kernel:ceph"},
		7300:  {"~kernel:ceph", "~kernel:ceph"},
		7301:  {"~kernel", "~kernel"},
		7788:  {"~kernel:drbd", "~kernel:drbd"},
		111:   {"~kernel:rpcbind", "~kernel:rpcbind"},
		0:     {"~kernel", "~kernel"},
		40000: {"~kernel", "~kernel"},
	} {
		for i, server := range []bool{false, true} {
			if got := KernelServiceName(port, server); got != want[i] {
				t.Errorf("KernelServiceName(%d, server=%t) = %q, want %q", port, server, got, want[i])
			}
		}
	}
}

func TestServiceJob(t *testing.T) {
	if got := (Service{Name: "cart"}).Job(); got != "cart" {
		t.Errorf("Job = %q", got)
	}
	if got := (Service{Name: "cart", Namespace: "shop"}).Job(); got != "shop/cart" {
		t.Errorf("Job = %q", got)
	}
}

func TestParseFallback(t *testing.T) {
	for in, want := range map[string]Fallback{"": FallbackExe, "exe": FallbackExe, "unit": FallbackUnit} {
		if got, err := ParseFallback(in); err != nil || got != want {
			t.Errorf("ParseFallback(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseFallback("comm"); err == nil {
		t.Error("ParseFallback(comm) succeeded")
	}
}

func TestMachineID(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc-machine-id")
	dbus := filepath.Join(dir, "dbus-machine-id")
	missing := filepath.Join(dir, "missing")
	os.WriteFile(dbus, []byte("dbus0123456789abcdef0123456789ab\n"), 0o644)
	if got := machineID(missing, dbus); got != "dbus0123456789abcdef0123456789ab" {
		t.Errorf("machineID fallback = %q", got)
	}
	// An empty /etc/machine-id (as in images before first boot) is skipped.
	os.WriteFile(etc, []byte("\n"), 0o644)
	if got := machineID(etc, dbus); got != "dbus0123456789abcdef0123456789ab" {
		t.Errorf("machineID with an empty file = %q", got)
	}
	os.WriteFile(etc, []byte("etc0123456789abcdef0123456789abc\n"), 0o644)
	if got := machineID(etc, dbus); got != "etc0123456789abcdef0123456789abc" {
		t.Errorf("machineID = %q", got)
	}
	if got := machineID(missing); got != "" {
		t.Errorf("machineID without files = %q", got)
	}
}

func TestOTelEnvTimeout(t *testing.T) {
	release := make(chan struct{})
	readEnviron = func(uint32) map[string]string {
		<-release
		return map[string]string{"OTEL_SERVICE_NAME": "late"}
	}
	t.Cleanup(func() { readEnviron = readOTelEnv })
	if env, ok := OTelEnv(4242); ok || env != nil {
		t.Fatalf("a blocked read returned %v, %v", env, ok)
	}
	// While the read is blocked, the process is not read again.
	start := time.Now()
	if _, ok := OTelEnv(4242); ok || time.Since(start) > environTimeout/2 {
		t.Errorf("a stuck process was read again")
	}
	close(release)
	// Once the read returns, the process backs off for a while.
	for i := 0; ; i++ {
		if v, _ := slowEnviron.Load(uint32(4242)); v != nil && !v.(time.Time).IsZero() {
			break
		}
		if i > 100 {
			t.Fatal("the process does not back off")
		}
		time.Sleep(10 * time.Millisecond)
	}
	readEnviron = func(uint32) map[string]string { return map[string]string{"OTEL_SERVICE_NAME": "ok"} }
	if _, ok := OTelEnv(4242); ok {
		t.Error("a slow process was read again within its backoff")
	}
	// After the backoff it is read again.
	slowEnviron.Store(uint32(4242), time.Now().Add(-time.Second))
	if env, ok := OTelEnv(4242); !ok || env["OTEL_SERVICE_NAME"] != "ok" {
		t.Errorf("after the backoff: %v, %v", env, ok)
	}
	if _, slow := slowEnviron.Load(uint32(4242)); slow {
		t.Error("the backoff is kept after it ended")
	}
}
