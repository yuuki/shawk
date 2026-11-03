package procinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
		workload        Service
		fb              Fallback
		want            Service
	}{
		{"service name variable", map[string]string{
			"OTEL_SERVICE_NAME":        "billing",
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=ignored,service.namespace=shop",
		}, "/usr/bin/ruby", "ruby", "billing.service", Service{}, FallbackExe, Service{"billing", "shop"}},
		{"resource attributes", map[string]string{
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=cart",
		}, "/usr/bin/java", "java", "cart.service", Service{}, FallbackExe, Service{"cart", ""}},
		{"blank service name", map[string]string{"OTEL_SERVICE_NAME": " "},
			"/usr/sbin/nginx", "nginx", "nginx.service", Service{}, FallbackExe, Service{"nginx", ""}},
		{"executable", nil, "/usr/lib/postgresql/16/bin/postgres", "postgres", "postgresql.service", Service{}, FallbackExe, Service{"postgres", ""}},
		{"comm without executable", nil, "", "kworker", "", Service{}, FallbackExe, Service{"kworker", ""}},
		{"unit without process", nil, "", "", "nfs-server.service", Service{}, FallbackExe, Service{"nfs-server.service", ""}},
		{"nothing known", nil, "", "", "", Service{}, FallbackExe, Service{UnknownService, ""}},
		{"unit", nil, "/usr/bin/ruby", "ruby", "billing.service", Service{}, FallbackUnit, Service{"billing.service", ""}},
		{"unit unknown", nil, "/usr/bin/ruby", "ruby", "", Service{}, FallbackUnit, Service{"ruby", ""}},
		{"environment wins over unit", map[string]string{"OTEL_SERVICE_NAME": "billing"},
			"/usr/bin/ruby", "ruby", "billing-v2.service", Service{}, FallbackUnit, Service{"billing", ""}},
		{"namespace without name", map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=shop"},
			"/usr/bin/php-fpm", "php-fpm", "", Service{}, FallbackExe, Service{"php-fpm", "shop"}},
		{"workload of a pod", nil, "/usr/bin/java", "java", "k8s/shop/cart/app",
			Service{"cart", "shop"}, FallbackExe, Service{"cart", "shop"}},
		{"workload before unit", nil, "/usr/bin/java", "java", "k8s/shop/cart/app",
			Service{"cart", "shop"}, FallbackUnit, Service{"cart", "shop"}},
		{"environment wins over workload", map[string]string{"OTEL_SERVICE_NAME": "billing"},
			"/usr/bin/java", "java", "k8s/shop/cart/app", Service{"cart", "shop"}, FallbackExe, Service{"billing", "shop"}},
		{"namespace of the environment wins", map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=eu"},
			"/usr/bin/java", "java", "k8s/shop/cart/app", Service{"cart", "shop"}, FallbackExe, Service{"cart", "eu"}},
	} {
		if got := ServiceName(tc.env, tc.exe, tc.comm, tc.unit, tc.workload, tc.fb); got != tc.want {
			t.Errorf("%s: ServiceName = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// The environment of a process, which any user sets, cannot make a name
// longer than 255 bytes; it is cut at the start of a character.
func TestServiceNameTruncated(t *testing.T) {
	long := strings.Repeat("a", 254) + "é" + strings.Repeat("b", 128<<10)
	got := ServiceName(map[string]string{
		"OTEL_SERVICE_NAME":        long,
		"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=" + long,
	}, "/usr/bin/ruby", "ruby", "", Service{}, FallbackExe)
	want := strings.Repeat("a", 254)
	if got.Name != want || got.Namespace != want {
		t.Errorf("ServiceName = %d and %d bytes, want %q", len(got.Name), len(got.Namespace), want)
	}
	short := strings.Repeat("a", 253) + "é"
	if got := ServiceName(map[string]string{"OTEL_SERVICE_NAME": short}, "", "", "", Service{}, FallbackExe); got.Name != short {
		t.Errorf("ServiceName = %q, want %q", got.Name, short)
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

// blockEnviron replaces the reader of environments for a test: the reads
// of PIDs from 1000 on block until released, the others return
// OTEL_SERVICE_NAME=ok. At the end of the test all reads are released and
// forgotten.
func blockEnviron(t *testing.T) *blockedEnviron {
	b := &blockedEnviron{release: make(chan struct{})}
	readEnviron = func(pid uint32) map[string]string {
		if pid < 1000 {
			return map[string]string{"OTEL_SERVICE_NAME": "ok"}
		}
		b.blocked.Add(1)
		defer b.blocked.Add(-1)
		<-b.release
		return map[string]string{"OTEL_SERVICE_NAME": "late"}
	}
	t.Cleanup(func() {
		b.releaseAll()
		waitEnviron(t, "the reads to return", func() bool { return environReads.running == 0 })
		readEnviron = readOTelEnv
		e := &environReads
		e.Lock()
		e.slow = map[uint32]time.Time{}
		e.Unlock()
	})
	return b
}

type blockedEnviron struct {
	release chan struct{}
	once    sync.Once
	blocked atomic.Int32 // the reads blocked
}

// releaseOne lets one blocked read return.
func (b *blockedEnviron) releaseOne() { b.release <- struct{}{} }

// releaseAll lets the blocked reads return, and those to come.
func (b *blockedEnviron) releaseAll() { b.once.Do(func() { close(b.release) }) }

// waitEnviron waits until cond holds, with environReads locked.
func waitEnviron(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; ; i++ {
		environReads.Lock()
		ok := cond()
		environReads.Unlock()
		if ok {
			return
		}
		if i > 300 {
			t.Fatalf("waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// slowUntil returns until when the process pid backs off, and whether it
// does.
func slowUntil(pid uint32) (time.Time, bool) {
	environReads.Lock()
	defer environReads.Unlock()
	t, ok := environReads.slow[pid]
	return t, ok
}

func TestOTelEnvTimeout(t *testing.T) {
	b := blockEnviron(t)
	if env, ok := OTelEnv(4242); ok || env != nil {
		t.Fatalf("a blocked read returned %v, %v", env, ok)
	}
	// While the read is blocked, the process is not read again.
	start := time.Now()
	if _, ok := OTelEnv(4242); ok || time.Since(start) > environTimeout/2 {
		t.Errorf("a stuck process was read again")
	}
	b.releaseAll()
	// Once the read returns, the process backs off for a while.
	waitEnviron(t, "the backoff", func() bool { return !environReads.slow[4242].IsZero() })
	if _, ok := OTelEnv(4242); ok {
		t.Error("a slow process was read again within its backoff")
	}
	// After the backoff it is read again.
	environReads.Lock()
	environReads.slow[4242] = time.Now().Add(-time.Second)
	environReads.Unlock()
	if env, ok := OTelEnv(4242); !ok || env["OTEL_SERVICE_NAME"] != "late" {
		t.Errorf("after the backoff: %v, %v", env, ok)
	}
	if _, slow := slowUntil(4242); slow {
		t.Error("the backoff is kept after it ended")
	}
}

// Reads that hang are bounded: once MaxEnvironReads are outstanding, no
// read starts and the processes are not read in time; a read that returns
// releases its slot.
func TestOTelEnvBoundsStuckReads(t *testing.T) {
	b := blockEnviron(t)
	before := StuckEnvironReads()
	goroutines := runtime.NumGoroutine()
	// Many processes that hang are read at once, as the readers of the
	// agent do.
	const hung = 10 * MaxEnvironReads
	var wg sync.WaitGroup
	var notRead atomic.Int32
	start := time.Now()
	for pid := uint32(1000); pid < 1000+hung; pid++ {
		wg.Go(func() {
			if _, ok := OTelEnv(pid); !ok {
				notRead.Add(1)
			}
		})
	}
	wg.Wait()
	if d := time.Since(start); d > 10*environTimeout {
		t.Errorf("reading %d stuck processes took %s", hung, d)
	}
	if got := notRead.Load(); got != hung {
		t.Errorf("%d of %d stuck processes read in time", hung-got, hung)
	}
	waitEnviron(t, "the reads to block", func() bool { return b.blocked.Load() >= MaxEnvironReads })
	if got := b.blocked.Load(); got != MaxEnvironReads {
		t.Errorf("%d reads blocked, want %d", got, MaxEnvironReads)
	}
	s := StuckEnvironReads()
	if s.Stuck != MaxEnvironReads || s.Skipped-before.Skipped != hung-MaxEnvironReads {
		t.Errorf("StuckEnvironReads = %+v, want %d stuck and %d more skipped", s, MaxEnvironReads, hung-MaxEnvironReads)
	}
	// One goroutine per stuck read is left, whatever the number of
	// processes that hang.
	waitGoroutines(t, goroutines+MaxEnvironReads)

	// While all slots are held, a process that does not hang is not read
	// either.
	if env, ok := OTelEnv(1); ok || env != nil {
		t.Errorf("a process was read with all slots held: %v, %v", env, ok)
	}
	if got := StuckEnvironReads().Skipped - s.Skipped; got != 1 {
		t.Errorf("%d reads skipped, want 1", got)
	}
	// A read that returns releases its slot, and its process backs off.
	b.releaseOne()
	waitEnviron(t, "a slot", func() bool { return environReads.running == MaxEnvironReads-1 })
	if got := StuckEnvironReads().Stuck; got != MaxEnvironReads-1 {
		t.Errorf("%d reads stuck after one returned, want %d", got, MaxEnvironReads-1)
	}
	if env, ok := OTelEnv(1); !ok || env["OTEL_SERVICE_NAME"] != "ok" {
		t.Errorf("a process read with a slot free: %v, %v", env, ok)
	}
	// Once all return, all slots are free and the goroutines gone.
	b.releaseAll()
	waitEnviron(t, "all slots", func() bool { return environReads.running == 0 })
	if got := StuckEnvironReads().Stuck; got != 0 {
		t.Errorf("%d reads stuck after all returned", got)
	}
	waitGoroutines(t, goroutines)
	for pid := uint32(1); pid < 1+2*MaxEnvironReads; pid++ {
		if env, ok := OTelEnv(pid); !ok || env["OTEL_SERVICE_NAME"] != "ok" {
			t.Fatalf("process %d after the reads returned: %v, %v", pid, env, ok)
		}
	}
	// The processes whose read timed out back off; the others were not read.
	slow := 0
	for pid := uint32(1000); pid < 1000+hung; pid++ {
		if until, ok := slowUntil(pid); ok && !until.IsZero() {
			slow++
		}
	}
	if slow != MaxEnvironReads {
		t.Errorf("%d processes back off, want %d", slow, MaxEnvironReads)
	}
}

// waitGoroutines waits until at most n goroutines run.
func waitGoroutines(t *testing.T, n int) {
	t.Helper()
	for i := 0; runtime.NumGoroutine() > n; i++ {
		if i > 300 {
			t.Fatalf("%d goroutines, want at most %d", runtime.NumGoroutine(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The PIDs that back off are bounded: a read that returns while
// maxSlowEnviron back off does not back off, and the PIDs whose backoff
// ended are forgotten when a read returns.
func TestOTelEnvBoundsBackoff(t *testing.T) {
	b := blockEnviron(t)
	e := &environReads
	e.Lock()
	for pid := range uint32(maxSlowEnviron) {
		e.slow[100000+pid] = time.Now().Add(time.Hour)
	}
	e.Unlock()
	if _, ok := OTelEnv(4242); ok {
		t.Fatal("a blocked read returned")
	}
	b.releaseOne()
	waitEnviron(t, "the read to return", func() bool { return e.running == 0 })
	if _, slow := slowUntil(4242); slow {
		t.Error("a process backs off beyond maxSlowEnviron")
	}
	waitEnviron(t, "the backoffs", func() bool { return len(e.slow) == maxSlowEnviron })

	e.Lock()
	for pid := range e.slow {
		e.slow[pid] = time.Now().Add(-time.Second)
	}
	e.Unlock()
	if _, ok := OTelEnv(4243); ok {
		t.Fatal("a blocked read returned")
	}
	b.releaseOne()
	waitEnviron(t, "the read to return", func() bool { return e.running == 0 })
	if until, slow := slowUntil(4243); !slow || until.Before(time.Now()) {
		t.Errorf("the process does not back off: %v, %v", until, slow)
	}
	waitEnviron(t, "the ended backoffs to be forgotten", func() bool { return len(e.slow) == 1 })
}
