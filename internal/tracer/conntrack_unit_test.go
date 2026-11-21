package tracer

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// TestConntrackBackoff checks that a load that fails with the module there
// is tried again after twice as long each time, up to an hour.
func TestConntrackBackoff(t *testing.T) {
	defer func(m string, f func(*Tracer) error) { conntrackModule, loadConntrack = m, f }(conntrackModule, loadConntrack)
	conntrackModule = t.TempDir()
	var calls []time.Duration
	t0 := time.Unix(1e9, 0)
	now := t0
	loadConntrack = func(*Tracer) error {
		calls = append(calls, now.Sub(t0))
		return errors.New("kprobes are not available")
	}
	tr := &Tracer{opts: Options{LearnTranslations: true}, conntrackSpec: &ebpf.CollectionSpec{}, log: slog.New(slog.DiscardHandler)}
	for now = t0; now.Before(t0.Add(5 * time.Hour)); now = now.Add(time.Minute) {
		tr.tryConntrack(now)
	}
	var want []time.Duration
	for _, m := range []int{0, 1, 3, 7, 15, 31, 63, 123, 183, 243} {
		want = append(want, time.Duration(m)*time.Minute)
	}
	if len(calls) != len(want) {
		t.Fatalf("loads at %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("loads at %v, want %v", calls, want)
		}
	}
}

// TestConntrackLogs checks that the agent logs that nf_conntrack is not
// loaded, and then once that the programs fail to load when it is, rather
// than staying silent after the first message.
func TestConntrackLogs(t *testing.T) {
	defer func(m string, f func(*Tracer) error) { conntrackModule, loadConntrack = m, f }(conntrackModule, loadConntrack)
	conntrackModule = filepath.Join(t.TempDir(), "nf_conntrack")
	loadConntrack = func(*Tracer) error { return errors.New("perf_event_open: operation not permitted") }
	var logs bytes.Buffer
	tr := &Tracer{opts: Options{LearnTranslations: true}, conntrackSpec: &ebpf.CollectionSpec{},
		log: slog.New(slog.NewTextHandler(&logs, nil))}
	t0 := time.Unix(1e9, 0)
	tr.tryConntrack(t0)
	if err := os.Mkdir(conntrackModule, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		tr.tryConntrack(t0.Add(time.Duration(i+1) * time.Hour))
	}
	if n := strings.Count(logs.String(), "nf_conntrack is not loaded"); n != 1 {
		t.Errorf("logged %d times that nf_conntrack is not loaded:\n%s", n, &logs)
	}
	if n := strings.Count(logs.String(), "operation not permitted"); n != 1 {
		t.Errorf("logged %d times that the programs failed to load:\n%s", n, &logs)
	}
}

// xlatPrograms writes the maps of the translations as the conntrack
// programs do, for tests of user space without the kprobes. The active index
// of the flow maps is that of the tracer.
type xlatPrograms struct {
	t  *testing.T
	tr *Tracer
}

func xlatTestKey(port uint16) bpfShawkXlatKey {
	return bpfShawkXlatKey{Vport: port, Bport: port, Proto: 6}
}

// confirm is shawk_ct_confirm for a translated entry at address ct.
func (p xlatPrograms) confirm(ct uint64, port uint16) {
	p.t.Helper()
	k := xlatTestKey(port)
	if err := p.tr.xlatConns.Update(ct, k, ebpf.UpdateAny); err != nil {
		p.t.Fatal(err)
	}
	k.Idx = uint8(p.tr.idx & 1)
	if err := p.tr.xlats.Update(k, uint8(1), ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		p.t.Fatal(err)
	}
}

// destroy is shawk_ct_destroy.
func (p xlatPrograms) destroy(ct uint64) {
	p.t.Helper()
	if err := p.tr.xlatConns.Delete(ct); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		p.t.Fatal(err)
	}
}

// newXlatTracer returns a tracer with the maps of the translations alone.
func newXlatTracer(t *testing.T) *Tracer {
	t.Helper()
	requireRoot(t)
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{}
	for _, m := range []struct {
		name string
		dst  **ebpf.Map
	}{{bpfMapXlats, &tr.xlats}, {bpfMapXlatConns, &tr.xlatConns}} {
		ms := spec.Maps[m.name].Copy()
		ms.MaxEntries = 16
		if *m.dst, err = ebpf.NewMap(ms); err != nil {
			skipUnavailable(t, "creating the map: %v", err)
		}
		t.Cleanup(func() { (*m.dst).Close() })
	}
	return tr
}

// TestTranslationsConcurrentPrograms checks that the confirms and destroys
// that run while user space reads the translations are neither lost nor
// kept for ever (#237): user space deleted a translation that a program
// could update and put it back, so that a destroy in between left it live,
// and a confirm in between was lost. It also checks that translations are
// reported in the interval of their confirm and while an entry is alive.
func TestTranslationsConcurrentPrograms(t *testing.T) {
	tr := newXlatTracer(t)
	progs := xlatPrograms{t, tr}
	// collect closes the interval as Collect does: it flips the flow maps,
	// after which the programs run (afterFlip), and reads.
	collect := func(afterFlip func()) []uint16 {
		t.Helper()
		tr.idx ^= 1
		if afterFlip != nil {
			afterFlip()
		}
		xs, err := tr.collectTranslations()
		if err != nil {
			t.Fatal(err)
		}
		var ports []uint16
		for _, x := range xs {
			ports = append(ports, x.VirtualPort)
		}
		slices.Sort(ports)
		return ports
	}
	check := func(what string, got, want []uint16) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s: translations of ports %v, want %v", what, got, want)
		}
	}
	recorded := func(ct uint64, port uint16) {
		t.Helper()
		k := xlatTestKey(port)
		k.Idx = uint8(tr.idx)
		if err := tr.xlats.Lookup(k, new(uint8)); err != nil {
			t.Errorf("the confirm of entry %d is lost: %v", ct, err)
		}
	}

	// A long-lived entry, and one that comes and goes in the interval.
	progs.confirm(1, 1)
	progs.confirm(2, 2)
	progs.destroy(2)
	check("interval 1", collect(nil), []uint16{1, 2})

	// Entries come and go while user space reads the next interval: after
	// the flip, and between the walks and the deletes, where the long-lived
	// entry goes and a translation it reads gets a new entry.
	progs.confirm(4, 2)
	progs.destroy(4)
	defer func(f func()) { afterTranslationWalk = f }(afterTranslationWalk)
	afterTranslationWalk = func() {
		progs.destroy(1)
		progs.confirm(3, 2)
	}
	check("interval 2", collect(func() {
		progs.confirm(5, 5)
		progs.destroy(5)
	}), []uint16{1, 2})
	afterTranslationWalk = nil
	// What the programs wrote meanwhile is as they left it.
	recorded(3, 2)
	recorded(5, 5)
	if n := mapLen(t, tr.xlats); n != 2 {
		t.Errorf("%d translations recorded, want the 2 confirmed during the read", n)
	}
	var k bpfShawkXlatKey
	if err := tr.xlatConns.Lookup(uint64(1), &k); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the entry destroyed during the read is back: %+v, %v", k, err)
	}
	if err := tr.xlatConns.Lookup(uint64(3), &k); err != nil || k != xlatTestKey(2) {
		t.Errorf("the entry confirmed during the read: %+v, %v", k, err)
	}

	// The confirms during the read are reported with their interval.
	progs.destroy(3)
	check("interval 3", collect(nil), []uint16{2, 5})
	// Nothing is left once every entry is gone.
	check("interval 4", collect(nil), nil)
	for _, m := range []*ebpf.Map{tr.xlats, tr.xlatConns} {
		if n := mapLen(t, m); n != 0 {
			t.Errorf("%d entries left in %s", n, m)
		}
	}
}

// TestCollectTranslationError checks that an error reading the
// translations does not lose the flows of the interval.
func TestCollectTranslationError(t *testing.T) {
	tr := startTracer(t, Options{})
	// A map whose keys are not translations: reading it fails.
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		skipUnavailable(t, "creating the map: %v", err)
	}
	defer m.Close()
	if err := m.Put(uint32(1), uint32(1)); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	tr.xlats, tr.xlatConns = m, m
	tr.mu.Unlock()
	if _, err := tr.collectTranslations(); err == nil {
		t.Fatal("reading the map does not fail")
	}
	snap, err := tr.Collect()
	if err != nil || snap == nil {
		t.Fatalf("Collect = %v, %v", snap, err)
	}
}
