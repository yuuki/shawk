package tracer

import (
	"errors"
	"log/slog"
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

// TestTranslationsIdleRace checks that a translation idle at the walk that
// gets a connection before it is deleted is put back and reported, and
// that idle ones are deleted. It uses the map alone, which user space
// writes as the programs would.
func TestTranslationsIdleRace(t *testing.T) {
	requireRoot(t)
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	ms := spec.Maps[bpfMapXlats].Copy()
	ms.MaxEntries = 16
	m, err := ebpf.NewMap(ms)
	if err != nil {
		skipUnavailable(t, "creating the map: %v", err)
	}
	defer m.Close()
	tr := &Tracer{xlats: m, xlatLast: map[bpfShawkXlatKey]bpfShawkXlatStats{}}
	key := func(port uint16) bpfShawkXlatKey { return bpfShawkXlatKey{Vport: port, Bport: port, Proto: 6} }
	for _, p := range []uint16{1, 2} {
		if err := m.Update(key(p), bpfShawkXlatStats{Conns: 1, Gen: 7}, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
	}
	collectN := func() int {
		xs, err := tr.collectTranslations()
		if err != nil {
			t.Fatal(err)
		}
		return len(xs)
	}
	if n := collectN(); n != 2 {
		t.Fatalf("%d new translations, want 2", n)
	}
	// Both are idle at the walk; key 1 gets a connection before the deletes.
	defer func(f func()) { afterTranslationWalk = f }(afterTranslationWalk)
	afterTranslationWalk = func() {
		if err := m.Update(key(1), bpfShawkXlatStats{Conns: 2, Live: 1, Gen: 7}, ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}
	}
	if n := collectN(); n != 1 {
		t.Errorf("%d translations reported, want the one that got a connection", n)
	}
	var v bpfShawkXlatStats
	if err := m.Lookup(key(1), &v); err != nil || v.Live != 1 || v.Conns != 2 {
		t.Errorf("translation with a connection: %+v, %v", v, err)
	}
	if err := m.Lookup(key(2), &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("idle translation kept: %+v, %v", v, err)
	}
}
