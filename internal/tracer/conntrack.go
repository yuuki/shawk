package tracer

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Translation is a translation of addresses that the host made, learned
// from conntrack: the client connected to Virtual on VirtualPort, and the
// backend at Backend on BackendPort saw the connection from Source, which
// is Client unless the host replaced the address of the client (SNAT,
// masquerade). DNAT, REDIRECT and IPVS change the virtual address or port
// into the backend.
type Translation struct {
	Proto       Proto
	NetNS       uint32 // the network namespace of the conntrack entry
	Client      netip.Addr
	Virtual     netip.Addr
	VirtualPort uint16
	Source      netip.Addr
	Backend     netip.Addr
	BackendPort uint16
}

// conntrackPrograms are attached to functions of the module nf_conntrack:
// the destroy program to the first of its targets that the kernel has.
var conntrackPrograms = []struct {
	prog    string
	targets []string
}{
	{bpfProgShawkCtConfirm, []string{"__nf_conntrack_confirm"}},
	// destroy_conntrack until Linux 5.19, where nf_ct_destroy was a pointer
	// to it; Rocky Linux 9 has the new name.
	{bpfProgShawkCtDestroy, []string{"nf_ct_destroy", "destroy_conntrack"}},
}

// conntrackMaps are created with the conntrack programs, only once
// nf_conntrack is loaded.
var conntrackMaps = []string{bpfMapXlats, bpfMapXlatConns}

// conntrackRetry is how often nf_conntrack is looked for until it is
// loaded. A load that fails with the module there is tried again after
// twice as long each time, up to conntrackMaxRetry: every attempt creates
// the maps, which are large, and relocates against the BTF of the modules.
const (
	conntrackRetry    = time.Minute
	conntrackMaxRetry = time.Hour
)

// conntrackModule exists while nf_conntrack is loaded or built in;
// replaced in tests.
var conntrackModule = "/sys/module/nf_conntrack"

// xlatConnsPerFlow sizes the table of live conntrack entries from MaxFlows.
const xlatConnsPerFlow = 4

// withoutConntrack removes the conntrack programs and their maps from a
// copy of the specification, so that another collection does not create
// the maps, which are large, on hosts without nf_conntrack.
func withoutConntrack(spec *ebpf.CollectionSpec) {
	for _, p := range conntrackPrograms {
		delete(spec.Programs, p.prog)
	}
	for _, m := range conntrackMaps {
		delete(spec.Maps, m)
	}
}

// TranslationsTraced reports whether the translations of addresses are
// learned from conntrack.
func (t *Tracer) TranslationsTraced() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.xlats != nil
}

// tryConntrack loads and attaches the conntrack programs if they are not,
// nf_conntrack is loaded, and the last attempt is older than
// conntrackRetry. That nf_conntrack is not loaded, and the first failure to
// load the programs, are logged once each. t.mu is held, or t is not
// shared yet.
func (t *Tracer) tryConntrack(now time.Time) {
	if !t.opts.LearnTranslations || t.xlats != nil || t.conntrackSpec == nil {
		return
	}
	wait := t.conntrackBackoff
	if wait == 0 {
		wait = conntrackRetry
	}
	if !t.conntrackTried.IsZero() && now.Sub(t.conntrackTried) < wait {
		return
	}
	t.conntrackTried = now
	if _, err := os.Stat(conntrackModule); err != nil {
		if !t.conntrackMissingLogged {
			t.conntrackMissingLogged = true
			t.log.Info("nf_conntrack is not loaded; translations of addresses are learned once it is")
		}
		return
	}
	if err := loadConntrack(t); err != nil {
		t.conntrackBackoff = min(max(2*t.conntrackBackoff, conntrackRetry), conntrackMaxRetry)
		if !t.conntrackFailLogged {
			t.conntrackFailLogged = true
			t.log.Warn("translations of addresses are not learned from conntrack; retrying, at most every hour", "error", err)
		}
		return
	}
	t.log.Info("learning translations of addresses from conntrack")
}

// loadConntrack is (*Tracer).loadConntrack; replaced in tests.
var loadConntrack = (*Tracer).loadConntrack

// loadConntrack loads the conntrack programs, sharing the maps of the core
// collection, and attaches them.
func (t *Tracer) loadConntrack() error {
	spec := t.conntrackSpec.Copy()
	want := map[string]bool{}
	for _, p := range conntrackPrograms {
		want[p.prog] = true
	}
	for name := range spec.Programs {
		if !want[name] {
			delete(spec.Programs, name)
		}
	}
	// The types of nf_conntrack may be in the BTF of its module, which
	// every load of a collection looks up again.
	replace := map[string]*ebpf.Map{}
	for name, m := range t.colls[0].Maps {
		replace[name] = m
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replace})
	if err != nil {
		return fmt.Errorf("loading the conntrack programs: %w", verifierError(err))
	}
	var links []link.Link
	fail := func(err error) error {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return err
	}
	for _, p := range conntrackPrograms {
		var errs []error
		for _, target := range p.targets {
			l, err := link.Kprobe(target, coll.Programs[p.prog], nil)
			if err == nil {
				links = append(links, l)
				errs = nil
				break
			}
			errs = append(errs, fmt.Errorf("%s: %w", target, err))
		}
		if errs != nil {
			return fail(fmt.Errorf("attaching %s: %w", p.prog, errors.Join(errs...)))
		}
	}
	drops, ok := t.colls[0].Variables[bpfVarXlatDrops]
	if !ok {
		return fail(errors.New("no variable xlat_drops"))
	}
	t.colls = append(t.colls, coll)
	t.links = append(t.links, links...)
	t.conntrackLinks = links
	for name, p := range coll.Programs {
		t.progs[name] = p
	}
	t.xlats = coll.Maps[bpfMapXlats]
	t.xlatConns = coll.Maps[bpfMapXlatConns]
	t.xlatDrops = drops
	return nil
}

// collectTranslations returns the translations used in the interval that
// flip() closed: those confirmed in it, which the programs recorded in xlats
// with the index of the flow maps of the interval, and those with a
// conntrack entry alive in xlat_conns. Then it deletes the keys of that
// index, which no program writes once the flip has waited for them. User
// space writes nothing else: deleting a key that a program may update, and
// putting it back, lost confirms and destroys that ran in between (#237).
func (t *Tracer) collectTranslations() ([]Translation, error) {
	if t.xlats == nil {
		return nil, nil
	}
	var (
		key  bpfShawkXlatKey
		one  uint8
		done []bpfShawkXlatKey
		out  []Translation
	)
	seen := map[bpfShawkXlatKey]bool{}
	add := func(k bpfShawkXlatKey) {
		k.Idx = 0
		if !seen[k] {
			seen[k] = true
			out = append(out, convertTranslation(&k))
		}
	}
	closed := uint8(t.idx ^ 1)
	it := t.xlats.Iterate()
	for it.Next(&key, &one) {
		// The others are of the interval that goes on. Keys that an error
		// left are read when their index is closed again.
		if key.Idx == closed {
			done = append(done, key)
			add(key)
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("reading translations: %w", err)
	}
	var ct uint64
	it = t.xlatConns.Iterate()
	for it.Next(&ct, &key) {
		add(key)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("reading the live entries of translations: %w", err)
	}
	if afterTranslationWalk != nil {
		afterTranslationWalk()
	}
	for i := range done {
		if err := t.xlats.Delete(&done[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("deleting a translation: %w", err)
		}
	}
	return out, nil
}

// afterTranslationWalk, if set, runs between the walks of the translations
// and the deletes of those confirmed in the interval; set in tests.
var afterTranslationWalk func()

func convertTranslation(k *bpfShawkXlatKey) Translation {
	return Translation{
		Proto:       Proto(k.Proto),
		NetNS:       k.Netns,
		Client:      addrFrom16(k.Client),
		Virtual:     addrFrom16(k.Virt),
		VirtualPort: k.Vport,
		Source:      addrFrom16(k.Source),
		Backend:     addrFrom16(k.Backend),
		BackendPort: k.Bport,
	}
}
