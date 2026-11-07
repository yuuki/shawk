package tracer

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// connectErrorPrograms record the error that ends an active open where the
// kernel produces it, before it stores it in sk_err, where an application
// that reads SO_ERROR may take it before the state change sees it: the
// failure would count as a timeout (#166). Each is attached on its own;
// without one, the reason of its failures is read from sk_err as before.
var connectErrorPrograms = []struct {
	prog, target string
	kprobe       bool
}{
	{bpfProgShawkTcpReceiveReset, "tcp_receive_reset", false},
	{bpfProgShawkIpIcmpError, "ip_icmp_error", true},
	// In the module ipv6 where IPv6 is not built in.
	{bpfProgShawkIpv6IcmpError, "ipv6_icmp_error", true},
}

// withoutConnectErrors removes connectErrorPrograms from a copy of the
// specification.
func withoutConnectErrors(spec *ebpf.CollectionSpec) {
	for _, p := range connectErrorPrograms {
		delete(spec.Programs, p.prog)
	}
}

// loadConnectErrors loads connectErrorPrograms, sharing the maps of the
// core collection, and attaches those it can. It returns the targets it
// attached, and an error for those it could not.
func (t *Tracer) loadConnectErrors(spec *ebpf.CollectionSpec) ([]string, error) {
	sub := spec.Copy()
	want := map[string]bool{}
	for _, p := range connectErrorPrograms {
		want[p.prog] = true
	}
	for name := range sub.Programs {
		if !want[name] {
			delete(sub.Programs, name)
		}
	}
	withoutConntrack(sub)
	coll, err := ebpf.NewCollectionWithOptions(sub, ebpf.CollectionOptions{MapReplacements: t.colls[0].Maps})
	if err != nil {
		return nil, fmt.Errorf("loading programs: %w", verifierError(err))
	}
	var (
		attached []string
		errs     []error
	)
	for _, p := range connectErrorPrograms {
		var (
			l   link.Link
			err error
		)
		if p.kprobe {
			l, err = link.Kprobe(p.target, coll.Programs[p.prog], nil)
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: coll.Programs[p.prog]})
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("attaching %s: %w", p.target, err))
			continue
		}
		t.links = append(t.links, l)
		attached = append(attached, p.target)
	}
	if len(attached) == 0 {
		coll.Close()
		return nil, errors.Join(errs...)
	}
	t.colls = append(t.colls, coll)
	for name, p := range coll.Programs {
		t.progs[name] = p
	}
	return attached, errors.Join(errs...)
}
