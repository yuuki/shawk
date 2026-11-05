package tracer

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/cilium/ebpf"
)

type sockAddrKey struct {
	proto Proto
	netns uint32
	addr  [16]uint8
	port  uint16
}

type owner struct {
	pid      uint32
	comm     string
	cgroupID uint64
}

// scanSockets walks TCP and UDP sockets and returns the listeners and the
// inodes of their sockets, where known. The Comm of a listener that the
// kernel may hold is KernelComm, until its owner is resolved.
//
// The iterators are opened in every network namespace, since an iterator
// only walks the namespace it was opened in.
func (t *Tracer) scanSockets() ([]Listener, []uint64, error) {
	for _, m := range []*ebpf.Map{t.listenPorts, t.udpListenPorts} {
		if err := clearMap(m); err != nil {
			return nil, nil, err
		}
	}
	readers, err := t.openAllNetNS()
	defer closeAll(readers)
	if err != nil {
		return nil, nil, err
	}

	var (
		listeners []Listener
		inos      []uint64
	)
	// The sockets of a SO_REUSEPORT group share an address and a port.
	seen := map[sockAddrKey]int{}
	for _, rd := range readers {
		recs, err := readRecords(rd)
		if err != nil {
			return nil, nil, err
		}
		for i := range recs {
			if recs[i].Type != recListener {
				continue
			}
			if recs[i].Ino != 0 {
				inos = append(inos, recs[i].Ino)
			}
			l := Listener{
				Proto:        Proto(recs[i].Proto),
				Addr:         addrFrom16(recs[i].Addr),
				Port:         recs[i].Port,
				NetNS:        recs[i].Netns,
				KernelChosen: recs[i].KernelChosen != 0,
			}
			if commString(recs[i].Comm) == KernelComm {
				l.Comm = KernelComm
			}
			k := listenerKey(&l)
			if j, ok := seen[k]; ok {
				if l.Comm != "" {
					listeners[j].Comm = l.Comm
				}
				listeners[j].KernelChosen = listeners[j].KernelChosen || l.KernelChosen
				continue
			}
			seen[k] = len(listeners)
			listeners = append(listeners, l)
		}
	}
	return listeners, inos, nil
}

func clearMap(m *ebpf.Map) error {
	var (
		key  bpfShawkListenKey
		val  uint8
		keys []bpfShawkListenKey
	)
	it := m.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// refreshOwners scans the owners and remembers the listeners, of those the
// last walk found, that it found no holder of.
func (t *Tracer) refreshOwners(listeners []Listener, inos []uint64) error {
	if err := t.scanOwners(); err != nil {
		return err
	}
	var skips uint64
	if err := t.iterSkips.Get(&skips); err != nil {
		return err
	}
	t.skipping = skips != t.lastSkips
	t.lastSkips = skips
	t.ownerless = map[sockAddrKey]bool{}
	t.kernel = map[sockAddrKey]bool{}
	for i := range listeners {
		if k := listenerKey(&listeners[i]); !t.hasOwner(k) {
			t.ownerless[k] = true
			if listeners[i].Comm == KernelComm {
				t.kernel[k] = true
			}
		}
	}
	t.unheld = map[uint64]bool{}
	t.listening = make(map[uint64]bool, len(inos))
	for _, ino := range inos {
		t.listening[ino] = true
		if !t.held[ino] {
			t.unheld[ino] = true
		}
	}
	return nil
}

// scanOwners walks the file descriptors of all processes. It assigns owners
// to adopted connections in the kernel and caches the owners of listening
// sockets.
func (t *Tracer) scanOwners() error {
	// Each walk records the owner of an MPTCP connection once, replacing
	// what an earlier walk recorded.
	t.ownerScans++
	if err := t.ownerScan.Set(t.ownerScans); err != nil {
		return err
	}
	recs, err := readIter(t.iterTaskFile)
	if err != nil {
		return err
	}
	owners := make(map[sockAddrKey][]owner, len(recs))
	held := make(map[uint64]bool, len(recs))
	for i := range recs {
		r := &recs[i]
		if r.Type != recOwner {
			continue
		}
		if r.Ino != 0 {
			held[r.Ino] = true
		}
		k := sockAddrKey{proto: Proto(r.Proto), netns: r.Netns, addr: r.Addr, port: r.Port}
		if slices.ContainsFunc(owners[k], func(o owner) bool { return o.pid == r.Pid }) {
			continue
		}
		owners[k] = append(owners[k], owner{pid: r.Pid, comm: commString(r.Comm), cgroupID: r.CgroupId})
	}
	t.owners = owners
	t.held = held
	t.lastOwnScan = time.Now()
	return nil
}

// hasNewListener reports whether the owners of listeners may have changed
// since the last owner scan: a listener appeared on a new address, or a
// socket appeared or went away on a known one. A service restarted in the
// same cgroup, which the cgroup of the connections it accepts does not tell
// from the former one, creates a new socket; with SO_REUSEPORT it may do so
// before the former process closes its own.
func (t *Tracer) hasNewListener(listeners []Listener, inos []uint64) bool {
	for i := range listeners {
		k := listenerKey(&listeners[i])
		if !t.hasOwner(k) && !t.ownerless[k] {
			return true
		}
	}
	current := make(map[uint64]bool, len(inos))
	for _, ino := range inos {
		if !t.held[ino] && !t.unheld[ino] {
			return true
		}
		current[ino] = true
	}
	for ino := range t.listening {
		if !current[ino] {
			return true
		}
	}
	return false
}

func (t *Tracer) hasOwner(k sockAddrKey) bool {
	return len(t.owners[k]) > 0
}

func listenerKey(l *Listener) sockAddrKey {
	return sockAddrKey{proto: l.Proto, netns: l.NetNS, addr: l.Addr.As16(), port: l.Port}
}

// listenerOwners returns the processes holding the socket listening on
// addr:port, falling back to wildcard listeners of the address family. An
// IPv4 connection may also be accepted by a dual-stack IPv6 listener.
//
// kernel reports a listener of the kernel: one that the BPF programs found
// the kernel may hold (created by the kernel, e.g. by nfsd, without a file,
// or used by the kernel, as a socket that rpc.nfsd creates and passes to
// nfsd), and that no process held at the last owner scan. Either alone is
// not enough: processes the agent cannot see, in another PID namespace,
// hold listeners too, and the first subflow of an MPTCP listener is a socket
// of the kernel that a process holds.
func (t *Tracer) listenerOwners(proto Proto, netns uint32, addr netip.Addr, port uint16) (holders []owner, kernel bool) {
	candidates := []netip.Addr{addr, netip.IPv6Unspecified()}
	if addr.Is4() {
		candidates = []netip.Addr{addr, netip.IPv4Unspecified(), netip.IPv6Unspecified()}
	}
	for _, a := range candidates {
		k := sockAddrKey{proto: proto, netns: netns, addr: a.As16(), port: port}
		if holders := t.owners[k]; len(holders) > 0 {
			return holders, false
		}
		if t.kernel[k] {
			return nil, true
		}
	}
	return nil, false
}

// chooseOwner picks the process an accepted connection belongs to among the
// holders of its listener. cgroupID is the cgroup of the accepted socket,
// i.e. of the process that created the listener, or zero if unknown.
func chooseOwner(cands []owner, cgroupID uint64) (owner, bool) {
	if len(cands) == 0 {
		return owner{}, false
	}
	// With socket activation, systemd (PID 1) creates the listener and shares
	// it with the service, so accepted sockets carry systemd's cgroup; the
	// service is the owner.
	var (
		rest      []owner
		activated bool
	)
	for _, c := range cands {
		if c.pid == 1 {
			activated = true
			continue
		}
		rest = append(rest, c)
	}
	if len(rest) == 0 {
		return cands[0], true
	}
	if cgroupID != 0 && !activated {
		// Programs sharing a port with SO_REUSEPORT have their own listeners
		// created in their own cgroups.
		return preferredOwner(slices.DeleteFunc(rest, func(c owner) bool { return c.cgroupID != cgroupID }))
	}
	return preferredOwner(rest)
}

// preferredOwner picks the owner of a socket held by several processes: the
// service rather than systemd (PID 1) for socket activation, and the parent
// (the lowest PID) among forked workers.
func preferredOwner(cands []owner) (owner, bool) {
	var (
		best owner
		ok   bool
	)
	for _, c := range cands {
		if !ok || preferOwner(c.pid, best.pid) {
			best, ok = c, true
		}
	}
	return best, ok
}

func preferOwner(pid, cur uint32) bool {
	if cur == 1 {
		return pid != 1
	}
	return pid != 1 && pid < cur
}
