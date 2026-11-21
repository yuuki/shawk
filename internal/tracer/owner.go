package tracer

import (
	"cmp"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
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

// unixListenerKey identifies a listening Unix socket by its name (see
// UnixName) and its network namespace. Names of paths belong to file
// systems rather than to namespaces, but a name is mostly bound in the
// namespace of its server, and the netns tells apart the servers of
// containers that bind the same path in file systems of their own.
type unixListenerKey struct {
	netns uint32
	path  string
}

// listenPortMap is the subset of *ebpf.Map used to keep listen_ports and
// udp_listen_ports in sync with the listeners observed by a socket walk.
type listenPortMap interface {
	keys() ([]bpfShawkListenKey, error)
	delete(key bpfShawkListenKey) error
	putNoExist(key bpfShawkListenKey) error
}

type ebpfListenMap struct{ m *ebpf.Map }

func (e ebpfListenMap) keys() ([]bpfShawkListenKey, error) {
	var (
		key  bpfShawkListenKey
		val  uint8
		keys []bpfShawkListenKey
	)
	it := e.m.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func (e ebpfListenMap) delete(key bpfShawkListenKey) error {
	return e.m.Delete(&key)
}

func (e ebpfListenMap) putNoExist(key bpfShawkListenKey) error {
	return e.m.Update(&key, uint8(1), ebpf.UpdateNoExist)
}

// beforeSocketWalk, if set, runs after listen_ports is cleared and
// udp_listen_ports is snapshotted, before opening the socket iterators;
// set in tests.
var beforeSocketWalk func()

// scanSockets walks TCP and UDP sockets and returns the listeners and the
// inodes of their sockets, where known. The Comm of a listener that the
// kernel may hold is KernelComm, until its owner is resolved.
//
// The iterators are opened in every network namespace, since an iterator
// only walks the namespace it was opened in. listen_ports is cleared before
// the walk because it is read only synchronously during iter/tcp (where
// TCP_LISTEN sockets precede established ones) and iter/task_file
// afterwards. By contrast, udp_listen_ports is read asynchronously on every
// UDP datagram by udp_direction(): its existing entries are kept during the
// walk and only pre-existing keys absent from the newly observed UDP
// listeners are pruned afterwards (preserving ports inserted concurrently
// by udp_direction() during the walk), followed by backfilling newly
// observed UDP ports that may not have fit while stale entries occupied the
// map.
func (t *Tracer) scanSockets() ([]Listener, []uint64, error) {
	return scanSocketsWith(
		ebpfListenMap{t.listenPorts},
		ebpfListenMap{t.udpListenPorts},
		t.openAllNetNS,
	)
}

func scanSocketsWith(tcpPorts, udpPorts listenPortMap, open func() ([]io.ReadCloser, error)) ([]Listener, []uint64, error) {
	prevUDP, err := udpPorts.keys()
	if err != nil {
		return nil, nil, err
	}
	if err := clearListenPorts(tcpPorts); err != nil {
		return nil, nil, err
	}
	if beforeSocketWalk != nil {
		beforeSocketWalk()
	}
	readers, err := open()
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
	activeUDP := make(map[bpfShawkListenKey]struct{}, len(prevUDP))
	for _, rd := range readers {
		recs, err := readRecords(rd)
		if err != nil {
			return nil, nil, err
		}
		for i := range recs {
			r := &recs[i]
			if r.Type != recListener {
				continue
			}
			if r.Ino != 0 {
				inos = append(inos, r.Ino)
			}
			if Proto(r.Proto) == ProtoUDP {
				activeUDP[bpfShawkListenKey{Netns: r.Netns, Port: r.Port}] = struct{}{}
			}
			listeners = addListener(listeners, seen, listenerOf(r))
		}
	}
	if err := syncUDPListenPorts(udpPorts, prevUDP, activeUDP); err != nil {
		return nil, nil, err
	}
	return listeners, inos, nil
}

// addListener adds a listener to those of a walk of the sockets, of which
// seen holds the indexes: the sockets that share its address and its port
// are one listener.
func addListener(listeners []Listener, seen map[sockAddrKey]int, l Listener) []Listener {
	k := listenerKey(&l)
	j, ok := seen[k]
	if !ok {
		seen[k] = len(listeners)
		return append(listeners, l)
	}
	if l.Comm != "" {
		listeners[j].Comm = l.Comm
	}
	listeners[j].KernelChosen = listeners[j].KernelChosen || l.KernelChosen
	return listeners
}

// listenerOf converts the record of a listening socket that a walk of the
// sockets found. Its Comm is KernelComm if the kernel may hold the socket,
// and empty otherwise.
func listenerOf(r *bpfShawkIterRec) Listener {
	l := Listener{
		Proto:        Proto(r.Proto),
		Addr:         addrFrom16(r.Addr),
		Port:         r.Port,
		NetNS:        r.Netns,
		KernelChosen: r.KernelChosen != 0,
	}
	if commString(r.Comm) == KernelComm {
		l.Comm = KernelComm
	}
	return l
}

func clearListenPorts(m listenPortMap) error {
	keys, err := m.keys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// syncUDPListenPorts deletes pre-existing keys absent from active and
// backfills newly observed keys that may not have fit while stale entries
// occupied the map during the walk.
func syncUDPListenPorts(m listenPortMap, prev []bpfShawkListenKey, active map[bpfShawkListenKey]struct{}) error {
	prevSet := make(map[bpfShawkListenKey]struct{}, len(prev))
	for _, key := range prev {
		prevSet[key] = struct{}{}
		if _, ok := active[key]; ok {
			continue
		}
		if err := m.delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	for key := range active {
		if _, ok := prevSet[key]; ok {
			continue
		}
		if err := m.putNoExist(key); err != nil && !errors.Is(err, ebpf.ErrKeyExist) && !errors.Is(err, unix.E2BIG) {
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
	unixOwners := map[unixListenerKey][]owner{}
	held := make(map[uint64]bool, len(recs))
	for i := range recs {
		r := &recs[i]
		if r.Type != recOwner {
			continue
		}
		if Proto(r.Proto) == ProtoUnix {
			k := unixListenerKey{netns: r.Netns, path: UnixName(recPath(r))}
			if !slices.ContainsFunc(unixOwners[k], func(o owner) bool { return o.pid == r.Pid }) {
				unixOwners[k] = append(unixOwners[k], owner{pid: r.Pid, comm: commString(r.Comm), cgroupID: r.CgroupId})
			}
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
	t.unixOwners = unixOwners
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

// recPath returns the bytes of the name of a Unix socket of a record.
func recPath(r *bpfShawkIterRec) []byte {
	b := make([]byte, min(int(r.PathLen), len(r.Path)))
	for i := range b {
		b[i] = byte(r.Path[i])
	}
	return b
}

// unixListeners returns the listening Unix sockets that the last owner scan
// found, each with its preferred owner: the service rather than systemd for
// socket activation, the parent among forked workers. They are found by the
// walks of the processes only, since iter/unix is not available on every
// kernel: a listener is reported from the scan after it appeared until the
// scan after it closed.
func (t *Tracer) unixListeners() []Listener {
	out := make([]Listener, 0, len(t.unixOwners))
	for k, owners := range t.unixOwners {
		if o, ok := preferredOwner(owners); ok {
			out = append(out, Listener{Proto: ProtoUnix, Path: k.path, NetNS: k.netns, PID: o.pid, Comm: o.comm, CgroupID: o.cgroupID})
		}
	}
	slices.SortFunc(out, func(a, b Listener) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), cmp.Compare(a.NetNS, b.NetNS))
	})
	return out
}

// hasUnixListener reports whether the last owner scan found a listener of
// the name path in any network namespace: a client may reach a path
// through a mount from another namespace than that of its server.
func (t *Tracer) hasUnixListener(path string) bool {
	for k := range t.unixOwners {
		if k.path == path {
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
