// Package tracer discovers network service dependencies by bundling TCP/UDP
// flows in the Linux kernel with eBPF.
package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	defaultMaxFlows = 16384
)

// Options configures a Tracer.
type Options struct {
	// NetNS restricts tracing to the network namespace with this inode
	// number. Zero traces all network namespaces.
	NetNS uint32
	// MaxFlows is the capacity of the in-kernel flow table per interval.
	MaxFlows uint32
	// OwnerScanInterval is how often the owners of listening sockets are
	// resolved by walking the file descriptors of all processes.
	OwnerScanInterval time.Duration
	// TraceSelf includes the flows of the tracing process itself, which are
	// excluded by default. It is meant for testing.
	TraceSelf bool
	// OnCgroup is called with the id and path of every cgroup v2 created on
	// the host, so that the paths of short-lived cgroups can be resolved
	// after they are removed. It is called from a separate goroutine.
	OnCgroup func(id uint64, path string)
	Logger   *slog.Logger
}

// Tracer loads the BPF programs and collects bundled flows.
type Tracer struct {
	opts  Options
	log   *slog.Logger
	colls []*ebpf.Collection
	progs map[string]*ebpf.Program
	links []link.Link
	udp   bool

	flowMaps       [2]*ebpf.Map
	flowsOuter     *ebpf.Map
	listenPorts    *ebpf.Map
	udpListenPorts *ebpf.Map
	initialScan    *ebpf.Variable
	activeIdx      *ebpf.Variable
	flowDrops      *ebpf.Variable
	adopted        *ebpf.Variable
	selfTgid       *ebpf.Variable

	cgroupEvents *ringbuf.Reader
	cgroupDone   chan struct{}

	iterTCP      *link.Iter
	iterUDP      *link.Iter
	iterTaskFile *link.Iter

	self  uint32 // global thread group id of this process
	netns uint32 // network namespace of this process

	mu     sync.Mutex
	idx    uint32
	owners map[sockAddrKey][]owner
	// ownerMissing requests an owner scan after an accepted connection
	// matched no holder of its listener.
	ownerMissing bool
	// ownerless are the listeners whose owner the last scan could not find,
	// e.g. sockets of the kernel. They do not trigger another scan.
	ownerless   map[sockAddrKey]bool
	lastOwnScan time.Time
	lastAdopted uint64
	statsCloser io.Closer
}

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

// udpPrograms hook kernel functions with BPF trampolines (fentry). They are
// loaded separately so that TCP tracing keeps working on kernels that do not
// support trampolines (e.g. arm64 before Linux 6.0).
var udpPrograms = []struct{ prog, target string }{
	{bpfProgShawkIpSendSkb, "ip_send_skb"},
	{bpfProgShawkIp6SendSkb, "ip6_send_skb"},
	{bpfProgShawkSkbConsumeUdp, "skb_consume_udp"},
}

// New loads and attaches the BPF programs. It requires CAP_BPF and
// CAP_PERFMON (or root) and a kernel with BTF.
func New(opts Options) (*Tracer, error) {
	if opts.MaxFlows == 0 {
		opts.MaxFlows = defaultMaxFlows
	}
	if opts.OwnerScanInterval == 0 {
		opts.OwnerScanInterval = time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	// Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	t := &Tracer{
		opts:   opts,
		log:    opts.Logger,
		owners: map[sockAddrKey][]owner{},
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		return nil, fmt.Errorf("finding the network namespace: %w", err)
	}
	t.netns = uint32(st.Ino)
	if err := t.configure(spec); err != nil {
		return nil, err
	}

	if err := t.loadCore(spec); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.loadUDP(spec); err != nil {
		t.log.Warn("UDP tracing is disabled", "error", err)
	} else {
		t.udp = true
	}

	// Adopt connections and listeners that existed before the tracer
	// started, then resolve their owners. The first walk also tells the
	// programs which process the tracer is, and marks the UDP server sockets.
	if err := t.initialScan.Set(uint32(1)); err != nil {
		t.Close()
		return nil, err
	}
	if _, err := t.scanSockets(); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.initialScan.Set(uint32(0)); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.selfTgid.Get(&t.self); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.scanOwners(); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// configure sets the load-time variables and the map sizes.
func (t *Tracer) configure(spec *ebpf.CollectionSpec) error {
	low, high := ephemeralPortRange()
	vars := map[string]any{
		bpfVarLearnSelf:   !t.opts.TraceSelf,
		bpfVarTargetNetns: t.opts.NetNS,
		bpfVarEphPortLow:  low,
		bpfVarEphPortHigh: high,
	}
	for name, v := range vars {
		if err := spec.Variables[name].Set(v); err != nil {
			return fmt.Errorf("setting %s: %w", name, err)
		}
	}
	for _, name := range []string{bpfMapFlows0, bpfMapFlows1} {
		spec.Maps[name].MaxEntries = t.opts.MaxFlows
	}
	spec.Maps[bpfMapFlows].InnerMap.MaxEntries = t.opts.MaxFlows
	return nil
}

// loadCore loads the maps, the TCP programs and the iterators.
func (t *Tracer) loadCore(spec *ebpf.CollectionSpec) error {
	core := spec.Copy()
	for _, p := range udpPrograms {
		delete(core.Programs, p.prog)
	}
	coll, err := ebpf.NewCollection(core)
	if err != nil {
		return fmt.Errorf("loading BPF objects: %w", verifierError(err))
	}
	t.colls = append(t.colls, coll)
	t.progs = maps.Clone(coll.Programs)
	t.flowMaps = [2]*ebpf.Map{coll.Maps[bpfMapFlows0], coll.Maps[bpfMapFlows1]}
	t.flowsOuter = coll.Maps[bpfMapFlows]
	t.listenPorts = coll.Maps[bpfMapListenPorts]
	t.udpListenPorts = coll.Maps[bpfMapUdpListenPorts]
	t.initialScan = coll.Variables[bpfVarInitialScan]
	t.activeIdx = coll.Variables[bpfVarActiveIdx]
	t.flowDrops = coll.Variables[bpfVarFlowDrops]
	t.adopted = coll.Variables[bpfVarAdoptedUnowned]
	t.selfTgid = coll.Variables[bpfVarSelfTgid]

	l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[bpfProgShawkInetSockSetState]})
	if err != nil {
		return fmt.Errorf("attaching inet_sock_set_state: %w", err)
	}
	t.links = append(t.links, l)

	if t.iterTCP, err = link.AttachIter(link.IterOptions{Program: coll.Programs[bpfProgShawkIterTcp]}); err != nil {
		return fmt.Errorf("attaching TCP iterator: %w", err)
	}
	t.links = append(t.links, t.iterTCP)
	if t.iterUDP, err = link.AttachIter(link.IterOptions{Program: coll.Programs[bpfProgShawkIterUdp]}); err != nil {
		return fmt.Errorf("attaching UDP iterator: %w", err)
	}
	t.links = append(t.links, t.iterUDP)
	if t.iterTaskFile, err = link.AttachIter(link.IterOptions{Program: coll.Programs[bpfProgShawkIterTaskFile]}); err != nil {
		return fmt.Errorf("attaching task_file iterator: %w", err)
	}
	t.links = append(t.links, t.iterTaskFile)

	if t.opts.OnCgroup != nil {
		if err := t.watchCgroups(coll); err != nil {
			t.log.Warn("paths of short-lived cgroups are not resolved", "error", err)
		}
	}
	return nil
}

// watchCgroups reports the cgroups created on the host to OnCgroup.
func (t *Tracer) watchCgroups(coll *ebpf.Collection) error {
	rd, err := ringbuf.NewReader(coll.Maps[bpfMapCgroupEvents])
	if err != nil {
		return err
	}
	l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[bpfProgShawkCgroupMkdir]})
	if err != nil {
		rd.Close()
		return fmt.Errorf("attaching cgroup_mkdir: %w", err)
	}
	t.links = append(t.links, l)
	t.cgroupEvents = rd
	t.cgroupDone = make(chan struct{})
	go func() {
		defer close(t.cgroupDone)
		var e bpfShawkCgroupEvent
		for {
			rec, err := rd.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					t.log.Error("reading cgroup events", "error", err)
				}
				return
			}
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &e); err != nil {
				continue
			}
			t.opts.OnCgroup(e.Id, cString(e.Path[:]))
		}
	}()
	return nil
}

// loadUDP loads the UDP programs sharing the maps of the core collection.
func (t *Tracer) loadUDP(spec *ebpf.CollectionSpec) error {
	udp := spec.Copy()
	want := map[string]bool{}
	for _, p := range udpPrograms {
		want[p.prog] = true
	}
	for name := range udp.Programs {
		if !want[name] {
			delete(udp.Programs, name)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(udp, ebpf.CollectionOptions{MapReplacements: t.colls[0].Maps})
	if err != nil {
		return fmt.Errorf("loading UDP programs: %w", verifierError(err))
	}
	var links []link.Link
	for _, p := range udpPrograms {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[p.prog]})
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			coll.Close()
			return fmt.Errorf("attaching %s: %w", p.target, err)
		}
		links = append(links, l)
	}
	t.colls = append(t.colls, coll)
	t.links = append(t.links, links...)
	for name, p := range coll.Programs {
		t.progs[name] = p
	}
	return nil
}

func verifierError(err error) error {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		return fmt.Errorf("%+v", verr)
	}
	return err
}

// SelfPID returns the process id of the tracer as the kernel sees it. It
// differs from os.Getpid() when the tracer runs in a PID namespace, in which
// case processes outside the namespace cannot be resolved as owners.
func (t *Tracer) SelfPID() uint32 { return t.self }

// UDPEnabled reports whether UDP datagrams are traced.
func (t *Tracer) UDPEnabled() bool { return t.udp }

// Close detaches and unloads the BPF programs.
func (t *Tracer) Close() error {
	if t.cgroupEvents != nil {
		t.cgroupEvents.Close()
		<-t.cgroupDone
		t.cgroupEvents = nil
	}
	for _, l := range t.links {
		l.Close()
	}
	t.links = nil
	if t.statsCloser != nil {
		t.statsCloser.Close()
		t.statsCloser = nil
	}
	for _, c := range t.colls {
		c.Close()
	}
	t.colls = nil
	return nil
}

// Collect closes the current interval and returns the bundled flows and the
// listening sockets observed in it.
func (t *Tracer) Collect() (*Snapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Walking sockets accounts the traffic of long-lived connections into the
	// current interval and refreshes the listening ports.
	listeners, err := t.scanSockets()
	if err != nil {
		return nil, err
	}
	var adopted uint64
	if err := t.adopted.Get(&adopted); err != nil {
		return nil, err
	}
	if adopted != t.lastAdopted || t.ownerMissing || time.Since(t.lastOwnScan) >= t.opts.OwnerScanInterval ||
		t.hasNewListener(listeners) {
		if err := t.scanOwners(); err != nil {
			return nil, err
		}
		t.lastAdopted = adopted
		t.ownerMissing = false
		t.ownerless = map[sockAddrKey]bool{}
		for i := range listeners {
			if k := listenerKey(&listeners[i]); !t.hasOwner(k) {
				t.ownerless[k] = true
			}
		}
	}
	for i := range listeners {
		if o, ok := preferredOwner(t.owners[listenerKey(&listeners[i])]); ok {
			listeners[i].PID = o.pid
			listeners[i].Comm = o.comm
			listeners[i].CgroupID = o.cgroupID
		}
	}

	flows, err := t.flip()
	if err != nil {
		return nil, err
	}
	flows = t.attribute(flows)
	var drops uint64
	if err := t.flowDrops.Get(&drops); err != nil {
		return nil, err
	}
	return &Snapshot{Flows: flows, Listeners: listeners, Drops: drops}, nil
}

// flip switches the active flow map and drains the previous one.
func (t *Tracer) flip() ([]Flow, error) {
	old := t.idx
	next := old ^ 1
	if err := t.activeIdx.Set(next); err != nil {
		return nil, fmt.Errorf("switching flow map: %w", err)
	}
	t.idx = next
	// Programs that read the old index may still be updating the old map.
	// Updating an element of a map-in-map makes the kernel wait for an RCU
	// grace period, after which they have all finished.
	if err := t.flowsOuter.Update(old, t.flowMaps[old], ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("waiting for programs: %w", err)
	}

	m := t.flowMaps[old]
	var (
		key   bpfShawkFlowKey
		val   bpfShawkFlowStats
		flows []Flow
		keys  []bpfShawkFlowKey
	)
	it := m.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
		flows = append(flows, convertFlow(&key, &val))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("reading flows: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("deleting flow: %w", err)
		}
	}
	return flows, nil
}

// attribute assigns incoming TCP flows to the owner of the listening
// socket, drops the flows of the tracer itself and merges flows that end up
// with the same key.
func (t *Tracer) attribute(flows []Flow) []Flow {
	merged := make(map[FlowKey]int, len(flows))
	out := flows[:0]
	for _, f := range flows {
		// Incoming connections that were adopted after their listener was
		// closed already carry the process holding them.
		if f.Direction == DirIn && f.Proto == ProtoTCP && f.PID == 0 {
			cands := t.listenerOwners(f.Proto, f.NetNS, f.LocalAddr, f.Port)
			if o, ok := chooseOwner(cands, f.CgroupID); ok {
				f.Comm = o.comm
				f.CgroupID = o.cgroupID
				f.PID = o.pid
			} else {
				// The listener is gone or changed hands since the last scan.
				// The cgroup taken from the socket still names the service.
				t.ownerMissing = true
			}
		}
		if !t.opts.TraceSelf && f.PID == t.self {
			continue
		}
		if i, ok := merged[f.FlowKey]; ok {
			out[i].FlowStats.Add(f.FlowStats)
			continue
		}
		merged[f.FlowKey] = len(out)
		out = append(out, f)
	}
	return out
}

// listenerOwners returns the processes holding the socket listening on
// addr:port, falling back to wildcard listeners of the address family. An
// IPv4 connection may also be accepted by a dual-stack IPv6 listener.
func (t *Tracer) listenerOwners(proto Proto, netns uint32, addr netip.Addr, port uint16) []owner {
	candidates := []netip.Addr{addr, netip.IPv6Unspecified()}
	if addr.Is4() {
		candidates = []netip.Addr{addr, netip.IPv4Unspecified(), netip.IPv6Unspecified()}
	}
	for _, a := range candidates {
		if holders := t.owners[sockAddrKey{proto: proto, netns: netns, addr: a.As16(), port: port}]; len(holders) > 0 {
			return holders
		}
	}
	return nil
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

func convertFlow(k *bpfShawkFlowKey, v *bpfShawkFlowStats) Flow {
	return Flow{
		FlowKey: FlowKey{
			Direction:  Direction(k.Direction),
			Proto:      Proto(k.Proto),
			LocalAddr:  addrFrom16(k.Laddr),
			RemoteAddr: addrFrom16(k.Raddr),
			Port:       k.Port,
			NetNS:      k.Netns,
			CgroupID:   k.CgroupId,
			Comm:       commString(k.Comm),
		},
		FlowStats: FlowStats{
			Conns:      uint64(v.Conns),
			ConnFails:  uint64(v.ConnFails),
			OpenConns:  uint64(v.OpenConns),
			BytesSent:  v.BytesSent,
			BytesRecv:  v.BytesRecv,
			MsgsSent:   uint64(v.MsgsSent),
			MsgsRecv:   uint64(v.MsgsRecv),
			Retrans:    uint64(v.Retrans),
			RTTSumUs:   v.RttSumUs,
			RTTSamples: uint64(v.RttSamples),
			PID:        v.Pid,
		},
	}
}

// scanSockets walks TCP and UDP sockets and returns the listening sockets.
//
// The iterators are opened in every network namespace, since an iterator
// only walks the namespace it was opened in.
func (t *Tracer) scanSockets() ([]Listener, error) {
	for _, m := range []*ebpf.Map{t.listenPorts, t.udpListenPorts} {
		if err := clearMap(m); err != nil {
			return nil, err
		}
	}
	var readers []io.ReadCloser
	for _, ns := range listNetNS(t.opts.NetNS) {
		if ns.inode == t.netns {
			rcs, err := openIters(t.iterTCP, t.iterUDP)
			if err != nil {
				closeAll(readers)
				return nil, err
			}
			readers = append(readers, rcs...)
			continue
		}
		rcs, err := openInNetNS(ns.path, t.iterTCP, t.iterUDP)
		if err != nil {
			// The namespace may have gone away since it was listed.
			t.log.Debug("skipping network namespace", "netns", ns.inode, "error", err)
			continue
		}
		readers = append(readers, rcs...)
	}
	defer closeAll(readers)

	var listeners []Listener
	for _, rd := range readers {
		recs, err := readRecords(rd)
		if err != nil {
			return nil, err
		}
		for i := range recs {
			if recs[i].Type != recListener {
				continue
			}
			listeners = append(listeners, Listener{
				Proto: Proto(recs[i].Proto),
				Addr:  addrFrom16(recs[i].Addr),
				Port:  recs[i].Port,
				NetNS: recs[i].Netns,
			})
		}
	}
	return listeners, nil
}

// scanOwners walks the file descriptors of all processes. It assigns owners
// to adopted connections in the kernel and caches the owners of listening
// sockets.
func (t *Tracer) scanOwners() error {
	recs, err := readIter(t.iterTaskFile)
	if err != nil {
		return err
	}
	owners := make(map[sockAddrKey][]owner, len(recs))
	for i := range recs {
		r := &recs[i]
		if r.Type != recOwner {
			continue
		}
		k := sockAddrKey{proto: Proto(r.Proto), netns: r.Netns, addr: r.Addr, port: r.Port}
		if slices.ContainsFunc(owners[k], func(o owner) bool { return o.pid == r.Pid }) {
			continue
		}
		owners[k] = append(owners[k], owner{pid: r.Pid, comm: commString(r.Comm), cgroupID: r.CgroupId})
	}
	t.owners = owners
	t.lastOwnScan = time.Now()
	return nil
}

func preferOwner(pid, cur uint32) bool {
	if cur == 1 {
		return pid != 1
	}
	return pid != 1 && pid < cur
}

// hasNewListener reports whether a listener appeared whose owner is not
// known yet.
func (t *Tracer) hasNewListener(listeners []Listener) bool {
	for i := range listeners {
		k := listenerKey(&listeners[i])
		if !t.hasOwner(k) && !t.ownerless[k] {
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

const (
	recListener = 1
	recOwner    = 2
)

func readIter(it *link.Iter) ([]bpfShawkIterRec, error) {
	rd, err := it.Open()
	if err != nil {
		return nil, fmt.Errorf("opening iterator: %w", err)
	}
	defer rd.Close()
	return readRecords(rd)
}

func readRecords(rd io.Reader) ([]bpfShawkIterRec, error) {
	buf, err := readIterOutput(rd)
	if err != nil {
		return nil, fmt.Errorf("reading iterator: %w", err)
	}
	return decodeRecords(buf)
}

// openIters opens the iterators in the current network namespace.
func openIters(its ...*link.Iter) ([]io.ReadCloser, error) {
	var rcs []io.ReadCloser
	for _, it := range its {
		rc, err := it.Open()
		if err != nil {
			closeAll(rcs)
			return nil, fmt.Errorf("opening iterator: %w", err)
		}
		rcs = append(rcs, rc)
	}
	return rcs, nil
}

// iterReadSize is the size of each read from an iterator. The kernel stops a
// walk whenever the buffer is full and resumes it at the next read, so a
// large buffer keeps a walk mostly uninterrupted.
const iterReadSize = 1 << 20

// readIterOutput reads an iterator to the end. A read fails with EAGAIN when
// it walked a million objects without output (MAX_ITER_OBJECTS), e.g. on a
// host with many established TCP sockets; the walk continues at the next
// read.
func readIterOutput(rd io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, iterReadSize)
	for {
		n, err := rd.Read(buf)
		out = append(out, buf[:n]...)
		switch {
		case err == io.EOF:
			return out, nil
		case errors.Is(err, unix.EAGAIN):
			continue
		case err != nil:
			return nil, err
		case n == 0:
			return out, nil
		}
	}
}

func decodeRecords(buf []byte) ([]bpfShawkIterRec, error) {
	size := binary.Size(bpfShawkIterRec{})
	if len(buf)%size != 0 {
		return nil, fmt.Errorf("iterator output has unexpected length %d", len(buf))
	}
	recs := make([]bpfShawkIterRec, len(buf)/size)
	if err := binary.Read(bytes.NewReader(buf), binary.NativeEndian, recs); err != nil {
		return nil, fmt.Errorf("decoding iterator output: %w", err)
	}
	return recs, nil
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

// ProgramStat is the cumulative run time of a BPF program.
type ProgramStat struct {
	Name     string
	RunCount uint64
	Runtime  time.Duration
}

// EnableStats turns on the kernel's run time accounting of BPF programs,
// which has a small overhead of its own.
func (t *Tracer) EnableStats() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.statsCloser != nil {
		return nil
	}
	c, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return err
	}
	t.statsCloser = c
	return nil
}

// ProgramStats returns the run time statistics of the attached programs.
func (t *Tracer) ProgramStats() ([]ProgramStat, error) {
	var out []ProgramStat
	for name, prog := range t.progs {
		s, err := prog.Stats()
		if err != nil {
			return nil, err
		}
		out = append(out, ProgramStat{Name: name, RunCount: s.RunCount, Runtime: s.Runtime})
	}
	return out, nil
}

// ephemeralPortRange returns the local port range used for ephemeral ports.
func ephemeralPortRange() (uint16, uint16) {
	low, high := uint16(32768), uint16(60999)
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return low, high
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return low, high
	}
	l, err1 := strconv.ParseUint(f[0], 10, 16)
	h, err2 := strconv.ParseUint(f[1], 10, 16)
	if err1 != nil || err2 != nil {
		return low, high
	}
	return uint16(l), uint16(h)
}
