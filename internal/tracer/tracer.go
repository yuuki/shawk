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

// The tables of listening ports are sized by MaxFlows within these bounds:
// they are preallocated, and hosts rarely listen on many ports.
var minListenPorts, maxListenPorts uint32 = 8192, 65536

// Options configures a Tracer.
type Options struct {
	// NetNS restricts tracing to the network namespace with this inode
	// number. Zero traces all network namespaces.
	NetNS uint32
	// MaxFlows is the capacity of the in-kernel flow table per interval. It
	// also sizes the tables of listening TCP and UDP ports and of the owners
	// of MPTCP connections, between 8192 and 65536.
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
	// Fold tells which flows fold their peers outside InternalPeers into
	// one flow per local endpoint (see FoldMode). The default keeps every
	// peer.
	Fold FoldMode
	// InternalPeers are the address ranges whose peers are kept exact when
	// Fold folds peers (see CheckInternalPeer). Loopback and the addresses
	// of the host are always kept.
	InternalPeers []netip.Prefix
	// LocalAddrs are the addresses of the host when the tracer starts, kept
	// from the first flow on, also for the connections it adopts;
	// SetLocalAddrs replaces them.
	LocalAddrs []netip.Addr
	// LearnTranslations learns the translations of addresses the host
	// makes (DNAT, SNAT, IPVS) from conntrack, once the module
	// nf_conntrack is loaded (see Snapshot.Translations).
	LearnTranslations bool
	Logger            *slog.Logger
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
	flowBusy       *ebpf.Variable
	listenDrops    *ebpf.Variable
	storageFails   *ebpf.Variable
	cgroupDrops    *ebpf.Variable
	adopted        *ebpf.Variable
	selfTgid       *ebpf.Variable
	ownerScan      *ebpf.Variable
	ownerScans     uint32
	walkGen        *ebpf.Variable
	walks          uint32
	iterSkips      *ebpf.Variable
	// lastSkips is iter_skips after the last owner scan, and skipping tells
	// that the scan found connections that the walk had missed (see
	// account_skipped() of the BPF programs): the processes are then walked
	// at every interval, until a scan finds none.
	lastSkips     uint64
	skipping      bool
	internalPeers *ebpf.Map
	// configuredPeers are the keys of internalPeers from the options, and
	// localPeers those of the addresses of the host (SetLocalAddrs).
	configuredPeers map[bpfShawkPeerPrefix]bool
	localPeers      map[bpfShawkPeerPrefix]bool

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
	// held are the inodes of the sockets held by the processes at the last
	// owner scan.
	held map[uint64]bool
	// ownerMissing requests an owner scan after an accepted connection
	// matched no holder of its listener.
	ownerMissing bool
	// ownerless are the listeners whose owner the last scan could not find,
	// and unheld the inodes of listening sockets that no process held then.
	// They do not trigger another scan. kernel are those of the ownerless
	// listeners that the kernel may hold (see listenerOwners).
	ownerless map[sockAddrKey]bool
	unheld    map[uint64]bool
	kernel    map[sockAddrKey]bool
	// listening are the inodes of the listening sockets at the last owner
	// scan.
	listening   map[uint64]bool
	lastOwnScan time.Time
	lastAdopted uint64
	// warnings rate-limits the warnings about kernel counters.
	warnings    map[string]counterWarning
	statsCloser io.Closer

	// conntrackSpec is the specification the conntrack programs are loaded
	// from once nf_conntrack is loaded, and conntrackTried the last
	// attempt. xlats is nil until they are loaded; xlatLast holds the
	// counts of each translation at the last read.
	conntrackSpec  *ebpf.CollectionSpec
	conntrackTried time.Time
	// conntrackMissingLogged and conntrackFailLogged tell that the absence
	// of nf_conntrack, and a failure to load the programs, were logged.
	conntrackMissingLogged, conntrackFailLogged bool
	// conntrackBackoff is the wait before the next load after one failed.
	conntrackBackoff time.Duration
	xlats            *ebpf.Map
	xlatDrops        *ebpf.Variable
	xlatLast         map[bpfShawkXlatKey]bpfShawkXlatStats
	// conntrackLinks are the links of conntrackPrograms, in their order, and
	// xlatConnsMap the entries counted live; for tests.
	conntrackLinks []link.Link
	xlatConnsMap   *ebpf.Map
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
	for _, p := range opts.InternalPeers {
		if err := CheckInternalPeer(p); err != nil {
			return nil, err
		}
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
	if opts.LearnTranslations {
		t.conntrackSpec = spec
		t.tryConntrack(time.Now())
	}

	// Adopt connections and listeners that existed before the tracer
	// started, then resolve their owners. The first walk also tells the
	// programs which process the tracer is, and marks the UDP server sockets.
	if err := t.initialScan.Set(uint32(1)); err != nil {
		t.Close()
		return nil, err
	}
	listeners, inos, err := t.scanSockets()
	if err != nil {
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
	if err := t.refreshOwners(listeners, inos); err != nil {
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
		bpfVarFoldMode:    uint8(t.opts.Fold),
	}
	for name, v := range vars {
		if err := spec.Variables[name].Set(v); err != nil {
			return fmt.Errorf("setting %s: %w", name, err)
		}
	}
	spec.Maps[bpfMapInternalPeers].MaxEntries = uint32(len(alwaysInternal)+len(t.opts.InternalPeers)) + maxLocalPeers
	for _, name := range []string{bpfMapFlows0, bpfMapFlows1} {
		spec.Maps[name].MaxEntries = t.opts.MaxFlows
	}
	for _, name := range []string{bpfMapListenPorts, bpfMapUdpListenPorts, bpfMapMptcpOwners} {
		spec.Maps[name].MaxEntries = min(max(t.opts.MaxFlows, minListenPorts), maxListenPorts)
	}
	spec.Maps[bpfMapFlows].InnerMap.MaxEntries = t.opts.MaxFlows
	spec.Maps[bpfMapXlats].MaxEntries = t.opts.MaxFlows
	spec.Maps[bpfMapXlatConns].MaxEntries = xlatConnsPerFlow * t.opts.MaxFlows
	return nil
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

// loadCore loads the maps, the TCP programs and the iterators.
func (t *Tracer) loadCore(spec *ebpf.CollectionSpec) error {
	core := spec.Copy()
	for _, p := range udpPrograms {
		delete(core.Programs, p.prog)
	}
	withoutConntrack(core)
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
	t.flowBusy = coll.Variables[bpfVarFlowBusy]
	t.listenDrops = coll.Variables[bpfVarListenPortDrops]
	t.storageFails = coll.Variables[bpfVarStorageFails]
	t.cgroupDrops = coll.Variables[bpfVarCgroupEventDrops]
	t.adopted = coll.Variables[bpfVarAdoptedUnowned]
	t.selfTgid = coll.Variables[bpfVarSelfTgid]
	t.ownerScan = coll.Variables[bpfVarOwnerScan]
	t.walkGen = coll.Variables[bpfVarWalkGen]
	t.iterSkips = coll.Variables[bpfVarIterSkips]
	t.internalPeers = coll.Maps[bpfMapInternalPeers]
	// The ranges are in place before the programs see the first flow.
	t.configuredPeers = map[bpfShawkPeerPrefix]bool{}
	t.localPeers = map[bpfShawkPeerPrefix]bool{}
	for _, p := range append(slices.Clone(alwaysInternal), t.opts.InternalPeers...) {
		k := peerPrefixKey(p)
		if err := t.internalPeers.Update(&k, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("adding the internal range %s: %w", p, err)
		}
		t.configuredPeers[k] = true
	}
	if err := t.setLocalAddrs(t.opts.LocalAddrs); err != nil {
		return err
	}

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
	withoutConntrack(udp)
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
