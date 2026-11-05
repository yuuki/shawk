package tracer

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// Collect closes the current interval and returns the bundled flows and the
// listening sockets observed in it.
func (t *Tracer) Collect() (*Snapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Walking sockets accounts the traffic of long-lived connections into the
	// current interval and refreshes the listening ports. Each walk has a
	// generation of its own, which the connections it accounts record.
	t.walks++
	if err := t.walkGen.Set(t.walks); err != nil {
		return nil, err
	}
	listeners, inos, err := t.scanSockets()
	if err != nil {
		return nil, err
	}
	t.warnOnIncrease(t.listenDrops, "more listening ports than the in-kernel tables hold; connections that predate the agent and UDP sockets on the others may get the wrong direction", "capacity", t.listenPorts.MaxEntries())
	t.warnOnIncrease(t.storageFails, "no socket storage for some TCP connections; they are counted from the next walk on, without their connection and earlier traffic")
	t.warnOnIncrease(t.cgroupDrops, "some new cgroups were not reported because the agent did not read the events fast enough; flows of short-lived ones among them are named by cgroup id")
	var adopted uint64
	if err := t.adopted.Get(&adopted); err != nil {
		return nil, err
	}
	t.warnOnIncrease(t.iterSkips, "the TCP iterator of the kernel skipped some connections, which the walk of the processes accounts at every interval instead; Linux 6.17 fixes the iterator")
	periodic := time.Since(t.lastOwnScan) >= t.opts.OwnerScanInterval
	if adopted != t.lastAdopted || t.ownerMissing || t.skipping || periodic || t.hasNewListener(listeners, inos) {
		if err := t.refreshOwners(listeners, inos); err != nil {
			return nil, err
		}
		t.lastAdopted = adopted
		t.ownerMissing = false
		if periodic {
			clear(t.unixMissing)
		}
	}
	for i := range listeners {
		k := listenerKey(&listeners[i])
		if o, ok := preferredOwner(t.owners[k]); ok {
			listeners[i].PID = o.pid
			listeners[i].Comm = o.comm
			listeners[i].CgroupID = o.cgroupID
		} else if !t.kernel[k] {
			// The kernel may hold it, but a process did at the last scan.
			listeners[i].Comm = ""
		}
	}

	listeners = append(listeners, t.unixListeners()...)

	flows, unixFlows, err := t.flip()
	if err != nil {
		return nil, err
	}
	flows = t.attribute(flows)
	for i := range unixFlows {
		// A client connected to a name that no scan found a listener of: a
		// server that started since the last scan.
		if f := &unixFlows[i]; f.Conns > 0 && !t.hasUnixListener(f.Path) && !t.unixMissing[f.Path] {
			t.unixMissing[f.Path] = true
			t.ownerMissing = true
		}
	}
	flows = append(flows, unixFlows...)
	t.tryConntrack(time.Now())
	// The flows are drained already: an error with the translations loses
	// those of the interval only.
	xlats, err := t.collectTranslations()
	if err != nil {
		t.warnOnce("reading the translations of addresses", err)
	}
	t.warnOnIncrease(t.flowBusy, "some flow updates were dropped because the flow table was being updated on the same CPU, not because it was full")
	snap := &Snapshot{Flows: flows, Listeners: listeners, Translations: xlats}
	counters := []struct {
		v   *ebpf.Variable
		dst *uint64
	}{{t.flowDrops, &snap.Drops}, {t.flowBusy, &snap.Contended}, {t.cgroupDrops, &snap.CgroupEventDrops}}
	if t.xlatDrops != nil {
		t.warnOnIncrease(t.xlatDrops, "some translations of addresses were not learned, or not kept while their connections are open, because their in-kernel tables were full; raise -max-flows",
			"translations", t.xlats.MaxEntries(), "connections", xlatConnsPerFlow*t.xlats.MaxEntries())
		counters = append(counters, struct {
			v   *ebpf.Variable
			dst *uint64
		}{t.xlatDrops, &snap.TranslationDrops})
	}
	for _, c := range counters {
		if err := c.v.Get(c.dst); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// flip switches the active flow maps and drains the previous ones: the
// flows, and those of Unix sockets with their open connections.
func (t *Tracer) flip() ([]Flow, []Flow, error) {
	old := t.idx
	next := old ^ 1
	if err := t.activeIdx.Set(next); err != nil {
		return nil, nil, fmt.Errorf("switching flow map: %w", err)
	}
	t.idx = next
	// Programs that read the old index may still be updating the old maps.
	// Updating an element of a map-in-map makes the kernel wait for an RCU
	// grace period, after which they have all finished.
	if err := t.flowsOuter.Update(old, t.flowMaps[old], ebpf.UpdateAny); err != nil {
		return nil, nil, fmt.Errorf("waiting for programs: %w", err)
	}
	flows, err := drainFlows(t.flowMaps[old])
	if err != nil {
		return nil, nil, err
	}
	unixFlows, err := t.drainUnix(t.unixFlowMaps[old])
	if err != nil {
		return nil, nil, err
	}
	return flows, unixFlows, nil
}

// drainFlows reads and deletes the flows of an inactive map.
func drainFlows(m *ebpf.Map) ([]Flow, error) {
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

// drainUnix reads and deletes the flows of Unix sockets of an inactive map,
// and counts the connections open now, which the programs add to and
// delete from unix_conns.
func (t *Tracer) drainUnix(m *ebpf.Map) ([]Flow, error) {
	var (
		key  bpfShawkUnixKey
		val  bpfShawkUnixStats
		keys []bpfShawkUnixKey
	)
	flows := map[FlowKey]*Flow{}
	it := m.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
		f := convertUnixFlow(&key, &val)
		flows[f.FlowKey] = &f
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("reading Unix flows: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("deleting Unix flow: %w", err)
		}
	}

	var (
		sk   uint64
		conn bpfShawkUnixConn
	)
	it = t.unixConns.Iterate()
	for it.Next(&sk, &conn) {
		k := unixFlowKey(&conn.Key)
		f, ok := flows[k]
		if !ok {
			f = &Flow{FlowKey: k}
			flows[k] = f
		}
		f.OpenConns++
		if f.PID == 0 {
			f.PID = conn.Pid
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("reading open Unix connections: %w", err)
	}
	out := make([]Flow, 0, len(flows))
	for _, f := range flows {
		out = append(out, *f)
	}
	return out, nil
}

// unixFlowKey converts the key of a flow of Unix sockets.
func unixFlowKey(k *bpfShawkUnixKey) FlowKey {
	b := make([]byte, min(int(k.PathLen), len(k.Path)))
	for i := range b {
		b[i] = byte(k.Path[i])
	}
	return FlowKey{
		Direction: DirOut,
		Proto:     ProtoUnix,
		Path:      UnixName(b),
		NetNS:     k.Netns,
		CgroupID:  k.CgroupId,
		Comm:      commString(k.Comm),
	}
}

// The reasons of struct shawk_unix_stats are those of FlowStats.
var _ [len(bpfShawkUnixStats{}.Fails)]struct{} = [len(FlowStats{}.Fails)]struct{}{}

func convertUnixFlow(k *bpfShawkUnixKey, v *bpfShawkUnixStats) Flow {
	f := Flow{
		FlowKey: unixFlowKey(k),
		FlowStats: FlowStats{
			Conns:     uint64(v.Conns),
			ConnFails: uint64(v.ConnFails),
			PID:       v.Pid,
		},
	}
	for i, n := range v.Fails {
		f.Fails[i] = uint64(n)
	}
	return f
}

// attribute assigns incoming TCP flows to the owner of the listening
// socket, drops the flows of the tracer itself and merges flows that end up
// with the same key.
func (t *Tracer) attribute(flows []Flow) []Flow {
	merged := make(map[FlowKey]int, len(flows))
	out := flows[:0]
	for _, f := range flows {
		// Incoming connections that were adopted after their listener was
		// closed already carry the process holding them, or the kernel.
		if f.Direction == DirIn && f.Proto == ProtoTCP && f.PID == 0 && !KernelOwned(f.Comm, f.CgroupID) {
			cands, kernel := t.listenerOwners(f.Proto, f.NetNS, f.LocalAddr, f.Port)
			if o, ok := chooseOwner(cands, f.CgroupID); ok {
				f.Comm = o.comm
				f.CgroupID = o.cgroupID
				f.PID = o.pid
			} else if kernel {
				f.Comm = KernelComm
				f.CgroupID = 0
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

// The buckets and reasons of struct shawk_flow_stats are those of FlowStats.
var (
	_ [len(bpfShawkFlowStats{}.HsBuckets)]struct{} = [len(FlowStats{}.Handshakes)]struct{}{}
	_ [len(bpfShawkFlowStats{}.Fails)]struct{}     = [len(FlowStats{}.Fails)]struct{}{}
)

func convertFlow(k *bpfShawkFlowKey, v *bpfShawkFlowStats) Flow {
	f := Flow{
		FlowKey: FlowKey{
			Direction:  Direction(k.Direction),
			Proto:      Proto(k.Proto),
			LocalAddr:  addrFrom16(k.Laddr),
			RemoteAddr: addrFrom16(k.Raddr),
			Port:       k.Port,
			NetNS:      k.Netns,
			CgroupID:   k.CgroupId,
			Comm:       commString(k.Comm),
			Folded:     k.Flags&keyFolded != 0,
		},
		FlowStats: FlowStats{
			Conns:          uint64(v.Conns),
			ConnFails:      uint64(v.ConnFails),
			OpenConns:      uint64(v.OpenConns),
			BytesSent:      v.BytesSent,
			BytesRecv:      v.BytesRecv,
			MsgsSent:       uint64(v.MsgsSent),
			MsgsRecv:       uint64(v.MsgsRecv),
			Retrans:        uint64(v.Retrans),
			RTTSumUs:       v.RttSumUs,
			RTTSamples:     uint64(v.RttSamples),
			HandshakeSumUs: v.HsSumUs,
			SynRetrans:     uint64(v.SynRetrans),
			PID:            v.Pid,
		},
	}
	for i, n := range v.HsBuckets {
		f.Handshakes[i] = uint64(n)
	}
	for i, n := range v.Fails {
		f.Fails[i] = uint64(n)
	}
	return f
}

type counterWarning struct {
	last   uint64
	warned time.Time
}

// warnOnIncrease warns, at most once an hour per message, when a cumulative
// counter of the BPF programs increased.
func (t *Tracer) warnOnIncrease(v *ebpf.Variable, msg string, args ...any) {
	var n uint64
	if err := v.Get(&n); err != nil {
		return
	}
	w := t.warnings[msg]
	if n == w.last {
		return
	}
	w.last = n
	if time.Since(w.warned) >= time.Hour {
		w.warned = time.Now()
		t.log.Warn(msg, append(args, "total", n)...)
	}
	if t.warnings == nil {
		t.warnings = map[string]counterWarning{}
	}
	t.warnings[msg] = w
}

// warnOnce logs an error at most once an hour for msg.
func (t *Tracer) warnOnce(msg string, err error) {
	w := t.warnings[msg]
	if time.Since(w.warned) < time.Hour {
		return
	}
	w.warned = time.Now()
	if t.warnings == nil {
		t.warnings = map[string]counterWarning{}
	}
	t.warnings[msg] = w
	t.log.Warn(msg, "error", err)
}
