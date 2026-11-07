//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/yuuki/shawk/internal/agent"
	"github.com/yuuki/shawk/internal/otlp"
)

// The cluster of fleet, after the assumptions of
// docs/proposals/slurm-hpc-clusters.md §1.6: compute nodes are TCP clients
// of slurmctld, 4 storage servers and 2 LDAP servers, and UDP clients of 2
// DNS and 2 NTP servers (on the same two hosts); slurmctld connects to the
// slurmd of every compute node and Prometheus scrapes every host.
type fleetHost struct {
	name  string
	addr  netip.Addr
	state *otlp.State
	seg   *otlp.Segment
	start time.Time
	// edges are the edges active in every interval; jobs those of the
	// ranks of the current jobs, replaced every job.
	edges, jobs []fleetEdge
	listens     []otlp.ListenerKey
}

type fleetEdge struct {
	key otlp.EdgeKey
	udp bool
}

func svc(name string) otlp.Process {
	return otlp.Process{Unit: name + ".service", Comm: name, Exe: "/usr/sbin/" + name, Service: name}
}

func (h *fleetHost) client(proto string, peer *fleetHost, port uint16, p otlp.Process) {
	h.edges = append(h.edges, fleetEdge{key: otlp.EdgeKey{Role: otlp.RoleClient, Proto: proto,
		LocalAddr: h.addr, PeerAddr: peer.addr, Port: port, Process: p}, udp: proto == "udp"})
	peer.serve(proto, h, port)
}

// serve adds the server side of a client edge of peer, and the listener.
func (h *fleetHost) serve(proto string, peer *fleetHost, port uint16) {
	p := serverProcs[port]
	h.edges = append(h.edges, fleetEdge{key: otlp.EdgeKey{Role: otlp.RoleServer, Proto: proto,
		LocalAddr: h.addr, PeerAddr: peer.addr, Port: port, Process: p}, udp: proto == "udp"})
	l := otlp.ListenerKey{Proto: proto, Addr: netip.IPv4Unspecified(), Port: port, Process: p}
	for _, o := range h.listens {
		if o == l {
			return
		}
	}
	h.listens = append(h.listens, l)
}

var serverProcs = map[uint16]otlp.Process{
	6817: svc("slurmctld"), 6818: svc("slurmd"), 2049: {Comm: "~kernel", Service: "~kernel:nfs"},
	389: svc("slapd"), 53: svc("named"), 123: svc("chronyd"), 9100: svc("node_exporter"),
}

// runFleet sends the series of the agents of a cluster to a connector,
// every interval, each host at its own phase, built as the agent builds
// them (otlp.State). With -mpi-peers, every compute node also runs ranks
// that talk over TCP to ranks of other compute nodes, on random ports that
// change with every job: the worst case, since Open MPI numbers the ports
// of the ranks of a node from 1024 and repeats them.
func runFleet(args []string) error {
	fs := flag.NewFlagSet("fleet", flag.ExitOnError)
	var (
		endpoint = fs.String("endpoint", "http://127.0.0.1:4327", "otlp/shawk receiver of the connector")
		compute  = fs.Int("compute", 190, "compute nodes")
		interval = fs.Duration("interval", 15*time.Second, "interval of the agents")
		idleTTL  = fs.Duration("idle-ttl", 15*time.Minute, "-idle-ttl of the agents")
		perReq   = fs.Int("max-series-per-request", 1000, "-max-series-per-request of the agents")
		duration = fs.Duration("duration", 20*time.Minute, "how long to send")
		mpiPeers = fs.Int("mpi-peers", 0, "compute nodes the ranks of a compute node talk to")
		mpiRanks = fs.Int("mpi-ranks", 1, "connections, each to a port of its own, from a compute node to each of its -mpi-peers")
		jobLen   = fs.Duration("job", 10*time.Minute, "how long a job runs, after which the ports of the ranks change")
	)
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()

	// As the agent with its defaults: the private ranges are internal.
	internal, err := agent.ParseInternalPeers("private")
	if err != nil {
		return err
	}
	base := netip.MustParseAddr("10.200.0.1")
	var hosts []*fleetHost
	add := func(name string) *fleetHost {
		h := &fleetHost{name: name, addr: base, state: otlp.NewState(*idleTTL)}
		base = base.Next()
		hosts = append(hosts, h)
		return h
	}
	ctl, prom := add("slurmctld01"), add("prometheus01")
	var storage, ldap, dns []*fleetHost
	for i := range 4 {
		storage = append(storage, add(fmt.Sprintf("oss%02d", i+1)))
	}
	for i := range 2 {
		ldap = append(ldap, add(fmt.Sprintf("ldap%02d", i+1)))
		dns = append(dns, add(fmt.Sprintf("ns%02d", i+1)))
	}
	var nodes []*fleetHost
	for i := range *compute {
		nodes = append(nodes, add(fmt.Sprintf("cn%03d", i+1)))
	}
	for _, n := range nodes {
		n.client("tcp", ctl, 6817, svc("slurmd"))
		for _, s := range storage {
			n.client("tcp", s, 2049, otlp.Process{Comm: "~kernel", Service: "~kernel:nfs"})
		}
		for _, l := range ldap {
			n.client("tcp", l, 389, svc("sssd_be"))
		}
		for _, d := range dns {
			n.client("udp", d, 53, svc("sssd_be"))
			n.client("udp", d, 123, svc("chronyd"))
		}
		ctl.client("tcp", n, 6818, svc("slurmctld"))
	}
	for _, h := range hosts {
		prom.client("tcp", h, 9100, svc("prometheus"))
	}

	var job int
	newJobs := func() {
		job++
		// New slices: the senders may still read the old ones.
		for _, n := range nodes {
			n.jobs = nil
		}
		if *mpiPeers == 0 {
			return
		}
		for i, n := range nodes {
			for k := 1; k <= *mpiPeers; k++ {
				peer := nodes[(i+k)%len(nodes)]
				for r := range *mpiRanks {
					p := otlp.Process{Unit: fmt.Sprintf("task_%d", r), Comm: "a.out", Exe: "/home/user/a.out", Service: "a.out"}
					port := uint16(1024 + rand.IntN(60000))
					n.jobs = append(n.jobs, fleetEdge{key: otlp.EdgeKey{Role: otlp.RoleClient, Proto: "tcp",
						LocalAddr: n.addr, PeerAddr: peer.addr, Port: port, Process: p}})
					peer.jobs = append(peer.jobs, fleetEdge{key: otlp.EdgeKey{Role: otlp.RoleServer, Proto: "tcp",
						LocalAddr: peer.addr, PeerAddr: n.addr, Port: port, Process: p}})
				}
			}
		}
	}
	newJobs()
	logf("fleet: %d hosts, %d edges per compute node, %d of jobs", len(hosts), len(nodes[0].edges), len(nodes[0].jobs))

	var mu sync.Mutex
	var wg sync.WaitGroup
	start := time.Now()
	for i, h := range hosts {
		exp, err := otlp.NewExporter(otlp.ExporterConfig{Endpoint: *endpoint, Protocol: otlp.ProtocolGRPC})
		if err != nil {
			return err
		}
		h.start = start
		h.seg = otlp.NewSegment(start, *idleTTL)
		res := otlp.Resource{MachineID: fmt.Sprintf("%032x", i+1), Hostname: h.name, Addrs: []netip.Addr{h.addr},
			Kernel: "5.14.0-687.10.1.el9_8.x86_64", AgentVersion: "0.8.1", PeerFold: "in", InternalPeers: internal}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer exp.Close()
			// The agents start at random phases within an interval.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(rand.Int64N(int64(*interval)))):
			}
			tick := time.NewTicker(*interval)
			defer tick.Stop()
			last := time.Now()
			for {
				now := time.Now()
				mu.Lock()
				jobs := h.jobs
				mu.Unlock()
				h.state.BeginInterval()
				for _, e := range append(h.edges, jobs...) {
					st := otlp.EdgeStats{BytesSent: 512, BytesRecv: 512}
					if e.udp {
						st.MsgsSent, st.MsgsRecv = 4, 4
					} else {
						st.OpenConns = 1
					}
					h.state.AddEdge(e.key, st, last, now)
				}
				for _, l := range h.listens {
					h.state.AddListener(l, now)
				}
				h.state.Expire(now)
				segStart := h.seg.Start(now)
				reqs := h.state.Requests(res, otlp.AgentStatus{Started: h.start, SegmentStart: segStart,
					NetNSScope: "all", UDPTraced: true}, now, *perReq)
				// As the agent (internal/agent tick): one deadline of 2/3 of
				// the interval for all requests of the interval.
				ok := true
				tctx, cancel := context.WithTimeout(ctx, max(*interval*2/3, time.Second))
				for _, r := range reqs {
					err := exp.Export(tctx, r)
					if err != nil {
						if ctx.Err() == nil {
							logf("fleet: %s: %v", h.name, err)
						}
						ok = false
						break
					}
				}
				cancel()
				if ok {
					h.seg.Succeeded(segStart, now)
				}
				last = now
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
	}
	if *mpiPeers > 0 {
		tick := time.NewTicker(*jobLen)
		defer tick.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-tick.C:
				mu.Lock()
				newJobs()
				mu.Unlock()
			}
		}
	}
	wg.Wait()
	return nil
}
