package otlp

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// FuzzRequests checks the requests of an interval whatever the names of the
// processes, which their environment sets, and the counts of their edges:
// every request marshals (its strings are valid UTF-8), stays below the
// byte limit and maxSeries, carries the metrics of the agent last, and each
// series is sent once or counted as oversized.
func FuzzRequests(f *testing.F) {
	f.Add("app", "shop", "/usr/bin/ruby", "puma", "app.service", "/run/postgresql/.s.PGSQL.5432", "", uint8(7), uint8(3), uint64(3), uint16(0))
	f.Add("billing", "", "/usr/lib/jvm/bin/java", "サービスワ\xe3\x83", "k8s/shop/cart/app", "@app/control",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", uint8(40), uint8(0), uint64(1<<63+5), uint16(9000))
	f.Add(strings.Repeat("x", 300), "\xff", "", "", "", "", "", uint8(63), uint8(1), uint64(0), uint16(60000))
	f.Fuzz(func(t *testing.T, service, ns, exe, comm, unit, path, ctr string, n, maxSeries uint8, v uint64, pad uint16) {
		// A small limit, so that requests split and some series do not fit.
		defer func(n int) { maxRequestBytes = n }(maxRequestBytes)
		maxRequestBytes = 64 << 10

		s := NewState(15 * time.Minute)
		proc := Process{Unit: unit, Comm: comm, Exe: exe, Service: service, ServiceNamespace: ns, ContainerID: ctr,
			UserID: uint32(v), HasUserID: v%2 == 1}
		end := t0.Add(15 * time.Second)
		st := EdgeStats{Conns: 1 + v%100, ConnFails: v, OpenConns: v, BytesSent: v, BytesRecv: v << 1, MsgsSent: v, MsgsRecv: v,
			Retrans: v, RTTSumUs: v, RTTSamples: v % 7, HandshakeSumUs: v, SynRetrans: v}
		for i := range st.Handshakes {
			st.Handshakes[i] = v >> i
		}
		for i := range st.Fails {
			st.Fails[i] = v >> (2 * i)
		}
		for i := range int(n % 64) {
			p := proc
			if i%5 == 4 {
				// A process with a long executable path.
				p.Exe += strings.Repeat("/x", int(pad)%20000)
			}
			k := EdgeKey{Role: RoleClient, Proto: "tcp", LocalAddr: netip.AddrFrom4([4]byte{10, 0, 0, 11}),
				PeerAddr: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), Port: uint16(i), NetNS: 4026531840, Process: p}
			switch i % 4 {
			case 1:
				k.Role = RoleServer
			case 2:
				k.Proto = "udp"
				k.PeerFolded = v%3 == 0
			case 3:
				k = EdgeKey{Role: RoleClient, Proto: TransportUnix, Path: path + strconv.Itoa(i), NetNS: 4026531840, Process: p}
			}
			s.AddEdge(k, st, t0, end)
			if i%2 == 0 {
				l := ListenerKey{Proto: "tcp", Addr: netip.IPv6Unspecified(), Port: uint16(i), KernelChosen: i%4 == 0, Process: p}
				if i%4 == 2 {
					l = ListenerKey{Proto: TransportUnix, Path: path + strconv.Itoa(i), Process: p}
				}
				s.AddListener(l, end)
			}
			if i%3 == 0 {
				s.AddTranslation(TranslationKey{Proto: "tcp", Client: k.LocalAddr, Virtual: netip.AddrFrom4([4]byte{10, 96, 0, byte(i)}),
					VirtualPort: 80, Source: k.LocalAddr, Backend: k.PeerAddr, BackendPort: uint16(i)}, end)
			}
		}
		series := len(s.Edges()) + len(s.Listeners()) + len(s.Translations())

		res := Resource{MachineID: ctr, Hostname: comm, Kernel: unit, AgentVersion: "v0.0.0", PeerFold: "in",
			Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")}, InternalPeers: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
		status := AgentStatus{Started: t0, SegmentStart: t0, NetNSScope: ns, UDPTraced: true, FlowsDropped: v,
			BPFPrograms: []BPFProgram{{Name: service, RunCount: v, RunTime: time.Duration(v % (1 << 40))}}}
		reqs := s.Requests(res, status, end, int(maxSeries%8))
		sent := 0
		for i, req := range reqs {
			b, err := proto.Marshal(req)
			if err != nil {
				t.Fatalf("request %d does not marshal: %v", i, err)
			}
			if len(b) > maxRequestBytes {
				t.Fatalf("request %d has %d bytes, more than %d", i, len(b), maxRequestBytes)
			}
			inRequest, agent := 0, false
			for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
				switch m.Name {
				case MetricEdgeLast, MetricListenerLast, MetricTranslationLast:
					inRequest += len(m.GetGauge().DataPoints)
				case MetricAgentUp:
					agent = true
				}
			}
			if limit := int(maxSeries % 8); limit > 0 && inRequest > limit {
				t.Fatalf("request %d has %d series, more than %d", i, inRequest, limit)
			}
			if agent != (i == len(reqs)-1) {
				t.Fatalf("request %d of %d: metrics of the agent %v", i, len(reqs), agent)
			}
			sent += inRequest
		}
		if sent+int(s.Oversized()) != series {
			t.Fatalf("%d series sent and %d oversized of %d", sent, s.Oversized(), series)
		}
	})
}
