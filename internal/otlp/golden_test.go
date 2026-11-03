package otlp

import (
	"flag"
	"net/netip"
	"os"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var update = flag.Bool("update", false, "rewrite the golden request")

// goldenPath is a request of the agent that the tests of the shawk connector
// decode. It keeps the agent and the connector, which are separate Go
// modules, in agreement on the format.
const goldenPath = "../../collector/shawkconnector/testdata/agent-request.json"

func goldenRequest() *colmetricspb.ExportMetricsServiceRequest {
	s := NewState(15 * time.Minute)
	app := Process{Unit: "app.service", Comm: "puma", Exe: "/usr/bin/ruby", Service: "app", ServiceNamespace: "shop"}
	s.AddEdge(EdgeKey{Role: RoleClient, Proto: "tcp", LocalAddr: netip.MustParseAddr("10.0.0.11"),
		PeerAddr: netip.MustParseAddr("10.0.0.10"), Port: 5432, NetNS: 4026531840, Process: app},
		EdgeStats{Conns: 3, ConnFails: 7, OpenConns: 2, BytesSent: 100, BytesRecv: 200, Retrans: 4, RTTSumUs: 1500, RTTSamples: 3,
			// Two handshakes of 0.3 ms and one of 1.2 s, after a lost SYN;
			// failures for every reason, which the connector must know,
			// two by timeout and one for another reason.
			Handshakes: [len(HandshakeBounds) + 1]uint64{2: 2, 9: 1}, HandshakeSumUs: 1_200_600, SynRetrans: 3,
			Fails: [len(FailReasons)]uint64{1, 2, 1, 1, 1}},
		t0, t0.Add(15*time.Second))
	s.AddEdge(EdgeKey{Role: RoleServer, Proto: "tcp", LocalAddr: netip.MustParseAddr("10.0.0.11"),
		PeerAddr: netip.MustParseAddr("10.0.0.5"), Port: 8080, NetNS: 4026531840, Process: app},
		EdgeStats{Conns: 10, BytesSent: 1000, BytesRecv: 500}, t0, t0.Add(15*time.Second))
	// The clients outside the internal ranges, folded into one edge.
	s.AddEdge(EdgeKey{Role: RoleServer, Proto: "tcp", LocalAddr: netip.MustParseAddr("10.0.0.11"),
		PeerAddr: netip.MustParseAddr("0.0.0.0"), PeerFolded: true, Port: 443, NetNS: 4026531840, Process: app},
		EdgeStats{Conns: 250, OpenConns: 40, BytesSent: 90000, BytesRecv: 12000}, t0, t0.Add(15*time.Second))
	s.AddEdge(EdgeKey{Role: RoleClient, Proto: "udp", LocalAddr: netip.MustParseAddr("10.0.0.11"),
		PeerAddr: netip.MustParseAddr("8.8.8.8"), Port: 53, NetNS: 4026531840,
		Process: Process{Unit: "app.service", Comm: "puma", Exe: "/usr/bin/ruby", Service: "app", ServiceNamespace: "shop"}},
		EdgeStats{MsgsSent: 2, MsgsRecv: 2, BytesSent: 80, BytesRecv: 160}, t0, t0.Add(15*time.Second))
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080, NetNS: 4026531840,
		Process: app}, t0.Add(15*time.Second))
	s.AddListener(ListenerKey{Proto: "udp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 68, NetNS: 4026531840}, t0.Add(15*time.Second))
	// kube-proxy on the host translates a ClusterIP to a pod, and
	// masquerades a container that leaves with the address of the host.
	s.AddTranslation(TranslationKey{Proto: "tcp", NetNS: 4026531840, Client: netip.MustParseAddr("10.0.0.11"),
		Virtual: netip.MustParseAddr("10.96.0.10"), VirtualPort: 5432, Source: netip.MustParseAddr("10.0.0.11"),
		Backend: netip.MustParseAddr("10.244.1.7"), BackendPort: 6432}, t0.Add(15*time.Second))
	s.AddTranslation(TranslationKey{Proto: "udp", NetNS: 4026531840, Client: netip.MustParseAddr("172.17.0.2"),
		Virtual: netip.MustParseAddr("10.0.0.53"), VirtualPort: 53, Source: netip.MustParseAddr("10.0.0.11"),
		Backend: netip.MustParseAddr("10.0.0.53"), BackendPort: 53}, t0.Add(15*time.Second))
	return s.Request(Resource{
		MachineID: "4c4c4544003910528036b4c04f4d3732", Hostname: "app-01", Kernel: "5.14.0-503.el9.x86_64",
		AgentVersion: "v0.9.0", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.11")},
		PeerFold: "in", InternalPeers: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::1/128"),
		},
	}, AgentStatus{
		Started: t0.Add(-time.Hour), SegmentStart: t0.Add(-time.Hour), NetNSScope: "all", UDPTraced: true,
		FlowsDropped: 7, CgroupEventsDropped: 3, ContainerReadsDrops: 2, ExportFailures: 1,
		TranslationsTraced: true, TranslationsDropped: 2,
		BPFPrograms: []BPFProgram{{Name: "shawk_inet_sock_set_state", RunCount: 42, RunTime: 3 * time.Millisecond}},
	}, t0.Add(15*time.Second))
}

func TestGoldenRequest(t *testing.T) {
	req := goldenRequest()
	if *update {
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var want colmetricspb.ExportMetricsServiceRequest
	if err := protojson.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(req, &want) {
		t.Errorf("the request differs from %s; if the change is intended, run go test ./internal/otlp/ -run TestGoldenRequest -args -update and update the shawk connector", goldenPath)
	}
}
