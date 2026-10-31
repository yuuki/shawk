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
		EdgeStats{Conns: 3, ConnFails: 1, OpenConns: 2, BytesSent: 100, BytesRecv: 200, Retrans: 4, RTTSumUs: 1500, RTTSamples: 3},
		t0, t0.Add(15*time.Second))
	s.AddEdge(EdgeKey{Role: RoleServer, Proto: "tcp", LocalAddr: netip.MustParseAddr("10.0.0.11"),
		PeerAddr: netip.MustParseAddr("10.0.0.5"), Port: 8080, NetNS: 4026531840, Process: app},
		EdgeStats{Conns: 10, BytesSent: 1000, BytesRecv: 500}, t0, t0.Add(15*time.Second))
	s.AddEdge(EdgeKey{Role: RoleClient, Proto: "udp", LocalAddr: netip.MustParseAddr("10.0.0.11"),
		PeerAddr: netip.MustParseAddr("8.8.8.8"), Port: 53, NetNS: 4026531840,
		Process: Process{Unit: "app.service", Comm: "puma", Exe: "/usr/bin/ruby", Service: "app", ServiceNamespace: "shop"}},
		EdgeStats{MsgsSent: 2, MsgsRecv: 2, BytesSent: 80, BytesRecv: 160}, t0, t0.Add(15*time.Second))
	s.AddListener(ListenerKey{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080, NetNS: 4026531840,
		Process: app}, t0.Add(15*time.Second))
	s.AddListener(ListenerKey{Proto: "udp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 68, NetNS: 4026531840}, t0.Add(15*time.Second))
	return s.Request(Resource{
		MachineID: "4c4c4544003910528036b4c04f4d3732", Hostname: "app-01", Kernel: "5.14.0-503.el9.x86_64",
		AgentVersion: "v0.9.0", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.11")},
	}, AgentStatus{
		Started: t0.Add(-time.Hour), SegmentStart: t0.Add(-time.Hour), NetNSScope: "all", UDPTraced: true,
		FlowsDropped: 7, ExportFailures: 1,
		BPFPrograms: []BPFProgram{{Name: "shawk_tcp_state", RunCount: 42, RunTime: 3 * time.Millisecond}},
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
