package shawkconnector

import (
	"context"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// The requests of agents come from the network: these targets decode
// arbitrary OTLP protobuf as the receiver passes it to the connector.

// addFuzzRequests adds the request written by the agent's tests and one of
// every kind of series, encoded as the receiver decodes them.
func addFuzzRequests(f *testing.F) {
	b, err := os.ReadFile("testdata/agent-request.json")
	if err != nil {
		f.Fatal(err)
	}
	golden, err := (&pmetric.JSONUnmarshaler{}).UnmarshalMetrics(b)
	if err != nil {
		f.Fatal(err)
	}
	unixTraced := true
	all := tAgent{host: "app-01", machineID: "4c4c4544003910528036b4c04f4d3732", addrs: []string{"10.0.0.11", "fe80::1%eth0"},
		time: t0.Add(15 * time.Second), unixTraced: &unixTraced, dropped: 3, fold: foldIn, internal: []string{"10.0.0.0/8", "::ffff:10.0.0.0/104"},
		edges: []tEdge{
			{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", ns: "shop",
				unit: "app.service", comm: "puma", exe: "/usr/bin/ruby", opened: 3, failed: 2, count: 1, tx: 10, rx: 20, rttSum: 0.5,
				rttCount: 2, handshakes: make([]uint64, len(handshakeBounds)+1), hsSum: 0.3, synRetrans: 1,
				reasons: map[string]tReason{"timeout": {value: 2}}},
			{role: roleServer, proto: "tcp", local: "10.0.0.11", peer: "0.0.0.0", folded: true, port: 443, svc: "app",
				unit: "app.service", comm: "puma", opened: 9},
			{role: roleClient, proto: "udp", local: "10.0.0.11", peer: "8.8.8.8", port: 53, svc: "app", unit: "slurm/step",
				comm: "a.out", user: "1001"},
			{role: roleClient, proto: transportUnix, path: "/run/postgresql/.s.PGSQL.5432", svc: "app", unit: "app.service",
				comm: "puma", opened: 4, failed: 1, reasons: map[string]tReason{"refused": {value: 1}}},
			// Names that are not valid UTF-8 or hold a NUL, which neither
			// PostgreSQL's text nor Prometheus's labels take.
			{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.12", port: 6379, svc: "サービ\xe3\x83",
				ns: "a\x00b", unit: "user@1000.service/\xff.service", comm: "\xfe\xff", exe: "/home/u/\xc0bin", opened: 1},
		},
		listeners: []tListener{
			{proto: "tcp", addr: "0.0.0.0", port: 8080, svc: "app", unit: "app.service", comm: "puma"},
			{proto: transportUnix, path: "@app/control", svc: "app", unit: "app.service", comm: "puma"},
		},
		translations: []tTranslation{{proto: "tcp", client: "10.0.0.11", virtual: "10.96.0.10", vport: 5432,
			backend: "10.244.1.7", bport: 6432}},
	}.metrics()
	// A cumulative value that is not a number, which must not reach the
	// outputs.
	nan := pmetric.NewMetrics()
	all.CopyTo(nan)
	ms := nan.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	for i := range ms.Len() {
		switch m := ms.At(i); m.Type() {
		case pmetric.MetricTypeSum:
			m.Sum().DataPoints().At(0).SetDoubleValue(math.NaN())
		case pmetric.MetricTypeHistogram:
			m.Histogram().DataPoints().At(0).SetSum(math.Inf(1))
		}
	}
	for _, md := range []pmetric.Metrics{golden, all, nan} {
		pb, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(md)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(pb)
	}
	f.Add([]byte{})
}

// cleanBounded tells whether a string of an agent is as getString keeps it.
func cleanBounded(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && len(s) <= maxStringBytes
}

func checkProcess(t *testing.T, p *process) {
	t.Helper()
	for _, s := range []string{p.unit, p.comm, p.exe, p.service, p.svcNS, p.containerID} {
		if !cleanBounded(s) {
			t.Fatalf("process %+v keeps %q", *p, s)
		}
	}
	if p.user != "" {
		if uid, err := strconv.ParseUint(p.user, 10, 32); err != nil || strconv.FormatUint(uid, 10) != p.user {
			t.Fatalf("process.user.id %q", p.user)
		}
	}
}

func checkAddr(t *testing.T, a netip.Addr) {
	t.Helper()
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
		t.Fatalf("address %v, which PostgreSQL's inet would not keep as it is", a)
	}
}

// FuzzParseResource checks what the connector keeps of a request: strings
// that PostgreSQL accepts, of bounded size; edges, listeners and
// translations of the kinds the agents send; and only the metrics of the
// agent that it forwards.
func FuzzParseResource(f *testing.F) {
	addFuzzRequests(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		md, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(data)
		if err != nil {
			return
		}
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			b, err := parseResource(rms.At(i))
			if err != nil {
				continue
			}
			for _, s := range []string{b.machineID, b.hostname, b.kernel, b.agentVersion, b.netnsScope, b.peerFold} {
				if !cleanBounded(s) {
					t.Fatalf("host %q keeps %q", b.hostname, s)
				}
			}
			if b.hostname == "" || b.key != hostKey(b.machineID, b.hostname) || len(b.peerInternal) > maxInternalPeers {
				t.Fatalf("host %q, key %q, %d internal ranges", b.hostname, b.key, len(b.peerInternal))
			}
			for _, a := range b.addrs {
				checkAddr(t, a)
			}
			for id, e := range b.edges {
				checkProcess(t, &id.process)
				if id != e.id || (id.role != roleClient && id.role != roleServer) {
					t.Fatalf("edge %+v", id)
				}
				switch id.proto {
				case "tcp", "udp":
					checkAddr(t, id.local)
					checkAddr(t, id.peer)
					if id.path != "" || (id.folded && !id.peer.IsUnspecified()) {
						t.Fatalf("edge %+v", id)
					}
				case transportUnix:
					if id.role != roleClient || id.path == "" || !cleanBounded(id.path) || id.local.IsValid() ||
						id.peer.IsValid() || id.port != 0 || id.netns > math.MaxUint32 {
						t.Fatalf("Unix edge %+v", id)
					}
				default:
					t.Fatalf("edge of %q", id.proto)
				}
				for k, p := range e.values {
					if (k.metric == metricHandshake) != (p.buckets != nil) ||
						(p.buckets != nil && len(p.buckets) != len(handshakeBounds)+1) {
						t.Fatalf("edge %+v: %s with buckets %v", id, k.metric, p.buckets)
					}
					if math.IsNaN(p.value) || math.IsInf(p.value, 0) {
						t.Fatalf("edge %+v: %s of %v", id, k.metric, p.value)
					}
				}
			}
			for id := range b.listeners {
				checkProcess(t, &id.process)
				switch id.proto {
				case "tcp", "udp":
					checkAddr(t, id.addr)
				case transportUnix:
					if id.path == "" || !cleanBounded(id.path) || id.addr.IsValid() || id.port != 0 || id.netns > math.MaxUint32 {
						t.Fatalf("Unix listener %+v", id)
					}
				default:
					t.Fatalf("listener of %q", id.proto)
				}
			}
			for id := range b.translations {
				for _, a := range []netip.Addr{id.client, id.virtual, id.source, id.backend} {
					checkAddr(t, a)
					if a.IsUnspecified() {
						t.Fatalf("translation %+v", id)
					}
				}
				if (id.proto != "tcp" && id.proto != "udp") || id.netns > math.MaxUint32 {
					t.Fatalf("translation %+v", id)
				}
			}
			// What is forwarded of the agent is what the agents send.
			names := map[string]bool{}
			for i := range b.agent.Len() {
				m := b.agent.At(i)
				desc, ok := agentMetrics[m.Name()]
				if !ok || names[m.Name()] || m.Unit() != desc.unit {
					t.Fatalf("forwarded the metric %q (unit %q) of the agent", m.Name(), m.Unit())
				}
				names[m.Name()] = true
				var dps pmetric.NumberDataPointSlice
				switch {
				case desc.gauge && m.Type() == pmetric.MetricTypeGauge:
					dps = m.Gauge().DataPoints()
				case !desc.gauge && m.Type() == pmetric.MetricTypeSum:
					dps = m.Sum().DataPoints()
				default:
					t.Fatalf("forwarded %s as a %v", m.Name(), m.Type())
				}
				values := map[string]bool{}
				for j := range dps.Len() {
					a := dps.At(j).Attributes()
					v := getString(a, desc.attr)
					if (desc.attr == "" && a.Len() != 0) || (desc.attr != "" && (a.Len() != 1 || !desc.valid(v))) ||
						values[v] || (j > 0 && !desc.perValue) {
						t.Fatalf("forwarded a point of %s with %v", m.Name(), a.AsRaw())
					}
					values[v] = true
				}
			}
		}
	})
}

// FuzzConsumeMetrics checks the outputs of a request: the metrics of the
// connector and of the agents only, with labels of bounded size that are
// valid UTF-8, and values that are numbers.
func FuzzConsumeMetrics(f *testing.F) {
	addFuzzRequests(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		md, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(data)
		if err != nil {
			return
		}
		c, _, sink, now := testConnector(t, nil)
		*now = now.Add(15 * time.Second)
		// Refusals are errors for the agent, not for the connector.
		_ = c.ConsumeMetrics(context.Background(), md)
		checkAttrs := func(where string, a pcommon.Map) {
			for k, v := range a.All() {
				if v.Type() != pcommon.ValueTypeStr {
					continue
				}
				limit := maxLabelValue
				if k == attrPeerService {
					limit = maxPeerName
				}
				if s := v.Str(); !utf8.ValidString(s) || len(s) > limit {
					t.Fatalf("%s: %s of %d bytes: %q", where, k, len(s), s)
				}
			}
		}
		checkNumber := func(name string, v float64) {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("%s: %v", name, v)
			}
		}
		for _, out := range sink.AllMetrics() {
			rms := out.ResourceMetrics()
			for i := range rms.Len() {
				checkAttrs("resource", rms.At(i).Resource().Attributes())
				sms := rms.At(i).ScopeMetrics()
				for j := range sms.Len() {
					ms := sms.At(j).Metrics()
					for k := range ms.Len() {
						m := ms.At(k)
						_, edge := outMetrics[m.Name()]
						_, agent := agentMetrics[m.Name()]
						if !edge && !agent {
							t.Fatalf("output metric %q", m.Name())
						}
						switch m.Type() {
						case pmetric.MetricTypeSum, pmetric.MetricTypeGauge:
							var dps pmetric.NumberDataPointSlice
							if m.Type() == pmetric.MetricTypeGauge {
								dps = m.Gauge().DataPoints()
							} else {
								dps = m.Sum().DataPoints()
							}
							for l := range dps.Len() {
								checkAttrs(m.Name(), dps.At(l).Attributes())
								if edge {
									checkNumber(m.Name(), numberValue(dps.At(l)))
								}
							}
						case pmetric.MetricTypeHistogram:
							dps := m.Histogram().DataPoints()
							for l := range dps.Len() {
								checkAttrs(m.Name(), dps.At(l).Attributes())
								checkNumber(m.Name(), dps.At(l).Sum())
							}
						default:
							t.Fatalf("output metric %q of type %v", m.Name(), m.Type())
						}
					}
				}
			}
		}
	})
}
