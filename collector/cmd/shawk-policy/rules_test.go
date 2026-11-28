package main

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testUntil = time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// testFlow returns a flow of the period of the tests, last seen at its end.
func testFlow(direction, service, proto, addr string, port int, peer string) flow {
	return flow{direction: direction, inPeriod: true, service: service, unit: service + ".service", proto: proto,
		addr: netip.MustParsePrefix(addr), port: port, portFrom: port, portTo: port, peer: peer,
		first: testUntil.Add(-80 * 24 * time.Hour), last: testUntil}
}

// testReport returns a report of the flows over the 90 days before
// testUntil, complete unless its status is changed.
func testReport(t testing.TB, tg target, format, ingressMode string, flows ...flow) *rulesReport {
	t.Helper()
	r := &rulesReport{Target: tg, Since: testUntil.Add(-90 * 24 * time.Hour), Until: testUntil, Status: statusComplete,
		Coverage: 1, MinCoverage: 1, coverage: "1.000000", minCoverage: "1.000000000000", Format: format,
		Reasons: []string{}, Caveats: []string{}, Gaps: []gap{}, Rules: []rule{}, Findings: []finding{}, Before: []pastFlow{},
		Observation: &observation{Host: tg.Host, Machines: 1, ToleranceSeconds: 180}, NetworkNamespaces: 1, TranslationsTraced: true}
	switch format {
	case formatNftables:
		r.Mode = modeAudit
	case formatSystemd:
		r.Mode = modeEnforce
	}
	if format != formatSystemd {
		r.Ingress = ingressMode
	}
	if err := r.build(flows, ingressMode); err != nil {
		t.Fatal(err)
	}
	return r
}

// appFlows are the flows of a host of an application.
func appFlows() []flow {
	pg := testFlow(egress, "shop/app", "tcp", "10.0.0.10/32", 5432, "shop/postgres")
	pg.peerHost = ptr("db-01")
	pg2 := testFlow(egress, "shop/app", "tcp", "10.0.0.20/32", 5432, "shop/postgres")
	pg2.peerHost = ptr("db-02")
	pg2.last = testUntil.Add(-48 * time.Hour)
	job := testFlow(egress, "shop/app", "tcp", "10.0.9.9/32", 9000, "~unresolved")
	job.inPeriod, job.last = false, testUntil.Add(-95*24*time.Hour)
	srun := testFlow(egress, "shop/app", "tcp", "10.0.0.60/32", 41000, "srun")
	srun.portFrom, srun.portTo = 1, 65535
	chosen := testFlow(egress, "shop/app", "tcp", "10.0.0.61/32", 45678, "x")
	chosen.kernelChosen = true
	backend := testFlow(egress, "kubelet", "tcp", "10.0.0.40/32", 6443, "~unresolved")
	backend.translated = true
	web := testFlow(ingress, "shop/app", "tcp", "10.0.0.12/32", 8080, "nginx")
	web.peerHost = ptr("web-01")
	return []flow{
		pg, pg2, job, srun, chosen, backend, web,
		testFlow(egress, "shop/app", "udp", "10.0.0.53/32", 53, "~unresolved"),
		testFlow(egress, "shop/app", "tcp", "0.0.0.0/0", 443, "~external"),
		testFlow(egress, "shop/app", "tcp", "::/0", 443, "~external"),
		testFlow(egress, "shop/app", "tcp", "192.0.2.7/32", 443, "~external"),
		testFlow(egress, "shop/app", "tcp", "2001:db8::7/128", 8443, "partner"),
		testFlow(egress, "shop/app", "tcp", "127.0.0.1/32", 6379, "redis"),
		testFlow(egress, "shop/app", "tcp", "::1/128", 6379, "redis"),
		testFlow(ingress, "shop/app", "tcp", "0.0.0.0/0", 8080, "~external"),
		testFlow(ingress, "sshd", "tcp", "10.0.5.5/32", 22, "~unresolved"),
		testFlow(ingress, "sshd", "tcp", "10.0.5.6/32", 22, "~unresolved"),
	}
}

// TestBuildRules: the flows of a peer on a port are one rule with their
// addresses, loopback and the flows seen before the period are in none,
// and the findings tell what the rules pin.
func TestBuildRules(t *testing.T) {
	r := testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, appFlows()...)
	var got []string
	for _, ru := range r.Rules {
		got = append(got, fmt.Sprintf("%s %s %s %v %v %v [%s]", ru.Direction, ru.portsOf(), ru.Peer, ru.PeerHosts,
			ru.Addresses, ru.Services, describeNotes(&ru)))
	}
	want := []string{
		"egress 1-65535/tcp srun [] [10.0.0.60/32] [shop/app] []",
		"egress 443/tcp ~external [] [0.0.0.0/0 ::/0] [shop/app] [folded peers]",
		"egress 5432/tcp shop/postgres [db-01 db-02] [10.0.0.10/32 10.0.0.20/32] [shop/app] []",
		"egress 6443/tcp ~unresolved [] [10.0.0.40/32] [kubelet] [translated by the host]",
		"egress 8443/tcp partner [] [2001:db8::7/128] [shop/app] []",
		"egress 45678/tcp x [] [10.0.0.61/32] [shop/app] [port chosen by the kernel]",
		"egress 53/udp ~unresolved [] [10.0.0.53/32] [shop/app] []",
		"ingress 22/tcp ~unresolved [] [10.0.5.5/32 10.0.5.6/32] [sshd] []",
		"ingress 8080/tcp nginx [web-01] [10.0.0.12/32] [shop/app] []",
		"ingress 8080/tcp ~external [] [0.0.0.0/0] [shop/app] [folded peers]",
		// The other way of the flow of UDP: what the resolver sends from
		// its port, whenever it does.
		"ingress 53/udp from 53 ~unresolved [] [10.0.0.53/32] [shop/app] [the other way of a UDP rule]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A rule is last seen when its latest flow was.
	if ru := r.Rules[2]; !ru.LastSeen.Equal(testUntil) || !ru.FirstSeen.Equal(testUntil.Add(-80*24*time.Hour)) {
		t.Errorf("the rule of postgres was seen from %s to %s", ru.FirstSeen, ru.LastSeen)
	}
	if r.Loopback != 2 || len(r.Before) != 1 || r.Before[0].Port != 9000 {
		t.Errorf("%d loopback flows, flows before the period %+v", r.Loopback, r.Before)
	}
	var codes []string
	for _, f := range r.Findings {
		codes = append(codes, f.Code+" "+strconv.Itoa(f.Count))
	}
	wantCodes := []string{"pinned_addresses 10", "folded_peers 2", "unresolved_peers 3", "port_ranges 1", "kernel_chosen_ports 1",
		"translated_backends 1", "udp_both_ways 1", "pinned_sources 3", "loopback_flows 2", "seen_before_period 1"}
	if !slices.Equal(codes, wantCodes) {
		t.Errorf("findings %v, want %v", codes, wantCodes)
	}

	// With -ingress ports the rules of the connections that the host
	// accepts pin no source; a unit tells the sockets without an owner.
	r = testReport(t, target{Host: "app-01"}, formatNftables, ingressPorts, appFlows()...)
	if n := slices.IndexFunc(r.Findings, func(f finding) bool { return f.Code == "pinned_sources" }); n >= 0 {
		t.Errorf("with -ingress ports: %+v", r.Findings[n])
	}
	if f := r.Findings[0]; f.Code != "pinned_addresses" || f.Count != 7 {
		t.Errorf("with -ingress ports: %+v", f)
	}
	// A socket without a known owner has no unit; a process that names
	// itself ~unknown in a unit is a process of that unit.
	unknown := testFlow(egress, unknownService, "tcp", "10.0.0.30/32", 9999, "~unresolved")
	unknown.unit = ""
	named := testFlow(egress, unknownService, "tcp", "10.0.0.31/32", 9998, "~unresolved")
	named.unit = "shop/app.service"
	r = testReport(t, target{Host: "app-01", Unit: "shop/app.service"}, formatSystemd, ingressSources, append(appFlows(), unknown, named)...)
	if n := slices.IndexFunc(r.Rules, func(ru rule) bool { return ru.PortFrom == 9999 }); n < 0 || !r.Rules[n].Unattributed ||
		slices.ContainsFunc(r.Rules, func(ru rule) bool { return ru.PortFrom != 9999 && ru.Unattributed }) {
		t.Errorf("the rule of the socket without an owner: %+v", r.Rules)
	}
	if n := slices.IndexFunc(r.Findings, func(f finding) bool { return f.Code == "unattributed_sockets" }); n < 0 || r.Findings[n].Count != 1 {
		t.Errorf("no finding for the sockets without an owner: %+v", r.Findings)
	}
	// A drop-in has no direction and no port: no rule of the other way,
	// and what allows a whole family is told as what limits nothing.
	if slices.ContainsFunc(r.Rules, func(ru rule) bool { return ru.SamePort }) {
		t.Errorf("a drop-in with rules of the other way of UDP: %+v", r.Rules)
	}
	codes = nil
	for _, f := range r.Findings {
		if f.Code == "family_open" {
			codes = append(codes, f.Text[:38])
		}
	}
	if !slices.Equal(codes, []string{"the drop-in limits nothing for IPv4: a", "the drop-in limits nothing for IPv6: a"}) {
		t.Errorf("findings of the families that are open: %q", codes)
	}
	// A host of containers.
	r = testReport(t, target{Host: "app-01"}, formatNftables, ingressSources)
	r.NetworkNamespaces = 3
	if f := r.findings(); len(f) != 1 || f[0].Code != "other_network_namespaces" {
		t.Errorf("findings of a host of containers: %+v", f)
	}
}

// TestBuildRulesBothWays: a flow of UDP on one port allows its peer the
// other way too, between that port on both sides and no other: a socket of
// UDP may send and receive first on one port, and one direction of it is
// recorded.
func TestBuildRulesBothWays(t *testing.T) {
	gossip := testFlow(ingress, "consul", "udp", "10.0.0.200/32", 8301, "~unresolved")
	dns := testFlow(egress, "shop/app", "udp", "10.0.0.53/32", 53, "~unresolved")
	web := testFlow(ingress, "shop/app", "tcp", "10.0.0.12/32", 8080, "nginx")
	// No exchange keeps a port that changes on both sides: a range of
	// ports, and a port that the kernel chose for the server.
	ranged := testFlow(egress, "shop/app", "udp", "10.0.0.61/32", 30100, "nodeport")
	ranged.portFrom, ranged.portTo = 30000, 32767
	chosen := testFlow(ingress, "shop/app", "udp", "10.0.0.62/32", 41234, "~unresolved")
	chosen.kernelChosen = true
	list := func(mode string, flows ...flow) []string {
		var out []string
		r := testReport(t, target{Host: "app-01"}, formatNftables, mode, flows...)
		for _, ru := range r.Rules {
			out = append(out, fmt.Sprintf("%s %s any=%t", ru.Direction, ru.portsOf(), ru.AnySource))
		}
		for _, f := range r.Findings {
			if f.Code == "udp_both_ways" || f.Code == "pinned_sources" || f.Code == "pinned_addresses" {
				out = append(out, f.Code+" "+strconv.Itoa(f.Count))
			}
		}
		return out
	}
	for mode, want := range map[string][]string{
		ingressSources: {"egress 53/udp any=false", "egress 8301/udp from 8301 any=false", "ingress 8080/tcp any=false",
			"ingress 53/udp from 53 any=false", "ingress 8301/udp any=false", "pinned_addresses 3", "udp_both_ways 2", "pinned_sources 2"},
		// With -ingress ports what the host accepts pins no source; what
		// it sends from that port stays pinned to the peers that were
		// seen, as everything that it sends is.
		ingressPorts: {"egress 53/udp any=false", "egress 8301/udp from 8301 any=false", "ingress 8080/tcp any=true",
			"ingress 53/udp from 53 any=false", "ingress 8301/udp any=true", "pinned_addresses 1", "udp_both_ways 2"},
		// With -ingress none nothing is written of what the host accepts,
		// and nothing of it is counted; what it sends from the port of its
		// server is still of what it sends.
		ingressNone: {"egress 53/udp any=false", "egress 8301/udp from 8301 any=false", "pinned_addresses 1", "udp_both_ways 1"},
	} {
		if got := list(mode, gossip, dns, web); !slices.Equal(got, want) {
			t.Errorf("-ingress %s: %q, want %q", mode, got, want)
		}
	}
	if got, want := list(ingressSources, ranged, chosen), []string{"egress 30000-32767/udp any=false", "ingress 41234/udp any=false",
		"pinned_addresses 2", "pinned_sources 1"}; !slices.Equal(got, want) {
		t.Errorf("a range of ports and a port that the kernel chose: %q, want %q", got, want)
	}
	// The table names the port on both sides, with the address of the
	// peer: the source port alone would open every port of the host to
	// whoever sends from it, and every port of the peer to the host.
	for _, mode := range []string{ingressSources, ingressPorts} {
		text := render(testReport(t, target{Host: "app-01"}, formatNftables, mode, gossip, dns, web))
		for _, want := range []string{"\t\tip saddr 10.0.0.53 udp sport 53 udp dport 53 accept\n",
			"\t\tip daddr 10.0.0.200 udp sport 8301 udp dport 8301 accept\n"} {
			if !strings.Contains(text, want) {
				t.Errorf("-ingress %s: no %q in\n%s", mode, want, text)
			}
		}
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "sport") &&
				!regexp.MustCompile(`^\t\tip [sd]addr [0-9.]+ udp sport (\d+) udp dport (\d+) accept$`).MatchString(line) {
				t.Errorf("-ingress %s: a rule by the source port that does not name the peer and both ports: %q", mode, line)
			}
		}
	}
}

// TestBuildRulesInvalid: a flow that the rules cannot be written from, as
// a row of a schema that this command does not know, is an error.
func TestBuildRulesInvalid(t *testing.T) {
	for name, mod := range map[string]func(*flow){
		"direction":  func(f *flow) { f.direction = "forward" },
		"transport":  func(f *flow) { f.proto = "sctp" },
		"proto text": func(f *flow) { f.proto = "tcp dport 1 accept\n" },
		"address":    func(f *flow) { f.addr = netip.Prefix{} },
		"ports":      func(f *flow) { f.portFrom, f.portTo = 10, 5 },
		"port":       func(f *flow) { f.portTo = 70000 },
		"negative":   func(f *flow) { f.portFrom = -1 },
	} {
		f := testFlow(egress, "a", "tcp", "10.0.0.1/32", 80, "b")
		mod(&f)
		r := &rulesReport{Target: target{Host: "h"}, Format: formatNftables}
		if err := r.build([]flow{f}, ingressSources); err == nil {
			t.Errorf("%s: a flow %+v is accepted", name, f)
		}
	}
}

func TestNormalizePrefixes(t *testing.T) {
	in := []string{"10.0.0.5/32", "10.0.0.0/24", "10.0.0.5/32", "10.0.1.7/32", "10.0.0.0/8", "192.0.2.1/32", "fd00::1/128",
		"fd00::/8", "::ffff:10.9.9.9/128", "2001:db8::1/128", "10.0.0.77/24"}
	var ps []netip.Prefix
	for _, s := range in {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	got := fmt.Sprint(normalizePrefixes(ps))
	if want := "[10.0.0.0/8 192.0.2.1/32 2001:db8::1/128 fd00::/8]"; got != want {
		t.Errorf("normalizePrefixes = %s, want %s", got, want)
	}
	if got := fmt.Sprint(normalizePrefixes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.0.0.1/32"),
		netip.MustParsePrefix("::/0")})); got != "[0.0.0.0/0 ::/0]" {
		t.Errorf("with whole families: %s", got)
	}
}

// randomPrefix makes a prefix from random numbers: both families, every
// length, with addresses close to each other so that prefixes nest.
func randomPrefix(rnd *rand.Rand) netip.Prefix {
	if rnd.IntN(3) == 0 {
		var b [16]byte
		b[0], b[1] = 0xfd, byte(rnd.IntN(2))
		b[15] = byte(rnd.IntN(4))
		bits := []int{0, 8, 16, 64, 126, 127, 128}[rnd.IntN(7)]
		return netip.PrefixFrom(netip.AddrFrom16(b), bits)
	}
	b := [4]byte{10, byte(rnd.IntN(2)), byte(rnd.IntN(2)), byte(rnd.IntN(6))}
	bits := []int{0, 8, 16, 24, 30, 31, 32, 32, 32}[rnd.IntN(9)]
	return netip.PrefixFrom(netip.AddrFrom4(b), bits)
}

// FuzzNormalizePrefixes: the prefixes kept are in order, none is within
// another, and together they hold what the prefixes given hold, no more.
func FuzzNormalizePrefixes(f *testing.F) {
	for _, seed := range []uint64{0, 1, 2, 3, 42, 1 << 40} {
		f.Add(seed, uint8(12))
	}
	f.Fuzz(func(t *testing.T, seed uint64, n uint8) {
		rnd := rand.New(rand.NewPCG(seed, 232))
		var in []netip.Prefix
		for range int(n % 40) {
			in = append(in, randomPrefix(rnd))
		}
		out := normalizePrefixes(in)
		for i, p := range out {
			if p != p.Masked() {
				t.Fatalf("%s is not masked", p)
			}
			for j, q := range out {
				if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
					t.Fatalf("%s is within %s in %v, of %v", p, q, out, in)
				}
			}
			if i > 0 && cmp.Or(out[i-1].Addr().Compare(p.Addr()), cmp.Compare(out[i-1].Bits(), p.Bits())) >= 0 {
				t.Fatalf("%v is not in order", out)
			}
			if !slices.ContainsFunc(in, func(q netip.Prefix) bool { return q.Masked() == p }) {
				t.Fatalf("%s of %v is none of %v", p, out, in)
			}
		}
		for _, p := range in {
			if !slices.ContainsFunc(out, func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Contains(p.Masked().Addr()) }) {
				t.Fatalf("%s of %v is in none of %v", p, in, out)
			}
		}
	})
}

// allowed is what a file of rules allows: a direction, a transport, ports
// and a prefix, or every address (any).
type allowed struct {
	direction, proto string
	from, to         int
	prefix           netip.Prefix
	anyAddr          bool
	// same tells that the packets come from the port too: the other way of
	// a UDP rule.
	same bool
}

func (a allowed) String() string {
	addr := a.prefix.String()
	if a.anyAddr {
		addr = "any"
	}
	return fmt.Sprintf("%s %s %s %d-%d %s", a.direction, a.proto, map[bool]string{false: "to", true: "between"}[a.same], a.from, a.to, addr)
}

// expected returns what the rules of a report allow, as nftables is asked
// to: per rule, each of its addresses, or every address.
func expected(r *rulesReport) []string {
	var out []string
	for _, ru := range r.Rules {
		if ru.Direction == ingress && r.Ingress == ingressNone {
			continue
		}
		if ru.AnySource {
			out = append(out, allowed{ru.Direction, ru.Proto, ru.PortFrom, ru.PortTo, netip.Prefix{}, true, ru.SamePort}.String())
			continue
		}
		for _, p := range ru.Addresses {
			out = append(out, allowed{ru.Direction, ru.Proto, ru.PortFrom, ru.PortTo, p, false, ru.SamePort}.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// The lines of a table of nftables that are not rules of flows, and the
// forms of those that are. A file that holds any other line is not what
// the command means to write: a name that became a rule, for one.
var (
	nftFixed = map[string]bool{
		"#!/usr/sbin/nft -f": true, "": true,
		"table inet shawk_policy": true, "delete table inet shawk_policy": true, "table inet shawk_policy {": true, "}": true,
		"\tchain output {": true, "\tchain input {": true, "\t}": true,
		"\t\ttype filter hook output priority filter; policy accept;": true,
		"\t\ttype filter hook input priority filter; policy accept;":  true,
		"\t\tct state established,related accept":                     true,
		"\t\toifname \"lo\" accept":                                   true, "\t\tiifname \"lo\" accept": true,
		"\t\tmeta l4proto != { tcp, udp } accept": true,
		"\tcounter egress_unlisted { }":           true, "\tcounter ingress_unlisted { }": true,
		// The end of a chain of the form that rejects.
		"\t\tlimit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted egress: \"":  true,
		"\t\tlimit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted ingress: \"": true,
		"\t\tcounter name \"egress_unlisted\" reject with icmpx admin-prohibited":                  true,
		"\t\tcounter name \"ingress_unlisted\" drop":                                               true,
		// What the audit form has in their place, and around the flows.
		"\t\tct state new,related ct label set 125":                                  true,
		"\t\tct state established,related ct label 125 ct label & 126 != 126 accept": true,
		"\t\tct state established,related ct label 125 ct label & 127 != 127 accept": true,
		"\t\tct direction reply accept":                                              true,
		"\t\tct label 126 counter name \"egress_unlisted\" accept":                   true,
		"\t\tct label 127 counter name \"ingress_unlisted\" accept":                  true,
		"\t\tct state new tcp flags & (fin | syn | rst | ack) != syn counter name \"egress_unlisted\" limit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted egress: \" accept":   true,
		"\t\tct state new tcp flags & (fin | syn | rst | ack) != syn counter name \"ingress_unlisted\" limit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted ingress: \" accept": true,
		"\t\tct label set 126 counter name \"egress_unlisted\" limit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted egress: \"":                                                 true,
		"\t\tct label set 127 counter name \"ingress_unlisted\" limit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted ingress: \"":                                               true,
	}
	// A set of more addresses than fit a line is written over several,
	// which nftJoin puts back on one.
	nftSetLines = regexp.MustCompile(`(?m) \{\n((?:\t\t\t[0-9a-f.:/]+(?:, [0-9a-f.:/]+)*,?\n)+)\t\t\} `)
	nftRule     = regexp.MustCompile(`^\t\t(?:(ip6?) ([sd]addr) (\{ [0-9a-f.:/, ]+ \}|[0-9a-f.:/]+) |meta nfproto (ipv[46]) )?(tcp|udp) (?:sport (\d+) udp )?dport (\d+)(?:-(\d+))? accept$`)
)

// parseNftables reads a table that writeNftables wrote and returns what it
// allows. It fails on a line that is neither a comment, a line of the
// frame of the table, nor a rule of a flow.
func parseNftables(t testing.TB, text string) []string {
	t.Helper()
	text = nftSetLines.ReplaceAllStringFunc(text, func(set string) string {
		lines := strings.Split(strings.TrimSuffix(nftSetLines.FindStringSubmatch(set)[1], "\n"), "\n")
		for i, l := range lines {
			if more := strings.HasSuffix(l, ","); more != (i < len(lines)-1) {
				t.Fatalf("a line of a set ends or goes on where it should not: %q", set)
			}
			lines[i] = strings.TrimSuffix(strings.TrimPrefix(l, "\t\t\t"), ",")
		}
		return " { " + strings.Join(lines, ", ") + " } "
	})
	var out []string
	chain := ""
	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(strings.TrimLeft(line, "\t"), "#") && i > 0:
			if !oneCommentLine(line) {
				t.Fatalf("line %d is a comment that does not end: %q", i+1, line)
			}
			continue
		case line == "\tchain output {":
			chain = egress
		case line == "\tchain input {":
			chain = ingress
		}
		if nftFixed[line] {
			continue
		}
		m := nftRule.FindStringSubmatch(line)
		if m == nil || chain == "" {
			t.Fatalf("line %d is no line of a table of rules: %q\n%s", i+1, line, text)
		}
		if (m[2] == "daddr") != (chain == egress) && m[2] != "" {
			t.Fatalf("line %d matches %s in the chain of %s", i+1, m[2], chain)
		}
		from, _ := strconv.Atoi(m[7])
		to := from
		if m[8] != "" {
			to, _ = strconv.Atoi(m[8])
		}
		// A rule by the source port is the other way of a UDP rule: of
		// UDP, with the address of its peer, and the same port on both
		// sides.
		if m[6] != "" && (m[5] != "udp" || m[6] != m[7] || m[8] != "" || (m[1] == "" && m[4] == "")) {
			t.Fatalf("line %d matches a source port otherwise than with the same port of UDP on both sides: %q", i+1, line)
		}
		a := allowed{direction: chain, proto: m[5], from: from, to: to, same: m[6] != ""}
		switch {
		case m[4] == "ipv4":
			a.prefix = netip.MustParsePrefix("0.0.0.0/0")
			out = append(out, a.String())
		case m[4] == "ipv6":
			a.prefix = netip.MustParsePrefix("::/0")
			out = append(out, a.String())
		case m[1] == "":
			a.anyAddr = true
			out = append(out, a.String())
		default:
			for _, s := range strings.Split(strings.Trim(m[3], "{} "), ", ") {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					addr, err := netip.ParseAddr(s)
					if err != nil {
						t.Fatalf("line %d: %q is no address: %q", i+1, s, line)
					}
					p = netip.PrefixFrom(addr, addr.BitLen())
				}
				if p.Addr().Is4() != (m[1] == "ip") {
					t.Fatalf("line %d: %s is matched as %s", i+1, p, m[1])
				}
				a.prefix = p
				out = append(out, a.String())
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var systemdAllow = regexp.MustCompile(`^IPAddressAllow=([0-9a-f.:/]+)$`)

// parseSystemd reads a drop-in that writeSystemd wrote and returns the
// prefixes it allows. It fails on a line that is neither a comment nor
// one of the settings of the drop-in.
func parseSystemd(t testing.TB, text string) []string {
	t.Helper()
	var out []string
	section, deny, local := 0, 0, 0
	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			if !oneCommentLine(line) {
				t.Fatalf("line %d is a comment that does not end: %q", i+1, line)
			}
		case line == "[Service]":
			section++
		case line == "IPAddressDeny=any":
			deny++
		case line == "IPAddressAllow=localhost":
			local++
		default:
			m := systemdAllow.FindStringSubmatch(line)
			if m == nil || section != 1 || deny != 1 {
				t.Fatalf("line %d is no line of a drop-in of rules: %q\n%s", i+1, line, text)
			}
			p, err := netip.ParsePrefix(m[1])
			if err != nil {
				addr, err := netip.ParseAddr(m[1])
				if err != nil {
					t.Fatalf("line %d: %q is no address", i+1, m[1])
				}
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			out = append(out, p.String())
		}
	}
	if section != 1 || deny != 1 || local != 1 {
		t.Fatalf("%d sections, %d IPAddressDeny=any and %d IPAddressAllow=localhost\n%s", section, deny, local, text)
	}
	slices.Sort(out)
	return out
}

// expectedSystemd returns the prefixes that the drop-in of a report must
// allow: every address of every rule, once.
func expectedSystemd(r *rulesReport) []string {
	var out []string
	for _, ru := range r.Rules {
		for _, p := range ru.Addresses {
			out = append(out, p.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func render(r *rulesReport) string {
	var b bytes.Buffer
	if err := writeRules(&b, r, 0); err != nil {
		panic(err)
	}
	return b.String()
}

// TestWriteNftables: the table of a host, as it is written.
func TestWriteNftables(t *testing.T) {
	r := testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, appFlows()...)
	got := render(r)
	golden(t, "app-01.audit.nft", got)
	if got, want := parseNftables(t, got), expected(r); !slices.Equal(got, want) {
		t.Errorf("the table allows\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// -ingress ports opens the ports that were seen to every source, and
	// -ingress none writes no chain for what the host accepts.
	r = testReport(t, target{Host: "app-01"}, formatNftables, ingressPorts, appFlows()...)
	got = render(r)
	for _, want := range []string{"\t\t# ingress 22/tcp: ~unresolved, of sshd, last seen 2026-11-28T00:00:00Z [from every address]\n\t\ttcp dport 22 accept\n",
		"\t\ttcp dport 8080 accept\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("with -ingress ports, no %q in\n%s", want, got)
		}
	}
	// The peer of what the host sends over UDP stays pinned the other way:
	// it is of what the host opens. No other source is pinned.
	if regexp.MustCompile(`saddr [^\n]* (tcp|udp) dport`).MatchString(strings.ReplaceAll(got, "ip saddr 10.0.0.53 udp sport 53 udp dport 53 accept", "")) ||
		!strings.Contains(got, "\t\tip saddr 10.0.0.53 udp sport 53 udp dport 53 accept\n") {
		t.Errorf("with -ingress ports, a source is pinned:\n%s", got)
	}
	if got, want := parseNftables(t, got), expected(r); !slices.Equal(got, want) {
		t.Errorf("with -ingress ports the table allows\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// With -ingress none the file tells that it filters what the host
	// opens only, and counts no rule of what it accepts.
	r = testReport(t, target{Host: "app-01"}, formatNftables, ingressNone, appFlows()...)
	if got = render(r); strings.Contains(got, "\tchain input {") || strings.Contains(got, "ingress rule") ||
		strings.Contains(got, "ingress_unlisted") || strings.Contains(got, "connections of the host itself (the hooks input and output)") ||
		!strings.Contains(got, "# It filters the connections that the host opens (the hook output) only: with -ingress none\n") ||
		!strings.Contains(got, "#   - 7 addresses are pinned") {
		t.Errorf("with -ingress none:\n%s", got)
	}
	if got, want := parseNftables(t, got), expected(r); !slices.Equal(got, want) {
		t.Errorf("with -ingress none the table allows\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The form that rejects: the same rules, and what no rule lists is
	// refused.
	r = testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, appFlows()...)
	audit := parseNftables(t, render(r))
	r.Mode = modeEnforce
	got = render(r)
	golden(t, "app-01.enforce.nft", got)
	if rejecting := parseNftables(t, got); !slices.Equal(rejecting, audit) {
		t.Errorf("the form that rejects allows\n%s\nand the audit form\n%s", strings.Join(rejecting, "\n"), strings.Join(audit, "\n"))
	}
	for form, ends := range map[string][2]string{
		modeAudit: {"\t\tct label set 126 counter name \"egress_unlisted\" limit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted egress: \"\n\t}\n",
			"\t\tct label set 127 counter name \"ingress_unlisted\" limit rate 10/second burst 20 packets log prefix \"shawk-policy unlisted ingress: \"\n\t}\n"},
		modeEnforce: {"\t\tcounter name \"egress_unlisted\" reject with icmpx admin-prohibited\n\t}\n",
			"\t\tcounter name \"ingress_unlisted\" drop\n\t}\n"},
	} {
		r.Mode = form
		text := render(r)
		// The audit form refuses nothing, anywhere in the file.
		refuses := regexp.MustCompile(`(?m)^[^#\n]*\b(reject|drop)\b`).MatchString(text)
		if !strings.Contains(text, ends[0]) || !strings.Contains(text, ends[1]) || refuses != (form == modeEnforce) {
			t.Errorf("the %s form ends its chains otherwise, or refuses: %t\n%s", form, refuses, text)
		}
	}
	// The two forms hold the same lines for the flows, in the same order:
	// what the audit form compares a connection with is what the form that
	// rejects accepts. They differ in their frame alone: the audit form
	// follows the connections that no rule lists, and every rule of its
	// frame lets the packet pass or go on.
	frames := map[string][]string{}
	for _, form := range []string{modeAudit, modeEnforce} {
		r.Mode = form
		var flows []string
		for _, line := range strings.Split(render(r), "\n") {
			switch {
			case strings.HasPrefix(strings.TrimSpace(line), "#") || !strings.HasPrefix(line, "\t\t"):
			case nftRule.MatchString(line) || strings.HasPrefix(line, "\t\t\t") || strings.HasSuffix(line, "{") || strings.HasPrefix(line, "\t\t} "):
				flows = append(flows, line)
			default:
				frames[form] = append(frames[form], strings.TrimSpace(line))
			}
		}
		frames[form+" flows"] = flows
	}
	if !slices.Equal(frames[modeAudit+" flows"], frames[modeEnforce+" flows"]) || len(frames[modeAudit+" flows"]) == 0 {
		t.Errorf("the lines of the flows differ between the forms:\n%s\nand\n%s", strings.Join(frames[modeAudit+" flows"], "\n"),
			strings.Join(frames[modeEnforce+" flows"], "\n"))
	}
	wantFrames := map[string][]string{
		modeEnforce: {
			"type filter hook output priority filter; policy accept;",
			"ct state established,related accept", `oifname "lo" accept`, "meta l4proto != { tcp, udp } accept",
			`limit rate 10/second burst 20 packets log prefix "shawk-policy unlisted egress: "`,
			`counter name "egress_unlisted" reject with icmpx admin-prohibited`,
			"type filter hook input priority filter; policy accept;",
			"ct state established,related accept", `iifname "lo" accept`, "meta l4proto != { tcp, udp } accept",
			`limit rate 10/second burst 20 packets log prefix "shawk-policy unlisted ingress: "`,
			`counter name "ingress_unlisted" drop`,
		},
		modeAudit: {
			"type filter hook output priority filter; policy accept;",
			"ct state new,related ct label set 125", "ct state established,related ct label 125 ct label & 126 != 126 accept",
			`oifname "lo" accept`, "meta l4proto != { tcp, udp } accept", "ct direction reply accept",
			`ct label 126 counter name "egress_unlisted" accept`,
			`ct state new tcp flags & (fin | syn | rst | ack) != syn counter name "egress_unlisted" limit rate 10/second burst 20 packets log prefix "shawk-policy unlisted egress: " accept`,
			`ct label set 126 counter name "egress_unlisted" limit rate 10/second burst 20 packets log prefix "shawk-policy unlisted egress: "`,
			"type filter hook input priority filter; policy accept;",
			"ct state new,related ct label set 125", "ct state established,related ct label 125 ct label & 127 != 127 accept",
			`iifname "lo" accept`, "meta l4proto != { tcp, udp } accept", "ct direction reply accept",
			`ct label 127 counter name "ingress_unlisted" accept`,
			`ct state new tcp flags & (fin | syn | rst | ack) != syn counter name "ingress_unlisted" limit rate 10/second burst 20 packets log prefix "shawk-policy unlisted ingress: " accept`,
			`ct label set 127 counter name "ingress_unlisted" limit rate 10/second burst 20 packets log prefix "shawk-policy unlisted ingress: "`,
		},
	}
	for form, want := range wantFrames {
		if !slices.Equal(frames[form], want) {
			t.Errorf("the frame of the %s form:\n%s\nwant:\n%s", form, strings.Join(frames[form], "\n"), strings.Join(want, "\n"))
		}
	}
	// The audit form tells what its counters count and what they cannot
	// show, and both forms what to check on a host that tracks no
	// connection yet.
	for form, wants := range map[string][]string{
		modeAudit: {"# How to go from this file to rules that reject\n", "#      stays open keeps counting after the counters are cleared",
			"# What the counters of this audit form cannot show\n", "#   - A connection whose opening side sends nothing while you watch",
			"# What this audit form costs\n", "net.netfilter.nf_conntrack_max"},
		modeEnforce: {"# Before loading this file\n", "is established when it is loaded, listed or not", "net.netfilter.nf_conntrack_max"},
	} {
		r.Mode = form
		text := render(r)
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Errorf("the %s form does not tell %q:\n%s", form, want, text)
			}
		}
	}
}

// golden compares a text with a file of testdata, which
// SHAWK_UPDATE_GOLDEN=1 writes again.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("SHAWK_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s:\n%s\nwant:\n%s", name, got, want)
	}
}

// TestWriteSystemd: the drop-in of a unit, as it is written.
func TestWriteSystemd(t *testing.T) {
	flows := slices.DeleteFunc(appFlows(), func(f flow) bool { return f.service != "shop/app" || f.addr.Bits() == 0 })
	// An address of two rules is allowed once.
	flows = append(flows, testFlow(ingress, "shop/app", "tcp", "10.0.0.10/32", 8080, "shop/postgres"))
	r := testReport(t, target{Host: "app-01", Unit: "app.service"}, formatSystemd, ingressSources, flows...)
	r.UnixSockets = true
	got := render(r)
	_, rules, _ := strings.Cut(got, "# To install it:")
	want := `  /etc/systemd/system/app.service.d/50-shawk-policy.conf, then
#                 systemctl daemon-reload, and restart the unit
# To check it:    systemd-analyze verify app.service
# IPAddressAllow= has no ports and one list for both directions: an address is allowed
# for every port and every IP protocol, to connect to and to be accepted from. The list
# holds for the unit and for the control groups under it (a container that it runs).

[Service]
IPAddressDeny=any
# Connections within the host are left open.
IPAddressAllow=localhost

# egress 1-65535/tcp: srun, of shop/app, last seen 2026-11-28T00:00:00Z
IPAddressAllow=10.0.0.60

# egress 443/tcp: ~external, of shop/app, last seen 2026-11-28T00:00:00Z
IPAddressAllow=192.0.2.7

# egress 5432/tcp: shop/postgres on db-01, db-02, of shop/app, last seen 2026-11-28T00:00:00Z
IPAddressAllow=10.0.0.10
IPAddressAllow=10.0.0.20

# egress 8443/tcp: partner, of shop/app, last seen 2026-11-28T00:00:00Z
IPAddressAllow=2001:db8::7

# egress 45678/tcp: x, of shop/app, last seen 2026-11-28T00:00:00Z [port chosen by the kernel]
IPAddressAllow=10.0.0.61

# egress 53/udp: ~unresolved, of shop/app, last seen 2026-11-28T00:00:00Z
IPAddressAllow=10.0.0.53

# ingress 8080/tcp: nginx on web-01, of shop/app, last seen 2026-11-28T00:00:00Z
IPAddressAllow=10.0.0.12

# ingress 8080/tcp: shop/postgres, of shop/app, last seen 2026-11-28T00:00:00Z
# (its addresses are allowed above)

# RestrictAddressFamilies= is left to the reviewer, as a comment: shawk records the
# addresses of connections, not the families of sockets. An AF_INET6 socket carries
# IPv4 peers, and AF_NETLINK, AF_PACKET and datagram AF_UNIX sockets are not observed,
# so a list made from what was seen could keep the unit from starting.
# Seen in the period: peers of IPv4 and IPv6; Unix stream sockets: used.
#RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
`
	if rules != want {
		t.Errorf("the drop-in:\n%s\nwant:\n%s", rules, want)
	}
	if !strings.HasPrefix(got, "# Drop-in of systemd for unit app.service of host app-01, written by shawk-policy for review.\n"+
		"# It blocks, as soon as the unit restarts with it, every address that it does not list, for\n"+
		"# every IP protocol. It has no audit form: check the host with the audit form of\n"+
		"# `shawk-policy rules -format nftables` first.\n"+
		"# shawk applied nothing: read this file, then install it yourself.\n#\n# Target   unit app.service of host app-01\n") {
		t.Errorf("the top of the drop-in:\n%s", got)
	}
	// What the drop-in tells is what IPAddressDeny=any does: every IP
	// protocol, and not the sockets that systemd passes.
	for _, want := range []string{
		"#   - protocols other than TCP and UDP: IPAddressDeny=any blocks every IP protocol of the unit,\n",
		"#   - sockets that systemd passes to the unit (socket activation): the list is not applied to\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in the drop-in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "filter nothing else") || strings.Contains(got, "only TCP and UDP are") {
		t.Errorf("the drop-in tells that it filters TCP and UDP alone:\n%s", got)
	}
	if got, want := parseSystemd(t, got), expectedSystemd(r); !slices.Equal(got, want) {
		t.Errorf("the drop-in allows %v, want %v", got, want)
	}
	// A unit that connected to nothing is allowed nothing but loopback.
	r = testReport(t, target{Host: "app-01", Unit: "idle.service"}, formatSystemd, ingressSources)
	if got := render(r); !strings.Contains(got, "\n[Service]\nIPAddressDeny=any\n# Connections within the host are left open.\nIPAddressAllow=localhost\n\n# RestrictAddressFamilies=") ||
		!strings.Contains(got, "Seen in the period: peers of none; Unix stream sockets: none.") {
		t.Errorf("the drop-in of a unit without connections:\n%s", got)
	}
}

// incomplete makes a report that of a host not observed for an hour.
func incomplete(r *rulesReport) {
	r.Status, r.Reasons, r.Coverage, r.coverage = statusIncomplete, []string{"not_observed", "udp_not_traced"}, 0.999537, "0.999537"
	r.Observation = &observation{Host: r.Target.Host, Machines: 1, UnobservedSeconds: 3600, Gaps: 12, UDPUntracedSeconds: 86400}
	r.Gaps = []gap{{"", testUntil.Add(-10 * 24 * time.Hour), testUntil.Add(-10*24*time.Hour + time.Hour), "agent"},
		{"", r.Since, r.Since.Add(time.Hour), "retention"}}
}

// TestIncomplete: a file that blocks is not written from a history that
// does not tell everything, unless asked for, and then says so first. The
// audit form, which blocks nothing, is written, and says so too.
func TestIncomplete(t *testing.T) {
	status := `Status   INCOMPLETE: the history does not tell every connection of the target in the period.
         Rules made from it deny what was not seen.
         (coverage 0.999537, of the 1 that -min-coverage asks for)
         - not observed by an agent for 1h of the period
         - the agent did not trace UDP for 1d of the period: connections over UDP, as to a
           resolver, are missing

Not observed
  2026-11-18T00:00:00Z to 2026-11-18T01:00:00Z (1h)
  2026-08-30T00:00:00Z to 2026-08-30T01:00:00Z (1h), before the retention of the connector
  and 10 more gaps
`
	for _, format := range []string{formatNftables, formatSystemd} {
		tg := target{Host: "app-01"}
		if format == formatSystemd {
			tg.Unit = "app.service"
		}
		r := testReport(t, tg, format, ingressSources, appFlows()...)
		r.Mode = modeEnforce
		incomplete(r)
		r.Refused = true
		got := render(r)
		if !strings.Contains(got, status) || !strings.HasSuffix(got, "\nNo file that blocks is written from an incomplete history. "+
			"-allow-incomplete writes it all the same,\nmarked as incomplete; -format report lists what it would hold, and "+
			"-format nftables without -enforce\nwrites the audit form, which blocks nothing.\n") ||
			strings.Contains(got, "accept\n") || strings.Contains(got, "\nIPAddressAllow=") {
			t.Errorf("%s, refused:\n%s", format, got)
		}
		r.Refused = false
		got = render(r)
		first := "# INCOMPLETE: written with -allow-incomplete from a history that does not tell every\n" +
			"# connection of the target. These rules deny what was not seen. Read the status below.\n#\n"
		if format == formatNftables {
			first = "#!/usr/sbin/nft -f\n" + first
		}
		if !strings.HasPrefix(got, first) || !strings.Contains(got, "# Status   INCOMPLETE: the history does not tell every connection "+
			"of the target in the period.\n#          Rules made from it deny what was not seen.\n") ||
			!strings.Contains(got, "#          - not observed by an agent for 1h of the period\n") {
			t.Errorf("%s, with -allow-incomplete:\n%s", format, got)
		}
	}
	// The audit form of an incomplete history: written, marked, and
	// without a rule that refuses.
	r := testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, appFlows()...)
	incomplete(r)
	got := render(r)
	if !strings.HasPrefix(got, "#!/usr/sbin/nft -f\n# INCOMPLETE: the history does not tell every connection of the target, and these rules\n"+
		"# lack what was not seen. This audit form blocks nothing; it shows what they lack.\n# Read the status below.\n#\n") ||
		!strings.Contains(got, "# AUDIT form: it rejects nothing.") || strings.Contains(got, "reject with") || strings.Contains(got, "\" drop") {
		t.Errorf("the audit form of an incomplete history:\n%s", got)
	}
	// A caller who accepts the gaps gets the rules, with what was
	// accepted: the status does not say that the history tells everything.
	r.Status, r.Caveats, r.Reasons, r.minCoverage = statusComplete, r.Reasons, []string{}, "0.999000000000"
	got = render(r)
	if !strings.Contains(got, "# Status   COMPLETE by -min-coverage 0.999 only: the history tells the connections of 0.999537 of the period\n"+
		"#          (1 is all of it). What the target did in the rest is not known, and the rules deny it.\n"+
		"#          Accepted as not observed:\n"+
		"#          - not observed by an agent for 1h of the period\n") || strings.HasPrefix(got, "#!/usr/sbin/nft -f\n# INCOMPLETE") ||
		strings.Contains(got, "tells every") {
		t.Errorf("with -min-coverage 0.999:\n%s", got)
	}
	// What an agent did not report, within the tolerance, is told with a
	// status of COMPLETE; several machines of one name, and the addresses
	// that an agent did not learn, with one of INCOMPLETE.
	r = testReport(t, target{Host: "app-01"}, formatReport, ingressSources, appFlows()...)
	r.Observation.ToleratedGaps, r.Observation.ToleratedSeconds = 2, 290
	if got := render(r); !strings.Contains(got, "         2 stretches without a report of the agent, of 3m or less each (4m50s in all), count as\n"+
		"         observed: the restart of an agent, or its latest report, which is not written yet\n") {
		t.Errorf("stretches within the tolerance:\n%s", got)
	}
	r.Status, r.Reasons, r.TranslationsTraced = statusIncomplete, []string{"several_machines", "translations_not_learned"}, false
	r.Observation.Machines = 2
	r.Gaps = []gap{{"id-1", testUntil.Add(-10 * 24 * time.Hour), testUntil.Add(-10*24*time.Hour + time.Hour), "agent"}}
	got = render(r)
	for _, want := range []string{
		"         - 2 machines reported under this host name in the period (shawk_v1.agents lists them): the\n",
		"         - an agent of the host did not learn every address that the host rewrites its connections\n",
		"  2026-11-18T00:00:00Z to 2026-11-18T01:00:00Z (1h), machine id-1\n",
		"  - destinations that the host rewrites (DNAT, as kube-proxy does): an agent of this host did",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// TestWriteReport: the report for a person, and as JSON.
func TestWriteReport(t *testing.T) {
	r := testReport(t, target{Host: "app-01"}, formatReport, ingressSources, appFlows()...)
	var b bytes.Buffer
	if err := writeRules(&b, r, 3); err != nil {
		t.Fatal(err)
	}
	_, got, _ := strings.Cut(b.String(), "\nRules\n")
	want := `DIRECTION  PORTS        PEER                          ADDRESSES             SERVICES  LAST SEEN             NOTES
egress     1-65535/tcp  srun                          10.0.0.60             shop/app  2026-11-28T00:00:00Z
egress     443/tcp      ~external                     0.0.0.0/0, ::/0       shop/app  2026-11-28T00:00:00Z  folded peers
egress     5432/tcp     shop/postgres (db-01, db-02)  10.0.0.10, 10.0.0.20  shop/app  2026-11-28T00:00:00Z
and 8 more rules (-limit 0 shows all)

Seen before the period, and in no rule
DIRECTION  PORT      PEER         ADDRESS   SERVICE   LAST SEEN
egress     9000/tcp  ~unresolved  10.0.9.9  shop/app  2026-08-25T00:00:00Z

shawk applied nothing. -format nftables writes the rules as a table that rejects nothing and counts
what they do not list (the audit form): load it first. -enforce writes the table that rejects, and
-format systemd -enforce the drop-in of a unit.
`
	if got != want {
		t.Errorf("the report:\n%s\nwant:\n%s", got, want)
	}
	if got := render(testReport(t, target{Host: "idle-01"}, formatReport, ingressSources)); !strings.Contains(got,
		"\nNo connection of TCP or UDP outside the host was seen in the period: the rules allow none.\n") {
		t.Errorf("the report of a host without connections:\n%s", got)
	}

	r.Format = formatJSON
	var doc struct {
		Target   target
		Status   string
		Coverage float64
		Refused  bool
		Rules    []struct {
			Direction, Proto, Peer string
			PortFrom               int `json:"port_from"`
			PortTo                 int `json:"port_to"`
			Addresses, Services    []string
			PeerHosts              []string `json:"peer_hosts"`
			Folded                 bool
		}
		Findings []finding
		Before   []struct{ Address string } `json:"seen_before_period"`
		Loopback int                        `json:"loopback_flows"`
	}
	if err := json.Unmarshal([]byte(render(r)), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Target.Host != "app-01" || doc.Status != statusComplete || doc.Coverage != 1 || doc.Refused || len(doc.Rules) != 11 ||
		len(doc.Findings) != 10 || doc.Loopback != 2 || len(doc.Before) != 1 || doc.Before[0].Address != "10.0.9.9/32" {
		t.Errorf("JSON = %+v", doc)
	}
	if ru := doc.Rules[2]; ru.Direction != egress || ru.Proto != "tcp" || ru.Peer != "shop/postgres" || ru.PortFrom != 5432 || ru.PortTo != 5432 ||
		!slices.Equal(ru.Addresses, []string{"10.0.0.10/32", "10.0.0.20/32"}) || !slices.Equal(ru.PeerHosts, []string{"db-01", "db-02"}) {
		t.Errorf("the rule of postgres as JSON = %+v", ru)
	}
}

// hostile are names that agents may send: text that would be a rule, a
// setting or a line of its own if it were written as it is.
var hostile = []string{
	"shop/app", "~external", "x\n\t\tip daddr 0.0.0.0/0 accept", "x\nIPAddressAllow=any", `end\`, "a\r\nb", "\x00", "# }", "}",
	"é\u2028IPAddressAllow=any", "\\\n", "\"", "a b", "[Service]", "\x1b[2J", strings.Repeat("n", 600), "", " ", "x\x00IPAddressAllow=any",
	"\xff\xfe", "-j ACCEPT", "; accept", "{ accept }",
}

// fuzzFlows makes flows from bytes: names of hostile, addresses and ports
// of every shape.
func fuzzFlows(data []byte) (flows []flow, tg target, mode string) {
	next := func() uint64 {
		var b [8]byte
		n := copy(b[:], data)
		data = data[n:]
		return binary.LittleEndian.Uint64(b[:])
	}
	name := func(v uint64, extra string) string {
		if v%5 == 0 && extra != "" {
			return extra
		}
		return hostile[v/5%uint64(len(hostile))]
	}
	head := next()
	raw := string(data)
	tg = target{Host: name(head, raw), Unit: "app.service"}
	mode = []string{ingressSources, ingressPorts, ingressNone}[head>>8%3]
	for len(data) > 0 && len(flows) < 64 {
		a, b := next(), next()
		rnd := rand.New(rand.NewPCG(a, b))
		f := flow{direction: []string{egress, ingress}[a%2], inPeriod: a>>1%8 != 0, proto: []string{"tcp", "udp"}[a>>4%2],
			service: name(a>>8, raw), unit: name(a>>16, raw), peer: name(a>>24, raw), addr: randomPrefix(rnd),
			translated: a>>40%4 == 0, kernelChosen: a>>42%4 == 0, first: testUntil.Add(-time.Duration(b%1e6) * time.Minute), last: testUntil}
		if a>>32%7 == 0 {
			f.peerHost = ptr(name(a>>48, raw))
		}
		if a>>44%8 == 0 {
			f.addr = netip.MustParsePrefix([]string{"127.0.0.1/32", "::1/128", "0.0.0.0/0", "::/0"}[a>>47%4])
		}
		// A few ports and peers most of the time, so that rules have many
		// addresses.
		f.port = int(b >> 8 % 65536)
		if b>>24%4 != 0 {
			f.port = []int{22, 443, 5432}[b>>26%3]
			f.peer = []string{"db", "~external"}[b>>28%2]
		}
		f.portFrom, f.portTo = f.port, f.port
		if b>>30%6 == 0 {
			f.portFrom, f.portTo = int(b>>32%65536), 65535
		}
		flows = append(flows, f)
	}
	return flows, tg, mode
}

// FuzzRuleFiles: whatever the names of hosts, units, services and peers
// hold, every line of a file of rules is a comment, a line of its frame or
// a rule of a flow, and the file allows the flows that were seen in the
// period, outside the host, and nothing else.
func FuzzRuleFiles(f *testing.F) {
	f.Add([]byte("\x00\x00\x00\x00\x00\x00\x00\x00shop/app\n accept\\"))
	f.Add(bytes.Repeat([]byte{0x5a, 0x01, 0xff, 0x00, 0x7f, 0x80, 0x10, 0x33}, 40))
	for i := range 6 {
		rnd := rand.New(rand.NewPCG(uint64(i), 7))
		b := make([]byte, 16*(i+1)*3)
		for j := range b {
			b[j] = byte(rnd.IntN(256))
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) { checkRuleFiles(t, data) })
}

// TestRuleFiles checks what FuzzRuleFiles does over flows made from random
// numbers, many of which share a peer and a port.
func TestRuleFiles(t *testing.T) {
	for i := range 300 {
		rnd := rand.New(rand.NewPCG(uint64(i), 11))
		data := make([]byte, 8+16*rnd.IntN(64))
		for j := range data {
			data[j] = byte(rnd.IntN(256))
		}
		checkRuleFiles(t, data)
	}
}

// checkRuleFiles checks the files of rules of the flows made from data.
func checkRuleFiles(t testing.TB, data []byte) {
	t.Helper()
	{
		flows, tg, mode := fuzzFlows(data)
		for _, format := range []string{formatNftables, formatSystemd, formatReport} {
			r := testReport(t, tg, format, mode, flows...)
			if len(data)%3 == 0 {
				incomplete(r)
			}
			text := render(r)
			switch format {
			case formatNftables:
				if got, want := parseNftables(t, text), expected(r); !slices.Equal(got, want) {
					t.Fatalf("the table allows\n%s\nwant\n%s\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"), text)
				}
			case formatSystemd:
				if got, want := parseSystemd(t, text), expectedSystemd(r); !slices.Equal(got, want) {
					t.Fatalf("the drop-in allows %v, want %v\n%s", got, want, text)
				}
			default:
				if strings.ContainsAny(text, "\r\x00\x1b") {
					t.Fatalf("the report holds control characters: %q", text)
				}
			}
		}
		// What the rules allow is what was seen: every flow of the period
		// outside the host is within a rule of its direction, transport and
		// ports, and every address of a rule is that of such a flow.
		r := testReport(t, tg, formatNftables, ingressSources, flows...)
		for _, fl := range flows {
			fl.addr = fl.addr.Masked()
			if !fl.inPeriod || fl.addr.Addr().IsLoopback() {
				continue
			}
			// The rule of what was seen and, for UDP on one port that the
			// kernel did not choose, the one of the other way.
			find := func(other bool) *rule {
				direction := fl.direction
				if other {
					direction = map[string]string{egress: ingress, ingress: egress}[direction]
				}
				n := slices.IndexFunc(r.Rules, func(ru rule) bool {
					return ru.Direction == direction && ru.SamePort == other && ru.Proto == fl.proto && ru.PortFrom == fl.portFrom &&
						ru.PortTo == fl.portTo && ru.Peer == fl.peer && slices.ContainsFunc(ru.Addresses, func(p netip.Prefix) bool {
						return p.Bits() <= fl.addr.Bits() && p.Contains(fl.addr.Addr())
					})
				})
				if n < 0 {
					return nil
				}
				return &r.Rules[n]
			}
			seen := find(false)
			if seen == nil {
				t.Fatalf("no rule allows the flow %+v", fl)
			}
			if want := fl.proto == "udp" && seen.PortFrom == seen.PortTo && !seen.KernelChosen; (find(true) != nil) != want {
				t.Fatalf("the flow %+v has a rule of the other way: %t, want %t", fl, !want, want)
			}
		}
		for _, ru := range r.Rules {
			direction := ru.Direction
			if ru.SamePort {
				if ru.Proto != "udp" || ru.PortFrom != ru.PortTo || ru.KernelChosen || ru.AnySource {
					t.Fatalf("the rule %+v is the other way of a flow that has none", ru)
				}
				direction = map[string]string{egress: ingress, ingress: egress}[direction]
			}
			for _, p := range ru.Addresses {
				if !slices.ContainsFunc(flows, func(fl flow) bool {
					return fl.inPeriod && fl.addr.Masked() == p && fl.direction == direction && fl.proto == ru.Proto &&
						fl.portFrom == ru.PortFrom && fl.portTo == ru.PortTo && fl.peer == ru.Peer
				}) {
					t.Fatalf("the rule %+v allows %s, which no flow has", ru, p)
				}
			}
		}
	}
}
