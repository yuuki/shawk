package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The tests in this file give what the command writes to the tools that
// read it on a host: nft, which loads the table into the kernel of a
// network namespace of its own and lists what the kernel holds, and
// systemd-analyze, which reads the drop-in as systemd does. They are
// skipped where the tools are missing, or where a network namespace cannot
// be made.

// inNetns returns the start of a command that runs in a new network
// namespace, as root or as root of a new user namespace.
func inNetns(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not available")
	}
	for _, c := range [][]string{{"unshare", "-n"}, {"unshare", "-rn"}} {
		if exec.Command(c[0], append(c[1:], "nft", "list", "ruleset")...).Run() == nil {
			return c
		}
	}
	t.Skip("nft cannot run in a network namespace of its own here (unshare -n, unshare -rn)")
	return nil
}

// span is a range of addresses.
type span struct{ lo, hi netip.Addr }

// prefixSpan is the range of the addresses of a prefix.
func prefixSpan(p netip.Prefix) span {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	hi, _ := netip.AddrFromSlice(b)
	return span{p.Addr(), hi}
}

// merge sorts ranges and joins those that touch.
func merge(in []span) []span {
	slices.SortFunc(in, func(a, b span) int { return a.lo.Compare(b.lo) })
	var out []span
	for _, s := range in {
		if n := len(out); n > 0 && out[n-1].lo.Is4() == s.lo.Is4() && (s.lo.Compare(out[n-1].hi) <= 0 || out[n-1].hi.Next() == s.lo) {
			if s.hi.Compare(out[n-1].hi) > 0 {
				out[n-1].hi = s.hi
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

var (
	allV4 = prefixSpan(netip.MustParsePrefix("0.0.0.0/0"))
	allV6 = prefixSpan(netip.MustParsePrefix("::/0"))
)

// describeSpans writes what is allowed, per direction, transport and
// ports, as ranges of addresses: one form for what a report asks for and
// for what the kernel lists, which joins the addresses that follow each
// other.
func describeSpans(by map[string][]span) []string {
	var out []string
	for k, spans := range by {
		for _, s := range merge(spans) {
			out = append(out, fmt.Sprintf("%s %s-%s", k, s.lo, s.hi))
		}
	}
	slices.Sort(out)
	return out
}

// wantSpans is what the rules of a report allow.
func wantSpans(r *rulesReport) []string {
	by := map[string][]span{}
	for _, ru := range r.Rules {
		if ru.Direction == ingress && r.Ingress == ingressNone {
			continue
		}
		k := fmt.Sprintf("%s %s %s %d-%d", ru.Direction, ru.Proto, map[bool]string{false: "to", true: "between"}[ru.SamePort],
			ru.PortFrom, ru.PortTo)
		if ru.AnySource {
			by[k] = append(by[k], allV4, allV6)
			continue
		}
		for _, p := range ru.Addresses {
			by[k] = append(by[k], prefixSpan(p))
		}
	}
	return describeSpans(by)
}

// nftAddrs reads the right side of a match of addresses as nft lists it.
func nftAddrs(t *testing.T, v any) []span {
	t.Helper()
	switch x := v.(type) {
	case string:
		a, err := netip.ParseAddr(x)
		if err != nil {
			t.Fatalf("nft lists the address %q", x)
		}
		return []span{{a, a}}
	case map[string]any:
		if p, ok := x["prefix"].(map[string]any); ok {
			a, err := netip.ParseAddr(p["addr"].(string))
			if err != nil {
				t.Fatalf("nft lists the prefix %v", p)
			}
			return []span{prefixSpan(netip.PrefixFrom(a, int(p["len"].(float64))))}
		}
		if r, ok := x["range"].([]any); ok && len(r) == 2 {
			lo, err1 := netip.ParseAddr(r[0].(string))
			hi, err2 := netip.ParseAddr(r[1].(string))
			if err1 != nil || err2 != nil {
				t.Fatalf("nft lists the range %v", r)
			}
			return []span{{lo, hi}}
		}
		if set, ok := x["set"].([]any); ok {
			var out []span
			for _, e := range set {
				out = append(out, nftAddrs(t, e)...)
			}
			return out
		}
	}
	t.Fatalf("nft lists the addresses %v", v)
	return nil
}

// listedSpans reads what the table that nft lists as JSON allows: the
// rules of its chains output and input but those of their frame, which it
// checks are there, and end as the form of the table does: enforce tells
// the form that rejects, rather than the audit form.
func listedSpans(t *testing.T, doc []byte, enforce bool) []string {
	t.Helper()
	var listing struct {
		Nftables []map[string]json.RawMessage
	}
	if err := json.Unmarshal(doc, &listing); err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	by := map[string][]span{}
	frame := map[string][]string{}
	for _, o := range listing.Nftables {
		if raw, ok := o["chain"]; ok {
			var c struct {
				Family, Table, Name, Type, Hook, Policy string
				Prio                                    int
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			if c.Family != "inet" || c.Table != nftTable || c.Type != "filter" || c.Hook != c.Name || c.Prio != 0 || c.Policy != "accept" ||
				(c.Name != "output" && c.Name != "input") {
				t.Fatalf("nft lists the chain %+v", c)
			}
			frame[c.Name] = []string{}
			continue
		}
		raw, ok := o["rule"]
		if !ok {
			continue
		}
		var ru struct {
			Chain string
			Expr  []map[string]any
		}
		if err := json.Unmarshal(raw, &ru); err != nil {
			t.Fatal(err)
		}
		direction := map[string]string{"output": egress, "input": ingress}[ru.Chain]
		last := ru.Expr[len(ru.Expr)-1]
		if _, accept := last["accept"]; !accept {
			frame[ru.Chain] = append(frame[ru.Chain], strings.Join(sortedMapKeys(last), ","))
			continue
		}
		var spans []span
		proto, ports, side := "", "", ""
		framed := ""
		for _, e := range ru.Expr[:len(ru.Expr)-1] {
			m, ok := e["match"].(map[string]any)
			if !ok {
				t.Fatalf("nft lists the expression %v", e)
			}
			left := m["left"].(map[string]any)
			switch {
			case left["ct"] != nil:
				framed = "established"
			case left["meta"] != nil && strings.HasSuffix(left["meta"].(map[string]any)["key"].(string), "ifname"):
				framed = "loopback " + fmt.Sprint(m["right"])
			case left["meta"] != nil && left["meta"].(map[string]any)["key"] == "l4proto":
				framed = fmt.Sprint("other protocols ", m["op"])
			case left["meta"] != nil && left["meta"].(map[string]any)["key"] == "nfproto":
				spans = []span{map[string]span{"ipv4": allV4, "ipv6": allV6}[m["right"].(string)]}
			default:
				p := left["payload"].(map[string]any)
				field := p["field"].(string)
				switch {
				case field == "dport" || field == "sport":
					proto = p["protocol"].(string)
					var of string
					switch r := m["right"].(type) {
					case float64:
						of = fmt.Sprintf("%d-%d", int(r), int(r))
					case map[string]any:
						rg := r["range"].([]any)
						of = fmt.Sprintf("%d-%d", int(rg[0].(float64)), int(rg[1].(float64)))
					default:
						t.Fatalf("nft lists the ports %v", m["right"])
					}
					// The source port is matched by the other way of a
					// UDP rule only, before the same port as the
					// destination.
					switch {
					case field == "sport" && side == "" && proto == "udp":
						side, ports = "between", of
					case field == "dport" && side == "":
						side, ports = "to", of
					case field == "dport" && side == "between" && ports == of && proto == "udp":
					default:
						t.Fatalf("nft lists a match of the ports %v in the rule %v", p, ru.Expr)
					}
				case (field == "daddr") == (direction == egress) && (field == "daddr" || field == "saddr"):
					spans = nftAddrs(t, m["right"])
					for _, s := range spans {
						if s.lo.Is4() != (p["protocol"] == "ip") {
							t.Fatalf("nft lists %s as an address of %v", s.lo, p["protocol"])
						}
					}
				default:
					t.Fatalf("nft lists a match of %v in the chain %s", p, ru.Chain)
				}
			}
		}
		if framed != "" {
			frame[ru.Chain] = append(frame[ru.Chain], framed)
			continue
		}
		if m, ok := ru.Expr[0]["match"].(map[string]any); !ok || m["op"] != "==" || proto == "" || direction == "" {
			t.Fatalf("nft lists the rule %v", ru.Expr)
		}
		if spans == nil {
			spans = []span{allV4, allV6}
		}
		k := fmt.Sprintf("%s %s %s %s", direction, proto, side, ports)
		by[k] = append(by[k], spans...)
		frame[ru.Chain] = append(frame[ru.Chain], "flow")
	}
	// What a chain accepts whatever the flows, before them, and what it
	// does with the rest, after them.
	// The audit form counts and logs the rest, and lets it pass; the form
	// that rejects logs it, then counts and refuses it.
	for name, got := range frame {
		end := []string{"log"}
		if enforce {
			end = append(end, map[string]string{"output": "reject", "input": "drop"}[name])
		}
		want := []string{"established", "loopback lo", "other protocols !="}
		for range len(got) - 3 - len(end) {
			want = append(want, "flow")
		}
		want = append(want, end...)
		if !slices.Equal(got, want) {
			t.Fatalf("the chain %s holds %v, want %v", name, got, want)
		}
	}
	// A counter per chain, by name, that the last rule of the chain counts
	// in.
	for name, counter := range map[string]string{"output": nftEgressCounter, "input": nftIngressCounter} {
		_, chain := frame[name]
		declared := strings.Contains(string(doc), `"counter": {"family": "inet", "name": "`+counter+`"`)
		used := strings.Contains(string(doc), `{"counter": "`+counter+`"}`)
		if declared != chain || used != chain {
			t.Fatalf("the counter %s is declared: %t, used: %t, with a chain %s: %t\n%s", counter, declared, used, name, chain, doc)
		}
	}
	if _, ok := frame["output"]; !ok {
		t.Fatalf("nft lists no chain output\n%s", doc)
	}
	return describeSpans(by)
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// loadNftables checks a table with nft, loads it into the kernel of a new
// network namespace, twice as a table that is written again would be, and
// returns what the kernel then holds, as JSON.
func loadNftables(t *testing.T, netns []string, text string) []byte {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy.nft")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `nft -c -f "$1" && nft -f "$1" && nft -f "$1" && nft -j list ruleset`
	cmd := exec.Command(netns[0], append(netns[1:], "sh", "-c", script, "sh", file)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("nft refuses the table: %v\n%s\n%s", err, errOut.String(), text)
	}
	if errOut.Len() > 0 {
		t.Fatalf("nft warns of the table: %s\n%s", errOut.String(), text)
	}
	return out.Bytes()
}

// randomReports returns reports of random flows, with names that agents
// may send, complete and not.
func randomReports(t *testing.T, format string, n int) []*rulesReport {
	t.Helper()
	var out []*rulesReport
	for i := range n {
		rnd := rand.New(rand.NewPCG(uint64(i), 232))
		data := make([]byte, 8+16*rnd.IntN(40))
		for j := range data {
			data[j] = byte(rnd.IntN(256))
		}
		flows, tg, mode := fuzzFlows(data)
		r := testReport(t, tg, format, mode, flows...)
		if i%4 == 0 {
			incomplete(r)
		}
		out = append(out, r)
	}
	return out
}

// TestNftablesLoads: nft accepts the tables that the command writes, and
// the kernel then allows what the rules of the report hold, no more and no
// less, whatever the names of the hosts, services and peers.
func TestNftablesLoads(t *testing.T) {
	netns := inNetns(t)
	adjacent := []flow{
		// Addresses that follow each other, which the kernel joins; nested
		// and whole networks; both families; ranges of ports.
		testFlow(egress, "a", "tcp", "10.0.0.10/32", 5432, "db"), testFlow(egress, "a", "tcp", "10.0.0.11/32", 5432, "db"),
		testFlow(egress, "a", "tcp", "10.0.0.12/31", 5432, "db"), testFlow(egress, "a", "tcp", "10.0.0.0/24", 5433, "db2"),
		testFlow(egress, "a", "tcp", "10.0.0.77/32", 5433, "db2"), testFlow(egress, "a", "tcp", "10.0.2.0/23", 5433, "db2"),
		testFlow(egress, "a", "udp", "fd00::1/128", 53, "dns"), testFlow(egress, "a", "udp", "fd00::2/128", 53, "dns"),
		testFlow(egress, "a", "udp", "10.0.0.53/32", 53, "dns"), testFlow(egress, "a", "tcp", "::/0", 443, "~external"),
		testFlow(ingress, "a", "tcp", "0.0.0.0/0", 80, "~external"), testFlow(ingress, "a", "tcp", "10.9.9.9/32", 80, "lb"),
		testFlow(ingress, "a", "udp", "255.255.255.255/32", 67, "~unresolved"), testFlow(egress, "a", "udp", "224.0.0.251/32", 5353, "mdns"),
		testFlow(egress, "a", "udp", "ff02::fb/128", 5353, "mdns"), testFlow(egress, "a", "tcp", "fe80::1/128", 22, "~unresolved"),
		testFlow(egress, "a", "tcp", "10.0.0.1/32", 0, "zero"), testFlow(egress, "a", "tcp", "10.0.0.1/32", 65535, "last"),
	}
	wide := testFlow(egress, "a", "tcp", "10.0.0.60/32", 41000, "srun")
	wide.portFrom, wide.portTo = 1, 65535
	ranged := testFlow(ingress, "a", "udp", "10.0.0.61/32", 30100, "nodeport")
	ranged.portFrom, ranged.portTo = 30000, 32767
	adjacent = append(adjacent, wide, ranged)
	// A server with many clients, of both families.
	for i := range 300 {
		adjacent = append(adjacent,
			testFlow(ingress, "a", "tcp", netip.AddrFrom4([4]byte{10, 7, byte(i / 100), byte(i * 3 % 256)}).String()+"/32", 5432, "clients"),
			testFlow(ingress, "a", "tcp", fmt.Sprintf("fd00:7::%x/128", i*5), 5432, "clients"))
	}
	var reports []*rulesReport
	for _, mode := range []string{ingressSources, ingressPorts, ingressNone} {
		reports = append(reports,
			testReport(t, target{Host: "app-01"}, formatNftables, mode, appFlows()...),
			testReport(t, target{Host: "app-01"}, formatNftables, mode, adjacent...),
			testReport(t, target{Host: "idle-01"}, formatNftables, mode))
	}
	reports = append(reports, randomReports(t, formatNftables, 40)...)
	for i, r := range reports {
		// Both forms of each table: the audit form, and the one that
		// rejects.
		if i%2 == 1 {
			r.Mode = modeEnforce
		}
		text := render(r)
		listed := loadNftables(t, netns, text)
		if got, want := listedSpans(t, listed, r.Mode == modeEnforce), wantSpans(r); !slices.Equal(got, want) {
			t.Errorf("report %d: the kernel allows\n%s\nwant\n%s\n%s", i, strings.Join(got, "\n"), strings.Join(want, "\n"), text)
		}
		// One table, with one chain per direction that is written.
		chains := strings.Count(string(listed), `"chain": {`)
		if want := map[string]int{ingressNone: 1}[r.Ingress]; (want == 1) != (chains == 1) || strings.Count(string(listed), `"table": {`) != 1 {
			t.Errorf("report %d with -ingress %s: nft lists %d chains", i, r.Ingress, chains)
		}
	}
}

// TestNftablesRefused: nft refuses a table that is not one, so that a
// table it accepts tells something.
func TestNftablesRefused(t *testing.T) {
	netns := inNetns(t)
	r := testReport(t, target{Host: "app-01"}, formatNftables, ingressSources, appFlows()...)
	text := strings.Replace(render(r), "ip daddr 10.0.0.40 tcp dport 6443 accept", "ip daddr 10.0.0.400 tcp dport 6443 accept", 1)
	file := filepath.Join(t.TempDir(), "policy.nft")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(netns[0], append(netns[1:], "nft", "-c", "-f", file)...).CombinedOutput(); err == nil {
		t.Errorf("nft accepts an address that is none: %s", out)
	}
}

// verifyDropIn gives a drop-in to systemd-analyze verify, as the drop-in
// of a unit that starts nothing, and returns what it reports of the
// drop-in and of the unit.
func verifyDropIn(t *testing.T, analyze, unit, text string) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, unit), []byte("[Unit]\nDescription=test\n\n[Service]\nExecStart=/bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(dir, unit+".d", "50-shawk-policy.conf")
	if err := os.MkdirAll(filepath.Dir(dropIn), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(analyze, "verify", filepath.Join(dir, unit)).CombinedOutput()
	var problems []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// systemd-analyze also loads the units of the host that the unit
		// pulls in, and reports their problems: only what names the
		// drop-in or the unit counts.
		if strings.Contains(line, dropIn) || strings.HasPrefix(line, unit+":") {
			problems = append(problems, line)
		}
	}
	return problems
}

// TestSystemdVerifies: systemd-analyze verify reads the drop-ins that the
// command writes without a word, whatever the names in their comments,
// and reports one that holds something else.
func TestSystemdVerifies(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not available")
	}
	// What it reports, so that its silence tells something: a setting that
	// is none, an address that is none, and a line that a comment
	// continued into.
	for _, bad := range []string{
		"[Service]\nIPAddressDeny=any\nIPAddressAllow=10.0.0.555\n",
		"[Service]\nIPAdressDeny=any\n",
		"[Service]\nIPAddressDeny=any\nIPAddressAllow=10.0.0.1 \\\n# a comment\nNoSuchSetting=1\n",
	} {
		if problems := verifyDropIn(t, analyze, "app.service", bad); len(problems) == 0 {
			t.Skipf("systemd-analyze verify does not report the drop-in %q here", bad)
		}
	}
	var reports []*rulesReport
	shop := slices.DeleteFunc(appFlows(), func(f flow) bool { return f.service != "shop/app" })
	reports = append(reports,
		testReport(t, target{Host: "app-01", Unit: "app.service"}, formatSystemd, ingressSources, shop...),
		testReport(t, target{Host: "app-01", Unit: "app.service"}, formatSystemd, ingressSources, appFlows()...),
		testReport(t, target{Host: "app-01", Unit: "app.service"}, formatSystemd, ingressSources))
	reports = append(reports, randomReports(t, formatSystemd, 40)...)
	for i, r := range reports {
		text := render(r)
		if problems := verifyDropIn(t, analyze, "app.service", text); len(problems) > 0 {
			t.Errorf("report %d: systemd-analyze verify reports\n%s\nof\n%s", i, strings.Join(problems, "\n"), text)
		}
		if got, want := parseSystemd(t, text), expectedSystemd(r); !slices.Equal(got, want) {
			t.Errorf("report %d: the drop-in allows %v, want %v", i, got, want)
		}
	}
}
