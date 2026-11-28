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

// inNetns returns what makes new network namespaces for the commands of a
// test, as root or as root of a new user namespace; the commands run
// through the guard of netnsguard_test.go, which keeps them out of the
// namespace of the test. The test is skipped where nft cannot run in a
// namespace of its own.
func inNetns(t *testing.T) netnsMaker {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not available")
	}
	own := ownNetns(t)
	for _, c := range [][]string{{"unshare", "-n"}, {"unshare", "-rn"}} {
		m := netnsMaker{own: own, unshare: c}
		if m.command("nft", "list", "ruleset").Run() == nil {
			return m
		}
	}
	t.Skip("nft cannot run in a network namespace of its own here (unshare -n, unshare -rn)")
	return netnsMaker{}
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

// describeExpr writes an expression of a rule as nft lists it in JSON, in
// a line: what the frame of a chain is compared by.
func describeExpr(e map[string]any) string {
	side := func(v any) string {
		var name func(v any) string
		name = func(v any) string {
			m, ok := v.(map[string]any)
			switch {
			case !ok:
				return strings.Trim(fmt.Sprint(v), "[]")
			case m["ct"] != nil:
				return "ct " + m["ct"].(map[string]any)["key"].(string)
			case m["meta"] != nil:
				return "meta " + m["meta"].(map[string]any)["key"].(string)
			case m["payload"] != nil:
				p := m["payload"].(map[string]any)
				return fmt.Sprint(p["protocol"], " ", p["field"])
			case m["&"] != nil:
				and := m["&"].([]any)
				return name(and[0]) + " & " + name(and[1])
			case m["set"] != nil:
				return "{" + name(m["set"]) + "}"
			}
			return fmt.Sprint(v)
		}
		return name(v)
	}
	for k, v := range e {
		switch k {
		case "match":
			m := v.(map[string]any)
			return fmt.Sprintf("%s %s %s", side(m["left"]), m["op"], side(m["right"]))
		case "mangle":
			m := v.(map[string]any)
			return fmt.Sprintf("set %s %s", side(m["key"]), side(m["value"]))
		case "counter":
			return "counter " + fmt.Sprint(v)
		case "limit":
			m := v.(map[string]any)
			return fmt.Sprintf("limit %v/%v burst %v", m["rate"], m["per"], m["burst"])
		case "log":
			return fmt.Sprintf("log %q", v.(map[string]any)["prefix"])
		case "reject":
			m := v.(map[string]any)
			return fmt.Sprintf("reject %v %v", m["type"], m["expr"])
		default:
			return k
		}
	}
	return ""
}

// nftFrame is what a chain holds beside the rules of its flows, in its
// order, as describeExpr writes it: before the flows what the chain
// accepts whatever they are, and after them what it does with the rest.
// The audit form counts and logs the rest and lets it pass, and follows
// the connections that no rule lists; the form that rejects logs the rest,
// then counts and refuses it.
func nftFrame(chain string, enforce bool) (before, after []string) {
	ifname, counter, label, direction, verdict := "oifname", nftEgressCounter, nftLabelEgress, egress, "reject icmpx admin-prohibited"
	if chain == "input" {
		ifname, counter, label, direction, verdict = "iifname", nftIngressCounter, nftLabelIngress, ingress, "drop"
	}
	log := fmt.Sprintf("limit 10/second burst 20; log %q", "shawk-policy unlisted "+direction+": ")
	common := []string{"meta " + ifname + " == lo; accept", "meta l4proto != {tcp udp}; accept"}
	if enforce {
		return append([]string{"ct state in established related; accept"}, common...), []string{log, "counter " + counter + "; " + verdict}
	}
	before = append([]string{
		fmt.Sprintf("ct state in related new; set ct label %d", nftLabelBegan),
		fmt.Sprintf("ct state in established related; ct label in %d; ct label & %d != %d; accept", nftLabelBegan, label, label),
	}, common...)
	return append(before, "ct direction == reply; accept"), []string{
		fmt.Sprintf("ct label in %d; counter %s; accept", label, counter),
		log,
		fmt.Sprintf("ct state in new; tcp flags & fin syn rst ack != syn; counter %s; accept", counter),
		fmt.Sprintf("set ct label %d; counter %s", label, counter),
	}
}

// listedSpans reads what the table that nft lists as JSON allows: the
// rules of the flows of its chains output and input. It checks that the
// other rules of a chain are those of the frame of its form, in their
// places: enforce tells the form that rejects, rather than the audit form.
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
		// The rule of a flow matches the family or the addresses of its
		// peer and its ports, and accepts; every other rule is of the
		// frame.
		var spans []span
		proto, ports, side := "", "", ""
		_, accepts := ru.Expr[len(ru.Expr)-1]["accept"]
		flow := accepts && len(ru.Expr) >= 2
		for _, e := range ru.Expr[:len(ru.Expr)-1] {
			m, _ := e["match"].(map[string]any)
			left, _ := m["left"].(map[string]any)
			p, _ := left["payload"].(map[string]any)
			field, _ := p["field"].(string)
			meta, _ := left["meta"].(map[string]any)
			switch {
			case !flow:
			case m == nil || m["op"] != "==":
				flow = false
			case meta != nil && meta["key"] == "nfproto":
				spans = []span{map[string]span{"ipv4": allV4, "ipv6": allV6}[m["right"].(string)]}
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
				flow = false
			}
		}
		if !flow || proto == "" || direction == "" {
			parts := make([]string, len(ru.Expr))
			for i, e := range ru.Expr {
				parts[i] = describeExpr(e)
			}
			frame[ru.Chain] = append(frame[ru.Chain], strings.Join(parts, "; "))
			continue
		}
		if spans == nil {
			spans = []span{allV4, allV6}
		}
		k := fmt.Sprintf("%s %s %s %s", direction, proto, side, ports)
		by[k] = append(by[k], spans...)
		frame[ru.Chain] = append(frame[ru.Chain], "flow")
	}
	for name, got := range frame {
		before, after := nftFrame(name, enforce)
		want := slices.Clone(before)
		for range len(got) - len(before) - len(after) {
			want = append(want, "flow")
		}
		want = append(want, after...)
		if !slices.Equal(got, want) {
			t.Fatalf("the chain %s holds\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	// A counter per chain, by name, that the chain counts in.
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

// loadNftables checks a table with nft, loads it into the kernel of a new
// network namespace, twice as a table that is written again would be, and
// returns what the kernel then holds, as JSON.
func loadNftables(t *testing.T, netns netnsMaker, text string) []byte {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy.nft")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `nft -c -f "$1" && nft -f "$1" && nft -f "$1" && nft -j list ruleset`
	cmd := netns.command("sh", "-c", script, "sh", file)
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
	if out, err := netns.command("nft", "-c", "-f", file).CombinedOutput(); err == nil || refused(err) {
		t.Errorf("nft accepts an address that is none, or was not run: %v: %s", err, out)
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
