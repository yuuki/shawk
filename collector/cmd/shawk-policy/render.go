package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf16"
)

// table writes rows in columns, as text/tabwriter does, without the
// spaces it leaves at the end of a line whose last cell is empty.
type table struct {
	buf strings.Builder
	tw  *tabwriter.Writer
}

func newTable() *table {
	t := &table{}
	t.tw = tabwriter.NewWriter(&t.buf, 0, 0, 2, ' ', 0)
	return t
}

// row adds a row of cells.
func (t *table) row(cells ...string) {
	fmt.Fprintln(t.tw, strings.Join(cells, "\t"))
}

// lines returns the rows, aligned.
func (t *table) lines() []string {
	t.tw.Flush()
	lines := strings.Split(strings.TrimRight(t.buf.String(), "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return lines
}

// writeTo writes the rows, aligned.
func (t *table) writeTo(b *strings.Builder) {
	for _, l := range t.lines() {
		b.WriteString(l + "\n")
	}
}

// writeJSON writes a report as one JSON document, in which every
// character that does not print is an escape: the names of services,
// peers and hosts are what agents sent, and encoding/json writes the
// controls above U+007F, the characters that turn the direction of a text
// around and those without a width as they are, which a terminal or a
// viewer would act on.
func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeJSON(buf.Bytes()))
	return err
}

// escapeJSON replaces the characters of a JSON document that do not
// print with their \u escapes. Outside its strings a document holds
// printing ASCII and line breaks only, so such a character is within a
// string, where the escape stands for it: U+007F too, which is ASCII and
// which encoding/json writes as it is.
func escapeJSON(doc []byte) []byte {
	hidden := func(r rune) bool { return r != '\n' && !unicode.IsPrint(r) }
	if !bytes.ContainsFunc(doc, hidden) {
		return doc
	}
	var out bytes.Buffer
	for _, r := range string(doc) {
		switch {
		case !hidden(r):
			out.WriteRune(r)
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(&out, `\u%04x`, r)
		}
	}
	return out.Bytes()
}

// describeTarget names the target of rules.
func describeTarget(t target) string {
	if t.Unit != "" {
		return "unit " + commentName(t.Unit) + " of host " + commentName(t.Host)
	}
	return "host " + commentName(t.Host)
}

// header returns what a report of rules tells before the rules, as lines
// without a line break in them: the target, the period, the status with
// what the history does not tell, the findings, and what shawk cannot
// observe. It is the top of the text report and, as comments, of the files
// of rules, so that a file carries what its reviewer must know wherever it
// goes.
func (r *rulesReport) header() []string {
	lines := []string{
		"Target   " + describeTarget(r.Target),
		fmt.Sprintf("Period   %s to %s (%s)", formatTime(r.Since), formatTime(r.Until), formatDuration(r.Until.Sub(r.Since))),
	}
	o := r.Observation
	if o == nil {
		o = &observation{}
	}
	switch {
	case r.Status == statusComplete && len(r.Caveats) == 0:
		lines = append(lines,
			"Status   COMPLETE: an agent observed the target for the whole period, so the history tells every",
			"         TCP and UDP connection that its sockets made in it",
			fmt.Sprintf("         (coverage %s; 1 is all of the period)", fraction(r.coverage)))
	case r.Status == statusComplete:
		// -min-coverage accepted time that was not observed: the history
		// does not tell every connection, and the status does not say so.
		lines = append(lines,
			fmt.Sprintf("Status   COMPLETE by -min-coverage %s only: the history tells the connections of %s of the period",
				fraction(r.minCoverage), fraction(r.coverage)),
			"         (1 is all of it). What the target did in the rest is not known, and the rules deny it.",
			"         Accepted as not observed:")
	default:
		lines = append(lines,
			"Status   "+commentName(r.Status)+": the history does not tell every connection of the target in the period.",
			"         Rules made from it deny what was not seen.",
			fmt.Sprintf("         (coverage %s, of the %s that -min-coverage asks for)", fraction(r.coverage), fraction(r.minCoverage)))
	}
	for _, code := range append(append([]string{}, r.Reasons...), r.Caveats...) {
		for i, l := range wrap(describeShortfall(code, r.Observation), 88) {
			if i == 0 {
				lines = append(lines, "         - "+l)
			} else {
				lines = append(lines, "           "+l)
			}
		}
	}
	if o.ToleratedGaps > 0 {
		// Time without a report that counts as observed: it is told, so
		// that a status of COMPLETE does not hide it.
		for _, l := range wrap(fmt.Sprintf("%s without a report of the agent, of %s or less each (%s in all), "+
			"%s as observed: the restart of an agent, or its latest report, which is not written yet",
			plural(o.ToleratedGaps, "stretch", "stretches"), seconds(o.ToleranceSeconds), seconds(o.ToleratedSeconds),
			map[bool]string{true: "counts", false: "count"}[o.ToleratedGaps == 1]), 88) {
			lines = append(lines, "         "+l)
		}
	}
	if len(r.Gaps) > 0 {
		lines = append(lines, "", "Not observed")
		for _, g := range r.Gaps {
			l := fmt.Sprintf("  %s to %s (%s)", formatTime(g.Start), formatTime(g.End), formatDuration(g.End.Sub(g.Start)))
			if g.Cause == "retention" {
				l += ", before the retention of the connector"
			}
			if o.Machines > 1 && g.Machine != "" {
				l += ", machine " + commentName(g.Machine)
			}
			lines = append(lines, l)
		}
		if o.Gaps > len(r.Gaps) && o.Machines <= 1 {
			lines = append(lines, "  and "+plural(o.Gaps-len(r.Gaps), "more gap"))
		} else if len(r.Gaps) == maxGaps {
			lines = append(lines, "  and maybe more (shawk_v1.policy_gaps lists them all)")
		}
	}
	item := func(text string) {
		for i, l := range wrap(text, 92) {
			if i == 0 {
				lines = append(lines, "  - "+l)
			} else {
				lines = append(lines, "    "+l)
			}
		}
	}
	lines = append(lines, "", "What the rules pin, and what they leave out")
	for _, f := range r.Findings {
		item(f.Text)
	}
	item("a connection that was not made in the period is denied: one made less often than the period, or only " +
		"when another server fails")

	// What no history of shawk can tell: a file that blocks is wrong about
	// these without a sign, so each is a check for its reviewer.
	lines = append(lines, "", "What shawk cannot observe: check each before the rules block anything")
	if r.Format == formatSystemd {
		item("protocols other than TCP and UDP: IPAddressDeny=any blocks every IP protocol of the unit, not TCP and UDP " +
			"alone. An address that the unit reaches by another protocol only (ICMP echo, VRRP, SCTP, a raw socket) is " +
			"not listed, and is blocked")
		item("sockets that systemd passes to the unit (socket activation): the list is not applied to them, so the " +
			"sources of what such a socket accepts are not limited")
	} else {
		item("protocols other than TCP and UDP (ICMP, VRRP, IPsec, GRE): shawk does not observe them, and the table " +
			"accepts them all")
		item("tunnels that the kernel makes (VXLAN, Geneve, WireGuard, IP-in-IP): no socket of a process sends their " +
			"outer packets, so no rule lists them. The rejecting form stops them (UDP 4789, 8472, 6081, 51820), and " +
			"every connection over the tunnel with them, although the rules list the addresses inside it")
		if r.Ingress != ingressNone {
			item("a host that balances connections for others in its kernel (IPVS: an LVS director, kube-proxy in " +
				"IPVS mode): a virtual service has no socket, so no ingress rule lists it, and the chain input runs " +
				"before IPVS takes its packets. shawk-policy was not run on such a host: use -ingress none there")
		}
		item("what the host forwards for containers or virtual machines: it does not pass the hooks input and " +
			"output, and no chain forward is written")
	}
	if r.TranslationsTraced {
		item("destinations that the host rewrites (DNAT, as kube-proxy does): the agents of this host learned them in " +
			"the period, and the rules list the backends they saw")
	} else {
		item("destinations that the host rewrites (DNAT, as kube-proxy does): an agent of this host did not learn " +
			"them all (see the status), so the rules may lack the address that the packets leave for")
	}
	return lines
}

// wrap cuts a text into lines of at most width characters, at its spaces.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// describeNotes tells what is particular to a rule.
func describeNotes(ru *rule) string {
	var notes []string
	if ru.AnySource {
		notes = append(notes, "from every address")
	}
	if ru.Folded {
		notes = append(notes, "folded peers")
	}
	if ru.Translated {
		notes = append(notes, "translated by the host")
	}
	if ru.KernelChosen {
		notes = append(notes, "port chosen by the kernel")
	}
	if ru.Unattributed {
		notes = append(notes, "socket without a known owner")
	}
	if ru.SourcePort {
		notes = append(notes, "the other way of a UDP rule")
	}
	return strings.Join(notes, "; ")
}

// describeAddresses lists addresses, the first `most` of them.
func describeAddresses(ps []netip.Prefix, most int) string {
	var b strings.Builder
	for i, p := range ps {
		if most > 0 && i == most {
			fmt.Fprintf(&b, " and %d more", len(ps)-most)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(address(p))
	}
	return b.String()
}

// address writes a prefix as an address when it is one, and as a network
// otherwise.
func address(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// writeRulesReport writes a report for a person: the header, the rules, at
// most limit of them (all if 0), and the flows seen before the period.
func writeRulesReport(b *strings.Builder, r *rulesReport, limit int) {
	for _, l := range r.header() {
		b.WriteString(l + "\n")
	}
	if r.Refused && r.unknownTarget() {
		b.WriteString("\nNo rules are written: nothing is known of the target. Check its name.\n")
		return
	}
	if r.Refused {
		fmt.Fprintf(b, "\nNo file that blocks is written from an incomplete history. -allow-incomplete writes it all the same,\n"+
			"marked as incomplete; -format report lists what it would hold, and -format nftables without -enforce\n"+
			"writes the audit form, which blocks nothing.\n")
		return
	}
	if len(r.Rules) > 0 {
		shown := r.Rules
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		b.WriteString("\nRules\n")
		tb := newTable()
		tb.row("DIRECTION", "PORTS", "PEER", "ADDRESSES", "SERVICES", "LAST SEEN", "NOTES")
		for i := range shown {
			ru := &shown[i]
			peer := commentName(ru.Peer)
			if len(ru.PeerHosts) > 0 {
				peer += " (" + describeStrings(ru.PeerHosts, 3) + ")"
			}
			tb.row(ru.Direction, ru.portsOf(), peer, describeAddresses(ru.Addresses, 3), describeStrings(ru.Services, 3),
				formatTime(ru.LastSeen), describeNotes(ru))
		}
		tb.writeTo(b)
		if n := len(r.Rules) - len(shown); n > 0 {
			fmt.Fprintf(b, "and %s (-limit 0 shows all)\n", plural(n, "more rule"))
		}
	} else {
		b.WriteString("\nNo connection of TCP or UDP outside the host was seen in the period: the rules allow none.\n")
	}
	if len(r.Before) > 0 {
		shown := r.Before
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		b.WriteString("\nSeen before the period, and in no rule\n")
		tb := newTable()
		tb.row("DIRECTION", "PORT", "PEER", "ADDRESS", "SERVICE", "LAST SEEN")
		for _, p := range shown {
			tb.row(p.Direction, strconv.Itoa(p.Port)+"/"+p.Proto, commentName(p.Peer), address(p.Address), commentName(p.Service),
				formatTime(p.LastSeen))
		}
		tb.writeTo(b)
		if n := len(r.Before) - len(shown); n > 0 {
			fmt.Fprintf(b, "and %s (-limit 0 shows all)\n", plural(n, "more flow"))
		}
	}
	b.WriteString("\nshawk applied nothing. -format nftables writes the rules as a table that rejects nothing and counts\n" +
		"what they do not list (the audit form): load it first. -enforce writes the table that rejects, and\n" +
		"-format systemd -enforce the drop-in of a unit.\n")
}

// comment writes lines as the comments of a file of rules, indented. A
// line stays a comment whatever it holds: a line break in it, or a NUL,
// which ends a line for systemd, is a space, and it does not end with a
// backslash, which would continue it with the next line in the files of
// systemd and nftables.
func comment(b *strings.Builder, indent string, lines ...string) {
	for _, l := range lines {
		l = strings.TrimRight(strings.NewReplacer("\n", " ", "\r", " ", "\x00", " ").Replace(l), " \t")
		if l == "" {
			b.WriteString(indent + "#\n")
			continue
		}
		if strings.HasSuffix(l, `\`) {
			l += "."
		}
		b.WriteString(indent + "# " + l + "\n")
	}
}

// ruleComment is what a file of rules tells of a rule above it: the peer,
// the services of the host, when it was last seen and what is particular
// to it.
func ruleComment(ru *rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: %s", ru.Direction, ru.portsOf(), commentName(ru.Peer))
	if len(ru.PeerHosts) > 0 {
		fmt.Fprintf(&b, " on %s", describeStrings(ru.PeerHosts, 3))
	}
	fmt.Fprintf(&b, ", of %s, last seen %s", describeStrings(ru.Services, 3), formatTime(ru.LastSeen))
	if notes := describeNotes(ru); notes != "" {
		fmt.Fprintf(&b, " [%s]", notes)
	}
	return b.String()
}

// incompleteBanner is the first lines of a file of rules written from an
// incomplete history.
func incompleteBanner(mode string) []string {
	if mode == modeAudit {
		return []string{
			"INCOMPLETE: the history does not tell every connection of the target, and these rules",
			"lack what was not seen. This audit form blocks nothing; it shows what they lack.",
			"Read the status below.",
			"",
		}
	}
	return []string{
		"INCOMPLETE: written with -allow-incomplete from a history that does not tell every",
		"connection of the target. These rules deny what was not seen. Read the status below.",
		"",
	}
}

// nftFamily returns the addresses of a family of a rule.
func nftFamily(ps []netip.Prefix, v4 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		if p.Addr().Is4() == v4 {
			out = append(out, p)
		}
	}
	return out
}

// nftMatch writes the match of the addresses of a family of a rule: the
// family alone for one that is whole, an address, or a set.
func nftMatch(ps []netip.Prefix, v4 bool, side string) string {
	family, nfproto := "ip6", "ipv6"
	if v4 {
		family, nfproto = "ip", "ipv4"
	}
	if len(ps) == 1 && ps[0].Bits() == 0 {
		return "meta nfproto " + nfproto
	}
	if len(ps) == 1 {
		return family + " " + side + " " + address(ps[0])
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = address(p)
	}
	if len(parts) <= nftPerLine {
		return family + " " + side + " { " + strings.Join(parts, ", ") + " }"
	}
	// A set of many addresses, a few per line: a server with thousands of
	// clients is one rule, which a reviewer can still read.
	var b strings.Builder
	b.WriteString(family + " " + side + " {")
	for i := 0; i < len(parts); i += nftPerLine {
		end := min(i+nftPerLine, len(parts))
		b.WriteString("\n\t\t\t" + strings.Join(parts[i:end], ", "))
		if end < len(parts) {
			b.WriteString(",")
		}
	}
	b.WriteString("\n\t\t}")
	return b.String()
}

// nftPerLine is how many addresses of a set are written on a line.
const nftPerLine = 4

// nftRules returns the lines of a rule: one per family of its addresses.
func nftRules(ru *rule) []string {
	port := "dport"
	if ru.SourcePort {
		port = "sport"
	}
	ports := fmt.Sprintf("%s %s %s accept", ru.Proto, port, ru.ports())
	if ru.AnySource {
		return []string{ports}
	}
	side := "daddr"
	if ru.Direction == ingress {
		side = "saddr"
	}
	var out []string
	for _, v4 := range []bool{true, false} {
		if ps := nftFamily(ru.Addresses, v4); len(ps) > 0 {
			out = append(out, nftMatch(ps, v4, side)+" "+ports)
		}
	}
	return out
}

// nftTable is the name of the table that the rules are written in: one of
// their own, so that loading them replaces no other rule of the host.
const nftTable = "shawk_policy"

// The counters of the table, which count the first packet of what no rule
// lists: named, so that `nft list counters` reads them and `nft reset
// counters` clears them.
const (
	nftEgressCounter  = "egress_unlisted"
	nftIngressCounter = "ingress_unlisted"
)

// nftLogLimit bounds the lines that the table writes to the kernel log.
const nftLogLimit = "limit rate 10/second burst 20 packets"

// writeNftables writes the rules of a host as a table of nftables: a
// chain for the connections it opens and, unless -ingress none, one for
// those it accepts. A chain accepts what belongs to a connection that is
// established, loopback, and every protocol but TCP and UDP, which shawk
// does not observe; then the flows that were seen. What is left is counted
// and logged, and then, in the enforcing form only, refused: the audit
// form, the default, lets it pass, so that what the history lacks shows
// before it breaks anything.
func writeNftables(b *strings.Builder, r *rulesReport) {
	audit := r.Mode != modeEnforce
	b.WriteString("#!/usr/sbin/nft -f\n")
	if r.Status != statusComplete {
		comment(b, "", incompleteBanner(r.Mode)...)
	}
	if audit {
		comment(b, "", "Rules of nftables for "+describeTarget(r.Target)+", written by shawk-policy for review.",
			"AUDIT form: it rejects nothing. What no rule lists is counted and logged, and passes.",
			"shawk applied nothing: read this file, then load it yourself.", "")
	} else {
		comment(b, "", "Rules of nftables for "+describeTarget(r.Target)+", written by shawk-policy for review.",
			"ENFORCING form: it rejects what no rule lists. Load the audit form first (below).",
			"shawk applied nothing: read this file, then load it yourself.", "")
	}
	comment(b, "", r.header()...)
	filters := "It filters the connections of the host itself (the hooks input and output), not what"
	if r.Ingress == ingressNone {
		filters = "It filters the connections that the host opens (the hook output) only: with -ingress none\n" +
			"what the host accepts is not filtered, and no chain input is written. It does not filter what"
	}
	comment(b, "", "")
	comment(b, "", strings.Split(filters, "\n")...)
	comment(b, "",
		"the host forwards. It is a table of its own: the other tables of the host still apply,",
		"and a packet passes only if every table accepts it.",
		"",
		"To check it without loading it:  nft -c -f FILE",
		"To load it:                      nft -f FILE",
		"To read what no rule lists:      nft list counters table inet "+nftTable,
		"                                 and the kernel log, lines with \"shawk-policy unlisted\"",
		"To remove it:                    nft delete table inet "+nftTable,
		"")
	if audit {
		comment(b, "",
			"How to go from this file to rules that reject",
			"  1. Load this audit form. Nothing is rejected. If the host did not track connections",
			"     before, loading it starts the tracking: the connections that are open are taken up",
			"     as their next packets pass (net.netfilter.nf_conntrack_tcp_loose = 1, the default).",
			"  2. A few minutes later, clear the counters: nft reset counters table inet "+nftTable,
			"     Until then they also count the connections that were open before the table.",
			"  3. Leave it for as long as the slowest job of the host takes to come round, and longer",
			"     than the longest silence of its open connections (TCP keepalive: 2 hours by default).",
			"     The counters count the packets that no rule lists, of each such connection until its",
			"     peer answers: a kernel tunnel, a rewritten destination, a job the period did not see.",
			"  4. Only while the counters stay at 0: write the rejecting form (the same command with",
			"     -enforce) and load it. It replaces this table in one transaction, and the",
			"     connections that the tracking knows by then stay established.",
			"  Loading the rejecting form on a host that did not track connections, without this",
			"  audit first, stops the open connections whose peer sends next: the tracking does not",
			"  know them, and takes their next packet for a new connection that no rule lists.")
	} else {
		comment(b, "",
			"Before loading this file",
			"  Load the audit form first (the same command without -enforce), clear its counters",
			"  after a few minutes (nft reset counters table inet "+nftTable+"), and load this file",
			"  only while they stay at 0 for as long as the slowest job of the host takes to come",
			"  round. The audit form also starts the connection tracking of the kernel if nothing",
			"  used it before, so that the connections that are open are known when this file is",
			"  loaded. Without it, on such a host, this file stops the open connections whose peer",
			"  sends next: their next packet is a new connection for the tracking, in no rule.",
			"  This file replaces the audit table in one transaction.")
	}
	fmt.Fprintf(b, "\ntable inet %s\ndelete table inet %s\n\ntable inet %s {\n", nftTable, nftTable, nftTable)
	fmt.Fprintf(b, "\tcounter %s { }\n", nftEgressCounter)
	if r.Ingress != ingressNone {
		fmt.Fprintf(b, "\tcounter %s { }\n", nftIngressCounter)
	}
	b.WriteString("\n")
	chain := func(name, direction, loopback, counter, verdict string) {
		fmt.Fprintf(b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy accept;\n\n", name, name)
		b.WriteString("\t\tct state established,related accept\n")
		fmt.Fprintf(b, "\t\t%s \"lo\" accept\n", loopback)
		comment(b, "\t\t", "shawk observes TCP and UDP only: nothing else is filtered.")
		b.WriteString("\t\tmeta l4proto != { tcp, udp } accept\n")
		for i := range r.Rules {
			if ru := &r.Rules[i]; ru.Direction == direction {
				b.WriteString("\n")
				comment(b, "\t\t", ruleComment(ru))
				for _, l := range nftRules(ru) {
					b.WriteString("\t\t" + l + "\n")
				}
			}
		}
		b.WriteString("\n")
		if audit {
			comment(b, "\t\t", "What no rule lists: counted and logged, not rejected (audit form).")
			fmt.Fprintf(b, "\t\tcounter name \"%s\" %s log prefix \"shawk-policy unlisted %s: \"\n", counter, nftLogLimit, direction)
		} else {
			comment(b, "\t\t", "What no rule lists: logged, counted and refused.")
			fmt.Fprintf(b, "\t\t%s log prefix \"shawk-policy unlisted %s: \"\n", nftLogLimit, direction)
			fmt.Fprintf(b, "\t\tcounter name \"%s\" %s\n", counter, verdict)
		}
		b.WriteString("\t}\n")
	}
	// A connection that the host opens and the rules deny fails at once,
	// rather than after the time limit of its client.
	chain("output", egress, "oifname", nftEgressCounter, "reject with icmpx admin-prohibited")
	if r.Ingress != ingressNone {
		b.WriteString("\n")
		chain("input", ingress, "iifname", nftIngressCounter, "drop")
	}
	b.WriteString("}\n")
}

// writeSystemd writes the rules of a unit as a drop-in of systemd:
// IPAddressDeny=any, and an IPAddressAllow= per address of a peer, in
// either direction, since the setting does not tell them apart and has no
// ports.
func writeSystemd(b *strings.Builder, r *rulesReport) {
	if r.Status != statusComplete {
		comment(b, "", incompleteBanner(r.Mode)...)
	}
	comment(b, "", "Drop-in of systemd for "+describeTarget(r.Target)+", written by shawk-policy for review.",
		"It blocks, as soon as the unit restarts with it, every address that it does not list, for",
		"every IP protocol. It has no audit form: check the host with the audit form of",
		"`shawk-policy rules -format nftables` first.",
		"shawk applied nothing: read this file, then install it yourself.", "")
	comment(b, "", r.header()...)
	comment(b, "",
		"",
		"To install it:  /etc/systemd/system/"+commentName(r.Target.Unit)+".d/50-shawk-policy.conf, then",
		"                systemctl daemon-reload, and restart the unit",
		"To check it:    systemd-analyze verify "+commentName(r.Target.Unit),
		"IPAddressAllow= has no ports and one list for both directions: an address is allowed",
		"for every port and every IP protocol, to connect to and to be accepted from. The list",
		"holds for the unit and for the control groups under it (a container that it runs).")
	b.WriteString("\n[Service]\nIPAddressDeny=any\n")
	comment(b, "", "Connections within the host are left open.")
	b.WriteString("IPAddressAllow=localhost\n")
	seen := map[netip.Prefix]bool{}
	for i := range r.Rules {
		ru := &r.Rules[i]
		b.WriteString("\n")
		comment(b, "", ruleComment(ru))
		written := false
		for _, p := range ru.Addresses {
			if seen[p] {
				continue
			}
			seen[p], written = true, true
			if p.Bits() == 0 {
				family := "IPv6"
				if p.Addr().Is4() {
					family = "IPv4"
				}
				comment(b, "", "Every address of "+family+": with this line the drop-in limits nothing for "+family+".")
			}
			b.WriteString("IPAddressAllow=" + address(p) + "\n")
		}
		if !written {
			comment(b, "", "(its addresses are allowed above)")
		}
	}
	families := "none"
	switch v4, v6 := r.hasFamily(true), r.hasFamily(false); {
	case v4 && v6:
		families = "IPv4 and IPv6"
	case v4:
		families = "IPv4"
	case v6:
		families = "IPv6"
	}
	unix := "none"
	if r.UnixSockets {
		unix = "used"
	}
	b.WriteString("\n")
	comment(b, "",
		"RestrictAddressFamilies= is left to the reviewer, as a comment: shawk records the",
		"addresses of connections, not the families of sockets. An AF_INET6 socket carries",
		"IPv4 peers, and AF_NETLINK, AF_PACKET and datagram AF_UNIX sockets are not observed,",
		"so a list made from what was seen could keep the unit from starting.",
		"Seen in the period: peers of "+families+"; Unix stream sockets: "+unix+".")
	b.WriteString("#RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n")
}

// hasFamily tells whether a rule of the report has an address of a family.
func (r *rulesReport) hasFamily(v4 bool) bool {
	for i := range r.Rules {
		if len(nftFamily(r.Rules[i].Addresses, v4)) > 0 {
			return true
		}
	}
	return false
}

// wholeFamily tells whether a rule of the report allows every address of
// a family.
func (r *rulesReport) wholeFamily(v4 bool) bool {
	for i := range r.Rules {
		for _, p := range r.Rules[i].Addresses {
			if p.Bits() == 0 && p.Addr().Is4() == v4 {
				return true
			}
		}
	}
	return false
}
