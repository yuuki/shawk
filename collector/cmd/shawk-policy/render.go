package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"
)

// writeJSON writes a report as one JSON document.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
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
// what the history does not tell, and the findings. It is the top of the
// text report and, as comments, of the files of rules, so that a file
// carries what its reviewer must know wherever it goes.
func (r *rulesReport) header() []string {
	lines := []string{
		"Target   " + describeTarget(r.Target),
		fmt.Sprintf("Period   %s to %s (%s)", formatTime(r.Since), formatTime(r.Until), formatDuration(r.Until.Sub(r.Since))),
	}
	switch r.Status {
	case statusComplete:
		lines = append(lines,
			"Status   COMPLETE: the history tells every TCP and UDP connection of the target in the period",
			fmt.Sprintf("         (coverage %s; 1 is all of the period)", fraction(r.coverage)))
		if len(r.Caveats) > 0 {
			lines = append(lines, fmt.Sprintf("         Accepted with -min-coverage %s:", fraction(r.minCoverage)))
		}
	default:
		lines = append(lines,
			"Status   "+commentName(r.Status)+": the history does not tell every connection of the target in the period.",
			"         Rules made from it deny what was not seen.",
			fmt.Sprintf("         (coverage %s, of the %s that -min-coverage asks for)", fraction(r.coverage), fraction(r.minCoverage)))
	}
	for _, code := range append(append([]string{}, r.Reasons...), r.Caveats...) {
		lines = append(lines, "         - "+describeShortfall(code, r.Observation))
	}
	if len(r.Gaps) > 0 {
		lines = append(lines, "", "Not observed")
		for _, g := range r.Gaps {
			l := fmt.Sprintf("  %s to %s (%s)", formatTime(g.Start), formatTime(g.End), formatDuration(g.End.Sub(g.Start)))
			if g.Cause == "retention" {
				l += ", before the retention of the connector"
			}
			lines = append(lines, l)
		}
		if r.Observation != nil && r.Observation.Gaps > len(r.Gaps) {
			lines = append(lines, "  and "+plural(r.Observation.Gaps-len(r.Gaps), "more gap"))
		}
	}
	lines = append(lines, "", "What the rules pin, and what they leave out")
	for _, f := range r.Findings {
		for i, l := range wrap(f.Text, 92) {
			if i == 0 {
				lines = append(lines, "  - "+l)
			} else {
				lines = append(lines, "    "+l)
			}
		}
	}
	lines = append(lines,
		"  - only TCP and UDP are observed: the rules filter nothing else, and what uses another protocol",
		"    (ICMP, VRRP, IPsec) is not known to shawk",
		"  - a connection that was not made in the period is denied: one made less often than the period, or",
		"    only when another server fails")
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
	if r.Refused {
		fmt.Fprintf(b, "\nNo rules are written from an incomplete history. -allow-incomplete writes them all the same,\n"+
			"marked as incomplete; -format report lists what they would hold.\n")
		return
	}
	if len(r.Rules) > 0 {
		shown := r.Rules
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		b.WriteString("\nRules\n")
		tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DIRECTION\tPORTS\tPEER\tADDRESSES\tSERVICES\tLAST SEEN\tNOTES")
		for i := range shown {
			ru := &shown[i]
			peer := commentName(ru.Peer)
			if len(ru.PeerHosts) > 0 {
				peer += " (" + commentNames(ru.PeerHosts) + ")"
			}
			fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\n", ru.Direction, ru.ports(), ru.Proto, peer,
				describeAddresses(ru.Addresses, 3), commentNames(ru.Services), formatTime(ru.LastSeen), describeNotes(ru))
		}
		tw.Flush()
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
		tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DIRECTION\tPORT\tPEER\tADDRESS\tSERVICE\tLAST SEEN")
		for _, p := range shown {
			fmt.Fprintf(tw, "%s\t%d/%s\t%s\t%s\t%s\t%s\n", p.Direction, p.Port, p.Proto, commentName(p.Peer), address(p.Address),
				commentName(p.Service), formatTime(p.LastSeen))
		}
		tw.Flush()
		if n := len(r.Before) - len(shown); n > 0 {
			fmt.Fprintf(b, "and %s (-limit 0 shows all)\n", plural(n, "more flow"))
		}
	}
	b.WriteString("\nshawk applied nothing. -format nftables or -format systemd writes the rules, for review.\n")
}

// comment writes lines as the comments of a file of rules, indented. A
// line stays a comment whatever it holds: a line break in it is a space,
// and it does not end with a backslash, which would continue it with the
// next line in the files of systemd and nftables.
func comment(b *strings.Builder, indent string, lines ...string) {
	for _, l := range lines {
		l = strings.TrimRight(strings.NewReplacer("\n", " ", "\r", " ").Replace(l), " \t")
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
	fmt.Fprintf(&b, "%s %s/%s: %s", ru.Direction, ru.ports(), ru.Proto, commentName(ru.Peer))
	if len(ru.PeerHosts) > 0 {
		fmt.Fprintf(&b, " on %s", commentNames(ru.PeerHosts))
	}
	fmt.Fprintf(&b, ", of %s, last seen %s", commentNames(ru.Services), formatTime(ru.LastSeen))
	if notes := describeNotes(ru); notes != "" {
		fmt.Fprintf(&b, " [%s]", notes)
	}
	return b.String()
}

// incompleteBanner is the first lines of a file of rules written from an
// incomplete history.
var incompleteBanner = []string{
	"INCOMPLETE: written with -allow-incomplete from a history that does not tell every",
	"connection of the target. These rules deny what was not seen. Read the status below.",
	"",
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
	return family + " " + side + " { " + strings.Join(parts, ", ") + " }"
}

// nftRules returns the lines of a rule: one per family of its addresses.
func nftRules(ru *rule) []string {
	ports := fmt.Sprintf("%s dport %s accept", ru.Proto, ru.ports())
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

// writeNftables writes the rules of a host as a table of nftables: a
// chain for the connections it opens and, unless -ingress none, one for
// those it accepts. A chain accepts what belongs to a connection that is
// established, loopback, and every protocol but TCP and UDP, which shawk
// does not observe; then the flows that were seen; and refuses the rest.
func writeNftables(b *strings.Builder, r *rulesReport) {
	b.WriteString("#!/usr/sbin/nft -f\n")
	if r.Status != statusComplete {
		comment(b, "", incompleteBanner...)
	}
	comment(b, "", "Rules of nftables for "+describeTarget(r.Target)+", written by shawk-policy for review.",
		"shawk applied nothing: read this file, then load it yourself.", "")
	comment(b, "", r.header()...)
	comment(b, "",
		"",
		"To check it without loading it:  nft -c -f FILE",
		"To load it:                      nft -f FILE",
		"To remove it:                    nft delete table inet "+nftTable,
		"It is a table of its own: the other tables of the host still apply, and a packet",
		"passes only if every table accepts it. It filters the connections of the host itself",
		"(the hooks input and output), not what the host forwards.")
	fmt.Fprintf(b, "\ntable inet %s\ndelete table inet %s\n\ntable inet %s {\n", nftTable, nftTable, nftTable)
	chain := func(name, direction, loopback, last string) {
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
		fmt.Fprintf(b, "\n\t\t%s\n\t}\n", last)
	}
	// A connection that the host opens and the rules deny fails at once,
	// rather than after the time limit of its client.
	chain("output", egress, "oifname", "counter reject with icmpx admin-prohibited")
	if r.Ingress != ingressNone {
		b.WriteString("\n")
		chain("input", ingress, "iifname", "counter drop")
	}
	b.WriteString("}\n")
}

// writeSystemd writes the rules of a unit as a drop-in of systemd:
// IPAddressDeny=any, and an IPAddressAllow= per address of a peer, in
// either direction, since the setting does not tell them apart and has no
// ports.
func writeSystemd(b *strings.Builder, r *rulesReport) {
	if r.Status != statusComplete {
		comment(b, "", incompleteBanner...)
	}
	comment(b, "", "Drop-in of systemd for "+describeTarget(r.Target)+", written by shawk-policy for review.",
		"shawk applied nothing: read this file, then install it yourself.", "")
	comment(b, "", r.header()...)
	comment(b, "",
		"",
		"To install it:  /etc/systemd/system/"+commentName(r.Target.Unit)+".d/50-shawk-policy.conf, then",
		"                systemctl daemon-reload, and restart the unit",
		"To check it:    systemd-analyze verify "+commentName(r.Target.Unit),
		"IPAddressAllow= has no ports and one list for both directions: an address is allowed",
		"for every port, to connect to and to be accepted from.")
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
