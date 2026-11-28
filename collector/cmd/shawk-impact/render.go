package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

// writeJSON writes a report as one JSON document.
func writeJSON(w io.Writer, r *report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// verdictLine is the verdict with what it stands for.
func verdictLine(r *report) string {
	switch r.Verdict {
	case verdictUnsafe:
		return "UNSAFE: active dependents"
	case verdictInconclusive:
		return "INCONCLUSIVE: insufficient observation coverage"
	}
	return r.Verdict
}

// writeText writes a report for a person: the verdict, how the target was
// observed, its dependents, at most limit of them (all if 0), and how the
// hosts that saw them were observed.
func writeText(w io.Writer, r *report, limit int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Target   %s\n", describeTarget(r.Target))
	fmt.Fprintf(&b, "Period   %s to %s (%s)\n\n", formatTime(r.Since), formatTime(r.Until), formatDuration(r.Until.Sub(r.Since)))

	fmt.Fprintf(&b, "Verdict  %s\n", printable(verdictLine(r)))
	switch {
	case r.Direct > 0:
		fmt.Fprintf(&b, "         %s used it in the period", plural(r.Direct, "dependent"))
		if r.Transitive > 0 {
			fmt.Fprintf(&b, ", and %s on them (to depth %d)", plural(r.Transitive, "more depends", "more depend"), r.Depth)
		}
		b.WriteString("\n")
	case r.Verdict == verdictSafe:
		fmt.Fprintf(&b, "         nothing used it in the period, of which the history covers %s (1 is all of it)\n", fraction(r.coverage))
	default:
		b.WriteString("         nothing was seen to use it in the period, but it was not watched enough to tell\n")
	}
	for _, reason := range r.Reasons {
		if s := describeShortfall(r, reason); s != "" {
			fmt.Fprintf(&b, "         - %s\n", s)
		}
	}
	if len(r.Caveats) > 0 {
		if r.Verdict == verdictUnsafe {
			b.WriteString("         The dependents below may not be all:\n")
		} else {
			fmt.Fprintf(&b, "         Accepted with -min-coverage %s:\n", fraction(r.minCoverage))
		}
		for _, caveat := range r.Caveats {
			if s := describeShortfall(r, caveat); s != "" {
				fmt.Fprintf(&b, "         - %s\n", s)
			}
		}
	}
	if len(r.Gaps) > 0 {
		b.WriteString("\nNot observed\n")
		for _, g := range r.Gaps {
			fmt.Fprintf(&b, "  %s to %s (%s)", formatTime(g.Start), formatTime(g.End), formatDuration(g.End.Sub(g.Start)))
			if g.Cause == "retention" {
				b.WriteString(", before the retention of the connector")
			}
			b.WriteString("\n")
		}
		if t := r.targetObserver(); t != nil && t.Gaps > len(r.Gaps) {
			fmt.Fprintf(&b, "  and %s\n", plural(int64(t.Gaps-len(r.Gaps)), "more gap"))
		}
	}
	if r.Incomplete != "" {
		fmt.Fprintf(&b, "\nThe rest of the report is missing: %s\n", printable(r.Incomplete))
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}

	if len(r.Dependents) > 0 {
		shown := r.Dependents
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		fmt.Fprintf(w, "\nDependents\n")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DEPTH\tCLIENT\tSERVER\tPORT\tSEEN BY\tCADENCE\tLAST SEEN\tNEXT ACTIVITY")
		for _, d := range shown {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Depth, describeClient(d), describeServer(d), describePort(d),
				printable(d.ObservedBy), describeCadence(d), formatTime(d.LastSeen), nextActivity(d, r.Until))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if n := len(r.Dependents) - len(shown); n > 0 {
			fmt.Fprintf(w, "and %s (-limit 0 shows all)\n", plural(int64(n), "more row"))
		}
		if slices.ContainsFunc(shown, func(d dependent) bool { return d.Cadence == nil }) {
			fmt.Fprintf(w, "The cadence is read to depth %d (-cadence-depth).\n", r.CadenceDepth)
		}
		// What the servers that are no service stand for, so that their
		// clients are not taken for clients of the service asked for.
		if slices.ContainsFunc(shown, func(d dependent) bool { return d.Relayed }) {
			fmt.Fprint(w, "~relay: the host relays the connections of this client in its kernel (a load balancer, a\n"+
				"NAT gateway), on the port shown. No process of the host accepts them; they count for\n"+
				"each of its services, since shawk does not know which one keeps the translations.\n")
		}
		if slices.ContainsFunc(shown, func(d dependent) bool { return d.ServerService != nil && *d.ServerService == "~unknown" }) {
			fmt.Fprint(w, "~unknown: a socket of the host whose owner is not known accepted the connections of this\n"+
				"client; they count for each of its services.\n")
		}
	}

	// The target, and the clients whose agents did not observe all along,
	// with which the cadences and the dependents of their dependents may be
	// wrong; the others are counted.
	var shown []observer
	complete := 0
	for _, ob := range r.Observers {
		if ob.Role != "target" && ob.complete() {
			complete++
			continue
		}
		if ob.Role == "target" || limit == 0 || len(shown) <= limit {
			shown = append(shown, ob)
		}
	}
	if len(shown) > 0 {
		fmt.Fprintf(w, "\nObservation of the hosts that tell\n")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "HOST\tROLE\tCOVERAGE\tNOT OBSERVED\tGAPS\tPARTLY OBSERVED\tNO UDP\tNO UNIX\tONE NETNS")
		for _, ob := range shown {
			if !ob.Agent {
				fmt.Fprintf(tw, "%s\t%s\tno agent\t-\t-\t-\t-\t-\t-\n", printable(ob.Host), ob.Role)
				continue
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", printable(ob.Host), ob.Role, fraction(ob.observed),
				seconds(ob.UnobservedSeconds), ob.Gaps, seconds(ob.PartlyObservedSeconds),
				seconds(ob.UDPUntracedSeconds), seconds(ob.UnixUntracedSeconds), seconds(ob.NetnsLimitedSeconds))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if n := len(r.Observers) - complete - len(shown); n > 0 {
			fmt.Fprintf(w, "and %s not observed all along (-limit 0 shows all)\n", plural(int64(n), "more client"))
		}
		if complete > 0 {
			fmt.Fprintf(w, "and %s observed all along\n", plural(int64(complete), "client"))
		}
		fmt.Fprint(w, "The coverage is from 0 to 1. A gap of 3m or less is not counted: an agent that\n"+
			"restarts within it is not seen to.\n")
	}
	_, err := fmt.Fprint(w, "\nOnly TCP, UDP and Unix stream sockets are observed. A host looks unused when it is used\n"+
		"over RDMA, less often than the period, or only forwards packets: a router, a hypervisor,\n"+
		"and a load balancer or gateway whose translations its agent does not learn (IPVS at its\n"+
		"defaults) and the configuration does not give (docs/design.md, sections 6.3 and 10).\n")
	return err
}

// printable returns a name with what is not printable escaped. The names
// of hosts and services are what agents send, which may hold control
// characters: written as they are, they could redraw the terminal, the
// verdict included.
func printable(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		q := strconv.QuoteRune(r)
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}

// describeTarget names a target: the host, with what narrows it.
func describeTarget(t target) string {
	t.Host, t.Service = printable(t.Host), printable(t.Service)
	var parts []string
	if t.Service != "" {
		parts = append(parts, "service "+t.Service)
	}
	if t.Port != 0 {
		parts = append(parts, "port "+strconv.Itoa(t.Port))
	}
	if t.Proto != "" {
		parts = append(parts, t.Proto)
	}
	if len(parts) == 0 {
		return t.Host
	}
	return t.Host + " (" + strings.Join(parts, ", ") + ")"
}

// describeShortfall tells a reason or a caveat of a verdict in words.
func describeShortfall(r *report, code string) string {
	t := r.targetObserver()
	if t == nil {
		t = &observer{}
	}
	switch code {
	case "active_dependents":
		return ""
	case "unknown_host":
		return fmt.Sprintf("no agent ever reported as %s, and the inventory has no such host: check the name", printable(r.Target.Host))
	case "no_agent":
		return fmt.Sprintf("%s runs no agent: its clients without an agent would not be seen", printable(r.Target.Host))
	case "unknown_service":
		return fmt.Sprintf("no process of %s had the service %s in the period: check the name", printable(r.Target.Host),
			printable(r.Target.Service))
	case "unknown_port":
		if r.Target.Service != "" {
			return fmt.Sprintf("no socket of %s listened on port %d of %s in the period: check the port", printable(r.Target.Service),
				r.Target.Port, printable(r.Target.Host))
		}
		return fmt.Sprintf("nothing listened on port %d of %s in the period: check the port", r.Target.Port, printable(r.Target.Host))
	case "not_observed":
		return fmt.Sprintf("not observed by an agent for %s of the period", seconds(t.UnobservedSeconds-t.BeforeRetentionSeconds))
	case "before_retention":
		return fmt.Sprintf("the first %s of the period are before the retention of the connector: the dependencies last seen then are deleted",
			seconds(t.BeforeRetentionSeconds))
	case "dropped_flows":
		return fmt.Sprintf("its agent dropped flows for %s (%s): dependencies active then may be missing",
			seconds(t.PartlyObservedSeconds), plural(t.DroppedFlows, "update"))
	case "udp_not_traced":
		return fmt.Sprintf("its agent did not trace UDP for %s", seconds(t.UDPUntracedSeconds))
	case "unix_not_traced":
		return fmt.Sprintf("its agent did not trace Unix sockets, or did not tell, for %s", seconds(t.UnixUntracedSeconds))
	case "netns_limited":
		return fmt.Sprintf("its agent traced one network namespace only for %s", seconds(t.NetnsLimitedSeconds))
	case "masquerade_not_traced":
		return "a pod or a container of it accepted connections from an address of the host itself, and its agent did not " +
			"learn the translations that would tell clients outside it, masqueraded by the host, from its own (it traces " +
			"none, or folds external peers: -fold-external none)"
	}
	return printable(code)
}

// describeClient names the client of a dependent: its host and service, or
// its address and the name of its range for a client without an agent,
// with the host the inventory gives the address.
func describeClient(d dependent) string {
	service := printable(d.ClientService)
	switch {
	case d.ClientAddr != nil && d.ClientHost != nil:
		return fmt.Sprintf("%s (%s) %s", printable(*d.ClientAddr), printable(*d.ClientHost), service)
	case d.ClientAddr != nil:
		return printable(*d.ClientAddr) + " " + service
	case d.ClientHost != nil:
		return printable(*d.ClientHost) + " " + service
	}
	return service
}

func describeServer(d dependent) string {
	if d.ServerService == nil {
		return printable(d.ServerHost) + " -"
	}
	return printable(d.ServerHost) + " " + printable(*d.ServerService)
}

// describePort is the port and transport: a Unix socket has no port, and
// port 0 stands for the ports of a service under the rules of ports.
func describePort(d dependent) string {
	switch {
	case d.Proto == "unix":
		return "unix"
	case d.Port == 0:
		return "*/" + printable(d.Proto)
	}
	return strconv.Itoa(d.Port) + "/" + printable(d.Proto)
}

// describeCadence is the cadence, with the period of one that has no name
// of its own.
func describeCadence(d dependent) string {
	switch {
	case d.Cadence == nil:
		return "-"
	case *d.Cadence == "periodic" && d.PeriodSeconds != nil:
		return "every " + seconds(*d.PeriodSeconds)
	}
	return printable(*d.Cadence)
}

// nextActivity tells when a dependent would next use its server, as far as
// its cadence tells: the time at which removing the server would break it.
func nextActivity(d dependent, until time.Time) string {
	if d.Cadence == nil {
		return "-"
	}
	switch *d.Cadence {
	case "continuous":
		return "now"
	case "one-off", "dormant":
		return "none expected"
	case "irregular", "unknown":
		return "unknown"
	}
	if d.NextExpected == nil {
		return "unknown"
	}
	if d.NextExpected.Before(until) {
		return "overdue since " + formatTime(*d.NextExpected)
	}
	return "about " + formatTime(*d.NextExpected)
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// seconds formats a number of seconds as a duration.
func seconds(s float64) string {
	return formatDuration(time.Duration(s * float64(time.Second)))
}

// formatDuration formats a duration in days, hours, minutes and seconds,
// with its two largest units: 90d, 3h28m, 14m, 45s.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	units := []struct {
		name string
		size time.Duration
	}{{"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}}
	var parts []string
	for _, u := range units {
		if n := d / u.size; n > 0 {
			parts = append(parts, strconv.FormatInt(int64(n), 10)+u.name)
			d -= n * u.size
		} else if len(parts) > 0 {
			// The units follow each other: 1d5m is written 1d.
			break
		}
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 0 {
		return "0s"
	}
	return strings.Join(parts, "")
}

// fraction trims a part of the period as PostgreSQL writes a numeric:
// 0.999800 is 0.9998, and 1.000000 is 1.
func fraction(s string) string {
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if s == "" {
		return "0"
	}
	return s
}

// plural formats a count with its noun: "1 gap", "2 gaps". many replaces
// the noun with an s for the counts other than one.
func plural(n int64, one string, many ...string) string {
	noun := one + "s"
	if len(many) > 0 {
		noun = many[0]
	}
	if n == 1 {
		noun = one
	}
	return strconv.FormatInt(n, 10) + " " + noun
}
