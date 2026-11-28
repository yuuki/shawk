package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const rulesUsage = `shawk-policy rules writes the connections of a host, or of a systemd unit of it,
over a period as rules that allow them and deny the rest, for review. It applies
nothing.

Usage:
  shawk-policy rules -host NAME [-unit NAME] [-format report|nftables|systemd|json] [flags]

  -format report    what the rules would hold, and what the history does not tell (default)
  -format nftables  a table of nftables for the host: its own connections (the hooks
                    input and output), TCP and UDP; needs no -unit
  -format systemd   a drop-in of the unit with IPAddressDeny= and IPAddressAllow=;
                    needs -unit, the name of a service unit
  -format json      the report, with the rules as data

A rule pins the addresses that the sockets of the host saw: shawk keeps no name
that a firewall could match. A peer that changes its address is denied until the
rules are written again; the report tells what is pinned and what that costs.

When the history does not tell every connection of the target for the whole period
(INCOMPLETE), rules would deny what was not seen: the report is written without
them, unless -allow-incomplete asks for them, and the exit status is 4 either way.

Exit status: 0 COMPLETE, and nothing else; 4 INCOMPLETE; 1 when the command fails;
2 when the command line is invalid, or asks for this help.

Flags:
`

// Formats of the rules.
const (
	formatReport   = "report"
	formatNftables = "nftables"
	formatSystemd  = "systemd"
	formatJSON     = "json"
)

// What the rules of the host allow of the connections it accepts.
const (
	ingressSources = "sources" // from the addresses that were seen
	ingressPorts   = "ports"   // from every address, on the ports that were seen
	ingressNone    = "none"    // nothing is written for them: they are not filtered
)

// The verdicts of shawk_v1.policy_verdict and baseline_verdict.
const (
	statusComplete   = "COMPLETE"
	statusIncomplete = "INCOMPLETE"
)

// rulesConfig is the command line of shawk-policy rules.
type rulesConfig struct {
	common
	host, unit      string
	format, ingress string
	allowIncomplete bool
	limit           int
}

// serviceUnit is the name of a service unit of systemd, which a drop-in
// is written for: the characters of a unit name, with one instance at
// most.
var serviceUnit = regexp.MustCompile(`^[A-Za-z0-9:_.\\-]+(@[A-Za-z0-9:_.\\-]*)?\.service$`)

func parseRules(args []string, stderr io.Writer) (*rulesConfig, error) {
	fs := newFlagSet("rules", rulesUsage, stderr)
	var c rulesConfig
	c.flags(fs, "90d", true)
	fs.StringVar(&c.host, "host", "", "host to write rules for, by the host.name of its agent")
	fs.StringVar(&c.unit, "unit", "", "unit of the host to write rules for alone, as in PostgreSQL (shawk.unit: nginx.service); without it, the whole host")
	fs.StringVar(&c.format, "format", formatReport, "report, nftables, systemd or json")
	fs.StringVar(&c.ingress, "ingress", ingressSources, "with nftables, what is allowed of the connections the host accepts: sources (from the addresses that were seen), ports (from every address, on the ports that were seen) or none (they are not filtered)")
	fs.BoolVar(&c.allowIncomplete, "allow-incomplete", false, "write the rules also when the history is INCOMPLETE: they deny what was not seen, and say so")
	fs.IntVar(&c.limit, "limit", 50, "rules to list in the report; 0 for all")
	// An hour is the least that tells anything of what a host connects to.
	if err := c.parse(fs, args, time.Hour); err != nil {
		return nil, err
	}
	set := given(fs)
	var err error
	switch {
	case c.host == "":
		err = errors.New("-host is required")
	case set["unit"] && c.unit == "":
		// A flag given with no value, as by a script whose variable is
		// empty, would widen the target to the whole host without a word.
		err = errors.New("-unit must not be empty: leave it out for the whole host")
	case c.format != formatReport && c.format != formatNftables && c.format != formatSystemd && c.format != formatJSON:
		err = errors.New("-format must be report, nftables, systemd or json")
	case c.ingress != ingressSources && c.ingress != ingressPorts && c.ingress != ingressNone:
		err = errors.New("-ingress must be sources, ports or none")
	case c.format == formatSystemd && c.unit == "":
		err = errors.New("-format systemd writes the drop-in of a unit: it needs -unit")
	case c.format == formatSystemd && !serviceUnit.MatchString(c.unit):
		err = fmt.Errorf("-format systemd writes the drop-in of a service unit, as nginx.service: %q is none "+
			"(a container, a session or a job has no unit file to drop it in)", c.unit)
	case c.format == formatSystemd && set["ingress"]:
		err = errors.New("-ingress is for nftables: IPAddressAllow= of systemd does not tell the two directions apart")
	case c.format == formatNftables && c.unit != "":
		err = errors.New("-format nftables writes the rules of a whole host: it takes no -unit " +
			"(rules of the host cannot tell the processes of a unit apart)")
	case c.limit < 0:
		err = errors.New("-limit must not be negative")
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	return &c, nil
}

// runRules runs shawk-policy rules and returns its exit status.
func runRules(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	c, err := parseRules(args, stderr)
	if err != nil {
		return exitUsage, err
	}
	var r *rulesReport
	if err := c.query(ctx, 0, func(ctx context.Context, tx pgx.Tx, since, until time.Time) error {
		r, err = readRules(ctx, tx, c, since, until)
		return err
	}); err != nil {
		return exitError, err
	}
	if err := writeRules(stdout, r, c.limit); err != nil {
		return exitError, err
	}
	if r.Status == statusComplete {
		return exitComplete, nil
	}
	if r.Status != statusIncomplete {
		// A verdict of a schema newer than this command: not COMPLETE.
		return exitError, fmt.Errorf("unknown status %q", r.Status)
	}
	if r.Refused {
		fmt.Fprintln(stderr, "shawk-policy: the history is INCOMPLETE: no rules are written (-allow-incomplete writes them all the same)")
	}
	return exitIncomplete, nil
}

// target is what the rules are for: a host, or a unit of it.
type target struct {
	Host string `json:"host"`
	Unit string `json:"unit,omitempty"`
}

// rulesReport is what shawk-policy rules tells of a target over a period:
// the row of shawk_v1.policy_verdict, and the rules made from the rows of
// policy_flows.
type rulesReport struct {
	Target target    `json:"target"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`

	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
	Caveats []string `json:"caveats"`
	// Coverage is the part of the period for which the history tells every
	// connection of the target, from 0 to 1, and MinCoverage what COMPLETE
	// takes.
	Coverage    float64 `json:"coverage"`
	MinCoverage float64 `json:"min_coverage"`
	// Observation is how the agent of the host observed, and Gaps the
	// first periods in which it did not.
	Observation *observation `json:"observation"`
	Gaps        []gap        `json:"gaps"`

	// Format and Ingress are what was asked for, and Refused tells that
	// the rules are not written because the history is incomplete.
	Format  string `json:"format"`
	Ingress string `json:"ingress,omitempty"`
	Refused bool   `json:"refused"`

	// Rules are what the target may connect to and accept, each with the
	// addresses it pins.
	Rules []rule `json:"rules"`
	// Findings tell what the rules pin and what that costs, and what they
	// leave out.
	Findings []finding `json:"findings"`
	// Loopback counts the flows within the host, which no rule covers.
	Loopback int `json:"loopback_flows"`
	// Before are the flows last seen before the period, which are not in
	// the rules.
	Before []pastFlow `json:"seen_before_period"`
	// NetworkNamespaces counts the network namespaces of the sockets of
	// the flows, and UnixSockets tells whether the target used Unix
	// sockets.
	NetworkNamespaces int  `json:"network_namespaces"`
	UnixSockets       bool `json:"unix_sockets"`

	// coverage is Coverage as PostgreSQL writes it, which is cut rather
	// than rounded: 1 is a target watched all along. minCoverage is
	// MinCoverage as it was asked for.
	coverage, minCoverage string
}

// observation is a row of shawk_v1.coverage.
type observation struct {
	Host                   string  `json:"host"`
	Agent                  bool    `json:"agent"`
	Observed               float64 `json:"observed"`
	UnobservedSeconds      float64 `json:"unobserved_seconds"`
	Gaps                   int     `json:"gaps"`
	PartlyObservedSeconds  float64 `json:"partly_observed_seconds"`
	DroppedFlows           int64   `json:"dropped_flows"`
	UDPUntracedSeconds     float64 `json:"udp_untraced_seconds"`
	NetnsLimitedSeconds    float64 `json:"netns_limited_seconds"`
	BeforeRetentionSeconds float64 `json:"before_retention_seconds"`
}

// gap is a period for which the history does not tell what the target
// did: before the retention of the connector (cause retention), or while
// no agent observed it (cause agent).
type gap struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Cause string    `json:"cause"`
}

// maxGaps is how many gaps a report lists.
const maxGaps = 10

// flow is a row of shawk_v1.policy_flows.
type flow struct {
	direction        string
	inPeriod         bool
	service, unit    string
	proto            string
	addr             netip.Prefix
	port             int
	portFrom, portTo int
	peer             string
	peerHost         *string
	translated       bool
	kernelChosen     bool
	first, last      time.Time
}

// Directions of a flow.
const (
	egress  = "egress"
	ingress = "ingress"
)

// rule allows the connections of the target with a peer on a port, or a
// range of ports: the connections it opens (egress) or accepts (ingress).
type rule struct {
	Direction string `json:"direction"`
	Proto     string `json:"proto"`
	PortFrom  int    `json:"port_from"`
	PortTo    int    `json:"port_to"`
	// Peer is the name of the other side, and PeerHosts its hosts where
	// their agents saw the connections: they tell what the rule is for,
	// and pin nothing.
	Peer      string   `json:"peer"`
	PeerHosts []string `json:"peer_hosts"`
	// Addresses are what the rule pins: the addresses of the peer as the
	// sockets of the target saw them, none within another. A network that
	// is a whole family stands for peers whose addresses the agent folded.
	Addresses []netip.Prefix `json:"addresses"`
	// AnySource tells an ingress rule that allows every address (-ingress
	// ports): Addresses are then what was seen, and pin nothing.
	AnySource bool `json:"any_source,omitempty"`
	// Services are the local services that the connections are of.
	Services  []string  `json:"services"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Folded tells that the agent folded peers of the rule: it allows
	// every address of their family. Translated, that it allows backends
	// that the host itself translates its connections to. KernelChosen,
	// that the server listened on a port the kernel chose. Unattributed,
	// that sockets without a known owner made it, which may not be of the
	// unit.
	Folded       bool `json:"folded"`
	Translated   bool `json:"translated"`
	KernelChosen bool `json:"kernel_chosen"`
	Unattributed bool `json:"unattributed"`
}

// ports is the port of a rule, or its range.
func (r *rule) ports() string {
	if r.PortFrom == r.PortTo {
		return strconv.Itoa(r.PortFrom)
	}
	return strconv.Itoa(r.PortFrom) + "-" + strconv.Itoa(r.PortTo)
}

// pastFlow is a flow last seen before the period.
type pastFlow struct {
	Direction string       `json:"direction"`
	Service   string       `json:"service"`
	Proto     string       `json:"proto"`
	Port      int          `json:"port"`
	Address   netip.Prefix `json:"address"`
	Peer      string       `json:"peer"`
	LastSeen  time.Time    `json:"last_seen"`
}

// finding tells something that a reviewer of the rules must know: what
// they pin, what they leave out, what may break.
type finding struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
	Text  string `json:"text"`
}

// readRules reads the report of a target.
func readRules(ctx context.Context, tx pgx.Tx, c *rulesConfig, since, until time.Time) (*rulesReport, error) {
	r := &rulesReport{Target: target{Host: c.host, Unit: c.unit}, Since: since, Until: until, Format: c.format,
		minCoverage: c.minCoverage, Reasons: []string{}, Caveats: []string{}, Gaps: []gap{}, Rules: []rule{},
		Findings: []finding{}, Before: []pastFlow{}}
	if c.format != formatSystemd {
		r.Ingress = c.ingress
	}
	var err error
	if r.MinCoverage, err = strconv.ParseFloat(c.minCoverage, 64); err != nil {
		return nil, err
	}
	var unit *string
	if c.unit != "" {
		unit = &c.unit
	}
	var reasons, caveats []string
	if err := tx.QueryRow(ctx, `
SELECT status, reasons, caveats, coverage::float8, coverage::text, network_namespaces, unix_sockets
FROM shawk_v1.policy_verdict($1, $2, $3, $4, $5::numeric)`, c.host, since, until, unit, c.minCoverage).
		Scan(&r.Status, &reasons, &caveats, &r.Coverage, &r.coverage, &r.NetworkNamespaces, &r.UnixSockets); err != nil {
		return nil, fmt.Errorf("the verdict: %w", err)
	}
	r.Reasons, r.Caveats = append(r.Reasons, reasons...), append(r.Caveats, caveats...)

	var o observation
	err = tx.QueryRow(ctx, `
SELECT host, agent, observed::float8, extract(epoch FROM unobserved)::float8, gaps,
       extract(epoch FROM partly_observed)::float8, dropped_flows, extract(epoch FROM udp_untraced)::float8,
       extract(epoch FROM netns_limited)::float8, extract(epoch FROM before_retention)::float8
FROM shawk_v1.coverage($1, $2, $3)`, since, until, []string{c.host}).
		Scan(&o.Host, &o.Agent, &o.Observed, &o.UnobservedSeconds, &o.Gaps, &o.PartlyObservedSeconds, &o.DroppedFlows,
			&o.UDPUntracedSeconds, &o.NetnsLimitedSeconds, &o.BeforeRetentionSeconds)
	if err != nil {
		return nil, fmt.Errorf("the coverage of the host: %w", err)
	}
	r.Observation = &o
	rows, err := tx.Query(ctx, `
SELECT gap_start, gap_end, cause FROM shawk_v1.coverage_gaps($1, $2, $3) ORDER BY gap_start LIMIT $4`,
		since, until, []string{c.host}, maxGaps)
	if err != nil {
		return nil, fmt.Errorf("the gaps: %w", err)
	}
	gaps, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (gap, error) {
		var g gap
		err := row.Scan(&g.Start, &g.End, &g.Cause)
		g.Start, g.End = g.Start.UTC(), g.End.UTC()
		return g, err
	})
	if err != nil {
		return nil, fmt.Errorf("the gaps: %w", err)
	}
	r.Gaps = append(r.Gaps, gaps...)

	rows, err = tx.Query(ctx, `
SELECT direction, in_period, service, unit, proto, peer_addr, port, port_from, port_to, peer, peer_host,
       translated, kernel_chosen, first_seen, last_seen
FROM shawk_v1.policy_flows($1, $2, $3, $4)`, c.host, since, until, unit)
	if err != nil {
		return nil, fmt.Errorf("the flows: %w", err)
	}
	flows, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (flow, error) {
		var f flow
		err := row.Scan(&f.direction, &f.inPeriod, &f.service, &f.unit, &f.proto, &f.addr, &f.port, &f.portFrom, &f.portTo,
			&f.peer, &f.peerHost, &f.translated, &f.kernelChosen, &f.first, &f.last)
		return f, err
	})
	if err != nil {
		return nil, fmt.Errorf("the flows: %w", err)
	}
	if err := r.build(flows, c.ingress); err != nil {
		return nil, err
	}
	// Rules made from a history that does not tell everything deny what
	// was not seen: they are not written unless asked for.
	r.Refused = r.Status != statusComplete && !c.allowIncomplete && (c.format == formatNftables || c.format == formatSystemd)
	return r, nil
}

// unknownService is the service of the sockets whose owner the agent does
// not know.
const unknownService = "~unknown"

// build makes the rules and the findings of a report from the flows of its
// target.
func (r *rulesReport) build(flows []flow, ingressMode string) error {
	type key struct {
		direction, proto, peer string
		from, to               int
	}
	byKey := map[key]*rule{}
	hosts := map[key]map[string]bool{}
	services := map[key]map[string]bool{}
	for _, f := range flows {
		if err := f.check(); err != nil {
			return err
		}
		f.addr = f.addr.Masked()
		if !f.inPeriod {
			r.Before = append(r.Before, pastFlow{f.direction, f.service, f.proto, f.port, f.addr, f.peer, f.last.UTC()})
			continue
		}
		if f.addr.Addr().IsLoopback() {
			// Connections within the host: no rule of addresses is for
			// them, and loopback is left open.
			r.Loopback++
			continue
		}
		k := key{f.direction, f.proto, f.peer, f.portFrom, f.portTo}
		ru := byKey[k]
		if ru == nil {
			ru = &rule{Direction: f.direction, Proto: f.proto, PortFrom: f.portFrom, PortTo: f.portTo, Peer: f.peer,
				FirstSeen: f.first.UTC(), LastSeen: f.last.UTC()}
			byKey[k], hosts[k], services[k] = ru, map[string]bool{}, map[string]bool{}
		}
		ru.Addresses = append(ru.Addresses, f.addr)
		if f.peerHost != nil {
			hosts[k][*f.peerHost] = true
		}
		services[k][f.service] = true
		if f.first.Before(ru.FirstSeen) {
			ru.FirstSeen = f.first.UTC()
		}
		if f.last.After(ru.LastSeen) {
			ru.LastSeen = f.last.UTC()
		}
		ru.Folded = ru.Folded || f.addr.Bits() == 0
		ru.Translated = ru.Translated || f.translated
		ru.KernelChosen = ru.KernelChosen || (f.kernelChosen && f.portFrom == f.portTo)
		ru.Unattributed = ru.Unattributed || (r.Target.Unit != "" && f.service == unknownService && f.unit != r.Target.Unit)
	}
	for k, ru := range byKey {
		ru.Addresses = normalizePrefixes(ru.Addresses)
		ru.PeerHosts = sortedKeys(hosts[k])
		ru.Services = sortedKeys(services[k])
		ru.AnySource = ru.Direction == ingress && ingressMode == ingressPorts && r.Format != formatSystemd
		r.Rules = append(r.Rules, *ru)
	}
	slices.SortFunc(r.Rules, func(a, b rule) int {
		return cmp.Or(cmp.Compare(a.Direction, b.Direction), cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.PortFrom, b.PortFrom),
			cmp.Compare(a.PortTo, b.PortTo), cmp.Compare(a.Peer, b.Peer))
	})
	slices.SortFunc(r.Before, func(a, b pastFlow) int {
		return cmp.Or(cmp.Compare(a.Direction, b.Direction), cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Port, b.Port),
			a.Address.Addr().Compare(b.Address.Addr()), cmp.Compare(a.Address.Bits(), b.Address.Bits()), cmp.Compare(a.Service, b.Service))
	})
	r.Findings = r.findings()
	return nil
}

// check refuses a flow that the rules cannot be written from: what the
// contract never returns, so that a row of a schema newer than this
// command is an error rather than a rule of something else.
func (f *flow) check() error {
	switch {
	case f.direction != egress && f.direction != ingress:
		return fmt.Errorf("a flow of an unknown direction %q", f.direction)
	case f.proto != "tcp" && f.proto != "udp":
		return fmt.Errorf("a flow of an unknown transport %q", f.proto)
	case !f.addr.IsValid() || f.addr.Addr().Zone() != "":
		return errors.New("a flow without a valid address")
	case f.portFrom < 0 || f.portTo > 65535 || f.portFrom > f.portTo || f.port < 0 || f.port > 65535:
		return fmt.Errorf("a flow with the ports %d to %d", f.portFrom, f.portTo)
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// normalizePrefixes returns prefixes in order, IPv4 first, each once and
// none within another: a set of nftables refuses intervals that overlap,
// and an address within a network that is allowed adds nothing.
func normalizePrefixes(in []netip.Prefix) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		// An IPv4-mapped address is the IPv4 address: the agents send
		// those, and the kernel matches them as IPv4.
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		ps = append(ps, p.Masked())
	}
	// The widest first among those that start at the same address, so that
	// a prefix follows every prefix that holds it.
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	var out []netip.Prefix
	for _, p := range ps {
		// Prefixes nest or are disjoint, so one that holds p is the last
		// that was kept: every prefix kept after it is within it or p.
		if n := len(out); n > 0 && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// findings tells what the rules of a report pin, what that costs, and what
// they leave out.
func (r *rulesReport) findings() []finding {
	var out []finding
	add := func(code string, n int, format string, args ...any) {
		if n > 0 {
			out = append(out, finding{code, n, fmt.Sprintf(format, args...)})
		}
	}
	count := func(match func(*rule) bool) int {
		n := 0
		for i := range r.Rules {
			if match(&r.Rules[i]) {
				n++
			}
		}
		return n
	}
	pinned := 0
	for _, ru := range r.Rules {
		if ru.AnySource {
			continue
		}
		for _, p := range ru.Addresses {
			if p.Bits() > 0 {
				pinned++
			}
		}
	}
	add("pinned_addresses", pinned, "%s pinned as the sockets saw them: a peer that gets another address (DHCP, "+
		"autoscaling, a replica that was not used, a failover) is denied until the rules are written again",
		plural(pinned, "address is", "addresses are"))
	n := count(func(ru *rule) bool { return ru.Folded })
	add("folded_peers", n, "%s every address of a family: the agent folded these peers and kept no address "+
		"(the agent keeps them with -fold-external none, or -internal-peers for the ranges that matter)",
		plural(n, "rule allows", "rules allow"))
	n = count(func(ru *rule) bool { return ru.Peer == "~unresolved" || strings.Contains(ru.Peer, "~unresolved") })
	add("unresolved_peers", n, "%s shawk could not name (~unresolved: no agent there, and no range of peer_cidrs): "+
		"check what they are before allowing them", plural(n, "rule is for a peer", "rules are for peers"))
	n = count(func(ru *rule) bool { return ru.PortFrom != ru.PortTo })
	add("port_ranges", n, "%s a range of ports, by the rules of ports of the connector (dynamic_ports, "+
		"port_agnostic_services): the server listens on another port at every run", plural(n, "rule allows", "rules allow"))
	n = count(func(ru *rule) bool { return ru.KernelChosen })
	add("kernel_chosen_ports", n, "%s a port that the kernel chose for the server, which no rule of ports covers: "+
		"the server listens on another one at its next run, and is denied then (shawk_v1.kernel_chosen_ports)",
		plural(n, "rule pins", "rules pin"))
	n = count(func(ru *rule) bool { return ru.Translated })
	add("translated_backends", n, "%s the backends that the host itself translates its connections to (DNAT in "+
		"its kernel, as kube-proxy does): they change when the translation does", plural(n, "rule allows", "rules allow"))
	n = count(func(ru *rule) bool { return ru.Unattributed })
	add("unattributed_sockets", n, "%s from sockets of the host whose owner is not known (~unknown): they may "+
		"be of the unit, so they are allowed", plural(n, "rule comes", "rules come"))
	n = count(func(ru *rule) bool { return ru.Direction == ingress && !ru.AnySource })
	if r.Format != formatSystemd && r.Ingress == ingressSources {
		add("pinned_sources", n, "%s to the sources that were seen: a client, or an administrator, at "+
			"another address is refused (-ingress ports opens the ports to every source)",
			plural(n, "ingress rule is pinned", "ingress rules are pinned"))
	}
	if r.Format != formatSystemd && r.NetworkNamespaces > 1 {
		add("other_network_namespaces", r.NetworkNamespaces, "the sockets of the flows are in %d network namespaces: "+
			"the connections of containers that the host forwards do not pass the hooks input and output, and "+
			"rules of the host do not filter them (no chain forward is written); their flows are allowed all the same",
			r.NetworkNamespaces)
	}
	add("loopback_flows", r.Loopback, "%s within the host (loopback): they are left open, and are in no rule",
		plural(r.Loopback, "flow is", "flows are"))
	add("seen_before_period", len(r.Before), "%s last seen before the period, and in no rule: a job that runs "+
		"less often than the period would be denied (a longer -lookback includes them)",
		plural(len(r.Before), "flow was", "flows were"))
	return out
}

// writeRules writes a report in its format.
func writeRules(w io.Writer, r *rulesReport, limit int) error {
	var b strings.Builder
	switch {
	case r.Format == formatJSON:
		return writeJSON(w, r)
	case r.Format == formatNftables && !r.Refused:
		writeNftables(&b, r)
	case r.Format == formatSystemd && !r.Refused:
		writeSystemd(&b, r)
	default:
		writeRulesReport(&b, r, limit)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

var _ flag.Value = (*names)(nil)
