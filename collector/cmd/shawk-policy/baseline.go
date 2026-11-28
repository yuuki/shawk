package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yuuki/shawk/collector/shawkconnector"
)

const baselineUsage = `shawk-policy baseline writes the dependencies of services over a period as a
baseline file, for review. The connector reads the file once it is approved
(baseline_file), and tells Prometheus the dependencies of those services that the
file does not hold. The command writes to its standard output only.

Usage:
  shawk-policy baseline (-service NAME ... | -all) [-merge FILE] [flags]

A dependency is a server, by its name (a service, a range of peer_cidrs,
~unresolved or ~external), a port (0 under the rules of ports of the connector)
and a transport, tcp or udp. Dependencies over Unix sockets are not listed.

-merge FILE writes FILE with the services asked for replaced by what was seen, or
added, and the others as they are: approve a change by reviewing the difference.

When the history does not tell every dependency of a service for the whole period
(INCOMPLETE), its baseline would miss some, and they would be told as a drift
later: the report is written without the file, unless -allow-incomplete asks for
it, and the exit status is 4 either way. A service that no process had in the
period is never written: its name may be mistyped.

Exit status: 0 COMPLETE, and nothing else; 4 INCOMPLETE; 1 when the command fails;
2 when the command line is invalid, or asks for this help.

Flags:
`

// baselineConfig is the command line of shawk-policy baseline.
type baselineConfig struct {
	common
	services        names
	all             bool
	merge           string
	allowIncomplete bool
	asJSON          bool
}

func parseBaseline(args []string, stderr io.Writer) (*baselineConfig, error) {
	fs := newFlagSet("baseline", baselineUsage, stderr)
	var c baselineConfig
	c.flags(fs, "90d", true)
	fs.Var(&c.services, "service", "service to write the baseline of, as in PostgreSQL ([namespace/]name); may be given several times")
	fs.BoolVar(&c.all, "all", false, "every service that opened connections in the period")
	fs.StringVar(&c.merge, "merge", "", "baseline file to write again with the services asked for replaced or added")
	fs.BoolVar(&c.allowIncomplete, "allow-incomplete", false, "write the file also when the history of a service is INCOMPLETE: its baseline may miss dependencies")
	fs.BoolVar(&c.asJSON, "json", false, "write the report as JSON, with the file in it")
	if err := c.parse(fs, args, time.Hour); err != nil {
		return nil, err
	}
	var err error
	switch {
	case c.all && len(c.services) > 0:
		err = errors.New("-all and -service exclude each other")
	case !c.all && len(c.services) == 0:
		err = errors.New("-service or -all is required")
	case slices.Contains(c.services, ""):
		// As of a script whose variable is empty.
		err = errors.New("-service must not be empty")
	case len(c.services) > shawkconnector.MaxBaselineServices:
		err = fmt.Errorf("more than %d services", shawkconnector.MaxBaselineServices)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	slices.Sort(c.services)
	c.services = slices.Compact(c.services)
	return &c, nil
}

// baselineReport is what shawk-policy baseline tells: the services with
// their dependencies and how they were observed, and the file.
type baselineReport struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	// Status is COMPLETE when every service is, and INCOMPLETE otherwise.
	Status      string            `json:"status"`
	MinCoverage float64           `json:"min_coverage"`
	Services    []baselineService `json:"services"`
	// Merged is the file whose other services are kept, and Kept how many.
	Merged string `json:"merged,omitempty"`
	Kept   int    `json:"kept_services"`
	// Refused tells that the file is not written because a service is
	// incomplete, and File is the file otherwise.
	Refused bool   `json:"refused"`
	File    string `json:"file,omitempty"`
	// Unnamed tells that a process without a service name opened
	// connections in the period (-all): a baseline cannot name it, so it
	// is in no file, and nothing judges it.
	Unnamed bool `json:"unnamed_service"`
	// Outside are the services of the baseline that the connector holds
	// which are not in the file: it was written as a part of that
	// baseline, and is not one to deploy alone.
	Outside []string `json:"outside_services"`

	// deployed are the services of the baseline that the connector holds.
	deployed []string

	minCoverage string
}

// baselineService is a row of shawk_v1.baseline_verdict with the rows of
// baseline_observed of the service.
type baselineService struct {
	Service string   `json:"service"`
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
	Caveats []string `json:"caveats"`
	// Hosts counts the hosts that ran the service in the period, Coverage
	// is that of the least observed, and ShortHosts lists the first of
	// those that were not observed enough.
	Hosts      int      `json:"hosts"`
	Coverage   float64  `json:"coverage"`
	ShortHosts []string `json:"short_hosts"`
	// UnobservedHosts counts the hosts that were not observed enough, of
	// which ShortHosts lists the first, and ShortSeconds how long each of
	// those was not observed. IdleHosts counts, for a service that runs
	// nowhere, the hosts that ran it last: UnobservedHosts and ShortHosts
	// are then of those.
	UnobservedHosts int          `json:"unobserved_hosts"`
	ShortSeconds    []int32      `json:"short_seconds"`
	IdleHosts       int          `json:"idle_hosts"`
	Dependencies    []dependency `json:"dependencies"`

	coverage string
}

// known tells whether a process had the service in the period.
func (s *baselineService) known() bool { return !slices.Contains(s.Reasons, "unknown_service") }

// lastHosts tells that the service runs on no host that is observed, and
// that a host that ran it last is not observed: it may run there.
func (s *baselineService) lastHosts() bool {
	return slices.Contains(s.Reasons, "last_hosts_not_observed")
}

// dependency is a row of shawk_v1.baseline_observed or baseline_drift.
type dependency struct {
	Service   string    `json:"service,omitempty"`
	Peer      string    `json:"peer"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Hosts are the hosts of the clients, Addresses the first of the
	// addresses they connected to, and NamedBy where the name of the
	// server comes from: edge, endpoint or address.
	Hosts     []string `json:"hosts"`
	Addresses []string `json:"addresses"`
	NamedBy   string   `json:"named_by"`
	// KernelChosen tells that the server listened on a port that the
	// kernel chose, another one at its next run: Port is then 0, and the
	// dependency is on the ports that the kernel chose for a server of
	// the name, and on no other (`port: kernel-chosen` in the file),
	// rather than on a port that a baseline would pin for nothing. Ports
	// are the first of the ports that the sockets saw.
	KernelChosen bool  `json:"kernel_chosen"`
	Ports        []int `json:"ports"`
	// Processes are the other services of the clients: processes in a
	// unit of the service that have a name of their own and no baseline,
	// which the baseline of the service judges.
	Processes []string `json:"processes"`
}

const dependencyColumns = `service, peer, port, proto, first_seen, last_seen, hosts, ARRAY(SELECT host(a) || CASE
  WHEN masklen(a) < CASE family(a) WHEN 4 THEN 32 ELSE 128 END THEN '/' || masklen(a) ELSE '' END FROM unnest(addrs) AS a), named_by,
  kernel_chosen, ports, processes`

func scanDependency(row pgx.CollectableRow) (dependency, error) {
	var d dependency
	var ports []int32
	err := row.Scan(&d.Service, &d.Peer, &d.Port, &d.Proto, &d.FirstSeen, &d.LastSeen, &d.Hosts, &d.Addresses, &d.NamedBy,
		&d.KernelChosen, &ports, &d.Processes)
	d.FirstSeen, d.LastSeen = d.FirstSeen.UTC(), d.LastSeen.UTC()
	d.Ports = make([]int, len(ports))
	for i, p := range ports {
		d.Ports[i] = int(p)
	}
	if d.Processes == nil {
		d.Processes = []string{}
	}
	return d, err
}

// sortDependencies orders dependencies by the bytes of their service and
// peer, then by port and transport: the order of a report is the same
// whatever the collation of the database it was read from.
func sortDependencies(deps []dependency) {
	slices.SortFunc(deps, func(a, b dependency) int {
		return cmp.Or(strings.Compare(a.Service, b.Service), strings.Compare(a.Peer, b.Peer), cmp.Compare(a.Port, b.Port),
			strings.Compare(a.Proto, b.Proto))
	})
}

// port is the port of a dependency as a file writes it: a number, or the
// word for the ports that the kernel chose.
func (d *dependency) port() string {
	if d.KernelChosen && d.Port == 0 {
		return "kernel-chosen"
	}
	return strconv.Itoa(d.Port)
}

// note tells what is particular to a dependency, for the line of the file
// and the tables: its port when the kernel chose it, and the processes of
// another name that made it.
func (d *dependency) note() string {
	var notes []string
	if d.KernelChosen && d.Port == 0 {
		ports := make([]string, len(d.Ports))
		for i, p := range d.Ports {
			ports[i] = strconv.Itoa(p)
		}
		notes = append(notes, "the ports that the kernel chose for a server named "+commentName(d.Peer)+" ("+strings.Join(ports, ", ")+
			" when seen), on any host, and no other port")
	}
	if len(d.Processes) > 0 {
		notes = append(notes, "by "+describeStrings(d.Processes, 3)+" in its unit")
	}
	return strings.Join(notes, "; ")
}

// runBaseline runs shawk-policy baseline and returns its exit status.
func runBaseline(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	c, err := parseBaseline(args, stderr)
	if err != nil {
		return exitUsage, err
	}
	// The file to merge with is read first: an invalid one fails the
	// command before it asks the database.
	var other *shawkconnector.Baseline
	if c.merge != "" {
		b, err := os.ReadFile(c.merge)
		if err != nil {
			return exitError, err
		}
		if other, err = shawkconnector.ParseBaseline(b); err != nil {
			return exitError, fmt.Errorf("%s: %w", c.merge, err)
		}
	}
	var r *baselineReport
	if err := c.query(ctx, 0, func(ctx context.Context, tx pgx.Tx, since, until time.Time) error {
		r, err = readBaseline(ctx, tx, c, since, until, other)
		return err
	}); err != nil {
		return exitError, err
	}
	r.Merged = c.merge
	if err := r.finish(other, c.allowIncomplete); err != nil {
		return exitError, err
	}
	if c.asJSON {
		err = writeJSON(stdout, r)
	} else {
		_, err = io.WriteString(stdout, r.text())
	}
	if err != nil {
		return exitError, err
	}
	if r.Status == statusComplete {
		return exitComplete, nil
	}
	if r.Refused {
		fmt.Fprintln(stderr, "shawk-policy: the history is INCOMPLETE: no baseline is written")
	}
	return exitIncomplete, nil
}

// readBaseline reads the verdicts and the dependencies of the services
// asked for. other is the file that they are merged with: its services
// have a baseline too, which judges their processes.
func readBaseline(ctx context.Context, tx pgx.Tx, c *baselineConfig, since, until time.Time, other *shawkconnector.Baseline) (*baselineReport, error) {
	r := &baselineReport{Since: since, Until: until, Status: statusComplete, minCoverage: c.minCoverage, Services: []baselineService{}}
	var err error
	if r.MinCoverage, err = strconv.ParseFloat(c.minCoverage, 64); err != nil {
		return nil, err
	}
	// The services that have a baseline once the file is deployed: those
	// asked for, those of the file to merge with, and those of the
	// baseline that the connector read, which the file is to replace or to
	// be merged with. A process of another name in a unit of one of them
	// is judged by the unit, by the drift and here alike; a service that
	// has a baseline of its own is not mixed into that of another. With
	// -all every service that was seen is in the file.
	var asked, judged []string
	if !c.all {
		asked = c.services
		judged = slices.Clone(asked)
		if other != nil {
			for _, s := range other.Services {
				judged = append(judged, s.Service)
			}
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT service FROM shawk_v1.baseline`)
		if err != nil {
			return nil, fmt.Errorf("the baseline: %w", err)
		}
		if r.deployed, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return nil, fmt.Errorf("the baseline: %w", err)
		}
		judged = append(judged, r.deployed...)
	}
	rows, err := tx.Query(ctx, `SELECT `+dependencyColumns+` FROM shawk_v1.baseline_observed($1, $2, $3, $4)`, since, until, asked, judged)
	if err != nil {
		return nil, fmt.Errorf("the dependencies: %w", err)
	}
	deps, err := pgx.CollectRows(rows, scanDependency)
	if err != nil {
		return nil, fmt.Errorf("the dependencies: %w", err)
	}
	sortDependencies(deps)
	byService := map[string][]dependency{}
	for _, d := range deps {
		s := d.Service
		d.Service = ""
		byService[s] = append(byService[s], d)
	}
	if c.all {
		for s := range byService {
			if s == "" {
				// A process whose telemetry has no service.name: a
				// baseline has no name to list it under.
				r.Unnamed = true
				continue
			}
			asked = append(asked, s)
		}
		slices.Sort(asked)
	}
	rows, err = tx.Query(ctx, `
SELECT service, status, reasons, caveats, hosts, coverage::float8, coverage::text, short_hosts, unobserved_hosts, short_seconds,
       idle_hosts
FROM shawk_v1.baseline_verdict($1, $2, $3, $4::numeric)`, asked, since, until, c.minCoverage)
	if err != nil {
		return nil, fmt.Errorf("the verdicts: %w", err)
	}
	if r.Services, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (baselineService, error) {
		s := baselineService{Dependencies: []dependency{}}
		err := row.Scan(&s.Service, &s.Status, &s.Reasons, &s.Caveats, &s.Hosts, &s.Coverage, &s.coverage, &s.ShortHosts,
			&s.UnobservedHosts, &s.ShortSeconds, &s.IdleHosts)
		s.Dependencies = append(s.Dependencies, byService[s.Service]...)
		return s, err
	}); err != nil {
		return nil, fmt.Errorf("the verdicts: %w", err)
	}
	// The order of the file, whatever the collation of the database.
	slices.SortFunc(r.Services, func(a, b baselineService) int { return strings.Compare(a.Service, b.Service) })
	for _, s := range r.Services {
		if s.Status != statusComplete {
			r.Status = statusIncomplete
		}
	}
	return r, nil
}

// finish makes the file of a report: the services that were seen, with
// those of other that were not asked for. A service that no process had
// is never written, and nothing is unless every service is complete or
// the caller allows it.
func (r *baselineReport) finish(other *shawkconnector.Baseline, allowIncomplete bool) error {
	if r.Status != statusComplete && !allowIncomplete {
		r.Refused = true
		return nil
	}
	out := &shawkconnector.Baseline{}
	asked := map[string]bool{}
	notes := map[string]string{}
	for _, s := range r.Services {
		if !s.known() {
			// Not written, and not taken out of the file to merge with
			// either: nothing was seen that could replace what it holds.
			continue
		}
		asked[s.Service] = true
		bs := shawkconnector.BaselineService{Service: s.Service, Dependencies: []shawkconnector.BaselineDependency{}}
		for _, d := range s.Dependencies {
			bd := shawkconnector.BaselineDependency{Peer: d.Peer, Port: d.Port, Proto: d.Proto, KernelChosen: d.KernelChosen && d.Port == 0}
			bs.Dependencies = append(bs.Dependencies, bd)
			if n := d.note(); n != "" {
				notes[fmt.Sprintf("%q %q %d %s %t", s.Service, bd.Peer, bd.Port, bd.Proto, bd.KernelChosen)] = n
			}
		}
		out.Services = append(out.Services, bs)
	}
	if other != nil {
		for _, s := range other.Services {
			if !asked[s.Service] {
				out.Services = append(out.Services, s)
				r.Kept++
			}
		}
	}
	// The services that have a baseline in PostgreSQL and none in the
	// file. The file leaves their dependencies to them, also what they do
	// in a unit of a service that it holds: without them it is not the
	// baseline that it was written for.
	inFile := map[string]bool{}
	for _, s := range out.Services {
		inFile[s.Service] = true
	}
	for _, s := range r.deployed {
		if !inFile[s] {
			r.Outside = append(r.Outside, s)
		}
	}
	slices.Sort(r.Outside)
	if len(out.Services) == 0 {
		// None of the services asked for was seen, and there is no file to
		// keep the others of: a file of no service, taken for the
		// baseline, would drop every baseline. Nothing is written, which
		// is not the answer of a history that is complete.
		r.Refused, r.Status = true, statusIncomplete
		return nil
	}
	out.Normalize()
	file, err := out.MarshalNotes(func(service string, d shawkconnector.BaselineDependency) string {
		return notes[fmt.Sprintf("%q %q %d %s %t", service, d.Peer, d.Port, d.Proto, d.KernelChosen)]
	})
	if err != nil {
		// A name that a baseline cannot hold, as one with control
		// characters that an agent made up.
		return fmt.Errorf("the baseline cannot be written: %w", err)
	}
	r.File = string(file)
	return nil
}

// lines returns what the report tells of the services, as lines without a
// line break in them: the period, and per service its status, with what
// the history does not tell, and the evidence of each dependency.
func (r *baselineReport) lines() []string {
	lines := []string{
		fmt.Sprintf("Period   %s to %s (%s)", formatTime(r.Since), formatTime(r.Until), formatDuration(r.Until.Sub(r.Since))),
	}
	if r.Merged != "" && !r.Refused {
		lines = append(lines, fmt.Sprintf("Merged   with %s, of which %s kept as they are", commentName(r.Merged),
			plural(r.Kept, "other service is", "other services are")))
	}
	for i := range r.Services {
		s := &r.Services[i]
		lines = append(lines, "", "Service  "+commentName(s.Service))
		switch {
		case !s.known():
			lines = append(lines, "Status   "+commentName(s.Status)+": not written")
		case s.Status == statusComplete:
			if len(s.Caveats) == 0 {
				lines = append(lines, fmt.Sprintf("Status   COMPLETE: %s observed for the whole period (coverage %s; 1 is all of the period)",
					plural(s.Hosts, "host that ran it was", "hosts that ran it were"), fraction(s.coverage)))
			} else {
				lines = append(lines,
					fmt.Sprintf("Status   COMPLETE by -min-coverage %s only: the least observed of the %s that ran it was observed",
						fraction(r.minCoverage), plural(s.Hosts, "host", "hosts")),
					fmt.Sprintf("         for %s of the period (1 is all of it). A dependency of the rest is missing here.",
						fraction(s.coverage)),
					"         Accepted as not observed:")
			}
		default:
			lines = append(lines,
				fmt.Sprintf("Status   %s: the history does not tell every dependency of the %s that ran it.", commentName(s.Status),
					plural(s.Hosts, "host", "hosts")),
				"         A dependency that is missing here is told as a drift when it is next used.",
				fmt.Sprintf("         (coverage of the least observed host %s, of the %s that -min-coverage asks for)",
					fraction(s.coverage), fraction(r.minCoverage)))
		}
		for _, code := range append(append([]string{}, s.Reasons...), s.Caveats...) {
			lines = append(lines, "         - "+describeShortfall(code, nil))
		}
		if len(s.ShortHosts) > 0 {
			lines = append(lines, "         not observed enough: "+commentNames(s.ShortHosts))
		}
		if !s.known() {
			continue
		}
		if len(s.Dependencies) == 0 {
			lines = append(lines, "  no connection of TCP or UDP was seen: the baseline approves none")
			continue
		}
		tb := newTable()
		tb.row("  PEER", "PORT", "HOSTS", "NAMED BY", "LAST SEEN", "ADDRESSES", "NOTES")
		for _, d := range s.Dependencies {
			tb.row("  "+commentName(d.Peer), d.port()+"/"+commentName(d.Proto), strconv.Itoa(len(d.Hosts)),
				commentName(d.NamedBy), formatTime(d.LastSeen), describeStrings(d.Addresses, 3), d.note())
		}
		lines = append(lines, tb.lines()...)
	}
	if r.Unnamed {
		lines = append(lines, "",
			"A process without a service name opened connections in the period (its telemetry has no",
			"service.name). A baseline cannot name it: it is not in the file, and nothing judges it.")
	}
	lines = append(lines, "",
		"A peer is a service by its name, as its agent or its listener tells it, a range of peer_cidrs,",
		"~unresolved (a private address that shawk cannot name) or ~external (a public address, or peers",
		"whose addresses the agent folded). Port 0 stands for every port, and kernel-chosen for the ports",
		"that the kernel chose for a server of the name, which change at each of its runs: for those and",
		"for no port that a server was given. A dependency that was not used",
		"in the period is not listed: one used less often than the period, or only when another server",
		"fails. Dependencies over Unix sockets are not part of a baseline. A process of another name in",
		"a unit of a service, which has no baseline of its own, is judged by the services of the unit:",
		"what it connected to is listed with the first of them. Units that unrelated processes share (the",
		"jobs of Slurm, login sessions) judge nothing. The last line of the file tells that it is whole:",
		"keep it last, and its counts right (or write `end: {}`).")
	return lines
}

// describeStrings lists strings that the database made, the first `most`.
func describeStrings(ss []string, most int) string {
	shown := ss
	if most > 0 && len(shown) > most {
		shown = shown[:most]
	}
	out := commentNames(shown)
	if n := len(ss) - len(shown); n > 0 {
		out += fmt.Sprintf(" and %d more", n)
	}
	return out
}

// text writes the report: the baseline file, with what the report tells
// as comments above it, or the report alone when the file is refused.
func (r *baselineReport) text() string {
	var b strings.Builder
	if r.Refused {
		for _, l := range r.lines() {
			b.WriteString(l + "\n")
		}
		if slices.ContainsFunc(r.Services, func(s baselineService) bool { return s.known() }) {
			b.WriteString("\nNo baseline is written from an incomplete history. -allow-incomplete writes it all the same,\n" +
				"marked as incomplete.\n")
		} else {
			b.WriteString("\nNo baseline is written: none of the services was seen in the period.\n")
		}
		return b.String()
	}
	if r.Status != statusComplete {
		comment(&b, "",
			"INCOMPLETE: written with -allow-incomplete from a history that does not tell every",
			"dependency of the services below. Read their status.", "")
	}
	comment(&b, "", "Baseline of dependencies, written by shawk-policy for review. The connector reads it once",
		"it is approved (baseline_file) and tells the dependencies of these services that are not here.", "")
	if n := len(r.Outside); n > 0 {
		// A part of a baseline, and no baseline: said first.
		lines := []string{"NOT A WHOLE BASELINE: written against the baseline that the connector holds, which has"}
		lines = append(lines, wrap(fmt.Sprintf("%s that %s not in this file (%s). What a service of this file and one of those do in the "+
			"same unit was left to the baseline of the other. Deployed alone, this file takes their baseline away, and what "+
			"they do becomes a drift of the services here (\"by NAME in its unit\"). Merge it into the baseline file of the "+
			"connector: the same command with -merge FILE writes that file with these services replaced.",
			plural(n, "service"), map[bool]string{true: "is", false: "are"}[n == 1], describeStrings(r.Outside, 5)), 92)...)
		comment(&b, "", append(lines, "")...)
	}
	comment(&b, "", r.lines()...)
	b.WriteString("\n" + r.File)
	return b.String()
}
