package main

import (
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
	Hosts        int          `json:"hosts"`
	Coverage     float64      `json:"coverage"`
	ShortHosts   []string     `json:"short_hosts"`
	Dependencies []dependency `json:"dependencies"`

	coverage string
}

// known tells whether a process had the service in the period.
func (s *baselineService) known() bool { return !slices.Contains(s.Reasons, "unknown_service") }

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
}

const dependencyColumns = `service, peer, port, proto, first_seen, last_seen, hosts, ARRAY(SELECT host(a) || CASE
  WHEN masklen(a) < CASE family(a) WHEN 4 THEN 32 ELSE 128 END THEN '/' || masklen(a) ELSE '' END FROM unnest(addrs) AS a), named_by`

func scanDependency(row pgx.CollectableRow) (dependency, error) {
	var d dependency
	err := row.Scan(&d.Service, &d.Peer, &d.Port, &d.Proto, &d.FirstSeen, &d.LastSeen, &d.Hosts, &d.Addresses, &d.NamedBy)
	d.FirstSeen, d.LastSeen = d.FirstSeen.UTC(), d.LastSeen.UTC()
	return d, err
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
		r, err = readBaseline(ctx, tx, c, since, until)
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
// asked for.
func readBaseline(ctx context.Context, tx pgx.Tx, c *baselineConfig, since, until time.Time) (*baselineReport, error) {
	r := &baselineReport{Since: since, Until: until, Status: statusComplete, minCoverage: c.minCoverage, Services: []baselineService{}}
	var err error
	if r.MinCoverage, err = strconv.ParseFloat(c.minCoverage, 64); err != nil {
		return nil, err
	}
	var asked []string
	if !c.all {
		asked = c.services
	}
	rows, err := tx.Query(ctx, `SELECT `+dependencyColumns+` FROM shawk_v1.baseline_observed($1, $2, $3)`, since, until, asked)
	if err != nil {
		return nil, fmt.Errorf("the dependencies: %w", err)
	}
	deps, err := pgx.CollectRows(rows, scanDependency)
	if err != nil {
		return nil, fmt.Errorf("the dependencies: %w", err)
	}
	byService := map[string][]dependency{}
	for _, d := range deps {
		s := d.Service
		d.Service = ""
		byService[s] = append(byService[s], d)
	}
	if c.all {
		for s := range byService {
			asked = append(asked, s)
		}
		slices.Sort(asked)
	}
	rows, err = tx.Query(ctx, `
SELECT service, status, reasons, caveats, hosts, coverage::float8, coverage::text, short_hosts
FROM shawk_v1.baseline_verdict($1, $2, $3, $4::numeric)`, asked, since, until, c.minCoverage)
	if err != nil {
		return nil, fmt.Errorf("the verdicts: %w", err)
	}
	if r.Services, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (baselineService, error) {
		s := baselineService{Dependencies: []dependency{}}
		err := row.Scan(&s.Service, &s.Status, &s.Reasons, &s.Caveats, &s.Hosts, &s.Coverage, &s.coverage, &s.ShortHosts)
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
	for _, s := range r.Services {
		if !s.known() {
			// Not written, and not taken out of the file to merge with
			// either: nothing was seen that could replace what it holds.
			continue
		}
		asked[s.Service] = true
		bs := shawkconnector.BaselineService{Service: s.Service, Dependencies: []shawkconnector.BaselineDependency{}}
		for _, d := range s.Dependencies {
			bs.Dependencies = append(bs.Dependencies, shawkconnector.BaselineDependency{Peer: d.Peer, Port: d.Port, Proto: d.Proto})
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
	if len(out.Services) == 0 {
		// None of the services asked for was seen, and there is no file to
		// keep the others of: a file of no service, taken for the
		// baseline, would drop every baseline.
		r.Refused = true
		return nil
	}
	out.Normalize()
	file, err := out.Marshal()
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
			lines = append(lines, fmt.Sprintf("Status   COMPLETE: %s observed for the whole period (coverage %s; 1 is all of the period)",
				plural(s.Hosts, "host that ran it was", "hosts that ran it were"), fraction(s.coverage)))
			if len(s.Caveats) > 0 {
				lines = append(lines, fmt.Sprintf("         Accepted with -min-coverage %s:", fraction(r.minCoverage)))
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
		tb.row("  PEER", "PORT", "HOSTS", "NAMED BY", "LAST SEEN", "ADDRESSES")
		for _, d := range s.Dependencies {
			tb.row("  "+commentName(d.Peer), strconv.Itoa(d.Port)+"/"+commentName(d.Proto), strconv.Itoa(len(d.Hosts)),
				commentName(d.NamedBy), formatTime(d.LastSeen), describeStrings(d.Addresses, 3))
		}
		lines = append(lines, tb.lines()...)
	}
	lines = append(lines, "",
		"A peer is a service by its name, as its agent or its listener tells it, a range of peer_cidrs,",
		"~unresolved (a private address that shawk cannot name) or ~external (a public address, or peers",
		"whose addresses the agent folded). Port 0 stands for every port. A dependency that was not used",
		"in the period is not listed: one used less often than the period, or only when another server",
		"fails. Dependencies over Unix sockets are not part of a baseline.")
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
	comment(&b, "", r.lines()...)
	b.WriteString("\n" + r.File)
	return b.String()
}
