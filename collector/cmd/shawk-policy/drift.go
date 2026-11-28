package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"
)

const driftUsage = `shawk-policy drift tells the dependencies of the services of the baseline that the
baseline does not hold: what the connector alerts on, with the hosts and the
addresses, which Prometheus does not have.

Usage:
  shawk-policy drift [-service NAME ...] [flags]

The verdict is CLEAN when the services of the baseline, or those asked for, did
nothing that it does not hold, and the history tells so; DRIFT when one did; and
INCONCLUSIVE when no drift was seen but nothing tells that there was none: no
connector read a baseline, a service asked for has none, or a host of a service
was not observed for the whole period.

The period ends 5 minutes ago by default, when both sides of a new connection are
written: before that, a server may still be named ~unresolved.

Exit status: 0 CLEAN, and nothing else; 3 DRIFT; 4 INCONCLUSIVE; 1 when the
command fails; 2 when the command line is invalid, or asks for this help.

Flags:
`

// The verdicts of shawk-policy drift.
const (
	verdictClean        = "CLEAN"
	verdictDrift        = "DRIFT"
	verdictInconclusive = "INCONCLUSIVE"
)

// driftDelay is how long before now the period of a drift ends by default,
// as that of the connector (docs/design.md §5.9).
const driftDelay = 5 * time.Minute

// driftConfig is the command line of shawk-policy drift.
type driftConfig struct {
	common
	services names
	asJSON   bool
	limit    int
}

func parseDrift(args []string, stderr io.Writer) (*driftConfig, error) {
	fs := newFlagSet("drift", driftUsage, stderr)
	var c driftConfig
	c.flags(fs, "1h", false)
	fs.Var(&c.services, "service", "service to tell the drift of, as in PostgreSQL ([namespace/]name); may be given several times (default: every service of the baseline)")
	fs.BoolVar(&c.asJSON, "json", false, "write the report as JSON")
	fs.IntVar(&c.limit, "limit", 50, "dependencies to list in the text report; 0 for all")
	// The edges keep the times of their agents to the second: a minute
	// tells a drift.
	if err := c.parse(fs, args, time.Minute); err != nil {
		return nil, err
	}
	var err error
	switch {
	case slices.Contains(c.services, ""):
		// As of a script whose variable is empty, which would widen the
		// question to every service without a word.
		err = errors.New("-service must not be empty: leave it out for every service of the baseline")
	case c.limit < 0:
		err = errors.New("-limit must not be negative")
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	slices.Sort(c.services)
	c.services = slices.Compact(c.services)
	return &c, nil
}

// driftReport is what shawk-policy drift tells.
type driftReport struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`

	Verdict string `json:"verdict"`
	// Reasons tell why a verdict is INCONCLUSIVE: no_baseline (no
	// connector read one), unlocked_service (a service asked for has
	// none) and not_observed (a host of a service was not observed for the
	// whole period). Caveats tell the same where a drift was seen all the
	// same, and stale_baseline: the latest read of a baseline_file failed,
	// so the baseline is not that of the file.
	Reasons []string `json:"reasons"`
	Caveats []string `json:"caveats"`

	// Baseline is the state of the baseline in PostgreSQL, nil if no
	// connector ever read or failed to read one.
	Baseline *baselineState `json:"baseline"`
	// Services are those asked for, or all those of the baseline.
	Asked []string `json:"services"`
	// Unlocked are the services asked for that have no baseline.
	Unlocked []string `json:"unlocked_services"`
	// Drift are the dependencies that the baseline of their service does
	// not hold.
	Drift []dependency `json:"drift"`
	// NotObserved are the services judged of which a host was not observed
	// for the whole period, with the first of those hosts.
	NotObserved []baselineService `json:"not_observed"`
	// NewServices are the services without a baseline first seen in the
	// period: no baseline judges them. They are listed when no service is
	// asked for.
	NewServices []newService `json:"new_services"`
}

// baselineState is the row of shawk_v1.baseline_status.
type baselineState struct {
	ReadAt       *time.Time `json:"read_at"`
	FailedAt     *time.Time `json:"failed_at"`
	Error        *string    `json:"error"`
	Services     int64      `json:"services"`
	Dependencies int64      `json:"dependencies"`
}

// newService is a row of shawk_v1.baseline_new_services.
type newService struct {
	Service   string    `json:"service"`
	FirstSeen time.Time `json:"first_seen"`
	Hosts     []string  `json:"hosts"`
}

// runDrift runs shawk-policy drift and returns its exit status.
func runDrift(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	c, err := parseDrift(args, stderr)
	if err != nil {
		return exitUsage, err
	}
	var r *driftReport
	if err := c.query(ctx, driftDelay, func(ctx context.Context, tx pgx.Tx, since, until time.Time) error {
		r, err = readDrift(ctx, tx, c, since, until)
		return err
	}); err != nil {
		return exitError, err
	}
	if c.asJSON {
		err = writeJSON(stdout, r)
	} else {
		_, err = io.WriteString(stdout, r.text(c.limit))
	}
	if err != nil {
		return exitError, err
	}
	switch r.Verdict {
	case verdictClean:
		return exitComplete, nil
	case verdictDrift:
		return exitDrift, nil
	}
	return exitInconclusive, nil
}

// readDrift reads the drift of the services asked for, or of every
// service of the baseline, and what tells whether its absence means
// anything.
func readDrift(ctx context.Context, tx pgx.Tx, c *driftConfig, since, until time.Time) (*driftReport, error) {
	r := &driftReport{Since: since, Until: until, Reasons: []string{}, Caveats: []string{}, Asked: []string{}, Unlocked: []string{},
		Drift: []dependency{}, NotObserved: []baselineService{}, NewServices: []newService{}}
	var st baselineState
	switch err := tx.QueryRow(ctx, `SELECT read_at, failed_at, error, services, dependencies FROM shawk_v1.baseline_status`).
		Scan(&st.ReadAt, &st.FailedAt, &st.Error, &st.Services, &st.Dependencies); {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, fmt.Errorf("the state of the baseline: %w", err)
	default:
		r.Baseline = &st
	}
	var shortfalls []string
	if r.Baseline == nil || r.Baseline.ReadAt == nil {
		// Nothing is judged without a baseline: no drift is no answer.
		shortfalls = append(shortfalls, "no_baseline")
	} else if r.Baseline.FailedAt != nil {
		r.Caveats = append(r.Caveats, "stale_baseline")
	}

	rows, err := tx.Query(ctx, `SELECT DISTINCT service FROM shawk_v1.baseline`)
	if err != nil {
		return nil, fmt.Errorf("the baseline: %w", err)
	}
	locked, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("the baseline: %w", err)
	}
	slices.Sort(locked)
	var asked []string // NULL: every service of the baseline
	if len(c.services) > 0 {
		asked = c.services
		r.Asked = append(r.Asked, asked...)
		for _, s := range asked {
			if _, ok := slices.BinarySearch(locked, s); !ok {
				r.Unlocked = append(r.Unlocked, s)
			}
		}
		if len(r.Unlocked) > 0 {
			shortfalls = append(shortfalls, "unlocked_service")
		}
	} else {
		r.Asked = append(r.Asked, locked...)
	}

	rows, err = tx.Query(ctx, `SELECT `+dependencyColumns+` FROM shawk_v1.baseline_drift($1, $2, $3)`, since, until, asked)
	if err != nil {
		return nil, fmt.Errorf("the drift: %w", err)
	}
	if r.Drift, err = pgx.CollectRows(rows, scanDependency); err != nil {
		return nil, fmt.Errorf("the drift: %w", err)
	}
	slices.SortFunc(r.Drift, func(a, b dependency) int {
		return strings.Compare(a.Service+"\x00"+a.Peer, b.Service+"\x00"+b.Peer)
	})

	// The services judged whose hosts were not observed all along: what
	// they did then is not known. A service that no process had in the
	// period did nothing that was seen, and is left out.
	judged := slices.DeleteFunc(slices.Clone(r.Asked), func(s string) bool {
		_, ok := slices.BinarySearch(locked, s)
		return !ok
	})
	if len(judged) > 0 {
		rows, err = tx.Query(ctx, `
SELECT service, status, reasons, caveats, hosts, coverage::float8, coverage::text, short_hosts
FROM shawk_v1.baseline_verdict($1, $2, $3)
WHERE status <> 'COMPLETE' AND NOT 'unknown_service' = ANY (reasons)`, judged, since, until)
		if err != nil {
			return nil, fmt.Errorf("the observation of the services: %w", err)
		}
		if r.NotObserved, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (baselineService, error) {
			s := baselineService{Dependencies: []dependency{}}
			err := row.Scan(&s.Service, &s.Status, &s.Reasons, &s.Caveats, &s.Hosts, &s.Coverage, &s.coverage, &s.ShortHosts)
			return s, err
		}); err != nil {
			return nil, fmt.Errorf("the observation of the services: %w", err)
		}
		slices.SortFunc(r.NotObserved, func(a, b baselineService) int { return strings.Compare(a.Service, b.Service) })
		if len(r.NotObserved) > 0 {
			shortfalls = append(shortfalls, "not_observed")
		}
	}

	if len(c.services) == 0 && r.Baseline != nil && r.Baseline.ReadAt != nil {
		rows, err = tx.Query(ctx, `SELECT service, first_seen, hosts FROM shawk_v1.baseline_new_services($1, $2)`, since, until)
		if err != nil {
			return nil, fmt.Errorf("the new services: %w", err)
		}
		if r.NewServices, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (newService, error) {
			var n newService
			err := row.Scan(&n.Service, &n.FirstSeen, &n.Hosts)
			n.FirstSeen = n.FirstSeen.UTC()
			return n, err
		}); err != nil {
			return nil, fmt.Errorf("the new services: %w", err)
		}
	}

	switch {
	case len(r.Drift) > 0:
		// A drift is evidence whatever was not observed.
		r.Verdict = verdictDrift
		r.Caveats = append(r.Caveats, shortfalls...)
	case len(shortfalls) > 0:
		r.Verdict = verdictInconclusive
		r.Reasons = append(r.Reasons, shortfalls...)
	default:
		r.Verdict = verdictClean
	}
	return r, nil
}

// describeDriftShortfall tells a reason or a caveat of a drift in words.
func (r *driftReport) describeDriftShortfall(code string) string {
	switch code {
	case "no_baseline":
		return "no connector read a baseline (baseline_file): nothing is judged"
	case "stale_baseline":
		msg := "the latest read of a baseline_file failed: the baseline is the one read before"
		if r.Baseline != nil && r.Baseline.FailedAt != nil {
			msg += ", at " + formatTime(*r.Baseline.FailedAt)
			if r.Baseline.Error != nil {
				msg += " (" + commentName(*r.Baseline.Error) + ")"
			}
		}
		return msg
	case "unlocked_service":
		return "no baseline for " + commentNames(r.Unlocked) + ": not judged"
	case "not_observed":
		var parts []string
		for _, s := range r.NotObserved {
			part := commentName(s.Service)
			if len(s.ShortHosts) > 0 {
				part += " (" + describeStrings(s.ShortHosts, 3) + ")"
			}
			parts = append(parts, part)
		}
		return "hosts were not observed for the whole period, so what their services did then is not known: " +
			strings.Join(parts, "; ")
	}
	return commentName(code)
}

// text writes the report for a person.
func (r *driftReport) text(limit int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Period   %s to %s (%s)\n", formatTime(r.Since), formatTime(r.Until), formatDuration(r.Until.Sub(r.Since)))
	if st := r.Baseline; st != nil && st.ReadAt != nil {
		fmt.Fprintf(&b, "Baseline %s with %s, read %s\n", plural(int(st.Services), "service"),
			plural(int(st.Dependencies), "dependency", "dependencies"), formatTime(*st.ReadAt))
	}
	b.WriteString("\n")
	switch r.Verdict {
	case verdictDrift:
		fmt.Fprintf(&b, "Verdict  DRIFT: %s not in the baseline of %s\n", plural(len(r.Drift), "dependency is", "dependencies are"),
			pluralPossessive(countServices(r.Drift)))
	case verdictClean:
		fmt.Fprintf(&b, "Verdict  CLEAN: %s did nothing over TCP or UDP that the baseline does not hold\n",
			plural(len(r.Asked), "service", "services"))
	default:
		fmt.Fprintf(&b, "Verdict  %s: no drift was seen, but nothing tells that there was none\n", commentName(r.Verdict))
	}
	for _, code := range r.Reasons {
		fmt.Fprintf(&b, "         - %s\n", r.describeDriftShortfall(code))
	}
	if len(r.Caveats) > 0 && r.Verdict == verdictDrift {
		b.WriteString("         The drift below may not be all:\n")
	}
	for _, code := range r.Caveats {
		fmt.Fprintf(&b, "         - %s\n", r.describeDriftShortfall(code))
	}
	if len(r.Drift) > 0 {
		shown := r.Drift
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		b.WriteString("\nNot in the baseline\n")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SERVICE\tPEER\tPORT\tHOSTS\tNAMED BY\tFIRST SEEN\tLAST SEEN\tADDRESSES")
		for _, d := range shown {
			fmt.Fprintf(tw, "%s\t%s\t%d/%s\t%s\t%s\t%s\t%s\t%s\n", commentName(d.Service), commentName(d.Peer), d.Port, commentName(d.Proto),
				describeStrings(d.Hosts, 3), commentName(d.NamedBy), formatTime(d.FirstSeen), formatTime(d.LastSeen),
				describeStrings(d.Addresses, 3))
		}
		tw.Flush()
		if n := len(r.Drift) - len(shown); n > 0 {
			fmt.Fprintf(&b, "and %s (-limit 0 shows all)\n", plural(n, "more dependency", "more dependencies"))
		}
		b.WriteString("To approve one, add it to the baseline file of the connector, as\n")
		d := shown[0]
		fmt.Fprintf(&b, "  - {peer: %s, port: %d, proto: %s}    under service %s\n", commentName(d.Peer), d.Port, commentName(d.Proto),
			commentName(d.Service))
		b.WriteString("or write the service again: shawk-policy baseline -service NAME -merge FILE.\n")
		if slices.ContainsFunc(shown, func(d dependency) bool { return d.Peer == "~unresolved" }) {
			b.WriteString("~unresolved: a private address that shawk cannot name. It may be a server whose agent is\n" +
				"stopped and whose listener is not known, or one without an agent: see the addresses.\n")
		}
	}
	if len(r.NewServices) > 0 {
		shown := r.NewServices
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		b.WriteString("\nNew services without a baseline, which nothing judges\n")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SERVICE\tFIRST SEEN\tHOSTS")
		for _, n := range shown {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", commentName(n.Service), formatTime(n.FirstSeen), describeStrings(n.Hosts, 3))
		}
		tw.Flush()
		if n := len(r.NewServices) - len(shown); n > 0 {
			fmt.Fprintf(&b, "and %s (-limit 0 shows all)\n", plural(n, "more service"))
		}
		b.WriteString("A new executable, or a process that names itself anew, is a service of its own: the baseline\n" +
			"of the service it runs in does not judge it.\n")
	}
	b.WriteString("\nOnly TCP and UDP are judged, by the name of the server and its port: a server of the same name\n" +
		"at another address is no drift, and ~external does not tell one public address from another.\n")
	return b.String()
}

// countServices counts the services of dependencies.
func countServices(deps []dependency) int {
	seen := map[string]bool{}
	for _, d := range deps {
		seen[d.Service] = true
	}
	return len(seen)
}

// pluralPossessive is "1 service" or "n services".
func pluralPossessive(n int) string { return plural(n, "service") }
