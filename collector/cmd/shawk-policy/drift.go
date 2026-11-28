package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yuuki/shawk/collector/shawkconnector"
)

const driftUsage = `shawk-policy drift tells the dependencies of the services of the baseline that the
baseline does not hold: what the connector alerts on, with the hosts and the
addresses, which Prometheus does not have.

Usage:
  shawk-policy drift [-service NAME ...] [flags]

The verdict is CLEAN when the services of the baseline, or those asked for, did
nothing that it does not hold, and the history tells so; DRIFT when one did; and
INCONCLUSIVE when no drift was seen but nothing tells that there was none: no
connector read a baseline, or it holds no service, a service asked for has none,
a host that runs a service was not observed for the whole period, or no host is
known to run a service or to have run it. A host runs a service when a process of
the service was seen on it within -hosts-lookback: a host whose agent went silent
counts as not observed until then, rather than as a host without the service. A
service that runs nowhere, on hosts that ran it before and are observed, did
nothing: that is CLEAN, with a note.

A process of another name in a unit of a workload, which has no baseline of its
own, is judged by the services of the baseline that run in the unit. A unit that
unrelated processes share (the jobs of Slurm, login sessions, transient units)
judges nothing: what is next to a baseline there is listed, and is no drift.

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
	// hostsLookback is how long before the end of the period a process of
	// a service was last seen on a host that still counts as running it.
	hostsLookback time.Duration
}

func parseDrift(args []string, stderr io.Writer) (*driftConfig, error) {
	fs := newFlagSet("drift", driftUsage, stderr)
	var c driftConfig
	c.flags(fs, "1h", false)
	fs.Var(&c.services, "service", "service to tell the drift of, as in PostgreSQL ([namespace/]name); may be given several times (default: every service of the baseline)")
	fs.BoolVar(&c.asJSON, "json", false, "write the report as JSON")
	fs.IntVar(&c.limit, "limit", 50, "dependencies to list in the text report; 0 for all")
	hosts := fs.String("hosts-lookback", "7d", "how long before the end of the period a process of a service was last seen on a host that still counts as running it, written as -lookback: a host that was not observed since counts as not observed (INCONCLUSIVE), not as gone")
	// The edges keep the times of their agents to the second: a minute
	// tells a drift.
	if err := c.parse(fs, args, time.Minute); err != nil {
		return nil, err
	}
	var err error
	if c.hostsLookback, err = parseLookback(*hosts, time.Minute); err != nil {
		return nil, fmt.Errorf("%w: -hosts-lookback: %w", errUsage, err)
	}
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
	// connector read one), empty_baseline (it holds no service),
	// unlocked_service (a service asked for has none), not_observed (a
	// host that runs a service was not observed for the whole period),
	// last_hosts_not_observed (no process of a service was seen since
	// HostsSince, and a host that ran it last was not observed: it may run
	// there) and no_host (no process of a service was ever seen on a host
	// that is known). Caveats tell the same where a drift was seen
	// all the same, and stale_baseline: the latest read of a
	// baseline_file failed, so the baseline is not that of the file.
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
	// HostsSince is since when a process of a service must have been seen
	// on a host for the host to run the service.
	HostsSince time.Time `json:"hosts_since"`
	// NotObserved are the services judged of which a host was not observed
	// for the whole period, with the first of those hosts, and those that
	// no host is known to run (reason unknown_service).
	NotObserved []baselineService `json:"not_observed"`
	// NotRunning are the services judged that run nowhere, on hosts that
	// ran them before and were observed: they did nothing, and nothing of
	// them was missed.
	NotRunning []string `json:"not_running"`
	// Unjudged are the dependencies of processes without a baseline in
	// units that unrelated processes share and in which services of the
	// baseline run: no drift, and listed, at most 100 of UnjudgedTotal.
	Unjudged      []unjudged `json:"unjudged"`
	UnjudgedTotal int64      `json:"unjudged_total"`
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

// unjudged is a row of shawk_v1.baseline_unjudged.
type unjudged struct {
	Unit      string    `json:"unit"`
	Process   string    `json:"process"`
	Peer      string    `json:"peer"`
	Proto     string    `json:"proto"`
	Ports     []int32   `json:"ports"`
	Hosts     []string  `json:"hosts"`
	Services  []string  `json:"services"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// maxUnjudged is how many rows of what is next to a baseline are read.
const maxUnjudged = 100

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
		Drift: []dependency{}, NotObserved: []baselineService{}, NewServices: []newService{}, NotRunning: []string{},
		Unjudged: []unjudged{}}
	// The rule of the connector: a period longer than -hosts-lookback
	// starts no later than the hosts are counted from.
	r.HostsSince = shawkconnector.BaselineHostsSince(since, until, c.hostsLookback)
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
	switch {
	case r.Baseline == nil || r.Baseline.ReadAt == nil:
		// Nothing is judged without a baseline: no drift is no answer.
		shortfalls = append(shortfalls, "no_baseline")
	case r.Baseline.Services == 0:
		// Nor with a baseline of no service.
		shortfalls = append(shortfalls, "empty_baseline")
	}
	if r.Baseline != nil && r.Baseline.ReadAt != nil && r.Baseline.FailedAt != nil {
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

	rows, err = tx.Query(ctx, `SELECT `+dependencyColumns+` FROM shawk_v1.baseline_drift($1, $2, $3, $4)`, since, until, asked,
		r.HostsSince)
	if err != nil {
		return nil, fmt.Errorf("the drift: %w", err)
	}
	if r.Drift, err = pgx.CollectRows(rows, scanDependency); err != nil {
		return nil, fmt.Errorf("the drift: %w", err)
	}
	sortDependencies(r.Drift)

	// The services judged whose hosts were not observed all along: what
	// they did then is not known. A host whose agent went silent, with
	// every process of it, still runs its services (HostsSince): it is not
	// observed, rather than out of the question. A service that no host is
	// known to run was not seen to do anything, and nothing was there to
	// see it either.
	judged := slices.DeleteFunc(slices.Clone(r.Asked), func(s string) bool {
		_, ok := slices.BinarySearch(locked, s)
		return !ok
	})
	if len(judged) > 0 {
		rows, err = tx.Query(ctx, `
SELECT service, status, reasons, caveats, hosts, coverage::float8, coverage::text, short_hosts, unobserved_hosts, short_seconds,
       idle_hosts
FROM shawk_v1.baseline_verdict($1, $2, $3, 1, make_interval(secs => $5), $4)
WHERE status <> 'COMPLETE' OR 'not_running' = ANY (caveats)`, judged, since, until, r.HostsSince, tolerance.Seconds())
		if err != nil {
			return nil, fmt.Errorf("the observation of the services: %w", err)
		}
		verdicts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (baselineService, error) {
			s := baselineService{Dependencies: []dependency{}}
			err := row.Scan(&s.Service, &s.Status, &s.Reasons, &s.Caveats, &s.Hosts, &s.Coverage, &s.coverage, &s.ShortHosts,
				&s.UnobservedHosts, &s.ShortSeconds, &s.IdleHosts)
			return s, err
		})
		if err != nil {
			return nil, fmt.Errorf("the observation of the services: %w", err)
		}
		slices.SortFunc(verdicts, func(a, b baselineService) int { return strings.Compare(a.Service, b.Service) })
		for _, s := range verdicts {
			if s.Status == statusComplete {
				r.NotRunning = append(r.NotRunning, s.Service)
			} else {
				r.NotObserved = append(r.NotObserved, s)
			}
		}
		if slices.ContainsFunc(r.NotObserved, func(s baselineService) bool { return s.known() && !s.lastHosts() }) {
			shortfalls = append(shortfalls, "not_observed")
		}
		if slices.ContainsFunc(r.NotObserved, func(s baselineService) bool { return s.lastHosts() }) {
			shortfalls = append(shortfalls, "last_hosts_not_observed")
		}
		if slices.ContainsFunc(r.NotObserved, func(s baselineService) bool { return !s.known() }) {
			shortfalls = append(shortfalls, "no_host")
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
		slices.SortFunc(r.NewServices, func(a, b newService) int { return strings.Compare(a.Service, b.Service) })
		rows, err = tx.Query(ctx, `
SELECT unit, process, peer, proto, ports, hosts, services, first_seen, last_seen, total
FROM shawk_v1.baseline_unjudged($1, $2, $3, $4)`, since, until, r.HostsSince, maxUnjudged)
		if err != nil {
			return nil, fmt.Errorf("what is next to the baseline: %w", err)
		}
		if r.Unjudged, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (unjudged, error) {
			var u unjudged
			err := row.Scan(&u.Unit, &u.Process, &u.Peer, &u.Proto, &u.Ports, &u.Hosts, &u.Services, &u.FirstSeen, &u.LastSeen,
				&r.UnjudgedTotal)
			u.FirstSeen, u.LastSeen = u.FirstSeen.UTC(), u.LastSeen.UTC()
			return u, err
		}); err != nil {
			return nil, fmt.Errorf("what is next to the baseline: %w", err)
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
	case "empty_baseline":
		return "the baseline holds no service: nothing is judged"
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
	case "not_observed", "last_hosts_not_observed":
		last := code == "last_hosts_not_observed"
		var parts []string
		for _, s := range r.NotObserved {
			if !s.known() || s.lastHosts() != last {
				continue
			}
			// Each host with how long it was not observed: a restart of 6
			// minutes is told as one, not as a host that is gone.
			var hosts []string
			for i, h := range s.ShortHosts {
				if i == 3 {
					hosts = append(hosts, fmt.Sprintf("and %d more", len(s.ShortHosts)-3))
					break
				}
				host := commentName(h)
				if i < len(s.ShortSeconds) {
					host += " for " + seconds(float64(s.ShortSeconds[i]))
				}
				hosts = append(hosts, host)
			}
			of := plural(s.Hosts, "host")
			if last {
				of = plural(s.IdleHosts, "host") + " that ran it last"
			}
			part := fmt.Sprintf("%s (%d of its %s: %s)", commentName(s.Service), s.UnobservedHosts, of, strings.Join(hosts, ", "))
			parts = append(parts, part)
		}
		observed := ". A host counts as observed for " + seconds(tolerance.Seconds()) +
			" after a report of its agent: a longer stretch without one, as a restart of the host, is not observed"
		if last {
			// The service was seen on no host since the memory began, and a
			// host that ran it last is silent: it may run there, and an
			// earlier run on a host that is observed tells nothing of it.
			return "no process of a service was seen since " + formatTime(r.HostsSince) + " (-hosts-lookback), and a host " +
				"that ran it last was not observed for the whole period: the service may run there still, so what it " +
				"did is not known: " + strings.Join(parts, "; ") + observed + ". If the host is gone for good, take the " +
				"service out of the baseline, or wait until another host runs it"
		}
		return "hosts that run a service were not observed for the whole period, so what the service did there is not " +
			"known: " + strings.Join(parts, "; ") + observed
	case "no_host":
		var names []string
		for _, s := range r.NotObserved {
			if !s.known() {
				names = append(names, s.Service)
			}
		}
		return "no host is known to run " + describeStrings(names, 5) + ": no process of it was ever seen on a host " +
			"that is still known, so nothing was there to see what it did. Check its name, or take it out of the baseline"
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
			plural(countServices(r.Drift), "service"))
	case verdictClean:
		fmt.Fprintf(&b, "Verdict  CLEAN: %s did nothing over TCP or UDP that the baseline does not hold, and every host\n"+
			"         that runs them was observed for the whole period\n",
			plural(len(r.Asked), "service", "services"))
		if n := len(r.NotRunning); n > 0 {
			rest := "no process of it was seen since %s, and the hosts that ran it last were observed, so it did nothing"
			if n > 1 {
				rest = "no process of them was seen since %s, and the hosts that ran them last were observed, so they did nothing"
			}
			for _, l := range wrap(fmt.Sprintf("%s nowhere now (%s): "+rest, plural(n, "service of the baseline runs",
				"services of the baseline run"), describeStrings(r.NotRunning, 5), formatTime(r.HostsSince)), 88) {
				b.WriteString("         " + l + "\n")
			}
		}
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
		tb := newTable()
		tb.row("SERVICE", "PEER", "PORT", "HOSTS", "NAMED BY", "FIRST SEEN", "LAST SEEN", "ADDRESSES", "NOTES")
		for _, d := range shown {
			tb.row(commentName(d.Service), commentName(d.Peer), d.port()+"/"+commentName(d.Proto),
				describeStrings(d.Hosts, 3), commentName(d.NamedBy), formatTime(d.FirstSeen), formatTime(d.LastSeen),
				describeStrings(d.Addresses, 3), d.note())
		}
		tb.writeTo(&b)
		if n := len(r.Drift) - len(shown); n > 0 {
			fmt.Fprintf(&b, "and %s (-limit 0 shows all)\n", plural(n, "more dependency", "more dependencies"))
		}
		b.WriteString("To approve one, add it to the baseline file of the connector, as\n")
		d := shown[0]
		fmt.Fprintf(&b, "  - {peer: %s, port: %s, proto: %s}    under service %s\n", commentName(d.Peer), d.port(), commentName(d.Proto),
			commentName(d.Service))
		b.WriteString("with the counts of the last line of the file (end:), or write the service again:\n" +
			"shawk-policy baseline -service NAME -merge FILE.\n")
		if slices.ContainsFunc(shown, func(d dependency) bool { return len(d.Processes) > 0 }) {
			b.WriteString("by NAME in its unit: a process of another name, without a baseline of its own, in a unit that\n" +
				"runs the service. The services of the baseline of the unit judge it together, and it is told\n" +
				"under the first of them: a name is what a process declares.\n")
		}
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
		tb := newTable()
		tb.row("SERVICE", "FIRST SEEN", "HOSTS")
		for _, n := range shown {
			tb.row(commentName(n.Service), formatTime(n.FirstSeen), describeStrings(n.Hosts, 3))
		}
		tb.writeTo(&b)
		if n := len(r.NewServices) - len(shown); n > 0 {
			fmt.Fprintf(&b, "and %s (-limit 0 shows all)\n", plural(n, "more service"))
		}
		b.WriteString("A new executable, or a process that names itself anew, is a service of its own. In a unit of a\n" +
			"workload that runs services of the baseline it is judged by them; anywhere else nothing judges it.\n")
	}
	if len(r.Unjudged) > 0 {
		shown := r.Unjudged
		if limit > 0 && len(shown) > limit {
			shown = shown[:limit]
		}
		b.WriteString("\nNext to the baseline, in units that unrelated processes share: not judged, and no drift\n")
		tb := newTable()
		tb.row("UNIT", "PROCESS", "PEER", "PORTS", "HOSTS", "LAST SEEN", "SERVICES OF THE BASELINE IN THE UNIT")
		for _, u := range shown {
			ports := make([]string, len(u.Ports))
			for i, p := range u.Ports {
				ports[i] = strconv.Itoa(int(p))
			}
			tb.row(commentName(u.Unit), commentName(u.Process), commentName(u.Peer), strings.Join(ports, ",")+"/"+commentName(u.Proto),
				describeStrings(u.Hosts, 3), formatTime(u.LastSeen), describeStrings(u.Services, 3))
		}
		tb.writeTo(&b)
		if n := int(r.UnjudgedTotal) - len(shown); n > 0 {
			fmt.Fprintf(&b, "and %s (shawk_v1.baseline_unjudged lists them)\n", plural(n, "more row"))
		}
		b.WriteString("The jobs of Slurm, login sessions and transient units hold the processes of many users: a baseline\n" +
			"of one of them says nothing of the others. To judge one of these processes, give its name a baseline.\n")
	}
	b.WriteString("\nOnly TCP and UDP are judged, by the name of the server and its port: a server of the same name\n" +
		"at another address is no drift, and ~external does not tell one public address from another.\n" +
		"A process is judged by the baseline of the name it declares, or, without one, by the services of\n" +
		"the baseline in its unit, unless the unit is one that unrelated processes share. A socket without\n" +
		"a known owner (~unknown), and a process that takes the name of another service of the baseline,\n" +
		"are not told apart from what that baseline approves.\n")
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
