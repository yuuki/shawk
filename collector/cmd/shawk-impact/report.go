package main

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The verdicts of shawk_v1.impact_verdict.
const (
	verdictSafe         = "SAFE"
	verdictUnsafe       = "UNSAFE"
	verdictInconclusive = "INCONCLUSIVE"
)

// target is what would be removed: a host, or a service, a port or a
// transport of it.
type target struct {
	Host    string `json:"host"`
	Service string `json:"service,omitempty"`
	Port    int    `json:"port,omitempty"`
	Proto   string `json:"proto,omitempty"`
}

// args returns the target as the arguments of the functions of the
// contract: NULL for what does not narrow it.
func (t target) args() []any {
	var service, proto *string
	var port *int
	if t.Service != "" {
		service = &t.Service
	}
	if t.Port != 0 {
		port = &t.Port
	}
	if t.Proto != "" {
		proto = &t.Proto
	}
	return []any{t.Host, service, port, proto}
}

// report is what shawk-impact tells of a target over a period: the rows of
// shawk_v1.impact_verdict, impact and coverage.
type report struct {
	Target target    `json:"target"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`

	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
	Caveats []string `json:"caveats"`
	// Direct and Transitive count the dependents of depth 1 and of the
	// depths after, up to Depth.
	Direct     int64 `json:"direct"`
	Transitive int64 `json:"transitive"`
	Depth      int   `json:"depth"`
	// Coverage is the part of the period in which the target was watched,
	// from 0 to 1, and MinCoverage what a verdict of SAFE takes.
	Coverage    float64 `json:"coverage"`
	MinCoverage float64 `json:"min_coverage"`

	Dependents []dependent `json:"dependents"`
	// Observers are the target, first, and the hosts whose agents saw its
	// dependents.
	Observers []observer `json:"observers"`
	// Gaps are the periods in which the target was not observed, the
	// first maxGaps of them.
	Gaps []gap `json:"target_gaps"`

	// coverage is Coverage in percent as PostgreSQL writes it, which is
	// cut rather than rounded: 100 is a target watched all along.
	coverage string
}

// dependent is a row of shawk_v1.impact.
type dependent struct {
	Depth         int        `json:"depth"`
	ClientHost    *string    `json:"client_host"`
	ClientService string     `json:"client_service"`
	ClientAddr    *string    `json:"client_addr"`
	ServerHost    string     `json:"server_host"`
	ServerService *string    `json:"server_service"`
	Port          int        `json:"port"`
	Proto         string     `json:"proto"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`
	ObservedBy    string     `json:"observed_by"`
	Cadence       string     `json:"cadence"`
	PeriodSeconds *float64   `json:"period_seconds"`
	NextExpected  *time.Time `json:"next_expected"`
	Runs          int        `json:"runs"`
}

// observer is a row of shawk_v1.coverage.
type observer struct {
	Host                  string  `json:"host"`
	Role                  string  `json:"role"` // target or client
	Agent                 bool    `json:"agent"`
	Observed              float64 `json:"observed"`
	UnobservedSeconds     float64 `json:"unobserved_seconds"`
	Gaps                  int     `json:"gaps"`
	PartlyObservedSeconds float64 `json:"partly_observed_seconds"`
	DroppedFlows          int64   `json:"dropped_flows"`
	UDPUntracedSeconds    float64 `json:"udp_untraced_seconds"`
	UnixUntracedSeconds   float64 `json:"unix_untraced_seconds"`
	NetnsLimitedSeconds   float64 `json:"netns_limited_seconds"`

	observed string // Observed in percent, cut
}

// complete tells whether the agent of the host observed over the whole
// period, everything.
func (o *observer) complete() bool {
	return o.Agent && o.UnobservedSeconds == 0 && o.PartlyObservedSeconds == 0 && o.UDPUntracedSeconds == 0 &&
		o.UnixUntracedSeconds == 0 && o.NetnsLimitedSeconds == 0
}

// gap is a period in which the target was not observed.
type gap struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// maxGaps is how many gaps of the target a report lists.
const maxGaps = 10

// options are what a report is made with.
type options struct {
	target      target
	lookback    time.Duration
	until       time.Time // the clock of the database if zero
	depth       int
	minCoverage string // from 0 to 1, as a decimal
}

// build reads the report of a target in one read-only transaction, so that
// the verdict, the dependents and the coverage are of the same data.
func build(ctx context.Context, conn *pgx.Conn, o options) (*report, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	// Nothing was written: the end of the transaction changes nothing.
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // see above
	r := &report{Target: o.target, Until: o.until, Depth: o.depth}
	if r.Until.IsZero() {
		// The period ends at the clock of the database, which the
		// heartbeats of the agents are compared with: a clock ahead of it
		// would add time that nothing observed yet.
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&r.Until); err != nil {
			return nil, err
		}
	}
	r.Until = r.Until.UTC()
	r.Since = r.Until.Add(-o.lookback)
	if r.MinCoverage, err = strconv.ParseFloat(o.minCoverage, 64); err != nil {
		return nil, err
	}
	period := []any{r.Since, r.Until}
	t := o.target.args()
	if err := tx.QueryRow(ctx, `
SELECT verdict, reasons, caveats, direct, transitive, coverage::float8, (coverage * 100)::text
FROM shawk_v1.impact_verdict($1, $2, $3, $4, $5, $6, $7::numeric, $8)`,
		t[0], period[0], period[1], t[1], t[2], t[3], o.minCoverage, o.depth).
		Scan(&r.Verdict, &r.Reasons, &r.Caveats, &r.Direct, &r.Transitive, &r.Coverage, &r.coverage); err != nil {
		return nil, fmt.Errorf("the verdict: %w", err)
	}
	rows, err := tx.Query(ctx, `
SELECT depth, client_host, client_service, host(client_addr), server_host, server_service, port, proto,
       first_seen, last_seen, observed_by, cadence, extract(epoch FROM period)::float8, next_expected, runs
FROM shawk_v1.impact($1, $2, $3, $4, $5, $6, $7)`, t[0], period[0], period[1], t[1], t[2], t[3], o.depth)
	if err != nil {
		return nil, fmt.Errorf("the dependents: %w", err)
	}
	r.Dependents, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (dependent, error) {
		var d dependent
		err := row.Scan(&d.Depth, &d.ClientHost, &d.ClientService, &d.ClientAddr, &d.ServerHost, &d.ServerService, &d.Port,
			&d.Proto, &d.FirstSeen, &d.LastSeen, &d.ObservedBy, &d.Cadence, &d.PeriodSeconds, &d.NextExpected, &d.Runs)
		d.FirstSeen, d.LastSeen = d.FirstSeen.UTC(), d.LastSeen.UTC()
		if d.NextExpected != nil {
			next := d.NextExpected.UTC()
			d.NextExpected = &next
		}
		return d, err
	})
	if err != nil {
		return nil, fmt.Errorf("the dependents: %w", err)
	}

	// The hosts whose agents tell: the target, and the clients with an
	// agent among its dependents.
	hosts := []string{o.target.Host}
	for _, d := range r.Dependents {
		if d.ClientHost != nil && d.ObservedBy != "server" && !slices.Contains(hosts, *d.ClientHost) {
			hosts = append(hosts, *d.ClientHost)
		}
	}
	rows, err = tx.Query(ctx, `
SELECT host, agent, observed::float8, (observed * 100)::text, extract(epoch FROM unobserved)::float8, gaps,
       extract(epoch FROM partly_observed)::float8, dropped_flows, extract(epoch FROM udp_untraced)::float8,
       extract(epoch FROM unix_untraced)::float8, extract(epoch FROM netns_limited)::float8
FROM shawk_v1.coverage($1, $2, $3)`, period[0], period[1], hosts)
	if err != nil {
		return nil, fmt.Errorf("the coverage: %w", err)
	}
	r.Observers, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (observer, error) {
		ob := observer{Role: "client"}
		err := row.Scan(&ob.Host, &ob.Agent, &ob.Observed, &ob.observed, &ob.UnobservedSeconds, &ob.Gaps,
			&ob.PartlyObservedSeconds, &ob.DroppedFlows, &ob.UDPUntracedSeconds, &ob.UnixUntracedSeconds, &ob.NetnsLimitedSeconds)
		if ob.Host == o.target.Host {
			ob.Role = "target"
		}
		return ob, err
	})
	if err != nil {
		return nil, fmt.Errorf("the coverage: %w", err)
	}
	// The target first, then the hosts by name.
	slices.SortFunc(r.Observers, func(a, b observer) int {
		if (a.Role == "target") != (b.Role == "target") {
			if a.Role == "target" {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Host, b.Host)
	})

	rows, err = tx.Query(ctx, `
SELECT gap_start, gap_end FROM shawk_v1.unobserved_by_name($1, $2) WHERE host = $3 ORDER BY gap_start LIMIT $4`,
		period[0], period[1], o.target.Host, maxGaps)
	if err != nil {
		return nil, fmt.Errorf("the gaps: %w", err)
	}
	r.Gaps, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (gap, error) {
		var g gap
		err := row.Scan(&g.Start, &g.End)
		g.Start, g.End = g.Start.UTC(), g.End.UTC()
		return g, err
	})
	if err != nil {
		return nil, fmt.Errorf("the gaps: %w", err)
	}
	if r.Reasons == nil {
		r.Reasons = []string{}
	}
	if r.Caveats == nil {
		r.Caveats = []string{}
	}
	if r.Dependents == nil {
		r.Dependents = []dependent{}
	}
	if r.Gaps == nil {
		r.Gaps = []gap{}
	}
	return r, nil
}

// targetObserver returns the coverage of the target, nil if it has none.
func (r *report) targetObserver() *observer {
	for i := range r.Observers {
		if r.Observers[i].Role == "target" {
			return &r.Observers[i]
		}
	}
	return nil
}
