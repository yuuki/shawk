package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	// Gaps are the periods for which the history does not tell what the
	// target was used for, the first maxGaps of them.
	Gaps []gap `json:"target_gaps"`
	// CadenceDepth is the depth up to which the dependents have a cadence.
	CadenceDepth int `json:"cadence_depth"`
	// Incomplete tells what failed after the verdict was read: the lists
	// after it are missing, or cut short.
	Incomplete string `json:"incomplete,omitempty"`

	// coverage is Coverage as PostgreSQL writes it, which is cut rather
	// than rounded: 1 is a target watched all along. minCoverage is
	// MinCoverage as it was asked for.
	coverage, minCoverage string
}

// dependent is a row of shawk_v1.impact.
type dependent struct {
	Depth         int       `json:"depth"`
	ClientHost    *string   `json:"client_host"`
	ClientService string    `json:"client_service"`
	ClientAddr    *string   `json:"client_addr"`
	ServerHost    string    `json:"server_host"`
	ServerService *string   `json:"server_service"`
	Port          int       `json:"port"`
	Proto         string    `json:"proto"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	ObservedBy    string    `json:"observed_by"`
	// Relayed tells a client whose connections the server host relays in
	// its kernel (server_service ~relay), rather than one that a process
	// of the host serves.
	Relayed       bool       `json:"relayed"`
	Cadence       *string    `json:"cadence"`
	PeriodSeconds *float64   `json:"period_seconds"`
	NextExpected  *time.Time `json:"next_expected"`
	Runs          *int       `json:"runs"`
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
	// BeforeRetentionSeconds is the part of UnobservedSeconds before the
	// retention of the connector.
	BeforeRetentionSeconds float64 `json:"before_retention_seconds"`

	observed string // Observed as PostgreSQL writes it, cut
}

// complete tells whether the agent of the host observed over the whole
// period, everything.
func (o *observer) complete() bool {
	return o.Agent && o.UnobservedSeconds == 0 && o.PartlyObservedSeconds == 0 && o.UDPUntracedSeconds == 0 &&
		o.UnixUntracedSeconds == 0 && o.NetnsLimitedSeconds == 0
}

// gap is a period for which the history does not tell what the target was
// used for: before the retention of the connector (cause retention), or
// while no agent observed it (cause agent).
type gap struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Cause string    `json:"cause"`
}

// maxGaps is how many gaps of the target a report lists.
const maxGaps = 10

// options are what a report is made with.
type options struct {
	target   target
	lookback time.Duration
	until    time.Time // the clock of the database if zero
	depth    int
	// cadenceDepth is the depth up to which the cadences are read.
	cadenceDepth int
	minCoverage  string // from 0 to 1, as a decimal
	// timeout is how long a statement may take.
	timeout time.Duration
}

// coverageColumns are the columns of shawk_v1.coverage that scanObserver
// reads.
const coverageColumns = `host, agent, observed::float8, observed::text, extract(epoch FROM unobserved)::float8, gaps,
       extract(epoch FROM partly_observed)::float8, dropped_flows, extract(epoch FROM udp_untraced)::float8,
       extract(epoch FROM unix_untraced)::float8, extract(epoch FROM netns_limited)::float8,
       extract(epoch FROM before_retention)::float8`

func scanObserver(row pgx.CollectableRow) (observer, error) {
	ob := observer{Role: "client"}
	err := row.Scan(&ob.Host, &ob.Agent, &ob.Observed, &ob.observed, &ob.UnobservedSeconds, &ob.Gaps,
		&ob.PartlyObservedSeconds, &ob.DroppedFlows, &ob.UDPUntracedSeconds, &ob.UnixUntracedSeconds, &ob.NetnsLimitedSeconds,
		&ob.BeforeRetentionSeconds)
	return ob, err
}

// build reads the report of a target in one read-only transaction, so that
// the verdict, the dependents and the coverage are of the same data. The
// verdict and what explains it are read first: when what follows fails,
// as the dependents of a hub may after the time limit, build returns the
// report so far with the error.
func build(ctx context.Context, conn *pgx.Conn, o options) (*report, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	// Nothing was written: the end of the transaction changes nothing.
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // see above
	// The time limit of the role (30 seconds for shawk_grafana) is a
	// default for dashboards: a period of months over a large fleet takes
	// longer, and -timeout bounds it instead. It is set in the transaction
	// rather than at the connection, which a pooler may refuse.
	if o.timeout > 0 {
		if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`,
			strconv.FormatInt(o.timeout.Milliseconds(), 10)); err != nil {
			return nil, err
		}
	}
	r := &report{Target: o.target, Until: o.until, Depth: o.depth, CadenceDepth: o.cadenceDepth, minCoverage: o.minCoverage,
		Reasons: []string{}, Caveats: []string{}, Dependents: []dependent{}, Observers: []observer{}, Gaps: []gap{}}
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
	var reasons, caveats []string
	if err := tx.QueryRow(ctx, `
SELECT verdict, reasons, caveats, direct, coverage::float8, coverage::text
FROM shawk_v1.impact_verdict($1, $2, $3, $4, $5, $6, $7::numeric)`,
		t[0], period[0], period[1], t[1], t[2], t[3], o.minCoverage).
		Scan(&r.Verdict, &reasons, &caveats, &r.Direct, &r.Coverage, &r.coverage); err != nil {
		// A database without the schema, or with one older than the
		// functions of the impact: nothing to give a verdict from.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "42883" || pgErr.Code == "3F000") {
			return nil, fmt.Errorf("the database has no shawk_v1.impact_verdict(): the impact report needs the PostgreSQL schema of "+
				"shawk, migrated by shawk-migrate up to 0005_impact.sql (the SQLite lightweight mode has none): %s", pgErr.Message)
		}
		return nil, fmt.Errorf("the verdict: %w", err)
	}
	r.Reasons, r.Caveats = append(r.Reasons, reasons...), append(r.Caveats, caveats...)

	// How the target was observed, which is quick to read.
	rows, err := tx.Query(ctx, `SELECT `+coverageColumns+` FROM shawk_v1.coverage($1, $2, $3)`, period[0], period[1], []string{o.target.Host})
	if err != nil {
		return r, fmt.Errorf("the coverage of the target: %w", err)
	}
	if r.Observers, err = pgx.CollectRows(rows, scanObserver); err != nil {
		return r, fmt.Errorf("the coverage of the target: %w", err)
	}
	for i := range r.Observers {
		r.Observers[i].Role = "target"
	}
	rows, err = tx.Query(ctx, `
SELECT gap_start, gap_end, cause FROM shawk_v1.coverage_gaps($1, $2, $3) ORDER BY gap_start LIMIT $4`,
		period[0], period[1], []string{o.target.Host}, maxGaps)
	if err != nil {
		return r, fmt.Errorf("the gaps: %w", err)
	}
	gaps, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (gap, error) {
		var g gap
		err := row.Scan(&g.Start, &g.End, &g.Cause)
		g.Start, g.End = g.Start.UTC(), g.End.UTC()
		return g, err
	})
	if err != nil {
		return r, fmt.Errorf("the gaps: %w", err)
	}
	r.Gaps = append(r.Gaps, gaps...)

	rows, err = tx.Query(ctx, `
SELECT depth, client_host, client_service, host(client_addr), server_host, server_service, port, proto,
       first_seen, last_seen, observed_by, cadence, extract(epoch FROM period)::float8, next_expected, runs
FROM shawk_v1.impact($1, $2, $3, $4, $5, $6, $7, $8)`, t[0], period[0], period[1], t[1], t[2], t[3], o.depth, o.cadenceDepth)
	if err != nil {
		return r, fmt.Errorf("the dependents: %w", err)
	}
	dependents, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dependent, error) {
		var d dependent
		err := row.Scan(&d.Depth, &d.ClientHost, &d.ClientService, &d.ClientAddr, &d.ServerHost, &d.ServerService, &d.Port,
			&d.Proto, &d.FirstSeen, &d.LastSeen, &d.ObservedBy, &d.Cadence, &d.PeriodSeconds, &d.NextExpected, &d.Runs)
		d.FirstSeen, d.LastSeen = d.FirstSeen.UTC(), d.LastSeen.UTC()
		d.Relayed = d.ServerService != nil && *d.ServerService == "~relay"
		if d.NextExpected != nil {
			next := d.NextExpected.UTC()
			d.NextExpected = &next
		}
		return d, err
	})
	if err != nil {
		return r, fmt.Errorf("the dependents: %w", err)
	}
	r.Dependents = append(r.Dependents, dependents...)
	// The dependents of the depths after the first: each client once.
	type client struct{ host, service, addr string }
	deeper := map[client]struct{}{}
	for _, d := range r.Dependents {
		if d.Depth > 1 {
			c := client{service: d.ClientService}
			if d.ClientHost != nil {
				c.host = *d.ClientHost
			}
			if d.ClientAddr != nil {
				c.addr = *d.ClientAddr
			}
			deeper[c] = struct{}{}
		}
	}
	r.Transitive = int64(len(deeper))

	// The other hosts whose agents tell: the clients with an agent among
	// the dependents, by name.
	var hosts []string
	for _, d := range r.Dependents {
		if d.ClientHost != nil && d.ObservedBy != "server" && *d.ClientHost != o.target.Host && !slices.Contains(hosts, *d.ClientHost) {
			hosts = append(hosts, *d.ClientHost)
		}
	}
	if len(hosts) == 0 {
		return r, nil
	}
	// By bytes, as the dependents are (shawk_v1.impact): the collation of
	// the database does not change the report.
	rows, err = tx.Query(ctx, `SELECT `+coverageColumns+` FROM shawk_v1.coverage($1, $2, $3) ORDER BY host COLLATE "C"`,
		period[0], period[1], hosts)
	if err != nil {
		return r, fmt.Errorf("the coverage of the clients: %w", err)
	}
	clients, err := pgx.CollectRows(rows, scanObserver)
	if err != nil {
		return r, fmt.Errorf("the coverage of the clients: %w", err)
	}
	r.Observers = append(r.Observers, clients...)
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
