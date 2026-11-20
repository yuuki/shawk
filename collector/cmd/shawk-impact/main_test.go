package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseLookback(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90d":   90 * 24 * time.Hour,
		"12w":   12 * 7 * 24 * time.Hour,
		"1.5d":  36 * time.Hour,
		"36h":   36 * time.Hour,
		"1h30m": 90 * time.Minute,
		"90s":   90 * time.Second,
	} {
		if got, err := parseLookback(in); err != nil || got != want {
			t.Errorf("parseLookback(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "w", "90", "ninety days", "-1d", "0d", "0s", "500ms", "1e9d", "NaNd", "Infw", "40000d",
		"1d2h", "3 d"} {
		if got, err := parseLookback(in); err == nil {
			t.Errorf("parseLookback(%q) = %v, want an error", in, got)
		}
	}
}

func FuzzParseLookback(f *testing.F) {
	for _, s := range []string{"90d", "12w", "36h", "1.5d", "-1d", "1e400d", "NaNw", "d", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := parseLookback(s)
		if err == nil && (d < time.Second || d > maxLookback) {
			t.Errorf("parseLookback(%q) = %v, out of bounds", s, d)
		}
	})
}

func TestParseCoverage(t *testing.T) {
	for in, want := range map[string]string{
		"100":          "1.000000000000",
		"99.9":         "0.999000000000",
		"99.999":       "0.999990000000",
		"0.1":          "0.001000000000",
		"0.0000000001": "0.000000000001",
	} {
		if got, err := parseCoverage(in); err != nil || got != want {
			t.Errorf("parseCoverage(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "-1", "100.1", "101", "99%", "1/2", "1e2", "all", "0.00000000000001"} {
		if got, err := parseCoverage(in); err == nil {
			t.Errorf("parseCoverage(%q) = %q, want an error", in, got)
		}
	}
}

func FuzzParseCoverage(f *testing.F) {
	for _, s := range []string{"100", "99.9", "0.1", "0", "100.1", "1/2", "1e2", "-1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := parseCoverage(s)
		if err != nil {
			return
		}
		// What impact_verdict takes: a decimal above 0, up to 1.
		v, perr := strconv.ParseFloat(c, 64)
		if perr != nil || v <= 0 || v > 1 || strings.ContainsAny(c, "eE/") {
			t.Errorf("parseCoverage(%q) = %q", s, c)
		}
	})
}

// TestUsage: an invalid command line is refused before anything is read.
func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-service", "postgres"},
		{"-host", "db-01", "extra"},
		{"-host", "db-01", "-no-such-flag"},
		{"-host", "db-01", "-port", "70000"},
		{"-host", "db-01", "-port", "-1"},
		{"-host", "db-01", "-proto", "sctp"},
		{"-host", "db-01", "-proto", "unix", "-port", "5432"},
		{"-host", "db-01", "-depth", "0"},
		{"-host", "db-01", "-depth", "11"},
		{"-host", "db-01", "-limit", "-1"},
		{"-host", "db-01", "-timeout", "0"},
		{"-host", "db-01", "-lookback", "soon"},
		{"-host", "db-01", "-until", "yesterday"},
		{"-host", "db-01", "-min-coverage", "0"},
		{"-host", "db-01", "-min-coverage", "110"},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != exitUsage {
			t.Errorf("exit status of %v = %d, want %d", args, code, exitUsage)
		}
		if errOut.Len() == 0 || out.Len() != 0 {
			t.Errorf("%v: stdout %q, stderr %q; want the error on stderr", args, out.String(), errOut.String())
		}
	}
	// The usage does not print the connection string of the environment,
	// which may hold a password.
	t.Setenv("SHAWK_POSTGRES_DSN", "postgres://shawk:secret@db.invalid/shawk")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "Exit status") ||
		strings.Contains(errOut.String(), "secret") {
		t.Errorf("-h: exit status %d, %q", code, errOut.String())
	}
	// Without a connection string, a valid command line fails.
	t.Setenv("SHAWK_POSTGRES_DSN", "")
	errOut.Reset()
	if code := run(context.Background(), []string{"-host", "db-01"}, &out, &errOut); code != exitError {
		t.Errorf("exit status without a connection string = %d, want %d", code, exitError)
	}
	// A connection string that cannot be parsed is not printed: it may hold
	// a password.
	errOut.Reset()
	if code := run(context.Background(), []string{"-host", "db-01", "-dsn", "postgres://shawk:secret@db:port/shawk"}, &out, &errOut); code != exitError ||
		strings.Contains(errOut.String(), "secret") {
		t.Errorf("an invalid connection string: exit status %d, %q", code, errOut.String())
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                              "0s",
		400 * time.Millisecond:         "0s",
		45 * time.Second:               "45s",
		14 * time.Minute:               "14m",
		14*time.Minute + 5*time.Second: "14m5s",
		3*time.Hour + 28*time.Minute:   "3h28m",
		90 * 24 * time.Hour:            "90d",
		26 * time.Hour:                 "1d2h",
		24*time.Hour + 5*time.Minute:   "1d",
		71*time.Hour + 57*time.Minute:  "2d23h",
		-time.Hour:                     "0s",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestPercent(t *testing.T) {
	for in, want := range map[string]string{"100.000000": "100", "99.980000": "99.98", "0.000000": "0", "96.668200": "96.6682", "100": "100"} {
		if got := percent(in); got != want {
			t.Errorf("percent(%q) = %q, want %q", in, got, want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// testReport is a report of every kind of dependent.
func testReport() *report {
	until := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	seen := until.Add(-time.Minute)
	return &report{
		Target: target{Host: "db-01", Service: "postgres"}, Since: until.Add(-90 * 24 * time.Hour), Until: until,
		Verdict: verdictUnsafe, Reasons: []string{"active_dependents"}, Caveats: []string{"not_observed", "dropped_flows"},
		Direct: 4, Transitive: 1, Depth: 3, Coverage: 0.9998, MinCoverage: 1, coverage: "99.980000",
		Dependents: []dependent{
			{Depth: 1, ClientHost: ptr("app-01"), ClientService: "shop/app", ServerHost: "db-01", ServerService: ptr("postgres"),
				Port: 5432, Proto: "tcp", LastSeen: seen, ObservedBy: "both", Cadence: "continuous", Runs: 1},
			{Depth: 1, ClientHost: ptr("batch-01"), ClientService: "billing", ServerHost: "db-01", ServerService: ptr("postgres"),
				Port: 5432, Proto: "tcp", LastSeen: until.Add(-29 * 24 * time.Hour), ObservedBy: "both", Cadence: "monthly",
				PeriodSeconds: ptr(30 * 86400.0), NextExpected: ptr(until.Add(24 * time.Hour)), Runs: 3},
			{Depth: 1, ClientHost: ptr("nas-01"), ClientService: "~unresolved", ClientAddr: ptr("10.0.9.9"), ServerHost: "db-01",
				ServerService: ptr("postgres"), Port: 5432, Proto: "tcp", LastSeen: until.Add(-80 * 24 * time.Hour),
				ObservedBy: "server", Cadence: "one-off", Runs: 1},
			{Depth: 1, ClientHost: ptr("db-01"), ClientService: "backup", ServerHost: "db-01", ServerService: ptr("postgres"),
				Proto: "unix", LastSeen: until.Add(-48 * time.Hour), ObservedBy: "both", Cadence: "periodic",
				PeriodSeconds: ptr(6 * 3600.0), NextExpected: ptr(until.Add(-42 * time.Hour)), Runs: 300},
			{Depth: 2, ClientService: "~external", ClientAddr: ptr("0.0.0.0"), ServerHost: "app-01", Port: 0, Proto: "tcp",
				LastSeen: seen, ObservedBy: "server", Cadence: "unknown"},
		},
		Observers: []observer{
			{Host: "db-01", Role: "target", Agent: true, Observed: 0.9998, observed: "99.980000", UnobservedSeconds: 840, Gaps: 12,
				PartlyObservedSeconds: 32400, DroppedFlows: 7},
			{Host: "app-01", Role: "client", Agent: true, Observed: 1, observed: "100.000000"},
			{Host: "batch-01", Role: "client", Agent: true, Observed: 0.5, observed: "50.000000", UnobservedSeconds: 45 * 86400, Gaps: 1,
				UDPUntracedSeconds: 3600, UnixUntracedSeconds: 7200, NetnsLimitedSeconds: 60},
			{Host: "gone-01", Role: "client"},
		},
		Gaps: []gap{{until.Add(-30 * 24 * time.Hour), until.Add(-30*24*time.Hour + 7*time.Minute)}},
	}
}

// TestWriteText: the report for a person.
func TestWriteText(t *testing.T) {
	var out bytes.Buffer
	if err := writeText(&out, testReport(), 4); err != nil {
		t.Fatal(err)
	}
	want := `Target   db-01 (service postgres)
Period   2026-08-01T00:00:00Z to 2026-10-30T00:00:00Z (90d)

Verdict  UNSAFE: active dependents
         4 dependents used it in the period, and 1 more depends on them (to depth 3)
         The dependents below may not be all:
         - not observed for 14m of the period, in 12 gaps
         - its agent dropped flows for 9h (7 updates): dependencies active then may be missing

Not observed
  2026-09-30T00:00:00Z to 2026-09-30T00:07:00Z (7m)
  and 11 more gaps

Dependents
DEPTH  CLIENT                         SERVER          PORT      SEEN BY  CADENCE     LAST SEEN             NEXT ACTIVITY
1      app-01 shop/app                db-01 postgres  5432/tcp  both     continuous  2026-10-29T23:59:00Z  now
1      batch-01 billing               db-01 postgres  5432/tcp  both     monthly     2026-10-01T00:00:00Z  about 2026-10-31T00:00:00Z
1      10.0.9.9 (nas-01) ~unresolved  db-01 postgres  5432/tcp  server   one-off     2026-08-11T00:00:00Z  none expected
1      db-01 backup                   db-01 postgres  unix      both     every 6h    2026-10-28T00:00:00Z  overdue since 2026-10-28T06:00:00Z
and 1 more row (-limit 0 shows all)

Observation of the hosts that tell
HOST      ROLE    OBSERVED  NOT OBSERVED  GAPS  PARTLY OBSERVED  NO UDP  NO UNIX  ONE NETNS
db-01     target  99.98%    14m           12    9h               0s      0s       0s
batch-01  client  50%       45d           1     0s               1h      2h       1m
gone-01   client  no agent  -             -     -                -       -        -
and 1 client observed all along

Only TCP, UDP and Unix stream sockets are observed: a host used over RDMA, or less
often than the period, looks unused (docs/design.md, sections 6.3 and 10).
`
	if got := out.String(); got != want {
		t.Errorf("report:\n%s\nwant:\n%s", got, want)
	}

	// Every dependent, and the folded clients of a dependent on any port.
	out.Reset()
	if err := writeText(&out, testReport(), 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2      0.0.0.0 ~external              app-01 -        */tcp     server   unknown     2026-10-29T23:59:00Z  unknown\n") ||
		strings.Contains(out.String(), "more row") {
		t.Errorf("report without a limit:\n%s", out.String())
	}
}

// TestWriteVerdicts: what the report says of each verdict.
func TestWriteVerdicts(t *testing.T) {
	r := testReport()
	r.Verdict, r.Reasons, r.Caveats, r.Direct, r.Transitive, r.Dependents = verdictSafe, nil, nil, 0, 0, nil
	r.Coverage, r.coverage, r.Gaps = 1, "100.000000", nil
	r.Observers = []observer{{Host: "db-01", Role: "target", Agent: true, Observed: 1, observed: "100.000000"}}
	var out bytes.Buffer
	if err := writeText(&out, r, 50); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Verdict  SAFE\n         nothing used it in the period, and it was watched for 100% of it\n") ||
		strings.Contains(out.String(), "Dependents") {
		t.Errorf("a safe target:\n%s", out.String())
	}

	// Safe with a gap that the caller accepts.
	r.Caveats, r.MinCoverage, r.minCoverage, r.Coverage, r.coverage = []string{"not_observed"}, 0.999, "99.9000000000", 0.9998, "99.980000"
	r.Observers[0].UnobservedSeconds, r.Observers[0].Gaps = 840, 2
	out.Reset()
	if err := writeText(&out, r, 50); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "watched for 99.98% of it\n         Accepted with a coverage of 99.9% at least:\n"+
		"         - not observed for 14m of the period, in 2 gaps\n") {
		t.Errorf("a safe target with an accepted gap:\n%s", out.String())
	}

	for reason, want := range map[string]string{
		"unknown_host":    "no agent ever reported as db-01, and the inventory has no such host: check the name",
		"no_agent":        "db-01 runs no agent: its clients without an agent would not be seen",
		"unknown_service": "no process of db-01 had the service postgres in the period: check the name",
		"unknown_port":    "nothing listened on port 5432 of db-01 in the period: check the port",
		"udp_not_traced":  "its agent did not trace UDP for 1h",
		"unix_not_traced": "its agent did not trace Unix sockets, or did not tell, for 2h",
		"netns_limited":   "its agent traced one network namespace only for 1m",
		"a_new_reason":    "a_new_reason",
	} {
		r.Verdict, r.Reasons, r.Caveats, r.Target.Port = verdictInconclusive, []string{reason}, nil, 5432
		r.Observers = []observer{{Host: "db-01", Role: "target", UDPUntracedSeconds: 3600, UnixUntracedSeconds: 7200, NetnsLimitedSeconds: 60}}
		out.Reset()
		if err := writeText(&out, r, 50); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Verdict  INCONCLUSIVE: insufficient observation coverage\n"+
			"         nothing was seen to use it in the period, but it was not watched enough to tell\n         - "+want+"\n") {
			t.Errorf("%s:\n%s", reason, out.String())
		}
	}
}

// TestWriteJSON: the report as JSON has the names of the columns of the
// contract, and no null where a list is empty.
func TestWriteJSON(t *testing.T) {
	var out bytes.Buffer
	if err := writeJSON(&out, testReport()); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Target      target
		Verdict     string
		Reasons     []string
		Coverage    float64
		MinCoverage float64 `json:"min_coverage"`
		Dependents  []map[string]any
		Observers   []map[string]any
		Gaps        []gap `json:"target_gaps"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got.Target.Host != "db-01" || got.Target.Service != "postgres" || got.Verdict != verdictUnsafe ||
		len(got.Reasons) != 1 || got.Coverage != 0.9998 || got.MinCoverage != 1 || len(got.Dependents) != 5 ||
		len(got.Observers) != 4 || len(got.Gaps) != 1 {
		t.Errorf("report = %+v", got)
	}
	d := got.Dependents[1]
	if d["client_host"] != "batch-01" || d["cadence"] != "monthly" || d["period_seconds"] != 30*86400.0 ||
		d["next_expected"] != "2026-10-31T00:00:00Z" || d["client_addr"] != nil || d["port"] != 5432.0 {
		t.Errorf("dependent = %v", d)
	}
	if ob := got.Observers[2]; ob["host"] != "batch-01" || ob["role"] != "client" || ob["unobserved_seconds"] != 45*86400.0 ||
		ob["udp_untraced_seconds"] != 3600.0 {
		t.Errorf("observer = %v", ob)
	}
}

// TestPrintable: the names that agents send are written without their
// control characters, which could redraw the terminal.
func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"db-01":                   "db-01",
		"shop/app":                "shop/app",
		"データベース":                  "データベース",
		"a\x1b[2K\rVerdict  SAFE": `a\x1b[2K\rVerdict  SAFE`,
		"a\nb\tc":                 `a\nb\tc`,
		"x\u202ey":                `x\u202ey`,
		"":                        "",
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
	r := testReport()
	r.Dependents = r.Dependents[:1]
	r.Dependents[0].ClientService = "app\x1b[1A\x1b[2KVerdict  SAFE"
	r.Dependents[0].ClientHost = ptr("app-01\nVerdict  SAFE")
	r.Target.Host = "db-01\x1b[31m"
	var out bytes.Buffer
	if err := writeText(&out, r, 0); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), 0x1b) || strings.Contains(out.String(), "\nVerdict  SAFE") ||
		!strings.Contains(out.String(), `app-01\nVerdict  SAFE app\x1b[1A\x1b[2KVerdict  SAFE`) {
		t.Errorf("report:\n%q", out.String())
	}
}
