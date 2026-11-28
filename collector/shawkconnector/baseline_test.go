package shawkconnector

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

const testBaseline = `
services:
  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~external, port: 443, proto: tcp}
      - {peer: resolver, port: 53, proto: udp}
      - {peer: shop/postgres, port: 5432, proto: tcp}
  - service: batch/report
    dependencies: []
`

// TestParseBaseline: a baseline is read in one form whatever the order of
// its file, and a service may be approved to have no dependency.
func TestParseBaseline(t *testing.T) {
	b, err := ParseBaseline([]byte(testBaseline))
	if err != nil {
		t.Fatal(err)
	}
	want := &Baseline{Services: []BaselineService{
		{Service: "batch/report", Dependencies: []BaselineDependency{}},
		{Service: "shop/app", Dependencies: []BaselineDependency{
			{"resolver", 53, "udp"}, {"shop/postgres", 5432, "tcp"}, {"~external", 443, "tcp"}}},
	}}
	if !reflect.DeepEqual(b, want) {
		t.Errorf("baseline = %+v, want %+v", b, want)
	}
	// JSON is YAML: a generator may write either.
	j, err := ParseBaseline([]byte(`{"services": [{"service": "batch/report", "dependencies": []},
	  {"service": "shop/app", "dependencies": [{"peer": "~external", "port": 443, "proto": "tcp"},
	    {"peer": "shop/postgres", "port": 5432, "proto": "tcp"}, {"peer": "resolver", "port": 53, "proto": "udp"}]}]}`))
	if err != nil || j.Digest() != b.Digest() {
		t.Errorf("the same baseline as JSON: %+v, %v", j, err)
	}
	// A baseline of no service is one, which drops every baseline.
	if e, err := ParseBaseline([]byte("services: []\n")); err != nil || len(e.Services) != 0 {
		t.Errorf("services: [] = %+v, %v", e, err)
	}
}

// TestParseBaselineInvalid: what would approve nothing, or something else
// than was written, without a word is refused.
func TestParseBaselineInvalid(t *testing.T) {
	for name, tc := range map[string]struct{ file, want string }{
		"empty":             {"", "no services"},
		"only a comment":    {"# none\n", "no services"},
		"no list":           {"services:\n", "no services"},
		"unknown field":     {"services: []\nservice: x\n", "field service not found"},
		"misspelt field":    {"services:\n  - service: a\n    depends: []\n", "field depends not found"},
		"no dependencies":   {"services:\n  - service: a\n", "no dependencies"},
		"null dependencies": {"services:\n  - service: a\n    dependencies:\n", "no dependencies"},
		"no service":        {"services:\n  - dependencies: []\n", "service: empty"},
		"twice":             {"services:\n  - {service: a, dependencies: []}\n  - {service: a, dependencies: []}\n", "listed twice"},
		"no peer":           {"services:\n  - service: a\n    dependencies: [{port: 1, proto: tcp}]\n", "peer: empty"},
		"no port":           {"services:\n  - service: a\n    dependencies: [{peer: b, proto: tcp}]\n", "no port"},
		"port":              {"services:\n  - service: a\n    dependencies: [{peer: b, port: 65536, proto: tcp}]\n", "not from 0 to 65535"},
		"negative port":     {"services:\n  - service: a\n    dependencies: [{peer: b, port: -1, proto: tcp}]\n", "not from 0 to 65535"},
		"proto":             {"services:\n  - service: a\n    dependencies: [{peer: b, port: 1, proto: unix}]\n", "not tcp or udp"},
		"no proto":          {"services:\n  - service: a\n    dependencies: [{peer: b, port: 1}]\n", "not tcp or udp"},
		"control character": {"services:\n  - service: \"a\\nb\"\n    dependencies: []\n", "control characters"},
		"long name":         {"services:\n  - service: " + strings.Repeat("a", maxPeerName+1) + "\n    dependencies: []\n", "longer than"},
		"two documents":     {"services: []\n---\nservices: []\n", "more than one YAML document"},
		"not a mapping":     {"- a\n", "cannot unmarshal"},
	} {
		_, err := ParseBaseline([]byte(tc.file))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one with %q", name, err, tc.want)
		}
	}
	var many strings.Builder
	many.WriteString("services:\n")
	for i := range MaxBaselineServices + 1 {
		many.WriteString("  - {service: s" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + ", dependencies: []}\n")
	}
	if _, err := ParseBaseline([]byte(many.String())); err == nil || !strings.Contains(err.Error(), "more than 10000 services") {
		t.Errorf("more services than the bound: %v", err)
	}
}

// TestBaselineMarshal: what Marshal writes is read back to the same
// baseline, a dependency per line, with the names that YAML would read as
// something else quoted.
func TestBaselineMarshal(t *testing.T) {
	b := &Baseline{Services: []BaselineService{
		{Service: "shop/app", Dependencies: []BaselineDependency{
			{"~external", 443, "tcp"}, {"shop/postgres", 5432, "tcp"}, {"null", 0, "udp"}, {"a: b", 1, "tcp"}, {"#x", 2, "tcp"}}},
		{Service: "~", Dependencies: []BaselineDependency{{"123", 80, "tcp"}, {" lead", 80, "tcp"}, {"'q\"", 80, "tcp"}}},
		{Service: "batch/report"},
	}}
	b.Normalize()
	out, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `services:
  - service: batch/report
    dependencies: []
  - service: shop/app
    dependencies:
      - {peer: '#x', port: 2, proto: tcp}
      - {peer: 'a: b', port: 1, proto: tcp}
      - {peer: "null", port: 0, proto: udp}
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~external, port: 443, proto: tcp}
  - service: "~"
    dependencies:
      - {peer: ' lead', port: 80, proto: tcp}
      - {peer: '''q"', port: 80, proto: tcp}
      - {peer: "123", port: 80, proto: tcp}
`
	if string(out) != want {
		t.Errorf("Marshal:\n%s\nwant:\n%s", out, want)
	}
	back, err := ParseBaseline(out)
	if err != nil || back.Digest() != b.Digest() {
		t.Errorf("read back: %+v, %v", back, err)
	}
	// Marshal refuses what ParseBaseline would.
	for _, bad := range []*Baseline{
		{Services: []BaselineService{{Service: ""}}},
		{Services: []BaselineService{{Service: "a"}, {Service: "a"}}},
		{Services: []BaselineService{{Service: "a", Dependencies: []BaselineDependency{{"b", 70000, "tcp"}}}}},
		{Services: []BaselineService{{Service: "a", Dependencies: []BaselineDependency{{"b\n", 1, "tcp"}}}}},
		{Services: []BaselineService{{Service: "a", Dependencies: []BaselineDependency{{"b", 1, "sctp"}}}}},
	} {
		if out, err := bad.Marshal(); err == nil {
			t.Errorf("Marshal(%+v) = %q, want an error", bad, out)
		}
	}
}

// baselineConnector returns a connector with a baseline_file of the given
// contents.
func baselineConnector(t *testing.T, contents string) (*shawkConnector, *fakeStore, func() []series, *time.Time, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	c, st, sink, now := testConnector(t, func(cfg *Config) { cfg.BaselineFile = path })
	out := func() []series {
		var out []series
		for _, md := range sink.AllMetrics() {
			out = append(out, flatten(md)...)
		}
		sink.Reset()
		return out
	}
	return c, st, out, now, path
}

// TestBaselineSync: the connector writes the baseline of its file, keeps
// the one written while the file is invalid, and records the failure.
func TestBaselineSync(t *testing.T) {
	c, st, _, now, path := baselineConnector(t, testBaseline)
	if st.baseline == nil || len(st.baseline.Services) != 2 || st.baselineSyncs != 1 || len(st.baselineFails) != 0 {
		t.Fatalf("baseline %+v, written %d times, failures %q", st.baseline, st.baselineSyncs, st.baselineFails)
	}
	first := st.baseline
	// An invalid file, as an edit that went wrong: the baseline stays.
	if err := os.WriteFile(path, []byte("services:\n  - service: shop/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	c.prepare(context.Background())
	if st.baseline != first || len(st.baselineFails) != 1 || !strings.Contains(st.baselineFails[0], "no dependencies") {
		t.Errorf("an invalid file replaced the baseline, or its failure is not recorded: %q", st.baselineFails)
	}
	// So does a file that is gone, or empty as a generator may leave it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if st.baseline != first || len(st.baselineFails) != 3 {
		t.Errorf("an empty or missing file replaced the baseline: %q", st.baselineFails)
	}
	if err := os.WriteFile(path, []byte("services: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if st.baseline == first || len(st.baseline.Services) != 0 {
		t.Errorf("the valid file is not read again: %+v", st.baseline)
	}
}

// TestBaselineUnset: without a baseline_file the connector leaves the
// baseline of other connectors, evaluates nothing and sends nothing.
func TestBaselineUnset(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	*now = now.Add(time.Hour)
	c.tick(context.Background())
	if st.baselineSyncs != 0 || len(st.baselineFails) != 0 || len(st.reports) != 0 || len(sink.AllMetrics()) != 0 {
		t.Errorf("written %d times, failures %q, evaluations %v, %d outputs", st.baselineSyncs, st.baselineFails, st.reports,
			len(sink.AllMetrics()))
	}
}

// baselineSeries returns the series of the metrics of the baseline as
// "metric{job,peer,port,transport} value", sorted.
func baselineSeries(out []series) []string {
	var got []string
	for _, s := range out {
		if !strings.HasPrefix(s.metric, "shawk.baseline.") {
			continue
		}
		labels := []string{s.job}
		if s.peer != "" {
			labels = append(labels, s.peer, itoa(s.port), s.transport)
		}
		got = append(got, s.metric+"{"+strings.Join(labels, ",")+"} "+itoa(int64(s.value)))
	}
	slices.Sort(got)
	return got
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TestBaselineMetrics: the drift is evaluated every five minutes over the
// last hour, up to five minutes ago, and sent every write interval, on a
// resource per service, without addresses or hosts.
func TestBaselineMetrics(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, testBaseline)
	st.report = &baselineReport{read: true,
		services: []baselineCount{{"batch/report", 0}, {"shop/app", 3}},
		drift: []driftRow{
			{"shop/app", "billing/api", 8443, "tcp", 12},
			{"shop/app", "~unresolved", 53, "udp", 1},
		},
		newServices: 2}
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	until := now.Add(-baselineDelay)
	if len(st.reports) != 1 || !st.reports[0][1].Equal(until) || !st.reports[0][0].Equal(until.Add(-baselineWindow)) {
		t.Fatalf("evaluated over %v, want the hour before %s", st.reports, until)
	}
	want := []string{
		"shawk.baseline.dependencies{batch/report} 0",
		"shawk.baseline.dependencies{shop/app} 3",
		"shawk.baseline.drift.hosts{shop/app,billing/api,8443,tcp} 12",
		"shawk.baseline.drift.hosts{shop/app,~unresolved,53,udp} 1",
		"shawk.baseline.drift.truncated{shawk-connector} 0",
		"shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(until.Unix()),
		"shawk.baseline.file.failed{shawk-connector} 0",
		"shawk.baseline.new_services{shawk-connector} 2",
	}
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("series:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The next interval sends the same result again, without evaluating.
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	if got := baselineSeries(out()); len(st.reports) != 1 || !slices.Equal(got, want) {
		t.Errorf("after a minute: %d evaluations, series %q", len(st.reports), got)
	}

	// Five minutes after the first, the next evaluation starts an hour
	// before the end of the last one, so that what was written late is
	// still judged.
	*now = now.Add(4 * time.Minute)
	st.report = &baselineReport{read: true, services: []baselineCount{{"shop/app", 4}}, failed: true, truncated: 7}
	c.tick(context.Background())
	if len(st.reports) != 2 || !st.reports[1][0].Equal(until.Add(-baselineWindow)) || !st.reports[1][1].Equal(now.Add(-baselineDelay)) {
		t.Errorf("second evaluation over %v", st.reports[len(st.reports)-1])
	}
	want = []string{
		"shawk.baseline.dependencies{shop/app} 4",
		"shawk.baseline.drift.truncated{shawk-connector} 7",
		"shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(now.Add(-baselineDelay).Unix()),
		"shawk.baseline.file.failed{shawk-connector} 1",
		"shawk.baseline.new_services{shawk-connector} 0",
	}
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("series:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestBaselineMetricsStale: while the evaluations fail, the last result is
// sent for a quarter of an hour, then only when it was made: a drift that
// is no longer known is not told, and neither is its absence.
func TestBaselineMetricsStale(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, testBaseline)
	st.report = &baselineReport{read: true, services: []baselineCount{{"shop/app", 3}},
		drift: []driftRow{{"shop/app", "billing/api", 8443, "tcp", 1}}}
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	evaluated := "shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(now.Add(-baselineDelay).Unix())
	if got := baselineSeries(out()); len(got) != 6 {
		t.Fatalf("series %q", got)
	}
	st.reportErr = errFake
	for range 14 {
		*now = now.Add(time.Minute)
		c.tick(context.Background())
	}
	if got := baselineSeries(out()); !slices.Contains(got, "shawk.baseline.drift.hosts{shop/app,billing/api,8443,tcp} 1") {
		t.Errorf("after 14 minutes of failures, series %q", got)
	}
	*now = now.Add(2 * time.Minute)
	c.tick(context.Background())
	want := []string{evaluated, "shawk.baseline.file.failed{shawk-connector} 0"}
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("after 16 minutes of failures, series %q, want %q", got, want)
	}
	// The evaluation that succeeds again covers the time of the failures.
	st.reportErr = nil
	*now = now.Add(5 * time.Minute)
	c.tick(context.Background())
	last := st.reports[len(st.reports)-1]
	if got := baselineSeries(out()); len(got) != 6 || last[1].Sub(last[0]) < baselineWindow+20*time.Minute {
		t.Errorf("after the failures: series %q, evaluated over %s", got, last[1].Sub(last[0]))
	}
	// After PostgreSQL was down for days, the period is bounded.
	st.reportErr = errFake
	*now = now.Add(72 * time.Hour)
	c.tick(context.Background())
	st.reportErr = nil
	*now = now.Add(5 * time.Minute)
	c.tick(context.Background())
	if last = st.reports[len(st.reports)-1]; last[1].Sub(last[0]) != maxBaselineLookback {
		t.Errorf("after days of failures, evaluated over %s, want %s", last[1].Sub(last[0]), maxBaselineLookback)
	}
}

// TestBaselineMetricsNeverRead: before a baseline was read from a valid
// file, nothing is judged; a failure to read the file is told all the
// same, so that it can be alerted on.
func TestBaselineMetricsNeverRead(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, "services:\n")
	if st.baseline != nil || len(st.baselineFails) != 1 {
		t.Fatalf("baseline %+v, failures %q", st.baseline, st.baselineFails)
	}
	st.report = &baselineReport{failed: true}
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	if got, want := baselineSeries(out()), []string{"shawk.baseline.file.failed{shawk-connector} 1"}; !slices.Equal(got, want) {
		t.Errorf("series %q, want %q", got, want)
	}
	// And nothing at all where no connector ever read one.
	st.report = &baselineReport{}
	*now = now.Add(5 * time.Minute)
	c.tick(context.Background())
	if got, want := baselineSeries(out()), []string{"shawk.baseline.file.failed{shawk-connector} 0"}; !slices.Equal(got, want) {
		t.Errorf("series %q, want %q", got, want)
	}
}

// TestBaselineMetricsBounded: the names of peers are cut as
// service.peer.name is, and two that are the same once cut are one series.
func TestBaselineMetricsBounded(t *testing.T) {
	long := strings.Repeat("p", maxPeerName)
	r := &baselineReport{read: true, services: []baselineCount{{"a", 0}},
		drift: []driftRow{{"a", long + "x", 80, "tcp", 2}, {"a", long + "y", 80, "tcp", 5}, {"b", "c", 1, "tcp", 1}}}
	md := pmetric.NewMetrics()
	now := t0
	appendBaselineMetrics(md, r, now, now, true)
	var got []string
	for _, s := range flatten(md) {
		if s.metric == metricBaselineDriftHosts {
			if len(s.peer) != maxPeerName {
				t.Errorf("peer of %d bytes", len(s.peer))
			}
			got = append(got, s.job+" "+itoa(s.port)+" "+itoa(int64(s.value)))
		}
	}
	// The drift of a service that is not in the baseline is not sent: the
	// contract returns none, and no resource would carry it.
	if want := []string{"a 80 5"}; !slices.Equal(got, want) {
		t.Errorf("drift series %q, want %q", got, want)
	}
	if md.DataPointCount() != 6 {
		t.Errorf("%d data points, want 6", md.DataPointCount())
	}
}

func TestConfigValidateBaselineSQLite(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "shawk.db")
	cfg.BaselineFile = "/etc/shawk/baseline.yaml"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "baseline_file is not supported with sqlite") {
		t.Errorf("Validate() = %v", err)
	}
}

// FuzzParseBaseline: any file is refused or read to a baseline that is
// valid, in the one form of Normalize, and that Marshal writes back to a
// file read to the same baseline.
func FuzzParseBaseline(f *testing.F) {
	f.Add([]byte(testBaseline))
	f.Add([]byte("services: []\n"))
	f.Add([]byte(`{"services": [{"service": "a", "dependencies": [{"peer": "~external", "port": 0, "proto": "udp"}]}]}`))
	f.Add([]byte("services:\n  - service: \"~\"\n    dependencies:\n      - {peer: 'null', port: 1, proto: tcp}\n      - {peer: \"a: b\", port: 1, proto: tcp}\n"))
	f.Add([]byte("services:\n  - &a {service: x, dependencies: []}\n  - *a\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseBaseline(data)
		if err != nil {
			return
		}
		if len(b.Services) > MaxBaselineServices || b.dependencies() > MaxBaselineDependencies {
			t.Fatalf("%d services and %d dependencies, beyond the bounds", len(b.Services), b.dependencies())
		}
		for i, s := range b.Services {
			if err := checkBaselineName(s.Service); err != nil {
				t.Fatalf("service %q: %v", s.Service, err)
			}
			if i > 0 && b.Services[i-1].Service >= s.Service {
				t.Fatalf("services %q and %q are not in order, or the same", b.Services[i-1].Service, s.Service)
			}
			for j, d := range s.Dependencies {
				if err := checkBaselineName(d.Peer); err != nil || d.Port < 0 || d.Port > 65535 || (d.Proto != "tcp" && d.Proto != "udp") {
					t.Fatalf("dependency %+v of %q: %v", d, s.Service, err)
				}
				if j > 0 && compareDependencies(s.Dependencies[j-1], d) >= 0 {
					t.Fatalf("dependencies %+v and %+v of %q are not in order, or the same", s.Dependencies[j-1], d, s.Service)
				}
			}
		}
		out, err := b.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		back, err := ParseBaseline(out)
		if err != nil {
			t.Fatalf("what Marshal wrote is not read back: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(back, b) {
			t.Fatalf("read back as %+v, want %+v\n%s", back, b, out)
		}
		again, err := back.Marshal()
		if err != nil || string(again) != string(out) {
			t.Fatalf("Marshal is not stable: %v\n%s\n%s", err, out, again)
		}
	})
}
