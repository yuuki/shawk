package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/shawk/collector/shawkconnector"
)

// testBaselineReport returns the report of services with a dependency
// each, over the 90 days before testUntil.
func testBaselineReport(services ...baselineService) *baselineReport {
	r := &baselineReport{Since: testUntil.Add(-90 * 24 * time.Hour), Until: testUntil, Status: statusComplete, MinCoverage: 1,
		minCoverage: "1.000000000000", Services: services}
	for i := range r.Services {
		s := &r.Services[i]
		if s.Status == "" {
			s.Status, s.Hosts, s.Coverage, s.coverage = statusComplete, 2, 1, "1.000000"
		}
		if s.Status != statusComplete {
			r.Status = statusIncomplete
		}
	}
	return r
}

func testDependency(peer string, port int, proto string) dependency {
	return dependency{Peer: peer, Port: port, Proto: proto, FirstSeen: testUntil.Add(-80 * 24 * time.Hour), LastSeen: testUntil,
		Hosts: []string{"app-01", "app-02"}, Addresses: []string{"10.0.0.10"}, NamedBy: "edge"}
}

// TestBaselineFile: the file of a report holds the services that were
// seen, in one order, with those of the file it is merged with that were
// not asked for; a service that no process had is not written, and not
// taken out of that file either.
func TestBaselineFile(t *testing.T) {
	other, err := shawkconnector.ParseBaseline([]byte(`
services:
  - service: shop/app
    dependencies: [{peer: old, port: 1, proto: tcp}]
  - service: kept
    dependencies: []
  - service: gone
    dependencies: [{peer: stays, port: 2, proto: udp}]
end: {services: 3, dependencies: 2}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := testBaselineReport(
		baselineService{Service: "shop/app", Dependencies: []dependency{testDependency("shop/postgres", 5432, "tcp"),
			testDependency("~external", 443, "tcp")}},
		baselineService{Service: "idle", Dependencies: []dependency{}},
		baselineService{Service: "gone", Status: statusIncomplete, Reasons: []string{"unknown_service"}, Dependencies: []dependency{}})
	if err := r.finish(other, false); err != nil || !r.Refused || r.File != "" {
		t.Fatalf("an incomplete report: refused %t, file %q, %v", r.Refused, r.File, err)
	}
	r.Refused = false
	if err := r.finish(other, true); err != nil || r.Refused || r.Kept != 2 {
		t.Fatalf("with -allow-incomplete: refused %t, kept %d, %v", r.Refused, r.Kept, err)
	}
	want := `services:
  - service: gone
    dependencies:
      - {peer: stays, port: 2, proto: udp}
  - service: idle
    dependencies: []
  - service: kept
    dependencies: []
  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~external, port: 443, proto: tcp}
end: {services: 4, dependencies: 3}
`
	if r.File != want {
		t.Errorf("file:\n%s\nwant:\n%s", r.File, want)
	}
	// The text is the file under what the report tells, as comments.
	text := r.text()
	if !strings.HasPrefix(text, "# INCOMPLETE: written with -allow-incomplete") || !strings.HasSuffix(text, "\n\n"+want) ||
		!strings.Contains(text, "# Service  gone\n# Status   INCOMPLETE: not written\n#          - no process of this service was seen on any host: check the name\n") ||
		!strings.Contains(text, "# Service  idle\n# Status   COMPLETE: 2 hosts that ran it were observed for the whole period (coverage 1; 1 is all of the period)\n"+
			"#   no connection of TCP or UDP was seen: the baseline approves none\n") {
		t.Errorf("text:\n%s", text)
	}
	// None of the services was seen, and no file holds others: nothing is
	// written, since a file of no service would drop every baseline.
	r = testBaselineReport(baselineService{Service: "gone", Status: statusIncomplete, Reasons: []string{"unknown_service"}})
	if err := r.finish(nil, true); err != nil || !r.Refused || r.File != "" ||
		!strings.HasSuffix(r.text(), "\nNo baseline is written: none of the services was seen in the period.\n") {
		t.Errorf("a report of services that were not seen: refused %t, file %q, %v\n%s", r.Refused, r.File, err, r.text())
	}
}

// FuzzBaselineText: whatever the names of services, peers and hosts hold,
// the text of a baseline is comments, then a file that the connector reads
// to the dependencies of the report.
func FuzzBaselineText(f *testing.F) {
	for _, s := range hostile {
		f.Add(s, s, uint16(443), true)
	}
	f.Add("shop/app", "shop/postgres", uint16(5432), false)
	f.Fuzz(func(t *testing.T, service, peer string, port uint16, udp bool) {
		proto := "tcp"
		if udp {
			proto = "udp"
		}
		d := testDependency(peer, int(port), proto)
		d.Hosts, d.Addresses, d.NamedBy = []string{peer, service}, []string{service}, peer
		r := testBaselineReport(baselineService{Service: service, Dependencies: []dependency{d}, ShortHosts: []string{peer},
			Reasons: []string{peer}, Caveats: []string{service}})
		r.Merged = service
		want := &shawkconnector.Baseline{Services: []shawkconnector.BaselineService{{Service: service,
			Dependencies: []shawkconnector.BaselineDependency{{Peer: peer, Port: int(port), Proto: proto}}}}}
		if _, err := want.Marshal(); err != nil {
			// A name that no baseline holds: the command fails, and writes
			// no file.
			if err := r.finish(nil, false); err == nil {
				t.Fatalf("a baseline of %q and %q is written: %q", service, peer, r.File)
			}
			return
		}
		if err := r.finish(nil, false); err != nil {
			t.Fatal(err)
		}
		text := r.text()
		head, file, ok := strings.Cut(text, "\n\nservices:\n")
		if !ok {
			t.Fatalf("no file in\n%s", text)
		}
		for _, l := range strings.Split(head, "\n") {
			if !oneCommentLine(l) {
				t.Fatalf("the line %q above the file is no comment\n%s", l, text)
			}
		}
		for _, in := range []string{text, "services:\n" + file} {
			got, err := shawkconnector.ParseBaseline([]byte(in))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("read back as %+v, %v; want %+v\n%s", got, err, want, in)
			}
		}
	})
}

// FuzzDriftText: whatever the names hold, the report of a drift has no
// control character, and each row of its tables is one line.
func FuzzDriftText(f *testing.F) {
	for _, s := range hostile {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, service, peer string) {
		d := testDependency(peer, 443, "tcp")
		d.Service, d.Hosts, d.Addresses, d.NamedBy = service, []string{peer, service}, []string{service}, peer
		at := testUntil
		r := &driftReport{Since: testUntil.Add(-time.Hour), Until: testUntil, Verdict: verdictDrift, Reasons: []string{peer},
			Caveats:  []string{"stale_baseline", "unlocked_service", "not_observed", service},
			Baseline: &baselineState{ReadAt: &at, FailedAt: &at, Error: &peer, Services: 1, Dependencies: 1},
			Asked:    []string{service}, Unlocked: []string{service, peer}, Drift: []dependency{d},
			NotObserved: []baselineService{{Service: service, ShortHosts: []string{peer}}},
			NewServices: []newService{{Service: peer, FirstSeen: at, Hosts: []string{service}}}}
		text := r.text(0)
		for _, c := range text {
			if c != '\n' && (c < ' ' || c == 0x7f || c == 0x85 || c == 0x2028 || c == 0x2029 || c == 0x1b) {
				t.Fatalf("the report holds the control character %q\n%q", c, text)
			}
		}
		// The table of the drift has its header, one row, and then the line
		// that tells how to approve.
		_, table, _ := strings.Cut(text, "\nNot in the baseline\n")
		if lines := strings.Split(table, "\n"); len(lines) < 3 || !strings.HasPrefix(lines[0], "SERVICE") ||
			!strings.HasPrefix(lines[2], "To approve one, add it to the baseline file of the connector, as") {
			t.Fatalf("the table of the drift:\n%s", table)
		}
	})
}
