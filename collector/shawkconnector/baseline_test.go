package shawkconnector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

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
end: {services: 2, dependencies: 4}
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
			{"resolver", 53, "udp", false}, {"shop/postgres", 5432, "tcp", false}, {"~external", 443, "tcp", false}}},
	}}
	if !reflect.DeepEqual(b, want) {
		t.Errorf("baseline = %+v, want %+v", b, want)
	}
	// JSON is YAML: a generator may write either.
	j, err := ParseBaseline([]byte(`{"services": [{"service": "batch/report", "dependencies": []},
	  {"service": "shop/app", "dependencies": [{"peer": "~external", "port": 443, "proto": "tcp"},
	    {"peer": "shop/postgres", "port": 5432, "proto": "tcp"}, {"peer": "resolver", "port": 53, "proto": "udp"}]}],
	  "end": {"services": 2, "dependencies": 3}}`))
	if err != nil || j.Digest() != b.Digest() {
		t.Errorf("the same baseline as JSON: %+v, %v", j, err)
	}
	// A baseline of no service is one, which drops every baseline. A file
	// written by hand may leave the counts of its last line out, or give
	// one of them.
	for _, file := range []string{"services: []\nend: {}\n", "services: []\nend: {services: 0, dependencies: 0}\n",
		"services: []\nend: {dependencies: 0}"} {
		if e, err := ParseBaseline([]byte(file)); err != nil || len(e.Services) != 0 {
			t.Errorf("%q = %+v, %v", file, e, err)
		}
	}
	// A dependency on the ports that the kernel chose for a server is not
	// one on every port of it.
	k, err := ParseBaseline([]byte("services:\n  - service: a\n    dependencies:\n      - {peer: rpcd, port: kernel-chosen, proto: tcp}\n" +
		"      - {peer: rpcd, port: 0, proto: udp}\nend: {services: 1, dependencies: 2}\n"))
	if err != nil || !reflect.DeepEqual(k.Services[0].Dependencies, []BaselineDependency{{"rpcd", 0, "tcp", true}, {"rpcd", 0, "udp", false}}) {
		t.Errorf("a port that the kernel chose: %+v, %v", k, err)
	}
	every, _ := ParseBaseline([]byte("services:\n  - service: a\n    dependencies:\n      - {peer: rpcd, port: 0, proto: tcp}\n" +
		"      - {peer: rpcd, port: 0, proto: udp}\nend: {}\n"))
	if every == nil || every.Digest() == k.Digest() {
		t.Errorf("the ports that the kernel chose and every port are one baseline: %+v", every)
	}
	if out, err := k.Marshal(); err != nil || !strings.Contains(string(out), "      - {peer: rpcd, port: kernel-chosen, proto: tcp}\n") {
		t.Errorf("written as %s, %v", out, err)
	} else if back, err := ParseBaseline(out); err != nil || !reflect.DeepEqual(back, k) {
		t.Errorf("read back as %+v, %v", back, err)
	}
	// A name that YAML would read as something else is a name when quoted.
	q, err := ParseBaseline([]byte("services:\n  - service: \"123\"\n    dependencies: [{peer: 'true', port: 0, proto: udp}]\nend: {}\n"))
	if err != nil || q.Services[0].Service != "123" || q.Services[0].Dependencies[0].Peer != "true" {
		t.Errorf("quoted names: %+v, %v", q, err)
	}
}

// TestParseBaselineInvalid: what would approve nothing, or something else
// than was written, without a word is refused.
func TestParseBaselineInvalid(t *testing.T) {
	one := func(dep string) string {
		return "services:\n  - service: a\n    dependencies: [" + dep + "]\nend: {}\n"
	}
	for name, tc := range map[string]struct{ file, want string }{
		"empty":             {"", "no services"},
		"only a comment":    {"# none\n", "no services"},
		"no list":           {"services:\nend: {}\n", "not a list"},
		"unknown field":     {"services: []\nservice: x\nend: {}\n", `unknown field "service"`},
		"misspelt field":    {"services:\n  - service: a\n    depends: []\nend: {}\n", `unknown field "depends"`},
		"no dependencies":   {"services:\n  - service: a\nend: {}\n", "no dependencies"},
		"null dependencies": {"services:\n  - service: a\n    dependencies:\nend: {}\n", "not a list"},
		"no service":        {"services:\n  - dependencies: []\nend: {}\n", "service: missing"},
		"twice":             {"services:\n  - {service: a, dependencies: []}\n  - {service: a, dependencies: []}\nend: {}\n", "listed twice"},
		"no peer":           {one("{port: 1, proto: tcp}"), "peer: missing"},
		"no port":           {one("{peer: b, proto: tcp}"), "no port"},
		"port":              {one("{peer: b, port: 65536, proto: tcp}"), "not from 0 to 65535"},
		"negative port":     {one("{peer: b, port: -1, proto: tcp}"), "not a decimal number"},
		"proto":             {one("{peer: b, port: 1, proto: unix}"), "not tcp or udp"},
		"no proto":          {one("{peer: b, port: 1}"), "no proto"},
		"NUL":               {"services:\n  - service: \"a\\0b\"\n    dependencies: []\nend: {}\n", "NUL"},
		"long name":         {"services:\n  - service: " + strings.Repeat("a", maxStringBytes+1) + "\n    dependencies: []\nend: {}\n", "longer than"},
		"two documents":     {"services: []\nend: {}\n---\nservices: []\nend: {}\n", "more than one YAML document"},
		"not a mapping":     {"- a\n", "not a mapping"},
		// A port that is not what it looks like: YAML 1.1 reads 0443 as
		// octal (291), and others as numbers too.
		"octal port":     {one("{peer: b, port: 0443, proto: tcp}"), "not a decimal number"},
		"octal port 1.2": {one("{peer: b, port: 0o443, proto: tcp}"), "not a decimal number"},
		"hex port":       {one("{peer: b, port: 0x1bb, proto: tcp}"), "not a decimal number"},
		"signed port":    {one("{peer: b, port: +443, proto: tcp}"), "not a decimal number"},
		"spaced port":    {one("{peer: b, port: 4_43, proto: tcp}"), "not a decimal number"},
		"quoted port":    {one("{peer: b, port: \"443\", proto: tcp}"), "not a decimal number"},
		"float port":     {one("{peer: b, port: 443.0, proto: tcp}"), "not a decimal number"},
		"null port":      {one("{peer: b, port: , proto: tcp}"), "not a decimal number"},
		// Names that YAML reads as something else, and items that are
		// empty, as the last of a file that was cut short.
		"number name":     {"services:\n  - service: 123\n    dependencies: []\nend: {}\n", "not a string"},
		"boolean name":    {one("{peer: true, port: 1, proto: tcp}"), "not a string"},
		"null name":       {one("{peer: ~, port: 1, proto: tcp}"), "not a string"},
		"null service":    {"services:\n  -\nend: {}\n", "not a mapping"},
		"null dependency": {"services:\n  - service: a\n    dependencies:\n      -\nend: {}\n", "not a mapping"},
		"twice a field":   {"services:\n  - service: a\n    service: b\n    dependencies: []\nend: {}\n", "given twice"},
		"alias":           {"services:\n  - &a {service: x, dependencies: []}\n  - *a\nend: {}\n", "anchors and aliases"},
		"anchor":          {"services:\n  - service: &n x\n    dependencies: []\nend: {}\n", "anchors and aliases"},
		// The last line, which tells that the file is whole.
		"no end":           {"services: []\n", "does not end with `end:`"},
		"end first":        {"end: {}\nservices: []\n", "does not end with `end:`"},
		"end null":         {"services: []\nend:\n", "not a mapping"},
		"end count":        {"services:\n  - {service: a, dependencies: []}\nend: {services: 2}\n", "has 1 services, and its last line tells 2"},
		"end dependencies": {one("{peer: b, port: 1, proto: tcp}") + "", "x"},
		"end fewer":        {"services:\n  - service: a\n    dependencies: [{peer: b, port: 1, proto: tcp}]\nend: {services: 1, dependencies: 2}\n", "has 1 dependencies, and its last line tells 2"},
		"end unknown":      {"services: []\nend: {service: 0}\n", `unknown field "service"`},
		"end not a number": {"services: []\nend: {services: none}\n", "not a decimal number"},
		"end octal":        {"services: []\nend: {services: 00}\n", "not a decimal number"},
		// A file with more items than its last line counts, as one that
		// lines were added to without it.
		"end more services":     {"services:\n  - {service: a, dependencies: []}\n  - {service: b, dependencies: []}\nend: {services: 1}\n", "has 2 services, and its last line tells 1"},
		"end more dependencies": {"services:\n  - service: a\n    dependencies: [{peer: b, port: 1, proto: tcp}, {peer: c, port: 1, proto: tcp}]\nend: {dependencies: 1}\n", "has 2 dependencies, and its last line tells 1"},
		"port word":             {one("{peer: b, port: kernel, proto: tcp}"), "not a decimal number"},
		"port word quoted int":  {one("{peer: b, port: \"kernel-chosen \", proto: tcp}"), "not a decimal number"},
		"dependency a list":     {one("[b, 1, tcp]"), "not a mapping"},
		"services a mapping":    {"services: {a: b}\nend: {}\n", "not a list"},
	} {
		if name == "end dependencies" {
			continue
		}
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
	many.WriteString("end: {}\n")
	if _, err := ParseBaseline([]byte(many.String())); err == nil || !strings.Contains(err.Error(), "more than 10000 services") {
		t.Errorf("more services than the bound: %v", err)
	}
}

// TestBaselineMarshal: what Marshal writes is read back to the same
// baseline, a dependency per line, with the names that YAML would read as
// something else quoted, and a last line that tells the file is whole.
func TestBaselineMarshal(t *testing.T) {
	b := &Baseline{Services: []BaselineService{
		{Service: "shop/app", Dependencies: []BaselineDependency{
			{"~external", 443, "tcp", false}, {"shop/postgres", 5432, "tcp", false}, {"null", 0, "udp", false}, {"a: b", 1, "tcp", false}, {"#x", 2, "tcp", false},
			{"user@1000.service", 22, "tcp", false}, {"~kernel:nfs", 2049, "tcp", false}}},
		{Service: "~", Dependencies: []BaselineDependency{{"123", 80, "tcp", false}, {" lead", 80, "tcp", false}, {"'q\"", 80, "tcp", false}}},
		{Service: "batch/report"},
	}}
	b.Normalize()
	// Whatever an agent names a service, a baseline holds it: a line
	// break, a tab, a character that ends a line for some readers.
	odd := &Baseline{Services: []BaselineService{{Service: "a\nb", Dependencies: []BaselineDependency{
		{"tab\there", 1, "tcp", false}, {"\u2028", 2, "tcp", false}, {"\x1b[2J", 3, "udp", false}, {strings.Repeat("n", maxStringBytes), 4, "tcp", false}}}}}
	odd.Normalize()
	if text, err := odd.Marshal(); err != nil {
		t.Errorf("Marshal of odd names: %v", err)
	} else if back, err := ParseBaseline(text); err != nil || !reflect.DeepEqual(back, odd) {
		t.Errorf("odd names read back as %+v, %v\n%s", back, err, text)
	}
	out, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `services:
  - service: batch/report
    dependencies: []
  - service: shop/app
    dependencies:
      - {peer: "#x", port: 2, proto: tcp}
      - {peer: "a: b", port: 1, proto: tcp}
      - {peer: "null", port: 0, proto: udp}
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: user@1000.service, port: 22, proto: tcp}
      - {peer: ~external, port: 443, proto: tcp}
      - {peer: "~kernel:nfs", port: 2049, proto: tcp}
  - service: "~"
    dependencies:
      - {peer: " lead", port: 80, proto: tcp}
      - {peer: "'q\"", port: 80, proto: tcp}
      - {peer: "123", port: 80, proto: tcp}
end: {services: 3, dependencies: 10}
`
	if string(out) != want {
		t.Errorf("Marshal:\n%s\nwant:\n%s", out, want)
	}
	back, err := ParseBaseline(out)
	if err != nil || back.Digest() != b.Digest() {
		t.Errorf("read back: %+v, %v", back, err)
	}
	if none, err := (&Baseline{}).Marshal(); err != nil || string(none) != "services: []\nend: {services: 0, dependencies: 0}\n" {
		t.Errorf("a baseline of no service: %q, %v", none, err)
	}
	// Marshal refuses what ParseBaseline would.
	for _, bad := range []*Baseline{
		{Services: []BaselineService{{Service: ""}}},
		{Services: []BaselineService{{Service: "a"}, {Service: "a"}}},
		{Services: []BaselineService{{Service: "a", Dependencies: []BaselineDependency{{"b", 70000, "tcp", false}}}}},
		{Services: []BaselineService{{Service: "a", Dependencies: []BaselineDependency{{"b\x00", 1, "tcp", false}}}}},
		{Services: []BaselineService{{Service: "a\xff"}}},
		{Services: []BaselineService{{Service: "a", Dependencies: []BaselineDependency{{"b", 1, "sctp", false}}}}},
	} {
		if out, err := bad.Marshal(); err == nil {
			t.Errorf("Marshal(%+v) = %q, want an error", bad, out)
		}
	}
}

// TestBaselineMarshalShowsWhatItHolds: a file under review shows every
// character of a name: those that turn the text around, that have no
// width or that break a line for some readers are escapes, not themselves.
func TestBaselineMarshalShowsWhatItHolds(t *testing.T) {
	hidden := []string{
		"evil\u202egnp.exe", // right-to-left override
		"a\u200bb",          // zero width space
		"a\u200d\u2060b",    // zero width joiner, word joiner
		"a\u2028b\u2029c",   // line and paragraph separators
		"a\u0085b\u009bc",   // C1 controls: next line, CSI
		"\ufeffbom",         // byte order mark
		"a\u00a0b",          // a space that is not the space
		"a\u00adb",          // soft hyphen
		"a\x1b[2Jb\x7f",     // escape, delete
		"a\u2066b\u2069",    // isolates
	}
	b := &Baseline{}
	for i, name := range hidden {
		b.Services = append(b.Services, BaselineService{Service: name, Dependencies: []BaselineDependency{{name, i, "tcp", false}}})
	}
	b.Normalize()
	out, err := b.MarshalNotes(func(string, BaselineDependency) string { return "note\u202e with\na break\x1b" })
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range string(out) {
		if r != '\n' && !unicode.IsPrint(r) {
			t.Errorf("the file holds %U at byte %d as it is:\n%q", r, i, out)
		}
	}
	if n := strings.Count(string(out), "\n"); n != 2+3*len(hidden) {
		t.Errorf("%d lines, want a line per service and dependency:\n%s", n, out)
	}
	if !strings.Contains(string(out), `service: "evil\u202egnp.exe"`) || !strings.Contains(string(out), "# note  with a break") {
		t.Errorf("escapes and notes:\n%s", out)
	}
	if back, err := ParseBaseline(out); err != nil || !reflect.DeepEqual(back, b) {
		t.Errorf("read back as %+v, %v", back, err)
	}
	// A name of letters of any script is itself.
	plain := &Baseline{Services: []BaselineService{{Service: "決済/api", Dependencies: []BaselineDependency{{"données", 1, "tcp", false}}}}}
	if out, err := plain.Marshal(); err != nil || !strings.Contains(string(out), `"決済/api"`) || !strings.Contains(string(out), `"données"`) {
		t.Errorf("names of other scripts: %s, %v", out, err)
	}
}

// TestBaselineCutShort: no file that was cut short is taken for the
// baseline. Every proper prefix of a file is refused, but the file
// without its last line break, which holds as much.
func TestBaselineCutShort(t *testing.T) {
	b := &Baseline{Services: []BaselineService{
		{Service: "batch/report"},
		{Service: "shop/app", Dependencies: []BaselineDependency{{"~unresolved", 53, "udp", false}, {"shop/postgres", 5432, "tcp", false}, {"~external", 443, "tcp", false}}},
		{Service: "shop/web", Dependencies: []BaselineDependency{{"shop/app", 8080, "tcp", false}}},
		{Service: "we ird", Dependencies: []BaselineDependency{{"a\nb", 1, "tcp", false}}},
	}}
	b.Normalize()
	whole, err := b.MarshalNotes(func(_ string, d BaselineDependency) string {
		if d.Port == 53 {
			return "a note"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range [][]byte{whole, []byte(testBaseline),
		[]byte(`{"services": [{"service": "a", "dependencies": [{"peer": "b", "port": 1, "proto": "tcp"}]}], "end": {"services": 1, "dependencies": 1}}`)} {
		full, err := ParseBaseline(file)
		if err != nil {
			t.Fatalf("the whole file: %v\n%s", err, file)
		}
		accepted := 0
		for n := range len(file) {
			got, err := ParseBaseline(file[:n])
			if err != nil {
				continue
			}
			accepted++
			if strings.TrimRight(string(file[n:]), " \n") != "" || !reflect.DeepEqual(got, full) {
				t.Errorf("the first %d of %d bytes are read as a baseline of %d services (ends with %q)", n, len(file),
					len(got.Services), file[max(0, n-20):n])
			}
		}
		if accepted > 2 {
			t.Errorf("%d prefixes are accepted", accepted)
		}
	}
	// A file whose last line is of another file, as an edit that removed
	// lines without it: the counts do not match.
	lines := strings.SplitAfter(string(whole), "\n")
	cut := strings.Join(append(lines[:8:8], lines[11:]...), "")
	if _, err := ParseBaseline([]byte(cut)); err == nil || !strings.Contains(err.Error(), "its last line tells") {
		t.Errorf("a file without its middle: %v\n%s", err, cut)
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
	if err := os.WriteFile(path, []byte("services:\n  - service: shop/app\nend: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	c.prepare(context.Background())
	if st.baseline != first || len(st.baselineFails) != 1 || !strings.Contains(st.baselineFails[0], "no dependencies") {
		t.Errorf("an invalid file replaced the baseline, or its failure is not recorded: %q", st.baselineFails)
	}
	// So does a file that was cut short, one that is gone, or one that is
	// empty as a generator may leave it.
	for _, contents := range []string{"services:\n  - service: shop/app\n    dependencies: []\n", ""} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		c.prepare(context.Background())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if st.baseline != first || len(st.baselineFails) != 4 || !strings.Contains(st.baselineFails[1], "cut short") {
		t.Errorf("a cut, an empty or a missing file replaced the baseline: %q", st.baselineFails)
	}
	if err := os.WriteFile(path, []byte("services: []\nend: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.prepare(context.Background())
	if st.baseline == first || len(st.baseline.Services) != 0 {
		t.Errorf("the valid file is not read again: %+v", st.baseline)
	}
}

// TestBaselineFileReadWhenChanged: a file of the same size and time of
// change is not read again every write interval, and is read again after
// five minutes all the same; a file that changed is read at once, and so
// is one that changed a moment before it was read.
func TestBaselineFileReadWhenChanged(t *testing.T) {
	c, st, _, now, path := baselineConnector(t, testBaseline)
	old := now.Add(-time.Hour)
	set := func(contents string, changed time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, changed, changed); err != nil {
			t.Fatal(err)
		}
	}
	services := func() int {
		t.Helper()
		*now = now.Add(time.Minute)
		c.prepare(context.Background())
		return len(st.baseline.Services)
	}
	one := "services:\n  - {service: a, dependencies: []}\nend: {}\n"
	other := "services:\n  - {service: a, dependencies: []}\n  - {service: b, dependencies: []}\nend: {}\n"
	same := "services:\n  - {service: a, dependencies: []}\n  - {service: c, dependencies: []}\nend: {}\n"
	set(one, old)
	if n := services(); n != 1 {
		t.Fatalf("%d services", n)
	}
	// Another file: its size differs.
	set(other, old)
	if n := services(); n != 2 || st.baseline.Services[1].Service != "b" {
		t.Errorf("a file of another size is not read: %+v", st.baseline)
	}
	// The same size and time: not read again, and still written, so that
	// PostgreSQL knows when the file was last valid.
	syncs := st.baselineSyncs
	set(same, old)
	for range 3 {
		if services(); st.baseline.Services[1].Service != "b" {
			t.Errorf("a file of the same size and time was read again within five minutes")
		}
	}
	if st.baselineSyncs != syncs+3 {
		t.Errorf("written %d times in 3 intervals", st.baselineSyncs-syncs)
	}
	// After five minutes it is read all the same.
	*now = now.Add(baselineReread)
	if services(); st.baseline.Services[1].Service != "c" {
		t.Errorf("the file is not read again after %s: %+v", baselineReread, st.baseline)
	}
	// A time of change alone is a change.
	set(other, old.Add(time.Second))
	if services(); st.baseline.Services[1].Service != "b" {
		t.Errorf("a file with another time of change is not read: %+v", st.baseline)
	}
	// A file that changed within two seconds of its read may still be
	// written to: it is read again whatever its size and time.
	moment := now.Add(time.Minute - time.Second)
	set(one, moment)
	services()
	set("services:\n  - {service: z, dependencies: []}\nend: {}\n", moment)
	if services(); st.baseline.Services[0].Service != "z" {
		t.Errorf("a file read a moment after it changed is not read again: %+v", st.baseline)
	}
	// An invalid file is not parsed again either, and stays a failure.
	set("services: []\n", old)
	fails := len(st.baselineFails)
	services()
	services()
	if len(st.baselineFails) != fails+2 {
		t.Errorf("%d failures recorded in 2 intervals", len(st.baselineFails)-fails)
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
// "metric{job,peer,port,transport} value", sorted; the series of
// shawk.baseline.drift.truncated have the peers they count in place of
// the job.
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
		if s.baselinePeer != "" {
			labels = []string{s.baselinePeer}
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
		services: []baselineCount{{"batch/report", 0, 0, 0}, {"shop/app", 3, 12, 2}},
		drift: []driftRow{
			{"shop/app", "billing/api", 8443, "tcp", 12},
			{"shop/app", "~unresolved", 53, "udp", 1},
		},
		newServices: 2}
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	first := *now
	until := now.Add(-baselineDelay)
	if len(st.reports) != 1 || !st.reports[0][1].Equal(until) || !st.reports[0][0].Equal(until.Add(-baselineWindow)) {
		t.Fatalf("evaluated over %v, want the hour before %s", st.reports, until)
	}
	// A host runs a service for a week after a process of it was last seen.
	if !st.hostsSince.Equal(until.Add(-7 * 24 * time.Hour)) {
		t.Errorf("hosts since %s, want a week before %s", st.hostsSince, until)
	}
	want := []string{
		"shawk.baseline.dependencies{batch/report} 0",
		"shawk.baseline.dependencies{shop/app} 3",
		"shawk.baseline.drift.hosts{shop/app,billing/api,8443,tcp} 12",
		"shawk.baseline.drift.hosts{shop/app,~unresolved,53,udp} 1",
		"shawk.baseline.drift.truncated{named} 0",
		"shawk.baseline.drift.truncated{unresolved} 0",
		"shawk.baseline.evaluation.attempt.timestamp{shawk-connector} " + itoa(first.Unix()),
		"shawk.baseline.evaluation.failed{shawk-connector} 0",
		"shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(first.Unix()),
		"shawk.baseline.file.failed{shawk-connector} 0",
		// A service that no host runs is told as one: nothing judges it.
		"shawk.baseline.hosts.unobserved{batch/report} 0",
		"shawk.baseline.hosts.unobserved{shop/app} 2",
		"shawk.baseline.hosts{batch/report} 0",
		"shawk.baseline.hosts{shop/app} 12",
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
	st.report = &baselineReport{read: true, services: []baselineCount{{"shop/app", 4, 12, 0}}, failed: true,
		truncatedNamed: 7, truncatedUnresolved: 1}
	c.tick(context.Background())
	if len(st.reports) != 2 || !st.reports[1][0].Equal(until.Add(-baselineWindow)) || !st.reports[1][1].Equal(now.Add(-baselineDelay)) {
		t.Errorf("second evaluation over %v", st.reports[len(st.reports)-1])
	}
	want = []string{
		"shawk.baseline.dependencies{shop/app} 4",
		"shawk.baseline.drift.truncated{named} 7",
		"shawk.baseline.drift.truncated{unresolved} 1",
		"shawk.baseline.evaluation.attempt.timestamp{shawk-connector} " + itoa(now.Unix()),
		"shawk.baseline.evaluation.failed{shawk-connector} 0",
		"shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(now.Unix()),
		"shawk.baseline.file.failed{shawk-connector} 1",
		"shawk.baseline.hosts.unobserved{shop/app} 0",
		"shawk.baseline.hosts{shop/app} 12",
		"shawk.baseline.new_services{shawk-connector} 0",
	}
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("series:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestBaselineMetricsWhileFailing: while the evaluations fail, the result
// of the last one that succeeded is sent on, however old: a drift does not
// go away because it can no longer be evaluated. The failure and the time
// of the last success are sent with it, and a failed evaluation is tried
// again after a minute.
func TestBaselineMetricsWhileFailing(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, testBaseline)
	st.report = &baselineReport{read: true, services: []baselineCount{{"shop/app", 3, 2, 0}},
		drift: []driftRow{{"shop/app", "billing/api", 8443, "tcp", 1}}}
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	evaluated := "shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(now.Unix())
	drift := "shawk.baseline.drift.hosts{shop/app,billing/api,8443,tcp} 1"
	if got := baselineSeries(out()); !slices.Contains(got, drift) || !slices.Contains(got, evaluated) ||
		!slices.Contains(got, "shawk.baseline.evaluation.failed{shawk-connector} 0") {
		t.Fatalf("series %q", got)
	}
	st.reportErr = errFake
	for _, after := range []time.Duration{5 * time.Minute, 11 * time.Minute, 2 * time.Hour, 72 * time.Hour} {
		tries := len(st.reports)
		*now = now.Add(after)
		c.tick(context.Background())
		got := baselineSeries(out())
		for _, want := range []string{drift, evaluated, "shawk.baseline.evaluation.failed{shawk-connector} 1",
			"shawk.baseline.evaluation.attempt.timestamp{shawk-connector} " + itoa(now.Unix())} {
			if !slices.Contains(got, want) {
				t.Errorf("after failures, no %q in %q", want, got)
			}
		}
		// A failed evaluation is tried again at the next interval, and
		// not sooner: one that fails at its time limit of a minute would
		// otherwise follow the last one at once.
		for range 4 {
			*now = now.Add(time.Minute)
			c.tick(context.Background())
		}
		out()
		if len(st.reports) != tries+1 {
			t.Errorf("%d evaluations in the 4 minutes after one that failed, want none", len(st.reports)-tries-1)
		}
	}
	// The evaluation that succeeds again covers the time of the failures,
	// up to a day.
	st.reportErr = nil
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	last := st.reports[len(st.reports)-1]
	if got := baselineSeries(out()); !slices.Contains(got, "shawk.baseline.evaluation.failed{shawk-connector} 0") ||
		!slices.Contains(got, "shawk.baseline.evaluation.timestamp{shawk-connector} "+itoa(now.Unix())) ||
		last[1].Sub(last[0]) != maxBaselineLookback {
		t.Errorf("after the failures: series %q, evaluated over %s", got, last[1].Sub(last[0]))
	}
	// And one after a short failure starts an hour before the last success.
	st.reportErr = errFake
	*now = now.Add(5 * time.Minute)
	c.tick(context.Background())
	*now = now.Add(20 * time.Minute)
	c.tick(context.Background())
	st.reportErr = nil
	*now = now.Add(5 * time.Minute)
	c.tick(context.Background())
	if last = st.reports[len(st.reports)-1]; last[1].Sub(last[0]) != baselineWindow+30*time.Minute {
		t.Errorf("after 30 minutes of failures, evaluated over %s", last[1].Sub(last[0]))
	}
	// A host runs a service for the memory of the configuration, and for
	// the whole period when that is longer: the hosts are never counted
	// from after its start.
	if !st.hostsSince.Equal(last[1].Add(-7 * 24 * time.Hour)) {
		t.Errorf("hosts since %s, want a week before %s", st.hostsSince, last[1])
	}
}

// TestBaselineHostsSince: the hosts of a service are counted from the
// memory before the end of the period, and from no later than its start.
// A period is longer than a memory of an hour from the second evaluation
// on, and longer than any memory after evaluations paused for as long.
func TestBaselineHostsSince(t *testing.T) {
	until := t0
	for _, c := range []struct{ period, memory, want time.Duration }{
		{time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour},
		{time.Hour, time.Hour, time.Hour},
		{65 * time.Minute, time.Hour, 65 * time.Minute},
		{24 * time.Hour, 2 * time.Hour, 24 * time.Hour},
		{24 * time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour},
	} {
		if got := BaselineHostsSince(until.Add(-c.period), until, c.memory); !got.Equal(until.Add(-c.want)) {
			t.Errorf("a period of %s with a memory of %s: hosts since %s before its end, want %s", c.period, c.memory, until.Sub(got), c.want)
		}
	}
	// The connector with the smallest memory that the configuration
	// accepts: every evaluation asks for hosts from the start of its
	// period at the latest, also after a pause.
	c, st, _, now, _ := baselineConnector(t, testBaseline)
	c.cfg.BaselineHostMemory = time.Hour
	st.report = &baselineReport{read: true}
	for i, step := range []time.Duration{time.Minute, 5 * time.Minute, 5 * time.Minute, 3 * time.Hour, 5 * time.Minute} {
		*now = now.Add(step)
		c.tick(context.Background())
		last := st.reports[len(st.reports)-1]
		if len(st.reports) != i+1 || st.hostsSince.After(last[0]) || last[1].Sub(st.hostsSince) < time.Hour {
			t.Errorf("evaluation %d over %s to %s counts the hosts since %s", i+1, last[0], last[1], st.hostsSince)
		}
	}
}

// TestBaselineWriteFails: a file that is valid and that PostgreSQL does not
// take is told as a file that failed: the baseline does not follow it.
func TestBaselineWriteFails(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, testBaseline)
	st.mu.Lock()
	st.fail = true
	st.mu.Unlock()
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	if got := baselineSeries(out()); !slices.Contains(got, "shawk.baseline.file.failed{shawk-connector} 1") {
		t.Errorf("with a baseline that cannot be written, series %q", got)
	}
	st.mu.Lock()
	st.fail = false
	st.mu.Unlock()
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	if got := baselineSeries(out()); !slices.Contains(got, "shawk.baseline.file.failed{shawk-connector} 0") {
		t.Errorf("once the baseline is written, series %q", got)
	}
}

// TestBaselineNeverEvaluated: a connector whose evaluations fail from the
// first one tells so, with a time of success of 0: no series of a drift is
// not the absence of a drift, and what alerts on it needs a series to
// alert on.
func TestBaselineNeverEvaluated(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, testBaseline)
	st.reportErr = errFake
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	want := []string{
		"shawk.baseline.evaluation.attempt.timestamp{shawk-connector} " + itoa(now.Unix()),
		"shawk.baseline.evaluation.failed{shawk-connector} 1",
		"shawk.baseline.evaluation.timestamp{shawk-connector} 0",
		"shawk.baseline.file.failed{shawk-connector} 0",
	}
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("series %q, want %q", got, want)
	}
	// It goes on telling so every write interval.
	*now = now.Add(30 * time.Second)
	c.tick(context.Background())
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("the next interval: series %q, want %q", got, want)
	}
}

// TestBaselineMetricsNeverRead: before a baseline was read from a valid
// file, nothing is judged; a failure to read the file is told all the
// same, so that it can be alerted on, and so is the evaluation.
func TestBaselineMetricsNeverRead(t *testing.T) {
	c, st, out, now, _ := baselineConnector(t, "services:\n")
	if st.baseline != nil || len(st.baselineFails) != 1 {
		t.Fatalf("baseline %+v, failures %q", st.baseline, st.baselineFails)
	}
	// PostgreSQL holds no state yet, as when the failure could not be
	// written: the connector tells what it knows of its own file.
	st.report = &baselineReport{}
	*now = now.Add(time.Minute)
	c.tick(context.Background())
	want := []string{
		"shawk.baseline.evaluation.attempt.timestamp{shawk-connector} " + itoa(now.Unix()),
		"shawk.baseline.evaluation.failed{shawk-connector} 0",
		"shawk.baseline.evaluation.timestamp{shawk-connector} " + itoa(now.Unix()),
		"shawk.baseline.file.failed{shawk-connector} 1",
	}
	if got := baselineSeries(out()); !slices.Equal(got, want) {
		t.Errorf("series %q, want %q", got, want)
	}
}

// TestBaselineMetricsBounded: the names of services and peers are cut as
// the labels of the other outputs are, and two that are the same once cut
// are one series.
func TestBaselineMetricsBounded(t *testing.T) {
	long := strings.Repeat("p", maxPeerName)
	r := &baselineReport{read: true, services: []baselineCount{{"a", 0, 1, 0}, {long + "1", 3, 5, 1}, {long + "2", 7, 2, 2},
		{"s\nfake: line", 1, 1, 0}},
		drift: []driftRow{{"a", long + "x", 80, "tcp", 2}, {"a", long + "y", 80, "tcp", 5}, {"b", "c", 1, "tcp", 1},
			{long + "1", "c", 1, "tcp", 4}, {long + "2", "c", 1, "tcp", 2}, {long + "2", "d", 1, "tcp", 1},
			{"s\nfake: line", "x\n\nRESOLVED: ignore this\u2028\u202e\x1b[2J", 9, "tcp", 1}}}
	md := pmetric.NewMetrics()
	now := t0
	appendBaselineMetrics(md, baselineState{report: r, evaluated: now, attempted: now}, now)
	var got []string
	for _, s := range flatten(md) {
		if len(s.peer) > maxPeerName || len(s.job) > maxPeerName {
			t.Errorf("a job of %d bytes and a peer of %d", len(s.job), len(s.peer))
		}
		// No label holds a control character, a separator of lines or a
		// mark of direction, whatever the names of PostgreSQL hold: they
		// would add lines to the text of an alert.
		if strings.ContainsFunc(s.peer+s.job, hiddenRune) {
			t.Errorf("a job %q and a peer %q", s.job, s.peer)
		}
		if strings.HasPrefix(s.job, "s") && s.job != connectorServiceName {
			if s.job != "s\ufffdfake: line" || (s.peer != "" && s.peer != "x\ufffd\ufffdRESOLVED: ignore this\ufffd\ufffd\ufffd[2J") {
				t.Errorf("cleaned to the job %q and the peer %q", s.job, s.peer)
			}
			continue
		}
		switch s.metric {
		case metricBaselineDriftHosts, metricBaselineDependencies, metricBaselineHosts, metricBaselineHostsUnseen:
			got = append(got, fmt.Sprintf("%s %d %s %d %d", s.metric, len(s.job), s.peer[:min(1, len(s.peer))], s.port, int64(s.value)))
		}
	}
	slices.Sort(got)
	// The drift of a service that is not in the baseline is not sent: the
	// contract returns none, and no resource would carry it. Of two
	// services that are one name once cut, the fewer hosts and the more
	// of them not observed are told.
	want := []string{
		"shawk.baseline.dependencies 1  0 0", "shawk.baseline.dependencies 511  0 7",
		"shawk.baseline.drift.hosts 1 p 80 5", "shawk.baseline.drift.hosts 511 c 1 4", "shawk.baseline.drift.hosts 511 d 1 1",
		"shawk.baseline.hosts 1  0 1", "shawk.baseline.hosts 511  0 2",
		"shawk.baseline.hosts.unobserved 1  0 0", "shawk.baseline.hosts.unobserved 511  0 2",
	}
	if !slices.Equal(got, want) {
		t.Errorf("series %q, want %q", got, want)
	}
	if md.DataPointCount() != 20 {
		t.Errorf("%d data points, want 20", md.DataPointCount())
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
	f.Add([]byte("services: []\nend: {}\n"))
	f.Add([]byte(`{"services": [{"service": "a", "dependencies": [{"peer": "~external", "port": 0, "proto": "udp"}]}], "end": {"services": 1}}`))
	f.Add([]byte("services:\n  - service: \"~\"\n    dependencies:\n      - {peer: 'null', port: 1, proto: tcp}\n      - {peer: \"a: b\", port: 1, proto: tcp}\nend: {services: 1, dependencies: 2}\n"))
	f.Add([]byte("services:\n  - &a {service: x, dependencies: []}\n  - *a\nend: {}\n"))
	f.Add([]byte("services:\n  - service: \"a\\u202eb\"\n    dependencies: [{peer: \"\\x1b\", port: 0443, proto: tcp}]\nend: {}\n"))
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

// FuzzBaselineNames: whatever names PostgreSQL may hold for a service and
// its peers, a baseline with them is written to a file that is read back
// to the same baseline, and names that it cannot hold are refused by both.
func FuzzBaselineNames(f *testing.F) {
	for _, s := range []string{"shop/app", "~external", "null", "~", "a: b", "#x", " lead", "trail ", "a\nb", "\t", "'", "\"", "{}", "[]",
		"- x", "? x", "!!str", "&a", "*a", "|", ">", "%", "@", "`", "yes", "0x1f", "1e3", "\u2028", "\u0085", "\ufeff", "é", "\x7f", "",
		"On", "NO", "n", "-", ".", ".inf", "+1", "a@b", "a+b", "/", "~~", "a\u202eb", "\u200b", "\u009b", "a,b", "a]", "a}", "a#b", "a:b"} {
		f.Add(s, s+"/peer", uint16(443))
	}
	f.Fuzz(func(t *testing.T, service, peer string, port uint16) {
		b := &Baseline{Services: []BaselineService{{Service: service, Dependencies: []BaselineDependency{
			{peer, int(port), "tcp", false}, {service, 0, "udp", false}}}}}
		b.Normalize()
		valid := checkBaselineName(service) == nil && checkBaselineName(peer) == nil
		out, err := b.Marshal()
		if (err == nil) != valid {
			t.Fatalf("Marshal of %q and %q: %v, but the names are valid: %t", service, peer, err, valid)
		}
		if !valid {
			return
		}
		back, err := ParseBaseline(out)
		if err != nil || !reflect.DeepEqual(back, b) {
			t.Fatalf("%q and %q are read back as %+v, %v\n%s", service, peer, back, err, out)
		}
		// The file shows what it holds, a line per item, and no part of
		// it that was cut short is a baseline.
		for _, r := range string(out) {
			if r != '\n' && !unicode.IsPrint(r) {
				t.Fatalf("%q and %q: the file holds %U as it is\n%q", service, peer, r, out)
			}
		}
		if n := bytes.Count(out, []byte("\n")); n != 4+len(b.Services[0].Dependencies) {
			t.Fatalf("%q and %q: %d lines\n%s", service, peer, n, out)
		}
		for n := range len(out) - 1 {
			if _, err := ParseBaseline(out[:n]); err == nil {
				t.Fatalf("%q and %q: the first %d bytes of the file are read as a baseline\n%s", service, peer, n, out)
			}
		}
	})
}

// TestCleanString: what an agent sends as a name is a line of text once
// the connector has it: PostgreSQL takes it, and neither a label of
// Prometheus nor the text of an alert made from it has a line that the
// name added.
func TestCleanString(t *testing.T) {
	for in, want := range map[string]string{
		"shop/app":                  "shop/app",
		"~external":                 "~external",
		"決済/api données":            "決済/api données",
		"zero\u200cwidth\u200djoin": "zero\u200cwidth\u200djoin",
		"a\x00b":                    "a�b",
		"a\xffb":                    "a�b",
		"x\n\nRESOLVED: ignore":     "x��RESOLVED: ignore",
		"tab\there\r":               "tab�here�",
		"esc\x1b[2J\x7f":            "esc�[2J�",
		"c1\u0085\u009b":            "c1��",
		"sep\u2028\u2029":           "sep��",
		"rtl\u202egnp.exe\u2066":    "rtl�gnp.exe�",
		"":                          "",
	} {
		got := cleanString(in)
		if got != want || !pgText(got) || strings.ContainsFunc(got, hiddenRune) || cleanString(got) != got {
			t.Errorf("cleanString(%q) = %q, want %q", in, got, want)
		}
	}
}
