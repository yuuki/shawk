package shawkconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

// The baseline of the dependencies of services (docs/design.md §5.9 and
// §6.4): baseline_file lists, per service, the dependencies that an
// operator approved, and the connector reports those of the services
// listed that are not among them.

// Baseline is the valid contents of a baseline file: the services whose
// dependencies are approved, sorted by name, each with its dependencies
// sorted and distinct.
type Baseline struct {
	Services []BaselineService
}

// BaselineService is a service of a baseline, by its name in PostgreSQL
// and in the job label ([namespace/]name), with the dependencies approved
// for it: none approves no dependency at all.
type BaselineService struct {
	Service      string
	Dependencies []BaselineDependency
}

// BaselineDependency is an approved dependency: the server by its name (a
// service, a range of peer_cidrs, ~unresolved or ~external), its port, 0
// for every port, and the transport, tcp or udp.
type BaselineDependency struct {
	Peer  string
	Port  int
	Proto string
}

// Bounds of a baseline: far above the services of a fleet and their
// dependencies, and what the connector writes to PostgreSQL in one
// transaction.
const (
	MaxBaselineServices     = 10000
	MaxBaselineDependencies = 100000
)

// The format of baseline_file, in YAML or JSON:
//
//	services:
//	  - service: shop/app
//	    dependencies:
//	      - {peer: shop/postgres, port: 5432, proto: tcp}
//	      - {peer: ~external, port: 443, proto: tcp}
//	  - service: batch/report
//	    dependencies: []          # approved to have none
//	end: {services: 2, dependencies: 2}
//
// `end` is the last key of the file, so that a file that was cut short,
// which is still YAML up to many of its bytes, is not taken for the
// baseline: without it a service, or the dependencies of one, would be
// dropped, or approved to have none, without a word. Its counts are those
// of the file; a file written by hand may leave them out (`end: {}`), and
// they are checked when they are there.
//
// The file is read strictly, since what it approves is what stays silent:
// a name is a string (one that YAML would read as a number, a boolean or
// nothing is quoted), a port is a decimal number (0443 is not 443 for
// YAML 1.1), and nothing is left out or given twice.

// errNoBaseline refuses a file without the list of services, as a
// generator that failed may leave: it would drop every baseline. A list
// that is there and empty is a baseline of no service.
var errNoBaseline = errors.New("no services: write `services: []` for a baseline of no service")

// errNoEnd refuses a file that does not end with `end:`: one that was cut
// short.
var errNoEnd = errors.New("the file does not end with `end:`: it may be cut short " +
	"(the last line of a baseline file is `end: {services: N, dependencies: N}`, or `end: {}`)")

// ParseBaseline parses and validates the contents of a baseline file.
// Unknown fields are refused, so that a misspelt field is not taken as
// absent, and so are a service without the list of its dependencies,
// which would otherwise approve none without a word, an item that is
// empty, as the last one of a file that was cut short, and a file without
// its last line.
func ParseBaseline(b []byte) (*Baseline, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errNoBaseline
		}
		return nil, err
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errNoBaseline
	}
	root, last, err := baselineFields(doc.Content[0], "the file", "services", "end")
	if err != nil {
		return nil, err
	}
	if root["services"] == nil {
		return nil, errNoBaseline
	}
	if root["end"] == nil || last != "end" {
		return nil, errNoEnd
	}
	list, err := baselineItems(root["services"], "services")
	if err != nil {
		return nil, err
	}
	if len(list) > MaxBaselineServices {
		return nil, fmt.Errorf("more than %d services", MaxBaselineServices)
	}
	out := &Baseline{Services: make([]BaselineService, 0, len(list))}
	seen := map[string]bool{}
	total := 0
	for i, item := range list {
		fields, _, err := baselineFields(item, fmt.Sprintf("services[%d]", i), "service", "dependencies")
		if err != nil {
			return nil, err
		}
		name, err := baselineName(fields["service"])
		if err != nil {
			return nil, fmt.Errorf("services[%d]: service: %w", i, err)
		}
		if seen[name] {
			return nil, fmt.Errorf("service %q is listed twice", name)
		}
		seen[name] = true
		if fields["dependencies"] == nil {
			return nil, fmt.Errorf("service %q: no dependencies: write `dependencies: []` for a service that has none", name)
		}
		deps, err := baselineItems(fields["dependencies"], "dependencies")
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", name, err)
		}
		if total += len(deps); total > MaxBaselineDependencies {
			return nil, fmt.Errorf("more than %d dependencies", MaxBaselineDependencies)
		}
		s := BaselineService{Service: name, Dependencies: make([]BaselineDependency, 0, len(deps))}
		for j, dep := range deps {
			d, err := baselineDependency(dep)
			if err != nil {
				return nil, fmt.Errorf("service %q: dependencies[%d]: %w", name, j, err)
			}
			s.Dependencies = append(s.Dependencies, d)
		}
		out.Services = append(out.Services, s)
	}
	// The counts of the last line are those of the file as it is written,
	// before the dependencies given twice are removed.
	counts, _, err := baselineFields(root["end"], "end", "services", "dependencies")
	if err != nil {
		return nil, err
	}
	for _, c := range []struct {
		key  string
		have int
	}{{"services", len(out.Services)}, {"dependencies", total}} {
		if counts[c.key] == nil {
			continue
		}
		n, err := baselineNumber(counts[c.key], MaxBaselineDependencies)
		if err != nil {
			return nil, fmt.Errorf("end: %s: %w", c.key, err)
		}
		if n != c.have {
			return nil, fmt.Errorf("end: the file has %d %s, and its last line tells %d: it may be cut short, or was "+
				"changed without its last line", c.have, c.key, n)
		}
	}
	out.Normalize()
	return out, nil
}

// baselineFields returns the values of a mapping of the file by key, and
// its last key. A key that is not of keys, or that is given twice, is
// refused, and so is what is no mapping: an item that is empty is one.
func baselineFields(n *yaml.Node, what string, keys ...string) (map[string]*yaml.Node, string, error) {
	if err := baselinePlain(n); err != nil {
		return nil, "", fmt.Errorf("%s: %w", what, err)
	}
	if n.Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("%s: not a mapping of %s (line %d): an empty item, as of a file that was cut short?",
			what, strings.Join(keys, ", "), n.Line)
	}
	out := map[string]*yaml.Node{}
	last := ""
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" || !slices.Contains(keys, k.Value) {
			return nil, "", fmt.Errorf("%s: unknown field %q (line %d)", what, cutLabel(k.Value, 64), k.Line)
		}
		if out[k.Value] != nil {
			return nil, "", fmt.Errorf("%s: %s is given twice (line %d)", what, k.Value, k.Line)
		}
		out[k.Value], last = v, k.Value
	}
	return out, last, nil
}

// baselineItems returns the items of a list of the file.
func baselineItems(n *yaml.Node, what string) ([]*yaml.Node, error) {
	if err := baselinePlain(n); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s: not a list (line %d): write `%s: []` for none", what, n.Line, what)
	}
	return n.Content, nil
}

// baselinePlain refuses the anchors and the aliases of YAML, which a file
// of data has no use for, and which make a small file a large one.
func baselinePlain(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("anchors and aliases are not read (line %d)", n.Line)
	}
	return nil
}

// baselineName returns a name of the file: a string, and nothing that
// YAML reads as something else (123, true, ~), which is quoted in a file.
func baselineName(n *yaml.Node) (string, error) {
	if n == nil {
		return "", errors.New("missing")
	}
	if err := baselinePlain(n); err != nil {
		return "", err
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", fmt.Errorf("not a string (line %d): quote a name that reads as a number, a boolean or nothing", n.Line)
	}
	if err := checkBaselineName(n.Value); err != nil {
		return "", err
	}
	return n.Value, nil
}

// baselineNumber returns a number of the file, from 0 to most: decimal
// digits and nothing else. YAML reads 0443 as octal or as a string, by
// its version, +443 and 4_43 as numbers, and "443" as a string: a port
// that is not what it looks like is refused.
func baselineNumber(n *yaml.Node, most int) (int, error) {
	if n == nil {
		return 0, errors.New("missing")
	}
	if err := baselinePlain(n); err != nil {
		return 0, err
	}
	v := n.Value
	decimal := v != "" && len(v) <= 9 && (v == "0" || v[0] != '0')
	for _, c := range []byte(v) {
		decimal = decimal && c >= '0' && c <= '9'
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" || !decimal {
		return 0, fmt.Errorf("%q is not a decimal number (line %d)", cutLabel(v, 64), n.Line)
	}
	i, err := strconv.Atoi(v)
	if err != nil || i > most {
		return 0, fmt.Errorf("%s is not from 0 to %d", v, most)
	}
	return i, nil
}

// baselineDependency reads a dependency of the file.
func baselineDependency(n *yaml.Node) (BaselineDependency, error) {
	var d BaselineDependency
	fields, _, err := baselineFields(n, "the dependency", "peer", "port", "proto")
	if err != nil {
		return d, err
	}
	if d.Peer, err = baselineName(fields["peer"]); err != nil {
		return d, fmt.Errorf("peer: %w", err)
	}
	if fields["port"] == nil {
		return d, errors.New("no port: write 0 for every port")
	}
	if d.Port, err = baselineNumber(fields["port"], 65535); err != nil {
		return d, fmt.Errorf("port: %w", err)
	}
	if fields["proto"] == nil {
		return d, errors.New("no proto: tcp or udp")
	}
	if p := fields["proto"]; p.Kind == yaml.ScalarNode && p.ShortTag() == "!!str" && p.Anchor == "" {
		d.Proto = p.Value
	}
	return d, d.check()
}

// check checks a dependency.
func (d BaselineDependency) check() error {
	if err := checkBaselineName(d.Peer); err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	if d.Port < 0 || d.Port > 65535 {
		return fmt.Errorf("port %d is not from 0 to 65535", d.Port)
	}
	if d.Proto != "tcp" && d.Proto != "udp" {
		return fmt.Errorf("proto %q is not tcp or udp", cutLabel(d.Proto, 64))
	}
	return nil
}

// checkBaselineName checks the name of a service or of a peer: any name
// that PostgreSQL may hold, so that whatever an agent names a service, a
// baseline can hold it and approve a dependency on it. The connector keeps
// the strings of agents up to maxStringBytes, as text of PostgreSQL: valid
// UTF-8 without NUL. A name of shawk may start with ~ (~external,
// ~kernel:nfs).
func checkBaselineName(s string) error {
	switch {
	case s == "":
		return errors.New("empty")
	case len(s) > maxStringBytes:
		return fmt.Errorf("longer than %d bytes", maxStringBytes)
	case !utf8.ValidString(s):
		return errors.New("not valid UTF-8")
	case strings.ContainsRune(s, 0):
		return errors.New("has a NUL character")
	}
	return nil
}

// Normalize sorts the services by name and the dependencies of each by
// peer, port and transport, and removes the dependencies listed twice, so
// that a baseline has one form whatever the order of its file.
func (b *Baseline) Normalize() {
	slices.SortFunc(b.Services, func(x, y BaselineService) int { return strings.Compare(x.Service, y.Service) })
	for i := range b.Services {
		d := b.Services[i].Dependencies
		slices.SortFunc(d, compareDependencies)
		b.Services[i].Dependencies = slices.Compact(d)
	}
}

func compareDependencies(x, y BaselineDependency) int {
	if c := strings.Compare(x.Peer, y.Peer); c != 0 {
		return c
	}
	if x.Port != y.Port {
		return x.Port - y.Port
	}
	return strings.Compare(x.Proto, y.Proto)
}

// Digest identifies the contents of a normalized baseline, so that the
// connector writes them to PostgreSQL only when they change.
func (b *Baseline) Digest() string {
	h := sha256.New()
	for _, s := range b.Services {
		fmt.Fprintf(h, "%q\n", s.Service)
		for _, d := range s.Dependencies {
			fmt.Fprintf(h, " %q %d %s\n", d.Peer, d.Port, d.Proto)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// dependencies counts the dependencies of a baseline.
func (b *Baseline) dependencies() int {
	n := 0
	for _, s := range b.Services {
		n += len(s.Dependencies)
	}
	return n
}

// Marshal writes a baseline as a file that ParseBaseline reads back to the
// same baseline: YAML, with the services and their dependencies in the
// order of Normalize, a dependency per line, so that a change of one is a
// line of a diff, and the last line that tells the file is whole. The
// baseline is checked as ParseBaseline checks a file, so that what is
// written can be read.
func (b *Baseline) Marshal() ([]byte, error) { return b.MarshalNotes(nil) }

// MarshalNotes is Marshal with a comment at the end of the line of the
// dependencies that note returns one for. A comment is kept on its line:
// its line breaks and control characters are spaces.
func (b *Baseline) MarshalNotes(note func(service string, d BaselineDependency) string) ([]byte, error) {
	var buf bytes.Buffer
	seen := map[string]bool{}
	total := 0
	if len(b.Services) == 0 {
		buf.WriteString("services: []\n")
	} else {
		buf.WriteString("services:\n")
	}
	for _, s := range b.Services {
		if err := checkBaselineName(s.Service); err != nil {
			return nil, fmt.Errorf("service %q: %w", s.Service, err)
		}
		if seen[s.Service] {
			return nil, fmt.Errorf("service %q is listed twice", s.Service)
		}
		seen[s.Service] = true
		buf.WriteString("  - service: " + yamlName(s.Service) + "\n")
		if len(s.Dependencies) == 0 {
			buf.WriteString("    dependencies: []\n")
			continue
		}
		buf.WriteString("    dependencies:\n")
		for _, d := range s.Dependencies {
			if err := d.check(); err != nil {
				return nil, fmt.Errorf("service %q: %w", s.Service, err)
			}
			total++
			fmt.Fprintf(&buf, "      - {peer: %s, port: %d, proto: %s}", yamlName(d.Peer), d.Port, d.Proto)
			if note != nil {
				if n := yamlComment(note(s.Service, d)); n != "" {
					buf.WriteString("  # " + n)
				}
			}
			buf.WriteString("\n")
		}
	}
	fmt.Fprintf(&buf, "end: {services: %d, dependencies: %d}\n", len(b.Services), total)
	return buf.Bytes(), nil
}

// yamlPlainName is a name that YAML reads as itself without quotes, in a
// list between braces too: letters, digits and the marks of the names of
// services and of shawk (shop/app, ~external, nginx.service), not starting
// with what starts something else in YAML.
func yamlPlainName(v string) bool {
	if v == "" || v == "~" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		letter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || c == '/' || c == '~'
		if !letter && (i == 0 || !(c >= '0' && c <= '9' || c == '.' || c == '-' || c == '@' || c == '+')) {
			return false
		}
	}
	// The words that a version of YAML reads as a boolean or as nothing.
	switch strings.ToLower(v) {
	case "true", "false", "null", "yes", "no", "on", "off", "y", "n":
		return false
	}
	return true
}

// yamlName writes a name of a baseline file. A name that is not plain is
// between double quotes with the escapes that Go and YAML share, on one
// line: a line break, a control character, and every character that does
// not print, such as those that turn the direction of the text around or
// have no width, are escapes, so that a file under review shows what it
// holds.
func yamlName(v string) string {
	if yamlPlainName(v) {
		return v
	}
	return strconv.Quote(v)
}

// yamlComment makes a text a comment of one line: what does not print is
// a space.
func yamlComment(v string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, v))
}

// baselineReread is how often baseline_file is read again although
// neither its size nor its time of change differ: a change that kept
// both, within the granularity of the time of a file system, is then read
// late rather than never.
const baselineReread = 5 * time.Minute

// baselineFileState is what the connector keeps of baseline_file between
// two write intervals: the file as it was when it was last read, and what
// reading it gave, a baseline or an error. One baseline at most, which
// maxFileBytes bounds.
type baselineFileState struct {
	size    int64
	changed time.Time
	readAt  time.Time
	b       *Baseline
	err     error
}

// readBaseline reads and validates baseline_file. A file of the size and
// the time of change of the last read is not read again before
// baselineReread: parsing a file of the largest size takes most of a
// second, every write interval. A file that changed within the last two
// seconds is always read again next time: its writer may not be done, and
// the time of a later change may not differ.
func (c *shawkConnector) readBaseline(now time.Time) (*Baseline, error) {
	path := c.cfg.BaselineFile
	st := &c.baselineFile
	fi, err := os.Stat(path)
	if err == nil && !st.readAt.IsZero() && fi.Size() == st.size && fi.ModTime().Equal(st.changed) &&
		now.Sub(st.readAt) < baselineReread && st.readAt.Sub(st.changed) > 2*time.Second {
		return st.b, st.err
	}
	*st = baselineFileState{}
	if err != nil {
		return nil, err
	}
	b, err := readBoundedFile(path)
	var bl *Baseline
	if err == nil {
		bl, err = ParseBaseline(b)
	}
	*st = baselineFileState{size: fi.Size(), changed: fi.ModTime(), readAt: now, b: bl, err: err}
	return bl, err
}

// syncBaseline reads baseline_file and writes it to PostgreSQL. It runs
// every write interval, once the schema is ready. Without a baseline_file
// it does nothing, so that a connector without one leaves the baseline of
// the others. A file that cannot be read or is invalid keeps the baseline
// written before, and the failure is recorded with its time, which
// Prometheus is told (shawk.baseline.file.failed): a baseline that no
// longer follows its file must not go unnoticed.
func (c *shawkConnector) syncBaseline(ctx context.Context) {
	if c.cfg.BaselineFile == "" {
		return
	}
	at := c.now()
	b, err := c.readBaseline(at)
	if err != nil {
		// The error may quote the file, so what is recorded is made
		// acceptable to PostgreSQL (see cleanString) and cut.
		msg := cleanString(cutLabel(err.Error(), maxStringBytes))
		if msg != c.baselineErr || at.Sub(c.lastBaselineLog) >= foldWarnInterval {
			c.log.Error("reading baseline_file; the baseline read before stays", zap.String("file", c.cfg.BaselineFile), zap.Error(err))
			c.baselineErr, c.lastBaselineLog = msg, at
		}
		c.baselineFailed = true
		if err := c.store.baselineFailed(ctx, at, msg); err != nil {
			c.log.Warn("recording the failure to read baseline_file in "+c.storeName(), zap.Error(err))
		}
		return
	}
	if digest := b.Digest(); digest != c.baselineDigest {
		c.log.Info("read the baseline", zap.String("file", c.cfg.BaselineFile),
			zap.Int("services", len(b.Services)), zap.Int("dependencies", b.dependencies()))
		c.baselineDigest = digest
	}
	c.baselineErr, c.baselineFailed = "", false
	if err := c.store.syncBaseline(ctx, b, at); err != nil {
		c.log.Warn("writing the baseline to "+c.storeName(), zap.Error(err))
	}
}

// How the drift from the baseline is evaluated and told to Prometheus.
const (
	// baselineWindow is the period of an evaluation: a dependency that is
	// not in the baseline of its service is told while it was active
	// within it. It also is how far before the previous evaluation the
	// next one starts, so that what was written late, by an agent whose
	// clock is behind or after PostgreSQL was down, is still judged.
	baselineWindow = time.Hour
	// baselineDelay is how long before now the period ends: both sides of
	// a new connection are written by then (docs/design.md §8), so that a
	// server is not named ~unresolved for the minute before its side is.
	baselineDelay = 5 * time.Minute
	// maxBaselineLookback bounds the period after evaluations failed for
	// long, as while PostgreSQL was down.
	maxBaselineLookback = 24 * time.Hour
	// baselineRetry is how soon an evaluation that failed is tried again,
	// rather than at the next refreshInterval.
	baselineRetry = time.Minute
	// maxDriftSeries bounds the series of the drift, and
	// maxDriftSeriesPerService those of one service: the dependencies
	// beyond them are counted (shawk.baseline.drift.truncated), not sent.
	// A service that drifts on a thousand ports, as a process that scans
	// does, uses its own share and none of the others'.
	maxDriftSeries           = 1000
	maxDriftSeriesPerService = 20
)

// Names of the metrics of the baseline, which the connector makes itself.
const (
	metricBaselineDriftHosts     = "shawk.baseline.drift.hosts"
	metricBaselineDependencies   = "shawk.baseline.dependencies"
	metricBaselineDriftTruncated = "shawk.baseline.drift.truncated"
	metricBaselineNewServices    = "shawk.baseline.new_services"
	metricBaselineHosts          = "shawk.baseline.hosts"
	metricBaselineHostsUnseen    = "shawk.baseline.hosts.unobserved"
	metricBaselineEvaluation     = "shawk.baseline.evaluation.timestamp"
	metricBaselineAttempt        = "shawk.baseline.evaluation.attempt.timestamp"
	metricBaselineEvalFailed     = "shawk.baseline.evaluation.failed"
	metricBaselineFileFailed     = "shawk.baseline.file.failed"

	// attrBaselinePeer tells the dependencies that
	// shawk.baseline.drift.truncated counts: those on a peer that shawk
	// names (named: a service, a range of peer_cidrs, ~external), whose
	// drift is critical, or on ~unresolved.
	attrBaselinePeer       = "shawk.baseline.peer"
	baselinePeerNamed      = "named"
	baselinePeerUnresolved = "unresolved"

	// connectorServiceName is the service.name of the metrics of the
	// connector that belong to no service.
	connectorServiceName = "shawk-connector"
)

// baselineReport is the result of an evaluation of the drift.
type baselineReport struct {
	// read tells that a baseline was read from a valid file, by any
	// connector; without one nothing is judged.
	read bool
	// failed tells that the latest read of a baseline_file failed.
	failed bool
	// services are the services of the baseline, each with how many
	// dependencies it has, how many hosts run it (a process of it was
	// seen there within baseline_host_memory) and how many of those were
	// not observed for the whole period: what such a host did is not
	// known, and a service without a host is not judged at all.
	services []baselineCount
	// drift are the dependencies that are not in the baseline of their
	// service: at most maxDriftSeriesPerService per service, those on a
	// named peer first, and maxDriftSeries in all, a service's first
	// before any other's second. truncatedNamed and truncatedUnresolved
	// count the others, by peer.
	drift                               []driftRow
	truncatedNamed, truncatedUnresolved int
	// newServices counts the services without a baseline first seen in
	// the period.
	newServices int
}

type baselineCount struct {
	service      string
	dependencies int
	hosts        int
	unobserved   int
}

// driftRow is a dependency that is not in the baseline of its service,
// with the number of hosts of the service that have it.
type driftRow struct {
	service, peer string
	port          int
	proto         string
	hosts         int
}

// evaluateBaselineIfDue evaluates the drift from the baseline every
// refreshInterval, with baseline_file, and keeps the result for
// emitBaseline. An evaluation that failed is tried again after
// baselineRetry; the result of the last one that succeeded stays, with
// the time it is of.
func (c *shawkConnector) evaluateBaselineIfDue(ctx context.Context) {
	if c.cfg.BaselineFile == "" || c.cfg.useSQLite() {
		return
	}
	wait := refreshInterval
	if c.baselineEvalFailed {
		wait = baselineRetry
	}
	if !c.lastBaselineTry.IsZero() && c.now().Sub(c.lastBaselineTry) < wait {
		return
	}
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if !ready {
		return
	}
	now := c.now()
	c.lastBaselineTry = now
	until := now.Add(-baselineDelay)
	since := until.Add(-baselineWindow)
	if !c.baselineUntil.IsZero() {
		if from := c.baselineUntil.Add(-baselineWindow); from.Before(since) {
			since = from
		}
		if oldest := until.Add(-maxBaselineLookback); since.Before(oldest) {
			since = oldest
		}
	}
	ectx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	r, err := c.store.baselineReport(ectx, since, until, until.Add(-c.cfg.baselineHostMemory()), maxDriftSeries, maxDriftSeriesPerService)
	if err != nil {
		c.log.Error("evaluating the drift from the baseline; the result of the last evaluation stays, and "+
			metricBaselineEvalFailed+" tells that it is old", zap.Error(err))
		c.baselineEvalFailed = true
		return
	}
	c.baselineEvalFailed = false
	c.baselineReport, c.baselineAt, c.baselineUntil = r, now, until
}

// emitBaseline sends the state of the evaluation of the drift to
// Prometheus, every write interval so that its series have no gaps, from
// the first attempt: whether the latest read of baseline_file failed,
// whether the latest evaluation failed, when the last attempt was and
// when the last one succeeded (0 before any did), so that a connector
// that never evaluated is told as one, not as one without a drift. The
// result of the last evaluation that succeeded is sent for as long as
// none replaces it: a drift does not go away because it can no longer be
// evaluated, and the time of the last success tells how old it is.
func (c *shawkConnector) emitBaseline(ctx context.Context) {
	if c.cfg.BaselineFile == "" || c.cfg.useSQLite() || c.lastBaselineTry.IsZero() {
		return
	}
	now := c.now()
	out := pmetric.NewMetrics()
	appendBaselineMetrics(out, baselineState{
		report: c.baselineReport, evaluated: c.baselineAt, attempted: c.lastBaselineTry,
		failed: c.baselineEvalFailed, fileFailed: c.baselineFailed,
	}, now)
	if err := c.next.ConsumeMetrics(ctx, out); err != nil {
		c.downstreamError(err, now)
	}
}

// baselineState is what a connector tells of its evaluation of the drift.
type baselineState struct {
	// report is the result of the last evaluation that succeeded, nil
	// before any did, and evaluated when it ran.
	report    *baselineReport
	evaluated time.Time
	// attempted is when the last evaluation was tried, and failed whether
	// it failed.
	attempted time.Time
	failed    bool
	// fileFailed tells that this connector could not read its
	// baseline_file at its last try.
	fileFailed bool
}

// appendBaselineMetrics appends the metrics of the evaluation of the drift
// to out, at now. The series of a service are on a resource of the
// service, so that Prometheus gives them its job, as it gives the series
// of its dependencies; they carry no address and no host.
func appendBaselineMetrics(out pmetric.Metrics, st baselineState, now time.Time) {
	ts := pcommon.NewTimestampFromTime(now)
	gauge := func(rm pmetric.ResourceMetrics, name, unit string) pmetric.NumberDataPointSlice {
		sms := rm.ScopeMetrics()
		if sms.Len() == 0 {
			sms.AppendEmpty().Scope().SetName(scopeName)
		}
		m := sms.At(0).Metrics().AppendEmpty()
		m.SetName(name)
		m.SetUnit(unit)
		return m.SetEmptyGauge().DataPoints()
	}
	point := func(dps pmetric.NumberDataPointSlice, v int64) pcommon.Map {
		dp := dps.AppendEmpty()
		dp.SetTimestamp(ts)
		dp.SetIntValue(v)
		return dp.Attributes()
	}
	flag := func(b bool) int64 {
		if b {
			return 1
		}
		return 0
	}
	r := st.report
	own := out.ResourceMetrics().AppendEmpty()
	own.Resource().Attributes().PutStr(attrServiceName, connectorServiceName)
	point(gauge(own, metricBaselineFileFailed, ""), flag(st.fileFailed || (r != nil && r.failed)))
	point(gauge(own, metricBaselineEvalFailed, ""), flag(st.failed))
	point(gauge(own, metricBaselineAttempt, "s"), st.attempted.Unix())
	evaluated := int64(0)
	if r != nil {
		evaluated = st.evaluated.Unix()
	}
	point(gauge(own, metricBaselineEvaluation, "s"), evaluated)
	if r == nil || !r.read {
		// No evaluation succeeded yet, or no baseline was read from a
		// valid file: nothing is judged.
		return
	}
	truncated := gauge(own, metricBaselineDriftTruncated, "{dependency}")
	point(truncated, int64(r.truncatedNamed)).PutStr(attrBaselinePeer, baselinePeerNamed)
	point(truncated, int64(r.truncatedUnresolved)).PutStr(attrBaselinePeer, baselinePeerUnresolved)
	point(gauge(own, metricBaselineNewServices, "{service}"), int64(r.newServices))

	// The names of services and peers are cut as the labels of the other
	// outputs are: two that are the same once cut are one series, with the
	// larger of their values.
	type key struct {
		peer  string
		port  int
		proto string
	}
	type service struct {
		dependencies, hosts, unobserved int
		drift                           map[key]int
	}
	services := map[string]*service{}
	var names []string
	for _, s := range r.services {
		name := cutLabel(s.service, maxPeerName)
		if services[name] == nil {
			services[name] = &service{drift: map[key]int{}, hosts: s.hosts}
			names = append(names, name)
		}
		sv := services[name]
		sv.dependencies = max(sv.dependencies, s.dependencies)
		// Of two services that are one name once cut, the one that is less
		// known: fewer hosts, and more of them not observed.
		sv.hosts = min(sv.hosts, s.hosts)
		sv.unobserved = max(sv.unobserved, s.unobserved)
	}
	for _, d := range r.drift {
		// The contract gives the drift of the services of the baseline
		// only; that of another service has no resource to be sent on.
		if s := services[cutLabel(d.service, maxPeerName)]; s != nil {
			k := key{cutLabel(d.peer, maxPeerName), d.port, d.proto}
			s.drift[k] = max(s.drift[k], d.hosts)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		s := services[name]
		rm := out.ResourceMetrics().AppendEmpty()
		rm.Resource().Attributes().PutStr(attrServiceName, name)
		point(gauge(rm, metricBaselineDependencies, "{dependency}"), int64(s.dependencies))
		point(gauge(rm, metricBaselineHosts, "{host}"), int64(s.hosts))
		point(gauge(rm, metricBaselineHostsUnseen, "{host}"), int64(s.unobserved))
		if len(s.drift) == 0 {
			continue
		}
		keys := make([]key, 0, len(s.drift))
		for k := range s.drift {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(x, y key) int {
			return compareDependencies(BaselineDependency{x.peer, x.port, x.proto}, BaselineDependency{y.peer, y.port, y.proto})
		})
		dps := gauge(rm, metricBaselineDriftHosts, "{host}")
		for _, k := range keys {
			attrs := point(dps, int64(s.drift[k]))
			attrs.PutStr(attrPeerService, k.peer)
			attrs.PutInt(attrServerPort, int64(k.port))
			attrs.PutStr(attrTransport, k.proto)
		}
	}
}
