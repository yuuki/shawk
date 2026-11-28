package shawkconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
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

// baselineFile is the format of baseline_file, in YAML or JSON:
//
//	services:
//	  - service: shop/app
//	    dependencies:
//	      - {peer: shop/postgres, port: 5432, proto: tcp}
//	      - {peer: ~external, port: 443, proto: tcp}
//	  - service: batch/report
//	    dependencies: []          # approved to have none
type baselineFile struct {
	Services *[]baselineFileService `yaml:"services"`
}

type baselineFileService struct {
	Service      string                `yaml:"service"`
	Dependencies *[]baselineFileDepend `yaml:"dependencies"`
}

type baselineFileDepend struct {
	Peer  string `yaml:"peer"`
	Port  *int   `yaml:"port"`
	Proto string `yaml:"proto"`
}

// errNoBaseline refuses a file without the list of services, as a
// generator that failed may leave: it would drop every baseline. A list
// that is there and empty is a baseline of no service.
var errNoBaseline = errors.New("no services: write `services: []` for a baseline of no service")

// ParseBaseline parses and validates the contents of a baseline file.
// Unknown fields are refused, so that a misspelt field is not taken as
// absent, and so is a service without the list of its dependencies, which
// would otherwise approve none without a word.
func ParseBaseline(b []byte) (*Baseline, error) {
	var f baselineFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errNoBaseline
		}
		return nil, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	if f.Services == nil {
		return nil, errNoBaseline
	}
	if len(*f.Services) > MaxBaselineServices {
		return nil, fmt.Errorf("more than %d services", MaxBaselineServices)
	}
	out := &Baseline{Services: make([]BaselineService, 0, len(*f.Services))}
	seen := map[string]bool{}
	total := 0
	for i, fs := range *f.Services {
		if err := checkBaselineName(fs.Service); err != nil {
			return nil, fmt.Errorf("services[%d]: service: %w", i, err)
		}
		if seen[fs.Service] {
			return nil, fmt.Errorf("service %q is listed twice", fs.Service)
		}
		seen[fs.Service] = true
		if fs.Dependencies == nil {
			return nil, fmt.Errorf("service %q: no dependencies: write `dependencies: []` for a service that has none", fs.Service)
		}
		s := BaselineService{Service: fs.Service, Dependencies: make([]BaselineDependency, 0, len(*fs.Dependencies))}
		for j, fd := range *fs.Dependencies {
			d, err := fd.dependency()
			if err != nil {
				return nil, fmt.Errorf("service %q: dependencies[%d]: %w", fs.Service, j, err)
			}
			s.Dependencies = append(s.Dependencies, d)
		}
		if total += len(s.Dependencies); total > MaxBaselineDependencies {
			return nil, fmt.Errorf("more than %d dependencies", MaxBaselineDependencies)
		}
		out.Services = append(out.Services, s)
	}
	out.Normalize()
	return out, nil
}

// dependency checks a dependency of the file.
func (fd baselineFileDepend) dependency() (BaselineDependency, error) {
	d := BaselineDependency{Peer: fd.Peer, Proto: fd.Proto}
	if err := checkBaselineName(d.Peer); err != nil {
		return d, fmt.Errorf("peer: %w", err)
	}
	if fd.Port == nil {
		return d, errors.New("no port: write 0 for every port")
	}
	if d.Port = *fd.Port; d.Port < 0 || d.Port > 65535 {
		return d, fmt.Errorf("port %d is not from 0 to 65535", d.Port)
	}
	if d.Proto != "tcp" && d.Proto != "udp" {
		return d, fmt.Errorf("proto %q is not tcp or udp", d.Proto)
	}
	return d, nil
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
// order of Normalize and a dependency per line, so that a change of one is
// a line of a diff. The baseline is checked as ParseBaseline checks a
// file, so that what is written can be read.
func (b *Baseline) Marshal() ([]byte, error) {
	services := &yaml.Node{Kind: yaml.SequenceNode}
	seen := map[string]bool{}
	for _, s := range b.Services {
		if err := checkBaselineName(s.Service); err != nil {
			return nil, fmt.Errorf("service %q: %w", s.Service, err)
		}
		if seen[s.Service] {
			return nil, fmt.Errorf("service %q is listed twice", s.Service)
		}
		seen[s.Service] = true
		deps := &yaml.Node{Kind: yaml.SequenceNode}
		for _, d := range s.Dependencies {
			if _, err := (baselineFileDepend{Peer: d.Peer, Port: &d.Port, Proto: d.Proto}).dependency(); err != nil {
				return nil, fmt.Errorf("service %q: %w", s.Service, err)
			}
			dep := yamlMapping("peer", yamlString(d.Peer), "port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(d.Port)},
				"proto", yamlString(d.Proto))
			dep.Style = yaml.FlowStyle
			deps.Content = append(deps.Content, dep)
		}
		services.Content = append(services.Content, yamlMapping("service", yamlString(s.Service), "dependencies", deps))
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(yamlMapping("services", services)); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// yamlString is a string of a baseline file. The encoder quotes what YAML
// would read as something else than the string. It would write a string
// with a line break as a block of several lines, and one that starts with
// a line break as a block that its own parser does not read back: such a
// string is quoted, on one line, as every name of a file under review.
func yamlString(v string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
	if strings.ContainsAny(v, "\n\r") {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}

// yamlMapping is a mapping of keys, which are words of the format, and
// their values.
func yamlMapping(pairs ...any) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(pairs); i += 2 {
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pairs[i].(string)}, pairs[i+1].(*yaml.Node))
	}
	return m
}

// readBaseline reads and validates baseline_file.
func readBaseline(path string) (*Baseline, error) {
	b, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBaseline(b)
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
	b, err := readBaseline(c.cfg.BaselineFile)
	if err != nil {
		// The error may quote the file, so what is recorded is made
		// acceptable to PostgreSQL (see cleanString) and cut.
		msg := cleanString(cutLabel(err.Error(), maxStringBytes))
		if msg != c.baselineErr || at.Sub(c.lastBaselineLog) >= foldWarnInterval {
			c.log.Error("reading baseline_file; the baseline read before stays", zap.String("file", c.cfg.BaselineFile), zap.Error(err))
			c.baselineErr, c.lastBaselineLog = msg, at
		}
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
	c.baselineErr = ""
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
	// maxDriftSeries bounds the series of the drift: the dependencies
	// beyond it are counted (shawk.baseline.drift.truncated), not sent.
	maxDriftSeries = 1000
	// baselineStale is how long the result of an evaluation is sent: once
	// evaluations have failed for longer, the series of the drift stop
	// rather than tell a drift, or none, that is no longer known.
	baselineStale = 15 * time.Minute
)

// Names of the metrics of the baseline, which the connector makes itself.
const (
	metricBaselineDriftHosts     = "shawk.baseline.drift.hosts"
	metricBaselineDependencies   = "shawk.baseline.dependencies"
	metricBaselineDriftTruncated = "shawk.baseline.drift.truncated"
	metricBaselineNewServices    = "shawk.baseline.new_services"
	metricBaselineEvaluation     = "shawk.baseline.evaluation.timestamp"
	metricBaselineFileFailed     = "shawk.baseline.file.failed"

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
	// services are the services of the baseline with how many
	// dependencies each has.
	services []baselineCount
	// drift are the dependencies that are not in the baseline of their
	// service, at most maxDriftSeries of them in the order of their
	// service, peer, port and transport, and truncated counts the others.
	drift     []driftRow
	truncated int
	// newServices counts the services without a baseline first seen in
	// the period.
	newServices int
}

type baselineCount struct {
	service      string
	dependencies int
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
// emitBaseline.
func (c *shawkConnector) evaluateBaselineIfDue(ctx context.Context) {
	if c.cfg.BaselineFile == "" || c.cfg.useSQLite() || c.now().Sub(c.lastBaselineTry) < refreshInterval {
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
	r, err := c.store.baselineReport(ectx, since, until, maxDriftSeries)
	if err != nil {
		c.log.Error("evaluating the drift from the baseline; its metrics stop once the last result is older than "+
			baselineStale.String(), zap.Error(err))
		return
	}
	c.baselineReport, c.baselineAt, c.baselineUntil = r, now, until
}

// emitBaseline sends the result of the latest evaluation of the drift to
// Prometheus, every write interval so that its series have no gaps.
// Whether the latest read of a baseline_file failed is sent for as long as
// there was an evaluation, and so is the end of its period once a baseline
// was read; the rest only while the result is fresh: a drift that is no
// longer known is not told, and neither is its absence.
func (c *shawkConnector) emitBaseline(ctx context.Context) {
	r := c.baselineReport
	if r == nil {
		return
	}
	now := c.now()
	out := pmetric.NewMetrics()
	appendBaselineMetrics(out, r, c.baselineUntil, now, now.Sub(c.baselineAt) <= baselineStale)
	if err := c.next.ConsumeMetrics(ctx, out); err != nil {
		c.downstreamError(err, now)
	}
}

// appendBaselineMetrics appends the metrics of an evaluation of the drift
// over a period that ended at until to out, at now. The series of a
// service are on a resource of the service, so that Prometheus gives them
// its job, as it gives the series of its dependencies; they carry no
// address and no host.
func appendBaselineMetrics(out pmetric.Metrics, r *baselineReport, until, now time.Time, fresh bool) {
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
	own := out.ResourceMetrics().AppendEmpty()
	own.Resource().Attributes().PutStr(attrServiceName, connectorServiceName)
	failed := int64(0)
	if r.failed {
		failed = 1
	}
	point(gauge(own, metricBaselineFileFailed, ""), failed)
	if !r.read {
		// No baseline was read from a valid file yet: nothing is judged.
		return
	}
	point(gauge(own, metricBaselineEvaluation, "s"), until.Unix())
	if !fresh {
		return
	}
	point(gauge(own, metricBaselineDriftTruncated, "{dependency}"), int64(r.truncated))
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
		dependencies int
		drift        map[key]int
	}
	services := map[string]*service{}
	var names []string
	for _, s := range r.services {
		name := cutLabel(s.service, maxPeerName)
		if services[name] == nil {
			services[name] = &service{drift: map[key]int{}}
			names = append(names, name)
		}
		services[name].dependencies = max(services[name].dependencies, s.dependencies)
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
