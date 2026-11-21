package packaging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/promql/parser"
	"go.yaml.in/yaml/v3"
)

const grafana = "../../packaging/grafana"

func loadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

// walk calls f with every object in v.
func walk(v any, f func(map[string]any)) {
	switch v := v.(type) {
	case map[string]any:
		f(v)
		for _, x := range v {
			walk(x, f)
		}
	case []any:
		for _, x := range v {
			walk(x, f)
		}
	}
}

func provisionedDatasources(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(grafana, "provisioning/datasources/shawk.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Datasources []struct {
			UID  string `yaml:"uid"`
			Type string `yaml:"type"`
		} `yaml:"datasources"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range doc.Datasources {
		out[d.UID] = d.Type
	}
	return out
}

var grafanaVar = regexp.MustCompile(`\$\{?(\w+)(:\w+)?\}?`)

// expandVars replaces the Grafana variables of a PromQL expression.
func expandVars(expr string) string {
	return grafanaVar.ReplaceAllStringFunc(expr, func(s string) string {
		switch {
		case strings.Contains(s, "__rate_interval"), strings.Contains(s, "__interval"):
			return "5m"
		case s == "$1":
			return s // label_replace references
		}
		return "x"
	})
}

func TestDashboards(t *testing.T) {
	records, _ := loadRules(t)
	datasources := provisionedDatasources(t)
	files, _ := filepath.Glob(filepath.Join(grafana, "dashboards/*.json"))
	if len(files) < 4 {
		t.Fatalf("%d dashboards", len(files))
	}
	uids := map[string]bool{}
	for _, f := range files {
		d := loadJSON(t, f)
		uid, _ := d["uid"].(string)
		if uid == "" || uids[uid] {
			t.Errorf("%s: missing or duplicate uid %q", f, uid)
		}
		uids[uid] = true
		ids := map[float64]bool{}
		for _, p := range d["panels"].([]any) {
			p := p.(map[string]any)
			id := p["id"].(float64)
			if ids[id] {
				t.Errorf("%s: duplicate panel id %v", f, id)
			}
			ids[id] = true
			if _, ok := p["gridPos"].(map[string]any); !ok {
				t.Errorf("%s: panel %v has no gridPos", f, p["title"])
			}
		}
		walk(d, func(o map[string]any) {
			if ds, ok := o["datasource"].(map[string]any); ok {
				uid, _ := ds["uid"].(string)
				typ, _ := ds["type"].(string)
				if typ != "grafana" && datasources[uid] != typ {
					t.Errorf("%s: data source %s of type %s is not provisioned", f, uid, typ)
				}
			}
			expr, ok := o["expr"].(string)
			if !ok {
				if q, ok := o["query"].(map[string]any); ok {
					expr, _ = q["query"].(string)
					// label_values(metric, label) is a Grafana function.
					if m := regexp.MustCompile(`^label_values\((.*), \w+\)$`).FindStringSubmatch(expr); m != nil {
						expr = m[1]
					} else {
						expr = ""
					}
				}
			}
			if expr == "" {
				return
			}
			e := expandVars(expr)
			if _, err := parser.NewParser(parser.Options{}).ParseExpr(e); err != nil {
				t.Errorf("%s: %v\n%s", f, err, e)
			}
			for _, m := range regexp.MustCompile(`shawk:[a-z_:0-9]+`).FindAllString(expr, -1) {
				if _, ok := records[m]; !ok {
					t.Errorf("%s: unknown recording rule %s", f, m)
				}
			}
		})
	}
}

// The peer hosts dashboard populates its variables from recording rules.
// UDP edges emit byte metrics rather than connections or failures, so each
// variable must match both byte recording rules (for asymmetric or
// response-only flows as well) alongside connections and failures, keep
// query and definition in sync, and only query rules that keep its label.
func TestHostsDashboardVariables(t *testing.T) {
	records, _ := loadRules(t)
	d := loadJSON(t, filepath.Join(grafana, "dashboards/shawk-hosts.json"))
	templating, _ := d["templating"].(map[string]any)
	list, _ := templating["list"].([]any)
	wantVars := map[string]bool{"dst": false, "src": false, "dst_host": false}
	wantRules := []string{
		"shawk:host_dependency_connections:rate5m",
		"shawk:host_dependency_connection_failures_by_reason:rate5m",
		"shawk:host_dependency_request_bytes:rate5m",
		"shawk:host_dependency_response_bytes:rate5m",
	}
	labelValuesRe := regexp.MustCompile(`^label_values\((.*), (\w+)\)$`)
	p := parser.NewParser(parser.Options{})
	for _, item := range list {
		v, _ := item.(map[string]any)
		name, _ := v["name"].(string)
		if _, ok := wantVars[name]; !ok {
			continue
		}
		wantVars[name] = true
		q, _ := v["query"].(map[string]any)
		query, _ := q["query"].(string)
		def, _ := v["definition"].(string)
		if query == "" || query != def {
			t.Errorf("variable %s: query %q != definition %q", name, query, def)
		}
		m := labelValuesRe.FindStringSubmatch(query)
		if m == nil || m[2] != name {
			t.Errorf("variable %s: unexpected label_values query %q", name, query)
			continue
		}
		parsed, err := p.ParseExpr(expandVars(m[1]))
		if err != nil {
			t.Errorf("variable %s: %v\n%s", name, err, m[1])
			continue
		}
		vs, ok := parsed.(*parser.VectorSelector)
		if !ok {
			t.Errorf("variable %s: selector %q parsed as %T, want *parser.VectorSelector", name, m[1], parsed)
			continue
		}
		var nameMatcher interface{ Matches(string) bool }
		for _, lm := range vs.LabelMatchers {
			if lm.Name == "__name__" {
				nameMatcher = lm
				break
			}
		}
		if nameMatcher == nil {
			t.Errorf("variable %s: no __name__ matcher in %q", name, m[1])
			continue
		}
		for _, rule := range wantRules {
			if !nameMatcher.Matches(rule) {
				t.Errorf("variable %s: __name__ matcher in %q does not match %s", name, m[1], rule)
			}
		}
	}
	for name, seen := range wantVars {
		if !seen {
			t.Errorf("shawk-hosts.json: missing variable %s", name)
		}
	}
	for _, rule := range wantRules {
		expr, ok := records[rule]
		if !ok {
			t.Errorf("recording rule %s not found in shawk-rules.yml", rule)
			continue
		}
		parsed, err := p.ParseExpr(expr)
		if err != nil {
			t.Errorf("recording rule %s: %v", rule, err)
			continue
		}
		agg, ok := parsed.(*parser.AggregateExpr)
		if !ok || agg.Without {
			t.Errorf("recording rule %s: expected sum by (...) expression, got %T", rule, parsed)
			continue
		}
		for name := range wantVars {
			if !slices.Contains(agg.Grouping, name) {
				t.Errorf("recording rule %s does not preserve label %s (grouping: %v)", rule, name, agg.Grouping)
			}
		}
	}
}

// grafanaInterpolation matches what Grafana interpolates in a query, like
// its variableRegex: $name, [[name]], [[name:format]], ${name},
// ${name.field} and ${name:format}.
var grafanaInterpolation = regexp.MustCompile(`\$(\w+)|\[\[(\w+?)(?::(\w+))?\]\]|\$\{(\w+)(?:\.([^:^\}]+))?(?::([^\}]+))?\}`)

// A link sets any value of a variable (?var-name=), even one that is not
// among its options, and the queries run as whoever opens it. The SQL of
// the dashboards interpolates variables only with the sqlstring format,
// which quotes each value and doubles its quotes; a number is cast from
// that string, e.g. ${depth:sqlstring}::int, so that a value that is not a
// number fails the query. Without a format, the PostgreSQL data source
// inserts a single value unquoted, which outside quotes is SQL; the
// singlequote format escapes a quote with a backslash, which PostgreSQL
// reads as a backslash (standard_conforming_strings), so that the quote
// ends the string. Macros ($__timeFrom() etc.) are not variables.
//
// A variable of several values (multi or includeAll) has none when its
// query finds none, e.g. options from Prometheus over a time range it no
// longer holds, and the sqlstring format then gives nothing: such a
// variable is interpolated as an array, ARRAY[${name:sqlstring}]::text[],
// which is empty then, rather than in IN (...), which fails.
func TestDashboardSQLVariables(t *testing.T) {
	sqlstring := regexp.MustCompile(`^\$\{\w+:sqlstring\}$`)
	files, _ := filepath.Glob(filepath.Join(grafana, "dashboards/*.json"))
	n := 0
	for _, f := range files {
		d := loadJSON(t, f)
		multi := map[string]bool{}
		templating, _ := d["templating"].(map[string]any)
		vars, _ := templating["list"].([]any)
		for _, v := range vars {
			v, _ := v.(map[string]any)
			if name, _ := v["name"].(string); v["multi"] == true || v["includeAll"] == true {
				multi[name] = true
			}
		}
		walk(d, func(o map[string]any) {
			var queries []string
			if s, ok := o["rawSql"].(string); ok {
				queries = append(queries, s)
			}
			// The options of a variable from PostgreSQL.
			if ds, ok := o["datasource"].(map[string]any); ok && ds["type"] == "grafana-postgresql-datasource" {
				for _, k := range []string{"query", "definition"} {
					if s, ok := o[k].(string); ok {
						queries = append(queries, s)
					}
				}
			}
			for _, sql := range queries {
				n++
				for _, m := range grafanaInterpolation.FindAllStringSubmatchIndex(sql, -1) {
					s := sql[m[0]:m[1]]
					if strings.HasPrefix(s, "$__") {
						continue
					}
					if !sqlstring.MatchString(s) {
						t.Errorf("%s: %s is interpolated without the sqlstring format:\n%s", f, s, sql)
						continue
					}
					if multi[sql[m[8]:m[9]]] &&
						(!strings.HasSuffix(sql[:m[0]], "ARRAY[") || !strings.HasPrefix(sql[m[1]:], "]::text[]")) {
						t.Errorf("%s: %s has several values, which are not interpolated as ARRAY[%[2]s]::text[]:\n%s", f, s, sql)
					}
				}
			}
		})
	}
	if n < 15 {
		t.Errorf("only %d SQL queries found", n)
	}
}

// The Node Graph refers to the arrowhead of an edge by the id of the edge,
// unescaped, in url(#...): the spaces of the ids of shawk_v1.graph_edges
// (client -> server) make the reference invalid and the arrowhead
// disappear. Edges queries hash them.
func TestNodeGraphEdgeIDs(t *testing.T) {
	hashed := regexp.MustCompile(`(?m)^SELECT md5\(\w+\.id\) AS id,`)
	files, _ := filepath.Glob(filepath.Join(grafana, "dashboards/*.json"))
	n := 0
	for _, f := range files {
		walk(loadJSON(t, f), func(p map[string]any) {
			if p["type"] != "nodeGraph" {
				return
			}
			targets, _ := p["targets"].([]any)
			for _, q := range targets {
				q, _ := q.(map[string]any)
				if q["refId"] != "edges" {
					continue
				}
				n++
				if sql, _ := q["rawSql"].(string); !hashed.MatchString(sql) {
					t.Errorf("%s: panel %v: the edges query must select md5(id) AS id:\n%s", f, p["title"], sql)
				}
			}
		})
	}
	if n == 0 {
		t.Error("no edges query of a node graph")
	}
}

func TestAlertRules(t *testing.T) {
	if n := checkAlertRules(t, "shawk-rules.yaml"); n < 3 {
		t.Errorf("%d alert rules", n)
	}
	// The opt-in rules for the compute nodes of HPC clusters.
	if n := checkAlertRules(t, "shawk-compute-nodes.yaml.example"); n != 1 {
		t.Errorf("%d alert rules for compute nodes", n)
	}
}

// checkAlertRules checks a file of alert rules of the provisioning and
// returns the number of its rules.
func checkAlertRules(t *testing.T, name string) int {
	t.Helper()
	datasources := provisionedDatasources(t)
	b, err := os.ReadFile(filepath.Join(grafana, "provisioning/alerting", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				UID         string `yaml:"uid"`
				Title       string `yaml:"title"`
				Condition   string `yaml:"condition"`
				NoDataState string `yaml:"noDataState"`
				Data        []struct {
					RefID         string         `yaml:"refId"`
					DatasourceUID string         `yaml:"datasourceUid"`
					Model         map[string]any `yaml:"model"`
				} `yaml:"data"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range doc.Groups {
		for _, r := range g.Rules {
			n++
			if r.NoDataState != "OK" {
				t.Errorf("%s: No Data must be Normal (OK), not %q", r.Title, r.NoDataState)
			}
			refs := map[string]bool{}
			for _, d := range r.Data {
				refs[d.RefID] = true
				if d.DatasourceUID != "__expr__" && datasources[d.DatasourceUID] == "" {
					t.Errorf("%s: unknown data source %s", r.Title, d.DatasourceUID)
				}
				if d.DatasourceUID == "shawk-postgres" {
					if d.Model["format"] != "time_series" {
						t.Errorf("%s: SQL alert queries must use the time series format", r.Title)
					}
					// Grafana requires rows sorted by time, and a series
					// without a value at the last time reduces to nothing:
					// every row carries the same time, now().
					sql, _ := d.Model["rawSql"].(string)
					if !strings.Contains(sql, "SELECT now() AS time") || !strings.Contains(sql, "ORDER BY 1") {
						t.Errorf("%s: an SQL alert query must select now() AS time and ORDER BY 1:\n%s", r.Title, sql)
					}
				}
				if d.Model["type"] == "reduce" {
					settings, _ := d.Model["settings"].(map[string]any)
					if settings["mode"] != "dropNN" {
						t.Errorf("%s: reduce %s does not drop nulls", r.Title, d.RefID)
					}
				}
			}
			if !refs[r.Condition] {
				t.Errorf("%s: condition %s is not a query", r.Title, r.Condition)
			}
		}
	}
	return n
}
