package packaging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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
func TestDashboardSQLVariables(t *testing.T) {
	sqlstring := regexp.MustCompile(`^\$\{\w+:sqlstring\}$`)
	files, _ := filepath.Glob(filepath.Join(grafana, "dashboards/*.json"))
	n := 0
	for _, f := range files {
		walk(loadJSON(t, f), func(o map[string]any) {
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
				for _, m := range grafanaInterpolation.FindAllString(sql, -1) {
					if !strings.HasPrefix(m, "$__") && !sqlstring.MatchString(m) {
						t.Errorf("%s: %s is interpolated without the sqlstring format:\n%s", f, m, sql)
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
	datasources := provisionedDatasources(t)
	b, err := os.ReadFile(filepath.Join(grafana, "provisioning/alerting/shawk-rules.yaml"))
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
	if n < 3 {
		t.Errorf("%d alert rules", n)
	}
}
