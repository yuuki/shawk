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
				if d.DatasourceUID == "shawk-postgres" && d.Model["format"] != "time_series" {
					t.Errorf("%s: SQL alert queries must use the time series format", r.Title)
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
