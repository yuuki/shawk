package packaging

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/promql/promqltest"
)

// The tests in this file evaluate the PromQL of dashboard variables and
// panels on series like those Prometheus holds, so that a variable that
// misses services or a panel that never matches is caught; parsing alone
// does not.

// variableQuery returns the query of a dashboard variable.
func variableQuery(t *testing.T, dashboard, name string) string {
	t.Helper()
	d := loadJSON(t, filepath.Join(grafana, "dashboards", dashboard))
	for _, v := range d["templating"].(map[string]any)["list"].([]any) {
		v := v.(map[string]any)
		if v["name"] == name {
			if q, ok := v["query"].(map[string]any); ok {
				return q["query"].(string)
			}
			return v["query"].(string)
		}
	}
	t.Fatalf("%s has no variable %s", dashboard, name)
	return ""
}

// panelExpr returns the PromQL of the first query of a panel.
func panelExpr(t *testing.T, dashboard, title string) string {
	t.Helper()
	d := loadJSON(t, filepath.Join(grafana, "dashboards", dashboard))
	for _, p := range d["panels"].([]any) {
		p := p.(map[string]any)
		if p["title"] == title {
			return p["targets"].([]any)[0].(map[string]any)["expr"].(string)
		}
	}
	t.Fatalf("%s has no panel %q", dashboard, title)
	return ""
}

var labelValues = regexp.MustCompile(`^label_values\((.*), (\w+)\)$`)

// asCount turns label_values(selector, label) into a PromQL expression that
// returns one series per value, with All selected in other variables.
func asCount(t *testing.T, q string) string {
	t.Helper()
	m := labelValues.FindStringSubmatch(q)
	if m == nil {
		t.Fatalf("not label_values: %s", q)
	}
	sel := strings.ReplaceAll(m[1], `"$src"`, `".*"`)
	return "count by (" + m[2] + ") (" + sel + ")"
}

const wiringSeries = `
load 1m
  shawk:dependency_connections:rate5m{src="shop/app", dst="postgres", server_port="5432", network_transport="tcp"} 1x10
  shawk:dependency_request_datagrams:rate5m{src="resolver", dst="~external", server_port="53", network_transport="udp"} 1x10
  shawk_connection_opened_total{job="shop/app", shawk_role="client"} 0+1x10
  shawk_connection_opened_total{job="postgres", shawk_role="server"} 0+1x10
  shawk_udp_datagrams_total{job="named", shawk_role="server"} 0+1x10
  traces_service_graph_request_total{client="app", server="postgres"} 0+1x10
`

func TestDashboardWiring(t *testing.T) {
	gap := panelExpr(t, "shawk-dependency.json", "Dependencies without application-layer instrumentation")
	gap = strings.NewReplacer(`"$src"`, `".*"`, `"$dst"`, `".*"`).Replace(gap)
	script := wiringSeries + `
# Clients and servers to choose include UDP dependencies.
eval instant at 5m ` + asCount(t, variableQuery(t, "shawk-dependency.json", "src")) + `
  {src="shop/app"} 1
  {src="resolver"} 1

eval instant at 5m ` + asCount(t, variableQuery(t, "shawk-dependency.json", "dst")) + `
  {dst="postgres"} 1
  {dst="~external"} 1

# Services to choose are local services, clients and servers alike.
eval instant at 5m ` + asCount(t, variableQuery(t, "shawk-application.json", "service")) + `
  {job="shop/app"} 1
  {job="postgres"} 1
  {job="named"} 1

# shop/app is instrumented as app: the service graph has no namespace.
eval instant at 5m ` + inline(gap, nil) + `

# A dependency of app absent from the service graph is a gap.
load 1m
  shawk:dependency_connections:rate5m{src="shop/app", dst="redis", server_port="6379", network_transport="tcp"} 1x10

eval instant at 5m ` + inline(gap, nil) + `
  {src="app", dst="redis"} 1
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}
