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

func TestLiteMapDashboardWiring(t *testing.T) {
	d := loadJSON(t, filepath.Join(grafana, "dashboards-lite/shawk-map-live.json"))
	var svcQuery string
	for _, v := range d["templating"].(map[string]any)["list"].([]any) {
		v := v.(map[string]any)
		if v["name"] == "service" {
			if v["allValue"] != ".*" {
				t.Errorf("service variable allValue = %v, want .*", v["allValue"])
			}
			svcQuery = v["query"].(map[string]any)["query"].(string)
		}
	}
	m := regexp.MustCompile(`^query_result\((.*)\)$`).FindStringSubmatch(svcQuery)
	if m == nil {
		t.Fatalf("unexpected service variable query %q", svcQuery)
	}
	svcExpr := m[1]

	var nodesExpr, edgesExpr string
	for _, p := range d["panels"].([]any) {
		p := p.(map[string]any)
		if p["type"] != "nodeGraph" {
			continue
		}
		for _, tgt := range p["targets"].([]any) {
			tgt := tgt.(map[string]any)
			switch tgt["refId"] {
			case "nodes":
				nodesExpr = tgt["expr"].(string)
			case "edges":
				edgesExpr = tgt["expr"].(string)
			}
		}
	}
	if nodesExpr == "" || edgesExpr == "" {
		t.Fatalf("missing nodes/edges expr in shawk-map-live.json")
	}
	allNodes := strings.ReplaceAll(nodesExpr, `"$service"`, `".*"`)
	allEdges := strings.ReplaceAll(edgesExpr, `"$service"`, `".*"`)
	hopNodes := strings.ReplaceAll(nodesExpr, `"$service"`, `"shop/app"`)
	hopEdges := strings.ReplaceAll(edgesExpr, `"$service"`, `"shop/app"`)

	script := wiringSeries + `
load 1m
  shawk:dependency_connections:rate5m{src="shop/app", dst="shop/app", server_port="8080", network_transport="tcp"} 3x10
  shawk:dependency_connections:rate5m{src="resolver", dst="~external", server_port="53", network_transport="tcp"} 2x10
  shawk:dependency_connection_failures:rate5m{src="Web Content", dst="dead-db", server_port="5432", network_transport="tcp"} 4x10
  shawk:dependency_response_datagrams:rate5m{src="ntp-client", dst="ntp-server", server_port="123", network_transport="udp"} 5x10

# $service variable includes both src and dst across TCP, failures, and UDP request/response rules.
eval instant at 5m ` + svcExpr + `
  {service="shop/app"} 1
  {service="postgres"} 1
  {service="resolver"} 1
  {service="~external"} 1
  {service="Web Content"} 1
  {service="dead-db"} 1
  {service="ntp-client"} 1
  {service="ntp-server"} 1

# All services: TCP+UDP on same pair, self-loop, failure-only, response-only UDP, and sanitized edge id.
eval instant at 5m ` + allEdges + `
  {dst="postgres", id="shop/app__postgres", source="shop/app", src="shop/app", target="postgres"} 1
  {dst="shop/app", id="shop/app__shop/app", source="shop/app", src="shop/app", target="shop/app"} 3
  {dst="~external", id="resolver__~external", source="resolver", src="resolver", target="~external"} 2
  {dst="dead-db", id="Web_Content__dead-db", source="Web Content", src="Web Content", target="dead-db"} 0
  {dst="ntp-server", id="ntp-client__ntp-server", source="ntp-client", src="ntp-client", target="ntp-server"} 0

# Node stat uses max(out, in) so self-loop shop/app->shop/app (3) + shop/app->postgres (1) = 4, not double-counted.
eval instant at 5m ` + allNodes + `
  {id="shop/app", title="shop/app"} 4
  {id="postgres", title="postgres"} 1
  {id="resolver", title="resolver"} 2
  {id="~external", title="~external"} 2
  {id="Web Content", title="Web Content"} 0
  {id="dead-db", title="dead-db"} 0
  {id="ntp-client", title="ntp-client"} 0
  {id="ntp-server", title="ntp-server"} 0

# Selecting one service shows only its 1-hop neighborhood.
eval instant at 5m ` + hopEdges + `
  {dst="postgres", id="shop/app__postgres", source="shop/app", src="shop/app", target="postgres"} 1
  {dst="shop/app", id="shop/app__shop/app", source="shop/app", src="shop/app", target="shop/app"} 3

eval instant at 5m ` + hopNodes + `
  {id="shop/app", title="shop/app"} 4
  {id="postgres", title="postgres"} 1
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}

func TestLiteFleetDashboardWiring(t *testing.T) {
	d := loadJSON(t, filepath.Join(grafana, "dashboards-lite/shawk-fleet-live.json"))
	var silentExpr, upExpr, dropsExpr string
	for _, p := range d["panels"].([]any) {
		p := p.(map[string]any)
		switch p["title"] {
		case "Silent agents (24h)":
			silentExpr = p["targets"].([]any)[0].(map[string]any)["expr"].(string)
		case "Live agents":
			for _, tgt := range p["targets"].([]any) {
				tgt := tgt.(map[string]any)
				switch tgt["refId"] {
				case "up":
					upExpr = tgt["expr"].(string)
				case "drops":
					dropsExpr = tgt["expr"].(string)
				}
			}
		}
	}
	if silentExpr == "" || upExpr == "" || dropsExpr == "" {
		t.Fatalf("missing expected queries in shawk-fleet-live.json")
	}

	script := `
# host-a is live (with two netns_scope labels from a restart) and has drops;
# host-b stopped 20m ago after dropping flows and must count as silent only.
load 5m
  shawk_agent_up{host_name="host-a", shawk_netns_scope="host"} 1x10
  shawk_agent_up{host_name="host-a", shawk_netns_scope="all"} 1x10
  shawk_agent_flows_dropped_total{host_name="host-a"} 0+1x10
  shawk_agent_up{host_name="host-b", shawk_netns_scope="all"} 1 1 1 1 1 _ _ _ _ _
  shawk_agent_flows_dropped_total{host_name="host-b"} 0 2 4 6 8 _ _ _ _ _

eval instant at 45m ` + silentExpr + `
  {} 1

eval instant at 45m ` + upExpr + `
  {host_name="host-a"} 1

eval instant at 45m ` + dropsExpr + `
  {host_name="host-a"} 9
`
	promqltest.RunTest(t, script, promqltest.NewTestEngine(t, false, 0, promqltest.DefaultMaxSamplesPerQuery))
}
