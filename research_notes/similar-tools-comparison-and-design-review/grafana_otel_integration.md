# Grafana / Prometheus / OpenTelemetry integration mechanics for a PostgreSQL relationship store + OTLP metrics design (state as of 2026-10-31)

Versions seen during research: Grafana docs "latest" list Grafana 13.3 as newest ([What's new index](https://grafana.com/docs/grafana/latest/whatsnew/)). Prometheus latest release is 3.15.1 (2026-10-21) ([CHANGELOG](https://github.com/prometheus/prometheus/blob/main/CHANGELOG.md)). PostgreSQL docs "current" = 18 (18.6) ([PostgreSQL docs](https://www.postgresql.org/docs/current/queries-with.html)).

## 1. Grafana Node Graph panel: data frame contract, frame recognition, limits, layouts, and Prometheus-based node graphs

### Takeaway
The Node Graph panel takes two frames (nodes and edges) recognised by refId/frame name `nodes`/`edges`, by `preferredVisualisationType = 'nodeGraph'`, or by an `id` field. So a PostgreSQL panel with two queries whose refIds are `nodes` and `edges`, returning correctly aliased columns, works with no transformation. The panel shows 200 visible nodes by default and hides the rest behind expandable markers. Layered layout gets slow above about 500 nodes, so N-hop SQL scoping is the right design. There is no built-in "Prometheus client/server labels → node graph" converter outside Tempo's service graph. Caretta shows a working pattern that uses Prometheus instant queries in table format with refIds `nodes`/`edges` and `label_replace`.

### Cited Findings
- **Frame recognition.** "Grafana recognizes node graph frames when `frame.meta.preferredVisualisationType = 'nodeGraph'`, when the frame name or `refId` is `nodes` or `edges`, or when a frame contains an `id` field." — [Grafana Node graph docs](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)
- **Edges frame.** Required fields: `id`, `source`, `target`. Optional fields: `mainstat`, `secondarystat`, `detail__*`, `thickness` (default 1), `highlighted` (default false), `color` (default `#999`), `strokeDasharray` (dash pattern; solid if unset). — [Node graph docs](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)
- **Nodes frame.** Required field: `id`. Optional fields: `title`, `subtitle`, `mainstat`, `secondarystat`, `arc__*`, `detail__*`, `color`, `icon`, `nodeRadius`, `highlighted`, `fixedX`, `fixedY`. — [Node graph docs](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)
  - `arc__*`: "All values in these fields should add up to 1."
  - `fixedX`/`fixedY`: if one node uses them, every node must provide them.
  - `icon`: only Grafana built-in icons are allowed, and it replaces the title/subtitle display.
  - `color` "Can be used to specify a single color instead of using the `arc__` fields."
- **Deprecation.** "Starting with 10.5, `highlighted` is deprecated". Use `color` for a highlighted edge instead. — [Node graph docs](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)
- **Visible node limit.** "Node graphs show up to 200 visible nodes by default". Extra nodes are hidden "for performance reasons" behind clickable markers that expand the graph around that node. — [Node graph docs](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/node-graph.md)
- **Layouts.** Layered is the default ("a predictable and orderly layout") and "can be slow when the graph has more than 500 nodes". Force is "useful with a large number of nodes (500+)". Grid shows nodes without edges, sortable by stats. Zoom mode can be Cooperative or Greedy. Node options include main stat unit, secondary stat unit, and arc sections. — [Node graph docs](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)
- **Data links.** Clicking a node or edge opens a context menu. "There also can be additional links in the context menu that can target either other parts of Grafana or any external link". Data links can be added with field overrides. Actions aren't supported. — [Node graph docs (md)](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/node-graph.md)
- **Supported sources.** The docs name only the X-Ray data source ("The first data source supporting this visualization is X-Ray data source for its Service map feature"). Prometheus isn't mentioned. — [Node graph docs](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)
- **Community report on SQL sources.** Users building node graphs from two SQL tables had to name or flag both frames. One reply said column aliases are case sensitive. Another report of "No Data" was attributed to a specific Grafana release. — [Grafana community: Node Graph with SQL-Tables](https://community.grafana.com/t/grafana-node-graph-with-sql-tables/61919)
- **Community report on large graphs.** On Grafana 11, a user saw "12 nodes are hidden for performance reasons" and the panel then hung at "Computing layout". — [Grafana community: nodes hidden for performance reasons](https://community.grafana.com/t/node-graph-issue-nodes-are-hidden-for-performance-reasons/147404)
- **Tempo service graph.** The Tempo data source's Service Graph renders a node graph from Prometheus metrics (`traces_service_graph_request_total`, `traces_service_graph_request_failed_total`, `traces_service_graph_request_server_seconds`, `traces_service_graph_request_client_seconds`). The metrics are produced by the Tempo metrics generator or Grafana Alloy, and the Prometheus data source is linked in the Tempo data source settings. — [Grafana Tempo service graph docs](https://grafana.com/docs/grafana/latest/datasources/tempo/service-graph/)
- **Caretta precedent (eBPF agent, Prometheus metric `caretta_links_observed`).** Caretta's shipped dashboard uses a Node Graph panel on a Prometheus data source with no transformations, verified by downloading `chart/dashboard.json`:
  - Two instant queries in table format, with refIds `nodes` and `edges`.
  - The nodes query is `sum by (id, title, subTitle, detail__kind, arc__color)(label_replace(... "id","$1","server_id" ...) or label_replace(... client_id ...))`.
  - The edges query is `sum by (id, source, target, mainStat)(label_replace(... "id" ← link_id, "source" ← client_id, "target" ← server_id, "mainStat" ← server_port))`, wrapped in `increase(...[$__range:$__interval]) > 0`.
  - The metric carries numeric `link_id`/`client_id`/`server_id` labels specifically for the node graph.
  - Sources: [groundcover-com/caretta chart/dashboard.json](https://github.com/groundcover-com/caretta/blob/main/chart/dashboard.json); label scheme in [Caretta repo](https://github.com/groundcover-com/caretta) and [DeepWiki summary](https://deepwiki.com/groundcover-com/caretta/2.4-metrics-and-observability).
- **Graphviz panel.** Grafana 13.0 added a Graphviz panel ("define interactive diagrams in the Graphviz DOT language", live data from any data source), tagged "Available in private preview". — [What's new in Grafana 13.0](https://grafana.com/docs/grafana/latest/whatsnew/whats-new-in-v13-0/)

### Inferences
- **PostgreSQL views map directly to the contract.** Planned views `graph_nodes(id,title,subtitle,mainstat)` and `graph_edges(id,source,target,mainstat)` fit the panel. Give the two panel queries refIds `nodes` and `edges` (or rely on the `id` field). PostgreSQL folds unquoted aliases to lower case, so `AS mainStat` arrives as `mainstat`, which matches the documented names. Caretta's `subTitle`/`mainStat` on Prometheus suggest Grafana matches these names case-insensitively in practice, but the community thread claims case sensitivity. Use lower-case names to be safe.
- **Use stable, unique node `id`s.** Edges reference nodes by `id`, so every `source`/`target` value must appear as a node `id` in the same panel. Otherwise edges dangle. A recursive N-hop query therefore needs to emit both the edge set and the closure of nodes it touches.
- **Scope the graph in SQL.** Because of the 200-visible-node default and layered-layout slowness above about 500 nodes, the SQL views should limit the graph (N hops, a time window, collapsing externals into "external"). Fleet-wide graphs should use Force layout or a table.
- **Prometheus-only node graphs are possible.** A node graph built purely from shawk's Prometheus metrics, without Postgres, can follow Caretta: `label_replace` the `service`/`peer_service` labels into `id`/`source`/`target`/`title`. This adds no new series, but it gives up first_seen/last_seen semantics and the history that SQL keeps.
- **Repurposing the Tempo service graph is a hack.** Emitting metrics named `traces_service_graph_request_total{client,server}` would render through the Tempo data source's service graph. It needs a Tempo data source configured, and those names imply trace-derived semantics. Not recommended (inference, not documented as a supported use).

### Gaps
- No primary-source statement was found on whether node-graph field-name matching is case-insensitive.
- No documented hard maximum node count was found (only the 200-visible default and the 500-node layered-layout warning). No Grafana GitHub issue benchmarking performance was located.
- The Graphviz panel's data contract and its timeline to general availability were not documented beyond "private preview".

## 2. Grafana PostgreSQL data source: macros, variables, annotations, alerting, limits, security

### Takeaway
All needed macros exist (`$__timeFilter`, `$__timeGroup[Alias]`, `$__unixEpochFilter`, `$__unixEpochGroup`, and more), and SQL annotations (`time`, `timeend`, `text`, `tags`) and query variables are first-class. The catch is alerting: the current PostgreSQL alerting page says only Time series format queries can be alert conditions. A "one alert instance per row" rule must therefore return a `time` column plus string label columns plus a numeric value, not a Table-format result, even though Grafana's generic tabular-alerting docs describe table data. Grafana has no per-data-source query timeout setting. Use a SELECT-only role with `statement_timeout` / `default_transaction_read_only` set on the role.

### Cited Findings
- **Time macros.** `$__time(col)`, `$__timeEpoch(col)`, `$__timeFilter(col)`, `$__timeFrom()`, `$__timeTo()` (RFC3339Nano), `$__timeGroup(col,'5m'[,fill])`, `$__timeGroupAlias(...)`. Fill modes are `0`/number, `NULL`, or `previous`. — [Grafana PostgreSQL query editor](https://grafana.com/docs/grafana/latest/datasources/postgres/query-editor/)
- **Epoch macros.** `$__unixEpochFilter`, `$__unixEpochNanoFilter`, `$__unixEpochFrom/To()`, `$__unixEpochNanoFrom/To()`, `$__unixEpochGroup[Alias]`. `$__interval` and `$__interval_ms` are also expanded. — [PostgreSQL query editor](https://grafana.com/docs/grafana/latest/datasources/postgres/query-editor/)
- **Macro details.** Comments are stripped before expansion. With the TimescaleDB toggle on, `$__timeGroup` uses `time_bucket()`. — [PostgreSQL query editor](https://grafana.com/docs/grafana/latest/datasources/postgres/query-editor/)
- **Table vs. time series format.**
  - Table: "you can execute virtually any type of SQL query".
  - Time series: "you must include a column named `time`". Results must be sorted by time and are returned in wide format.
  - "String-type columns (`text`, `varchar`, `char`, `bpchar`) are treated as label columns that split the result into multiple series."
  - Grafana applies a server-side row limit and truncates beyond it.
  - Source: [PostgreSQL query editor](https://grafana.com/docs/grafana/latest/datasources/postgres/query-editor/)
- **Row limit default.** The `[dataproxy] row_limit` setting defaults to 1,000,000 rows for SQL data sources. — [Grafana defaults.ini (mirror of grafana/grafana)](https://forger.sitiv.fr/apitech/grafana/src/commit/6c47968f6c92f358c023b3f3625fe44c17fd1153/conf/defaults.ini) (secondary mirror; not checked against official docs)
- **Template variables.**
  - Legacy `__text`/`__value` columns are still supported (example: `SELECT hostname AS __text, id AS __value FROM host`).
  - Variables that use `$__timeFilter` need refresh "On Time Range Change".
  - Multi-value variables need `IN (...)`. Values are auto-quoted only for multi-value variables, and `${var:csv}` disables quoting.
  - Source: [PostgreSQL template variables](https://grafana.com/docs/grafana/latest/datasources/postgres/template-variables/)
- **Annotations.** The query "must return a `time` column and can optionally include `timeend`, `text`, and `tags` columns". `time` may be a native timestamp or UNIX epoch. `timeend` "Creates a shaded region instead of a vertical line". `tags` is a comma-separated string. Examples include a deployments table. Best practice: always include `$__timeFilter()`/`$__unixEpochFilter()` and index time and filter columns. — [PostgreSQL annotations](https://grafana.com/docs/grafana/latest/datasources/postgres/annotations/)
- **Alerting support.**
  - "Only **time series** queries can be used in alert rule conditions". Table format isn't supported. A `time` column and numeric value columns are required.
  - Adding a string column (e.g. `hostname`) creates one series per value, and "Grafana creates one alert instance per unique label value".
  - The `$__timeGroup` fill parameter isn't applied during alert evaluation.
  - "Dashboard template variables aren't supported in alert queries".
  - NULL values are treated as no data.
  - Include `$__timeFilter`, or every evaluation scans the entire table. Leave headroom between query duration and the evaluation interval.
  - Source: [Grafana PostgreSQL alerting](https://grafana.com/docs/grafana/latest/datasources/postgres/alerting/); the configure page also says alerting is "(time series format only)" — [PostgreSQL configure](https://grafana.com/docs/grafana/latest/datasources/postgres/configure/)
- **Conflicting docs on tabular alerting.** Grafana's generic best-practice page describes tabular alerting: "Grafana treats each row as a separate alert instance". It requires "Only one numeric column" and says "The column name becomes a label name; and the cell value becomes the label value". "Each row must be uniquely identifiable by its labels", or the rule fails. Its example is SQL (`SELECT Host, Disk, AVG(PercentFree) ... GROUP BY Host, Disk`). — [Grafana alerting: table data](https://grafana.com/docs/grafana/latest/alerting/best-practices/table-data/); also [queries and conditions](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rules/queries-conditions/) ("The query must return data in a table format with only one numeric column"). This **conflicts** with the PostgreSQL-specific page above. An older AWS Managed Grafana 10.x guide lists Postgres among tabular-alerting sources ([AWS docs](https://docs.aws.amazon.com/grafana/latest/userguide/v10-alerting-overview-numeric.html)).
- **Security and connection settings.**
  - "the database user you specify should have only `SELECT` permissions on the relevant schemas and tables".
  - "Grafana does not validate the safety of queries, so users could run potentially harmful SQL (for example, `DROP TABLE`)". Example: `GRANT SELECT ON schema.table TO grafanareader;`.
  - Connection pool defaults: Max open 100, Max idle 100, Max lifetime 14400 s, plus an "Auto max idle" toggle.
  - The page does not mention a query timeout setting.
  - Source: [PostgreSQL configure](https://grafana.com/docs/grafana/latest/datasources/postgres/configure/)
- **PostgreSQL timeouts.**
  - `statement_timeout`: "Abort any statement that takes more than the specified amount of time … A value of zero (the default) disables the timeout". Setting it in `postgresql.conf` is "not recommended because it would affect all sessions".
  - `default_transaction_read_only` sets the default read-only status of new transactions.
  - `transaction_timeout` exists in current docs.
  - Source: [PostgreSQL runtime-config-client](https://www.postgresql.org/docs/current/runtime-config-client.html)
- **Recursive CTE cycle safety.** PostgreSQL has a built-in `CYCLE id SET is_cycle USING path` clause and `SEARCH DEPTH|BREADTH FIRST BY ... SET ordercol`. The docs warn that the `LIMIT` trick for runaway recursion is "not recommended" in production and "usually won't work if you make the outer query sort the recursive query's results or join them". — [PostgreSQL WITH queries (v18)](https://www.postgresql.org/docs/current/queries-with.html)

### Inferences
- **Shape the "new dependency in last 15 min" alert as time series.** Use something like `SELECT max(first_seen) AS time, src_service, dst_service, port::text, 1::int AS value FROM dependency_changes WHERE $__timeFilter(first_seen) GROUP BY 2,3,4 ORDER BY 1`, then a Reduce (last) and a Threshold (> 0). Each distinct string-column combination becomes one alert instance. Cast numeric columns that should be labels (e.g. port) to text, or they become value fields.
- **Role setup for Grafana.** Create a dedicated role, e.g. `ALTER ROLE grafana_ro SET statement_timeout='10s'; ALTER ROLE ... SET default_transaction_read_only=on;` with SELECT-only grants on the views. Per-role `ALTER ROLE ... SET` for these parameters is standard PostgreSQL behaviour, but it wasn't explicitly confirmed on the fetched page. This caps runaway recursive CTEs from ad-hoc panels and protects the ingest path, which shares the DB.
- **Annotations fit the planned feeds.** `dependency_changes` and `service.version` changes can be served directly as annotation queries on Prometheus dashboards (time + text + tags). Region annotations (`timeend`) could show an edge's lifetime.
- **Recursive CTEs must handle cycles.** Service graphs are cyclic, so use the `CYCLE` clause plus a depth limit in the recursive term.

### Gaps
- No Grafana-side SQL query timeout setting was found for the PostgreSQL plugin. Only the general alert evaluation timeout (30 s default; see section 3) was documented.
- There is no authoritative Grafana statement on whether Table format ever works for PostgreSQL alert rules in 13.x. The docs conflict, so a test on the target version is needed.
- I did not verify how `$__timeFilter` in alert rules maps to the rule's relative query time range. It is presumably the rule's "from/to", but the fetched page didn't state it.

## 3. Grafana Alerting patterns for "new entity appeared" / "something disappeared" and noise control

### Takeaway
A "new dependency" alert works naturally as a multi-dimensional Grafana-managed rule. Each new edge row/series is an instance, and when it ages out of the query window the instance goes stale and auto-resolves after the "missing series evaluations to resolve" count (default 2), with reason `MissingSeries`. Zero rows means No Data. Set "No data → Normal" (or Keep last state), or every quiet period produces `DatasourceNoData` alerts. Noise control uses label matchers in notification policies, grouping (default `alertname` + `grafana_folder`), group wait/interval/repeat (30 s / 5 m / 4 h defaults), mute timings (recurring), and silences (one-off). None of these stop evaluation.

### Cited Findings
- **No Data options.** No Data (default), Alerting, Normal, or Keep last state. Error handling has the same options. Errors can come from "evaluation timeouts (default: `30s`) or repeated failures (default: `3`)". — [No Data and Error states](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/nodata-and-error-states/)
- **DatasourceNoData instances.** "When entering the **No Data** state, the alert rule creates a new `DatasourceNoData` alert instance". These instances are independent from the original instance. — [No Data and Error states](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/nodata-and-error-states/)
- **Stale alert instances.**
  - An instance is stale when its series disappears for consecutive evaluations while the rule still returns other data.
  - "Missing series evaluations to resolve" defaults to 2 evaluation intervals. After that the instance becomes Normal with `grafana_state_reason=MissingSeries`, is removed from the UI, and a resolved notification is sent.
  - This applies only to Grafana-managed rules.
  - Sources: [Stale alert instances](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/stale-alert-instances/); "Alerting instances … transition to the `Normal` state when the series disappear" — [No Data and Error states](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/nodata-and-error-states/)
- **Notification policy routing.**
  - Matchers use `=`, `!=`, `=~`, `!~`. Multiple matchers are ANDed.
  - "once a matching policy is found, the system does not continue to look for sibling policies" unless "Continue matching siblings" is enabled.
  - Children inherit the contact point, grouping, and timing settings.
  - Source: [Notification policies](https://grafana.com/docs/grafana/latest/alerting/fundamentals/notifications/notification-policies/)
- **Grouping.**
  - Default grouping is by `alertname` and `grafana_folder`. Grouping by the special label `...` disables grouping.
  - Defaults: group wait 30 s, group interval 5 min, repeat interval 4 h.
  - Source: [Group alert notifications](https://grafana.com/docs/grafana/latest/alerting/fundamentals/notifications/group-alert-notifications/)
- **Mute timings, active time intervals, and silences.**
  - Mute timings are recurring intervals, and they take precedence over active time intervals. Neither can be assigned to the root policy.
  - Silences are fixed-window and label-matched.
  - They "do not prevent alert rules from being evaluated or stop alert instances from appearing in the user interface".
  - Source: [Mute timings](https://grafana.com/docs/grafana/latest/alerting/configure-notifications/mute-timings/)
- **Grafana 13.0 alerting changes.** The documented changes are API and permission items, e.g. the Alertmanager status endpoint "now requires a dedicated `alert.notifications.system-status:read` permission". There were no changes to rule semantics. — [What's new in 13.0](https://grafana.com/docs/grafana/latest/whatsnew/whats-new-in-v13-0/)

### Inferences
- **Suggested "new dependency" rule.**
  - Run a time series SQL rule with a query window of about 15 minutes, evaluated every 1–5 min to match the upsert cadence, with pending period 0.
  - Set "No data → Normal" so quiet periods don't page.
  - Each new edge fires once. When it leaves the 15-minute window it auto-resolves after 2 missing evaluations, which produces a "resolved" notification. Disable resolved messages on the contact point if those are noise.
  - Put `service`/`peer_service`/`host` labels on the rows so policies can route per team.
- **Grouping for burst-y new edges.** Many new edges at once (e.g. after a deploy) are grouped into one notification per group interval by default. Adding `service` to group_by keeps per-team digests manageable.
- **"Disappeared" alerts.** Write them as SQL that explicitly selects rows with `last_seen < now() - X AND last_seen > now() - X - window`. Relying on stale-instance resolution is the wrong tool, because a disappearance is itself an event to be emitted as a row.
- **"Agent down" with OTLP push.** There is no scrape-based `up` series. The alert must use absence of a heartbeat metric/`target_info` per `host.name` (e.g. `absent_over_time` or count comparisons), or Grafana's stale-series behaviour. This is an inference from Prometheus push semantics, not from a fetched doc.

### Gaps
- No Grafana doc was found with a canonical "new entity appeared" recipe. The pattern above is synthesised from the multi-dimensional, No Data, and stale-instance documentation.
- I did not verify the exact UI and provisioning field name for "missing series evaluations to resolve" in Grafana 13.x provisioning YAML.

## 4. Grafana data links, correlations, Mixed data source, joins across Postgres and Prometheus

### Takeaway
Postgres → Prometheus navigation should use panel data links: a URL to a Prometheus dashboard with `var-service=${__data.fields.service}` and `${__url_time_range}`. Correlations only render links in Explore (Logs panel and Table), so they're unsuitable for dashboards. Client-side "Join by field" (inner/outer) can join a Postgres table and a Prometheus instant-table query in one panel. Server-side "SQL Expressions" (enabled by default in current Grafana, MySQL-like dialect) can JOIN results across data sources and also feed alert/recording rules, within a 100,000-cell input limit and a 10 s timeout.

### Cited Findings
- **Data link variables.** `__url_time_range`, `__from`, `__to`, `__field.name`, `__field.displayName`, `__field.labels.<LABEL>`, `__series.name`, `__value.raw`, `__value.text`, `__data.fields[i]`, `__data.fields["NameOfField"]`.
  - Linking to another dashboard uses `var-<name>=` (example `/d/xxxx/dashboard-b?orgId=1&var-server=web02`), and "You use the variable *name*, and not the label".
  - "Only one data link can have **One click** enabled at a time".
  - Table visualizations support data links.
  - Source: [Configure data links](https://grafana.com/docs/grafana/latest/panels-visualizations/configure-data-links/)
- **Correlations.** "A correlation defines how data in one data source is used to query data in another data source". The example "A user name from an SQL data source can query related logs". Links are shown in "Explore visualizations", listed as the Logs panel and Table. Correlations are configurable through provisioning, the admin page, or Explore. — [Correlations](https://grafana.com/docs/grafana/latest/administration/correlations/)
- **Join by field.** Inner join, outer join (time series), outer join (SQL-like/tabular), and a "Keep unjoined" option. "A join drops any query that doesn't contain the field you're joining on". "Join by labels" converts multiple time series into a wide table. "Merge" combines results into one table. "Config from query results" can take thresholds and options from a query. — [Transform data](https://grafana.com/docs/grafana/latest/panels-visualizations/query-transform-data/transform-data/)
- **SQL Expressions.**
  - Status and dialect: "Grafana enables SQL expressions by default". The syntax is MySQL-like, and "You can JOIN data from many data source queries, subject to the input cell limit".
  - Conversion: time series inputs are converted to `FullLong` tables.
  - Alerting and recording rules: the result fails if it has no numeric column or more than one. Rows need unique string-column combinations, and recording rules write one series per row.
  - Limits: `sql_expression_cell_limit` 100000 (input), `sql_expression_output_cell_limit` 100000, `sql_expression_timeout` 10s.
  - Data source support: PostgreSQL has "Full support" and Prometheus has "Partial support".
  - Source: [SQL expressions](https://grafana.com/docs/grafana/latest/panels-visualizations/query-transform-data/sql-expressions/)
- **SQL Expressions status in 13.0.** The 13.0 release notes tag "SQL Expressions support in Grafana Assistant" as GA in Cloud and public preview in OSS/Enterprise. The tag doesn't cleanly separate the SQL Expressions feature itself. — [What's new in 13.0](https://grafana.com/docs/grafana/latest/whatsnew/whats-new-in-v13-0/)

### Inferences
- **Hybrid alerts are possible but bounded.** SQL Expressions make cross-store logic possible, e.g. "new dependency from Postgres AND its failure rate from Prometheus" in one Grafana-managed rule. With per-edge Prometheus series, the 100k input-cell limit can be hit quickly on large fleets, and Prometheus support is only "partial". Prefer keeping alerts single-source.
- **Annotations overlay works without Mixed.** Annotation queries are defined per dashboard and choose their own data source. A Postgres annotation can therefore overlay Prometheus panels without the Mixed data source (consistent with the annotations doc treating them as separate dashboard-level queries).
- **Join key consistency is a design requirement.** To make joins and data links work, Postgres views and Prometheus labels must use identical identifiers for `service`, `peer_service`, `host`, and `port` (same normalisation, same "external" collapsing).

### Gaps
- I did not fetch the Mixed data source docs page. Mixed-specific limitations (e.g. with alerting) are unverified.
- No documentation was found on SQL Expressions' behaviour for Prometheus range queries beyond "partial support".

## 5. Prometheus OTLP ingestion as of late 2026

### Takeaway
Prometheus 3.x has a stable native OTLP/HTTP receiver at `/api/v1/otlp/v1/metrics`, enabled with `--web.enable-otlp-receiver` (since 3.0.0). By default no resource attributes become labels. `service.name`/`service.namespace` → `job` and `service.instance.id` → `instance`, and other resource attributes live only on `target_info`, so `host.name` must be explicitly promoted. Name translation defaults to `UnderscoreEscapingWithSuffixes` (adds `_total`/unit suffixes). Delta temporality is experimental in two forms: `otlp-deltatocumulative` and `otlp-native-delta-ingestion`. The docs recommend an out-of-order window of about 30 m. The Collector `prometheusremotewrite` exporter (beta) is the alternative, but it drops delta sums.

### Cited Findings
- **Enabling the receiver.** Flag `--web.enable-otlp-receiver`, disabled by default "similarly to the Remote Write receiver". Endpoint `/api/v1/otlp/v1/metrics`. Client example: `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:9090/api/v1/otlp`, and `OTEL_METRIC_EXPORT_INTERVAL=15000` gives 15 s. — [Prometheus OTel guide](https://prometheus.io/docs/guides/opentelemetry/)
- **Version history (from the changelog).**
  - 3.0.0 (2024-11-14): "The OTLP receiver endpoint can now be enabled using `--web.enable-otlp-receiver` instead of `--enable-feature=otlp-write-receiver`"; UTF-8 enabled by default; `NoUTF8EscapingWithSuffixes` added.
  - 3.2.0 (2025-02-17): feature flag `otlp-deltatocumulative`.
  - 3.4.0 (2025-05-17): "primitive support for ingesting OTLP delta metrics as-is", the no-translation option, and NHCB conversion.
  - 3.5.0 (2025-07-14): `promote_all_resource_attributes`/`ignore_resource_attributes`.
  - 3.6.0 (2025-09-17): `UnderscoreEscapingWithoutSuffixes`, `promote_scope_metadata`, `__type__`/`__unit__` labels.
  - 3.7.0 (2025-10-15): "OTLP: Write directly to TSDB instead of passing through a Remote-Write adapter".
  - 3.8.0 (2025-11-28): native histograms stable but optional.
  - 3.14.0 (2026-08-17): warning plus `prometheus_api_otlp_translation_warnings_total` when attribute names collide after sanitisation (e.g. `k8s.pod.name` vs `k8s_pod_name`).
  - Latest is 3.15.1 (2026-10-21).
  - Source: [Prometheus CHANGELOG](https://github.com/prometheus/prometheus/blob/main/CHANGELOG.md)
- **The `otlp:` config block (docs for 3.15).**
  - `promote_resource_attributes` (list, default empty; can't be combined with `promote_all_resource_attributes: true`).
  - `promote_all_resource_attributes` (default false; warned to cause series churn and high memory use) and `ignore_resource_attributes` (only valid with promote_all).
  - `translation_strategy`: `UnderscoreEscapingWithSuffixes` (default), `NoUTF8EscapingWithSuffixes`, `UnderscoreEscapingWithoutSuffixes`, or the experimental `NoTranslation` (risk of harder PromQL and series collisions).
  - `keep_identifying_resource_attributes` (default false).
  - `convert_histograms_to_nhcb`, `promote_scope_metadata` (default false).
  - `label_name_underscore_sanitization` and `label_name_preserve_multiple_underscores` (default true).
  - Source: [Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- **Default promotion and `target_info`.**
  - "By default, Prometheus won't be promoting any attributes".
  - A `target_info` series is generated per resource that has `service.instance.id` and/or `service.name`.
  - `service.instance.id` → `instance`. `service.name` → `job`, or `<service.namespace>/<service.name>`.
  - `keep_identifying_resource_attributes: true` also keeps them on `target_info`.
  - Joining with the `info()` function requires `--enable-feature=promql-experimental-functions`.
  - Source: [Prometheus OTel guide](https://prometheus.io/docs/guides/opentelemetry/)
- **UTF-8 and suffixes.** UTF-8 metric and label names are supported from 3.x. Strategies without escaping require UTF-8 support. `UnderscoreEscapingWithoutSuffixes` "can cause name collisions". — [Prometheus OTel guide](https://prometheus.io/docs/guides/opentelemetry/)
- **Out-of-order ingestion.** The guide recommends `storage.tsdb.out_of_order_time_window: 30m` and says 30 minutes has been enough for most cases. — [Prometheus OTel guide](https://prometheus.io/docs/guides/opentelemetry/)
- **Delta temporality (both experimental).**
  - `otlp-deltatocumulative` converts deltas using the OTel deltatocumulative processor. In-memory state is lost on restart, causing a counter reset, and it "can have negative impact on performance". It can't be combined with `otlp-native-delta-ingestion`.
  - `otlp-native-delta-ingestion` stores raw delta samples, is in "a very early stage of development", and `rate()`/`increase()` give incorrect results on it (use `sum_over_time()`).
  - Related experimental features: `type-and-unit-labels` (`__type__`/`__unit__`) and `st-storage` (start timestamps).
  - Source: [Prometheus feature flags](https://prometheus.io/docs/prometheus/latest/feature_flags/)
- **Collector `prometheusremotewrite` exporter (beta).**
  - "Non-cumulative monotonic, histogram, and summary OTLP metrics are dropped by this exporter". It needs a WAL for durability.
  - It supports the same `translation_strategy` values, `resource_constant_labels` (include/exclude wildcard patterns of resource attributes to turn into labels; replaces the deprecated `resource_to_telemetry_conversion`), and `target_info.enabled` (default true).
  - Remote Write 2.0 (`io.prometheus.write.v2.Request`) is "In Development … not ready for usage". Only snappy compression is supported.
  - Source: [prometheusremotewriteexporter README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter)

### Inferences
- **Recommended configuration for shawk.**
  - Agent: use cumulative temporality (the OTel Go SDK default), which avoids every delta caveat.
  - Prometheus: run with `--web.enable-otlp-receiver` and `otlp.promote_resource_attributes: [host.name, service.version?]`. Keep `service.name`/`service.instance.id` meaningful (e.g. `service.name=shawk`, `service.instance.id=<host>`) so `job`/`instance` and `target_info` are useful for an "agent down" check.
  - Expect the default strategy to rename e.g. `shawk.connections` → `shawk_connections_total` and bytes → `..._bytes_total`. Label keys with dots become underscores (`host.name` → `host_name`), which collides conceptually with the datapoint label `host`. Pick one.
- **Collector → Prometheus path.** With the Collector in front, either export OTLP/HTTP to Prometheus's receiver (`otlphttp` exporter) or use `prometheusremotewrite`. Both are viable. The native OTLP receiver writes directly to the TSDB since 3.7 and gets Prometheus-side translation/promotion config. `prometheusremotewrite` works with non-Prometheus stores (Mimir, Thanos, VictoriaMetrics) but silently drops delta sums.
- **Out-of-order risk.** With 15 s pushes from many hosts and Collector retries/batching, out-of-order samples are possible. Enabling a modest `out_of_order_time_window` is prudent.

### Gaps
- I did not fetch the OTel spec "Prometheus and OpenMetrics compatibility" page for exact unit-to-suffix mapping rules (e.g. `{connection}` annotation units being dropped). The examples above are inferences.
- No statement was found on when (or whether) the OTLP delta features will leave experimental status.

## 6. OpenTelemetry semantic conventions relevant to connection/flow metrics

### Takeaway
No stable OTel semconv metric exists for per-peer TCP/UDP connection flows. The closest are `system.network.connection.count` (UpDownCounter, Development; attributes `network.connection.state`, `network.transport`, `network.interface.name`) and interface-level `system.network.io/errors/packet.dropped`. Peer and transport attributes are stable (`network.peer.address/port`, `network.local.address/port`, `network.transport`, `network.type`). The peer-service concept is `service.peer.name`/`service.peer.namespace` (Development), not `peer.service`. OTel's own eBPF instrumentation (OBI) uses a project-namespaced metric `obi.network.flow.bytes` with `src.*`/`dst.*` attributes and leaves addresses and ports out by default for cardinality reasons. That is a reasonable precedent for a `shawk.*` namespace.

### Cited Findings
- **`system.network.connection.count`.** UpDownCounter, unit `{connection}`, Development, "The number of connections". Attributes: `network.connection.state` (Development; RFC 9293 states such as `established`, `listen`, `time_wait`), `network.interface.name` (RC), `network.transport` (Stable; `tcp`, `udp`, `quic`, `unix`, `pipe`). — [OTel system metrics semconv](https://opentelemetry.io/docs/specs/semconv/system/system-metrics/)
- **Interface-level metrics.** `system.network.io` (Counter, `By`), `system.network.errors` (`{error}`; Linux `/proc/net/dev` errs), `system.network.packet.dropped`, and `system.network.packet.count`. All are Development, with attributes `network.interface.name` and `network.io.direction`. — [OTel system metrics semconv](https://opentelemetry.io/docs/specs/semconv/system/system-metrics/)
- **Network attributes.**
  - Stable: `network.peer.address`, `network.peer.port`, `network.local.address`, `network.local.port`, `network.transport` (set it whenever a port is set), `network.type`, `network.protocol.name`.
  - Development: `network.connection.state`.
  - RC: `network.io.direction`, which describes interface receive/transmit, not "the logical direction of a stateful connection".
  - Deprecated `net.*` attributes map to `network.*`, `server.*`, and `client.*` (e.g. `net.peer.name` → `server.address`/`client.address`).
  - Source: [OTel network attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/)
- **Service attributes.** `service.name`, `service.version`, `service.namespace`, and `service.instance.id` are Stable. `service.peer.name` and `service.peer.namespace` are Development ("Logical name of the service on the other side of a connection"). `service.criticality` is Alpha. — [OTel service attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/)
- **Metric naming guidance.** Namespacing comes from the hierarchical structure (prefer `jvm.gc*` over `gc.*`). Conventional metrics "SHOULD NOT include the unit in the name". Units such as `{request}` use singular annotations. The general guidelines are Development, while units and instrument types are Stable. — [OTel general metrics semconv](https://opentelemetry.io/docs/specs/semconv/general/metrics/)
- **Prometheus disagrees on units in names.** "Prometheus strongly recommends including unit and type in a metric name", whereas OTel conventions "do not recommend or even do not allow" it. — [Prometheus naming](https://prometheus.io/docs/practices/naming/)
- **OBI (OpenTelemetry eBPF Instrumentation) network metrics.**
  - Metrics: `obi.network.flow.bytes` (Prometheus `obi_network_flow_bytes_total`), `obi.network.flow.packets`, `obi.network.inter.zone.bytes`.
  - Attributes: `direction` (request/response/unknown), `iface.direction` (ingress/egress), `src.address`/`dst.address`, `src.port`/`dst.port`, `src.name`/`dst.name`, `src.cidr`/`dst.cidr`, `transport`, `network.type`, `network.protocol.name`, `service.name`/`service.namespace` (local), `service.peer.name`/`service.peer.namespace` (remote), `k8s.src.*`/`k8s.dst.*`, `obi.ip`.
  - "leaves many high-cardinality attributes, including endpoint addresses and ports, out by default", with per-process pre-aggregation and named CIDR ranges.
  - The page lists no connection or RTT metrics.
  - Source: [OBI network metrics](https://opentelemetry.io/docs/zero-code/obi/network/)

### Inferences
- **Suggested naming for shawk.**
  - Metrics in an own namespace, e.g. `shawk.connection.count` (UpDownCounter), `shawk.connection.opened` / `shawk.connection.failed` (Counters), `shawk.network.io` (`By`, with a direction attribute), `shawk.tcp.retransmits`, `shawk.tcp.rtt` (prefer a histogram in seconds over manual sum/count).
  - Attributes aligned with semconv names: `network.transport`, `network.peer.port`/`server.port`, `network.peer.address`, `service.peer.name` (instead of the custom `peer_service`), and `service.name`.
  - These translate to Prometheus labels with underscores (`network_peer_port`, etc.).
  - Process identity belongs in resource or datapoint attributes per semconv `process.*` (not fetched; see gaps).
- **Direction attribute naming.** The planned `direction` label (client/server role) should not be named `network.io.direction`, since semconv reserves that for interface rx/tx. A custom attribute such as `shawk.role` or `network.connection.role`-like naming avoids misuse (inference; no semconv attribute for role was found).

### Gaps
- No OTel semantic convention for "network flow" or per-connection TCP metrics (RTT, retransmits, failed connects) was found. OBI's metrics are project-namespaced, not semconv.
- I did not fetch the `process.*` resource attribute registry (e.g. `process.executable.name`, `process.pid`, `process.command_line`) or the `server.*`/`client.*` registry pages. Their stability levels are not verified here.
- The current semconv release number was not displayed on the fetched pages. The general metrics page links to OTel spec v1.59.0.

## 7. Prometheus cardinality guidance and OTel Collector processors for cardinality control

### Takeaway
Prometheus guidance is explicit:
- Keep most metrics' cardinality below 10.
- Investigate anything at or above 100.
- Never use unbounded dimensions as labels.

`peer_addr` (IP) and ephemeral `port` labels are exactly that risk. Collapsing external addresses to "external" and using only server ports helps, but per-host × per-peer-address × 7–8 metrics can still reach millions of series on a large fleet. The Collector can enforce limits with `transform` (OTTL `delete_key`/`keep_keys`/`limit`/`aggregate_on_attributes`; beta for metrics), `filter` (alpha), and `metricstransform` (`aggregate_labels`; beta). `deltatocumulative` (alpha) and `interval` (alpha) are stateful and need `max_streams`/`max_stale` limits.

### Cited Findings
- **Prometheus instrumentation guidance.** "Each labelset is an additional time series that has RAM, CPU, disk, and network costs". "As a general guideline, try to keep the cardinality of your metrics below 10". "If you have a metric that has a cardinality over 100 or the potential to grow that large, investigate alternate solutions". "The vast majority of your metrics should have no labels." — [Prometheus instrumentation practices](https://prometheus.io/docs/practices/instrumentation/)
- **Prometheus naming guidance.** "Do not use labels to store dimensions with high cardinality (many different label values), such as user IDs, email addresses, or other unbounded sets of values." Units are base units (`_seconds`, `_bytes`), and counters end in `_total`. — [Prometheus naming](https://prometheus.io/docs/practices/naming/)
- **Promote-all warning.** `promote_all_resource_attributes` is warned to cause series churn and high memory use. — [Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- **transform processor (beta for traces/metrics/logs).**
  - Supported functions include `keep_keys`, `delete_key`, `delete_matching_keys`, `replace_pattern`, and `limit(datapoint.attributes, 100, ["host.name"])`.
  - `aggregate_on_attributes(function, [attrs])` "aggregates all data points in the metric". Functions are sum/max/min/mean/median/count, and only `sum` applies to histograms. It is metric context only, and it can be combined with `delete_matching_keys` to drop keys and re-aggregate.
  - Source: [transformprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor)
- **filter processor.** Alpha for traces/metrics/logs. Drops data via OTTL conditions, e.g. by resource attribute or `HasAttrOnDatapoint`. — [filterprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/filterprocessor)
- **metricstransform processor.** Beta. Operations `add_label`, `update_label`, `delete_label_value`, `aggregate_labels` (with `label_set` and `aggregation_type` sum/mean/min/max/count/median), and `aggregate_label_values`. — [metricstransformprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/metricstransformprocessor)
- **deltatocumulative processor.** Alpha, with a "Statefulness" warning. Config `max_stale` (default 5m) and `max_streams` (default max int; "new streams exceeding this limit will be dropped"). — [deltatocumulativeprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/deltatocumulativeprocessor)
- **Other processors.** `cumulativetodelta` is beta for metrics. `interval` is alpha. `groupbyattrs` is beta. — READMEs for [cumulativetodelta](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/cumulativetodeltaprocessor), [interval](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/intervalprocessor), [groupbyattrs](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/groupbyattrsprocessor)
- **Precedent.** OBI keeps endpoint addresses and ports out of default network-flow attributes and pre-aggregates per process. — [OBI network metrics](https://opentelemetry.io/docs/zero-code/obi/network/)
- **Prometheus collision warning.** Prometheus 3.14 added `prometheus_api_otlp_translation_warnings_total` for attribute-name collisions after sanitisation. — [Prometheus CHANGELOG](https://github.com/prometheus/prometheus/blob/main/CHANGELOG.md)

### Inferences
- **Rough series estimate.** Labels (host, service, direction, peer_addr, port, proto, peer_service) with about 7–8 metric streams (connections, failed, open, bytes in/out, retransmits, RTT sum, RTT count) give roughly series ≈ Σ_hosts(distinct (service, peer, port, direction, proto) tuples) × 8. At 1,000 hosts × 200 tuples that is about 1.6 M active series. `peer_addr` multiplies tuples by the number of replica IPs per peer service, and ephemeral client-side ports would be unbounded. **Recommendation:** drop `peer_addr` from metrics (keep it in Postgres), keep only the server-side port, and rely on `peer_service`.
- **Do the reduction in the agent.** Agent-side aggregation is safer than Collector-side `aggregate_on_attributes` on cumulative counters. Collector re-aggregation of cumulative streams across batches and restarts can produce resets or double counting unless done carefully (inference; the README doesn't discuss cumulative-reset semantics).
- **Collector as a safety net.** Use `transform` with `limit()`/`delete_key` as a guard rail (e.g. drop `network.peer.address` when it isn't in an allowlist), not as the primary design.

### Gaps
- No Prometheus primary source gives a numeric per-metric series limit beyond the 10/100 rule of thumb. Server-side `sample_limit`/`label_limit` style protections apply to scrapes. No equivalent OTLP-receiver per-request limit was found in the fetched docs.
- The Collector OTTL function stability for metrics-context aggregation functions was not individually verified ("There are currently no experimental functions" per README header).

## 8. rqlite with Grafana (plugin, Infinity, alerting)

### Takeaway
A dedicated rqlite Grafana data source exists: `g42-rqlite-datasource` v1.1.5 (May 2026; requires Grafana ≥ 12.3.0; first released 2026-02-21; query builder, code editor, query variables). Nothing in its listing or changelog mentions alerting, macros, or a backend mode, so Grafana Alerting support is unverified. The Infinity plugin can query rqlite's HTTP API (`/db/query?q=...`, JSON `columns`/`types`/`values`, or `?associative`). Infinity alerting works only with backend parsers (JSONata/JQ), not with UQL/GROQ/frontend parsers, and column types must be declared for numeric detection. That is materially weaker than the first-class PostgreSQL plugin (macros, annotations, time series alerting).

### Cited Findings
- **g42 plugin listing.** The rqlite plugin is listed by "g42" with a "Grafana >=12.3.0" dependency, version 1.1.5, and screenshots of "Query Builder" and "Query Code". Pricing, signature level, and alerting aren't stated on the page. — [Grafana plugin catalog: rqlite](https://grafana.com/grafana/plugins/g42-rqlite-datasource/)
- **g42 plugin changelog.**
  - 1.0.0 (2026-02-21): "remove plugin signing until Grafana catalog approval".
  - 1.1.0 (2026-02-25): "add datasource query variable support".
  - 1.1.2 (2026-04-23): "harden rqlite error handling".
  - 1.1.5 (2026-05-06): "sign release artifacts with Grafana token".
  - No entries mention alerting, macros, or time series.
  - Source: [rqlite plugin changelog](https://grafana.com/grafana/plugins/g42-rqlite-datasource/changelog/)
- **rqlite HTTP API.**
  - `/db/query` "accepts **only** read requests (`SELECT`)", via GET `?q=` or POST JSON/plain text.
  - The response has `results[].columns/types/values`. "`types` contains the declared type of the columns, not the Storage Class". `?associative` returns rows as maps.
  - Parameterized queries use JSON arrays or named dictionaries.
  - "By default, SQL queries do not time out". `db_timeout` applies per statement.
  - "Only if _Strong_ read consistency is requested does a query go through the Raft log".
  - Source: [rqlite HTTP API](https://rqlite.io/docs/api/api/)
- **Infinity alerting.** Only backend parsers (JSONata default, JQ) support alerting. Frontend parsers (Default, UQL, GROQ) do not. The docs say Infinity is not intended for massive datasets. — [Infinity query docs](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/query/); [Infinity docs home](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/)
- **Infinity CSV typing.** With Infinity CSV, "all the columns are parsed and returned as strings," so tabular alerts fail unless column types are specified. — [Grafana alerting: table data](https://grafana.com/docs/grafana/latest/alerting/best-practices/table-data/)
- **Community report on JSONata alerting.** A user reported a JSONata Infinity query that works on a dashboard but fails in an alert rule, with no resolution shown. — [Grafana community thread](https://community.grafana.com/t/jsonata-queries-not-working-while-creating-alert-rule/108968)
- **SQLite plugins and alerting.** The separate `frser-sqlite-datasource` plugin (local SQLite files, not rqlite clusters) supports alerting, but variables aren't supported in alerting. — [SQLite plugin](https://grafana.com/grafana/plugins/frser-sqlite-datasource)

### Inferences
- **Choosing rqlite costs Grafana functionality.**
  - The `$__timeFilter`-style macros and SQL annotation semantics would have to be hand-built (Infinity URL templating with `${__from}`/`${__to}`).
  - Node graph frames would need Infinity's refId naming plus JSONata reshaping of rqlite's columnar JSON.
  - Alerting would rest on Infinity's backend parser or an unverified third-party plugin.
- **Read path has no timeout by default.** rqlite queries have no timeout unless `db_timeout` is passed, and reads may hit followers unless Strong consistency is requested. Grafana panels must therefore set `db_timeout` explicitly.
- **Bottom line.** For a Grafana-only UI, PostgreSQL is clearly the lower-risk choice.

### Gaps
- Whether `g42-rqlite-datasource` is a backend plugin and supports Grafana Alerting could not be determined from public pages. Its licence and pricing were also unclear: one search summary called it paid, but the catalog page did not state it.
- I did not find any production reports of Grafana + rqlite.
- SQLite (and therefore rqlite) supports `WITH RECURSIVE`, but rqlite-specific docs did not mention it. This is unverified here.

## 9. Existing projects storing/visualising service topology with Grafana Node Graph, and lessons

### Takeaway
The closest open-source precedent is Caretta (groundcover). It is an eBPF agent that exports a Prometheus gauge per observed link and renders a Grafana Node Graph directly from PromQL using refIds `nodes`/`edges` and `label_replace`. Grafana's own service-graph path (Tempo/Alloy metrics → Prometheus → Tempo data source) is trace-derived. No open-source project storing topology in PostgreSQL and rendering it with Node Graph was found. Community threads confirm the SQL path works but needs careful aliasing and frame naming.

### Cited Findings
- **Caretta.** Caretta's metric `caretta_links_observed` represents socket-level links between workloads, with role (1 = client, 2 = server), client/server kind, name, namespace, `server_port`, and numeric `link_id`/`client_id`/`server_id` labels used by the Node Graph. Namespace/kind may be "node" or "external". The Helm chart ships VictoriaMetrics and Grafana. — [Caretta repo](https://github.com/groundcover-com/caretta); [DeepWiki summary](https://deepwiki.com/groundcover-com/caretta/2.4-metrics-and-observability)
- **Caretta dashboard implementation.** Instant table queries with refIds `nodes`/`edges`, no transformations, and `increase(...[$__range:$__interval]) > 0` to show only links active in the dashboard range. — [Caretta dashboard.json](https://github.com/groundcover-com/caretta/blob/main/chart/dashboard.json)
- **Tempo service graph.** Service graph metrics are generated by the Tempo metrics generator or Grafana Alloy and visualised through the Tempo data source. — [Tempo service graph](https://grafana.com/docs/grafana/latest/datasources/tempo/service-graph/)
- **OBI.** OBI produces flow metrics with `service.peer.name` etc. The docs don't describe a node-graph dashboard. — [OBI network metrics](https://opentelemetry.io/docs/zero-code/obi/network/)
- **SQL tables community thread.** Lessons: name the queries `nodes`/`edges` or set `preferredVisualisationType`, alias columns exactly, and watch for version-specific "No Data" bugs. — [Grafana community thread](https://community.grafana.com/t/grafana-node-graph-with-sql-tables/61919)
- **Large graph community thread.** The panel hides nodes and can freeze at "Computing layout". — [Grafana community thread](https://community.grafana.com/t/node-graph-issue-nodes-are-hidden-for-performance-reasons/147404)
- **Recursive CTE guidance.** Cycles are a real risk in dependency graphs. Use visited-node arrays, statement timeouts, or depth limits. — [Graph retrieval using Postgres recursive CTEs](https://www.sheshbabu.com/posts/graph-retrieval-using-postgres-recursive-ctes/); [PostgreSQL WITH queries](https://www.postgresql.org/docs/current/queries-with.html)

### Inferences
- **Lesson from Caretta.** Its design keeps topology inside Prometheus with gauges plus `increase()` over the dashboard range. That gives "seen in range" semantics for free but no durable first_seen/last_seen history and no new-dependency events. shawk's Postgres store adds exactly those (history, change events, annotations, SQL alerts), at the cost of a second store.
- **Optional extra.** A lightweight Prometheus-only fallback node graph (Caretta-style) could be offered alongside the SQL one, at no extra cardinality, since edges are already labelled by `service`/`peer_service`.

### Gaps
- No public project, blog, or post-mortem was found describing service topology in PostgreSQL rendered with Grafana Node Graph at scale. Lessons are therefore drawn from the Caretta (Prometheus) precedent and community threads.
- Caretta's maintenance status in 2026 was not checked.
