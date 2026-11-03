// Package packaging tests the examples shipped in packaging/: the
// Prometheus rules and web configuration, the Grafana dashboards, data
// sources and alert rules, the collector configuration, and the release
// archives and packages with their systemd units and copyright files. It is a separate module so that its test
// dependencies (Prometheus) stay out of shawk and the shawk connector.
package packaging
