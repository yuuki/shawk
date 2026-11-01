// Package packaging tests the examples shipped in packaging/: the
// Prometheus rules, the Grafana dashboards and alert rules, the collector
// configuration, and the release archives and packages with their systemd
// units and copyright files. It is a separate module so that its test
// dependencies (Prometheus) stay out of shawk and the shawk connector.
package packaging
