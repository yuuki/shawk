// Package shawkconnector implements the shawk connector of the
// OpenTelemetry Collector. It consumes the OTLP metrics of shawk agents and
//
//   - writes the dependencies, listeners, processes, addresses and
//     observation segments of every host to PostgreSQL;
//   - names the peer of every edge (service.peer.name) from the listeners
//     known in PostgreSQL;
//   - aggregates the edge metrics without addresses into one resource per
//     host and local service, and emits them to a metrics pipeline bound
//     for Prometheus.
package shawkconnector

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
)

// Type is the type of the connector in the configuration.
var Type = component.MustNewType("shawk")

// NewFactory returns the factory of the shawk connector.
func NewFactory() connector.Factory {
	return connector.NewFactory(Type,
		func() component.Config { return createDefaultConfig() },
		connector.WithMetricsToMetrics(createMetricsToMetrics, component.StabilityLevelAlpha))
}

func createMetricsToMetrics(_ context.Context, set connector.Settings, cfg component.Config, next consumer.Metrics) (connector.Metrics, error) {
	return newConnector(set, cfg.(*Config), next)
}
