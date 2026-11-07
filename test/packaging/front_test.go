package packaging

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestFrontCollector checks the example of a front collector that spreads
// agents over connectors (#128): it routes by the identity of the host,
// not by its resource, which changes; over a static list of connectors;
// and forwards the requests of an agent in their order, one at a time,
// without queues, batches or retries.
func TestFrontCollector(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root, "packaging/collector/front.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Receivers map[string]struct {
			Protocols map[string]struct {
				TLS struct {
					ClientCAFile string `yaml:"client_ca_file"`
				} `yaml:"tls"`
			} `yaml:"protocols"`
		} `yaml:"receivers"`
		Processors map[string]any `yaml:"processors"`
		Exporters  map[string]struct {
			RoutingKey        string   `yaml:"routing_key"`
			RoutingAttributes []string `yaml:"routing_attributes"`
			SendingQueue      *struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"sending_queue"`
			Resolver map[string]any `yaml:"resolver"`
			Protocol struct {
				OTLP struct {
					SendingQueue *struct {
						Enabled bool `yaml:"enabled"`
					} `yaml:"sending_queue"`
					RetryOnFailure *struct {
						Enabled bool `yaml:"enabled"`
					} `yaml:"retry_on_failure"`
					TLS map[string]string `yaml:"tls"`
				} `yaml:"otlp"`
			} `yaml:"protocol"`
		} `yaml:"exporters"`
		Service struct {
			Pipelines map[string]struct {
				Receivers  []string `yaml:"receivers"`
				Processors []string `yaml:"processors"`
				Exporters  []string `yaml:"exporters"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	lb, ok := cfg.Exporters["load_balancing/shawk"]
	if !ok {
		t.Fatalf("no load_balancing/shawk exporter: %v", cfg.Exporters)
	}
	if lb.RoutingKey != "attributes" || !slices.Equal(lb.RoutingAttributes, []string{"host.id", "host.name"}) {
		t.Errorf("routing by %q %v, want the attributes host.id and host.name", lb.RoutingKey, lb.RoutingAttributes)
	}
	// The exporter and the OTLP exporters it makes queue by default.
	if lb.SendingQueue == nil || lb.SendingQueue.Enabled {
		t.Error("the queue of the load_balancing exporter is not disabled")
	}
	otlp := lb.Protocol.OTLP
	if otlp.SendingQueue == nil || otlp.SendingQueue.Enabled {
		t.Error("the queue of the OTLP exporters is not disabled")
	}
	if otlp.RetryOnFailure == nil || otlp.RetryOnFailure.Enabled {
		t.Error("the retries of the OTLP exporters are not disabled")
	}
	if otlp.TLS["cert_file"] == "" || otlp.TLS["key_file"] == "" || otlp.TLS["ca_file"] == "" {
		t.Errorf("the OTLP exporters do not verify the connectors with a client certificate: %v", otlp.TLS)
	}
	if _, ok := lb.Resolver["static"]; !ok || len(lb.Resolver) != 1 {
		t.Errorf("resolver %v, want static only", lb.Resolver)
	}
	if p := cfg.Receivers["otlp/shawk"].Protocols["grpc"]; p.TLS.ClientCAFile == "" {
		t.Error("the receiver of agents does not require client certificates")
	}
	if len(cfg.Service.Pipelines) != 1 {
		t.Fatalf("pipelines = %v", cfg.Service.Pipelines)
	}
	for name, p := range cfg.Service.Pipelines {
		if !slices.Equal(p.Receivers, []string{"otlp/shawk"}) || !slices.Equal(p.Exporters, []string{"load_balancing/shawk"}) {
			t.Errorf("pipeline %s = %+v", name, p)
		}
		for _, proc := range p.Processors {
			if proc != "memory_limiter" {
				t.Errorf("pipeline %s has the processor %s, which may batch or reorder requests", name, proc)
			}
		}
	}
}
