package packaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/exporter-toolkit/web"
	yamlv2 "go.yaml.in/yaml/v2"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
)

// TestPrometheusWebConfig checks the web configuration of Prometheus as
// Prometheus reads it (--web.config.file), and that the clients of the
// examples can use it. The OTLP receiver writes whatever series it is
// sent, so that whoever can push can silence the alerts on agents: every
// request needs TLS and a user.
func TestPrometheusWebConfig(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root, "packaging/prometheus/web.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var c web.Config
	if err := yamlv2.UnmarshalStrict(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.TLSConfig.TLSCertPath == "" || c.TLSConfig.TLSKeyPath == "" {
		t.Errorf("no TLS: %+v", c.TLSConfig)
	}
	if len(c.Users) == 0 {
		t.Fatal("no basic_auth_users: anyone can push")
	}
	for user, hash := range c.Users {
		// A hash of a known password would let anyone in where the example
		// is used as is; with a placeholder, Prometheus refuses to start.
		if _, err := bcrypt.Cost([]byte(hash)); err == nil {
			t.Errorf("%s: the example has a password", user)
		}
	}
	if c.Users["shawk-collector"] == "" {
		t.Error("no user for the collector")
	}

	// The data source of Grafana logs in over TLS as a user.
	b, err = os.ReadFile(filepath.Join(grafana, "provisioning/datasources/shawk.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Datasources []struct {
			UID           string            `yaml:"uid"`
			URL           string            `yaml:"url"`
			BasicAuth     bool              `yaml:"basicAuth"`
			BasicAuthUser string            `yaml:"basicAuthUser"`
			Secure        map[string]string `yaml:"secureJsonData"`
		} `yaml:"datasources"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range doc.Datasources {
		if d.UID != "shawk-prometheus" {
			continue
		}
		found = true
		if !strings.HasPrefix(d.URL, "https://") {
			t.Errorf("Grafana reads Prometheus in cleartext: %s", d.URL)
		}
		if !d.BasicAuth || c.Users[d.BasicAuthUser] == "" || d.Secure["basicAuthPassword"] == "" {
			t.Errorf("Grafana does not log in as a user of web.yml: %+v", d)
		}
	}
	if !found {
		t.Error("no data source shawk-prometheus")
	}
}
