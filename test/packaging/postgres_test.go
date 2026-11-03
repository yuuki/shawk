package packaging

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestSetupPasswords checks that setup.sql writes no password: it creates
// the roles without one and has psql ask for the password of each.
func TestSetupPasswords(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root, "packaging/postgres/setup.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	if m := regexp.MustCompile(`(?i)\bPASSWORD\s+'[^']*'`).FindString(sql); m != "" {
		t.Errorf("setup.sql sets a known password: %s", m)
	}
	roles := regexp.MustCompile(`(?im)^CREATE ROLE (\w+) .*\bLOGIN\b`).FindAllStringSubmatch(sql, -1)
	if len(roles) != 3 {
		t.Errorf("roles that log in = %v", roles)
	}
	for _, r := range roles {
		if !regexp.MustCompile(`(?m)^\\password ` + r[1] + `$`).MatchString(sql) {
			t.Errorf(`setup.sql does not ask for the password of %s (\password %[1]s)`, r[1])
		}
	}
}

// TestPostgresTLS checks that the connections to PostgreSQL in the
// examples verify the certificate of the server and its name: sslmode=require
// accepts any certificate.
func TestPostgresTLS(t *testing.T) {
	dsn := regexp.MustCompile(`postgres(ql)?://[^\s'"]+`)
	n := 0
	err := filepath.WalkDir(filepath.Join(root, "packaging"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, u := range dsn.FindAllString(string(b), -1) {
			n++
			if !strings.Contains(u, "sslmode=verify-full") {
				t.Errorf("%s: %s does not verify the server (sslmode=verify-full)", path, u)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Errorf("only %d connection strings found", n)
	}

	b, err := os.ReadFile(filepath.Join(grafana, "provisioning/datasources/shawk.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Datasources []struct {
			Type     string            `yaml:"type"`
			JSONData map[string]string `yaml:"jsonData"`
		} `yaml:"datasources"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range doc.Datasources {
		if d.Type != "grafana-postgresql-datasource" {
			continue
		}
		found = true
		j := d.JSONData
		if j["sslmode"] != "verify-full" || j["tlsConfigurationMethod"] != "file-path" || j["sslRootCertFile"] == "" {
			t.Errorf("the PostgreSQL data source does not verify the server against a CA: %v", j)
		}
	}
	if !found {
		t.Error("no PostgreSQL data source")
	}
}
