package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	os.Setenv("SHAWK_CMDB_NAME", "testdb")
	os.Setenv("SHAWK_CMDB_HOST", "testhost")
	os.Setenv("SHAWK_CMDB_PORT", "12345")
	os.Setenv("SHAWK_CMDB_USER", "testuser")
	os.Setenv("SHAWK_CMDB_PASSWORD", "testpassword")
	os.Setenv("SHAWK_CMDB_CONNECT_TIMEOUT", "10s")

	os.Setenv("SHAWK_PROBE_MODE", "streaming")
	os.Setenv("SHAWK_PROBE_INTERVAL", "3s")
	os.Setenv("SHAWK_PROBE_FLUSH_INTERVAL", "10s")

	os.Setenv("SHAWK_DEBUG", "1")

	err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if v := Config.CMDB.Name; v != "testdb" {
		t.Errorf("Config.CNDBName should be not '%v', but 'testdb'", v)
	}
	if v := Config.CMDB.Host; v != "testhost" {
		t.Errorf("Config.CNDBHost should be not '%v', but 'testhost'", v)
	}
	if v := Config.CMDB.Port; v != "12345" {
		t.Errorf("Config.CNDBPort should be not '%v', but '12345'", v)
	}
	if v := Config.CMDB.User; v != "testuser" {
		t.Errorf("Config.CNDBUser should be not '%v', but 'testuser'", v)
	}
	if v := Config.CMDB.Password; v != "testpassword" {
		t.Errorf("Config.CNDBPassword should be not '%v', but 'testpassword'", v)
	}
	want, _ := time.ParseDuration("10s")
	if v := Config.CMDB.ConnectTimeout; v != want {
		t.Errorf("Config.CNDBConnectTimeout should be not '%v', but %v", v, want)
	}

	if v := Config.ProbeMode; v != "streaming" {
		t.Errorf("Config.ProbeMode should be not '%v', but 10", v)
	}
	want, _ = time.ParseDuration("3s")
	if v := Config.ProbeInterval; v != want {
		t.Errorf("Config.ProbeInterval should be not '%v', but '%v'", v, want)
	}
	want, _ = time.ParseDuration("10s")
	if v := Config.ProbeFlushInterval; v != want {
		t.Errorf("Config.ProbeFlushInterval should be not '%v', but '%v'", v, want)
	}

	if v := Config.Debug; !v {
		t.Errorf("Config.ProbeFlushInterval should be not '%v', but true", v)
	}
}
