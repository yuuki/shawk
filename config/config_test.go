package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	os.Setenv("SHAWK_CMDB_URL", "postgres://shawk:testpass@127.0.0.1:5432/testdb?sslmode=disable&connect_timeout=5")

	os.Setenv("SHAWK_PROBE_MODE", "streaming")
	os.Setenv("SHAWK_PROBE_INTERVAL", "3s")
	os.Setenv("SHAWK_PROBE_FLUSH_INTERVAL", "10s")

	os.Setenv("SHAWK_DEBUG", "1")

	err := Load()
	if err != nil {
		t.Fatal(err)
	}

	{
		want := "postgres://shawk:testpass@127.0.0.1:5432/testdb?sslmode=disable&connect_timeout=5"
		if v := Config.CMDB.URL; v != want {
			t.Errorf("Config.CNDBURL should be not '%v', but '%v'", v, want)
		}
	}

	{
		if v := Config.ProbeMode; v != "streaming" {
			t.Errorf("Config.ProbeMode should be not '%v', but 10", v)
		}
		want, _ := time.ParseDuration("3s")
		if v := Config.ProbeInterval; v != want {
			t.Errorf("Config.ProbeInterval should be not '%v', but '%v'", v, want)
		}
		want, _ = time.ParseDuration("10s")
		if v := Config.ProbeFlushInterval; v != want {
			t.Errorf("Config.ProbeFlushInterval should be not '%v', but '%v'", v, want)
		}
	}

	if v := Config.Debug; !v {
		t.Errorf("Config.ProbeFlushInterval should be not '%v', but true", v)
	}
}
