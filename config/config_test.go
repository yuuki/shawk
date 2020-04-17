package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	os.Setenv("SHAWK_CMDB_NAME", "testdb")

	err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if v := Config.CMDBName; v != "testdb" {
		t.Errorf("Config.CNDBName should be not '%s', but 'testdb'", v)
	}
}
