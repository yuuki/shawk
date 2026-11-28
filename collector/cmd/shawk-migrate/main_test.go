package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// password is the password of the synthetic connection strings below.
const password = "s3cretPW"

// asMain tells the test binary, run again by command, to run main.
const asMain = "SHAWK_MIGRATE_TEST_AS_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(asMain) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// command runs main in a new process with the arguments and the
// environment variable $SHAWK_POSTGRES_DSN (unset if env is empty), and
// returns its output, stdout and stderr together, and its exit status.
func command(t *testing.T, env string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), asMain+"=1")
	cmd.Env = append(cmd.Env, "SHAWK_POSTGRES_DSN="+env)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), 0
}

// TestNoPasswordInOutput checks that neither the usage nor the errors print
// the password of a connection string given by $SHAWK_POSTGRES_DSN or by a
// flag, in a form that pgx hides and in forms that it does not.
func TestNoPasswordInOutput(t *testing.T) {
	url := "postgres://shawk:" + password + "@db.example.test:5432/shawk"
	cases := []struct {
		name string
		env  string
		args []string
		exit int
	}{
		{"help with the environment", url, []string{"-h"}, 0},
		{"help with the flag", "", []string{"-dsn", url, "-h"}, 0},
		{"undefined flag with the environment", url, []string{"-bogus"}, 2},
		{"bad flag syntax", "", []string{"---dsn=" + url}, 2},
		{"connection string as a flag name", "", []string{"-" + url}, 2},
		{"connection string as a boolean", "", []string{"-list=" + url}, 2},
		{"connection string as a duration", "", []string{"-timeout=" + url}, 2},
		{"key and value with spaces in the environment", "host=db.example.test password = " + password + " port=x", nil, 1},
		{"key and value with spaces in the flag", "", []string{"-dsn", "host=db.example.test password = " + password + " port=x"}, 1},
		{"password with @ in the environment", "postgres://shawk:x@" + password + "@db.example.test:bad/shawk", nil, 1},
		{"password with @ in the flag", "", []string{"-dsn=postgres://shawk:x@" + password + "@db.example.test:bad/shawk"}, 1},
		{"invalid port in the flag", "", []string{"-dsn", "postgres://shawk:" + password + "@db.example.test:bad/shawk"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, exit := command(t, tc.env, tc.args...)
			if strings.Contains(out, password) {
				t.Errorf("the output holds the password:\n%s", out)
			}
			if exit != tc.exit {
				t.Errorf("exit status %d, want %d:\n%s", exit, tc.exit, out)
			}
		})
	}
}

// TestFlags checks that the flags and the environment variable work as
// before: the usage lists the flags, -dsn wins over the environment even
// when empty, and -dsn-file over both.
func TestFlags(t *testing.T) {
	bad := "postgres://shawk:" + password + "@db.example.test:bad/shawk"
	out, _ := command(t, bad, "-h")
	for _, f := range []string{"-dsn string", "(default $SHAWK_POSTGRES_DSN)", "-dsn-file string", "-list", "-print string", "-timeout duration", "(default 1m0s)"} {
		if !strings.Contains(out, f) {
			t.Errorf("the usage lacks %q:\n%s", f, out)
		}
	}
	out, _ = command(t, "", "-bogus")
	if !strings.Contains(out, "flag provided but not defined: -bogus") {
		t.Errorf("the error does not name the flag:\n%s", out)
	}
	out, _ = command(t, "", "-timeout=xyz")
	if !strings.Contains(out, `invalid value "xyz" for flag -timeout`) {
		t.Errorf("the error does not quote a plain value:\n%s", out)
	}

	const missing = "set -dsn, -dsn-file or $SHAWK_POSTGRES_DSN"
	const invalid = "invalid PostgreSQL connection string"
	file := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(file, []byte(bad+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  string
		args []string
		want string
	}{
		{"nothing", "", nil, missing},
		{"the environment", bad, nil, invalid},
		{"the flag", "", []string{"-dsn", bad}, invalid},
		{"an empty flag wins over the environment", bad, []string{"-dsn="}, missing},
		{"the file", "", []string{"-dsn-file", file}, invalid},
		{"an empty file wins over the flag", "", []string{"-dsn", bad, "-dsn-file", empty}, missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, exit := command(t, tc.env, tc.args...)
			if exit != 1 || !strings.Contains(out, tc.want) {
				t.Errorf("exit status %d and output %q, want 1 and %q", exit, out, tc.want)
			}
		})
	}

	out, exit := command(t, bad, "-list")
	if exit != 0 || !strings.Contains(out, "0001_schema.sql") {
		t.Errorf("-list: exit status %d:\n%s", exit, out)
	}
}
