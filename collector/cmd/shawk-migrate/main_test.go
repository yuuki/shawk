package main

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// passwords are the synthetic passwords of the connection strings below:
// characters that %q escapes (", \, a line break, a tab), that quoting
// in keyword/value strings or URLs uses (', %, a space) and a non-ASCII
// letter. Each holds marker, so that a part of one is also found.
var passwords = []string{
	"s3cretPW" + marker,
	`pa"ss` + marker,
	`pa\ss` + marker,
	`pa'ss` + marker,
	"pa%ss" + marker,
	"pa\u00dfss" + marker,
	"pa ss" + marker,
	"pa\tss" + marker,
	"pa\nss" + marker,
}

// marker is in every password and in no text that the command prints.
const marker = "W0rdQx7"

// leaks tells whether out holds secret, its Go-quoted forms or marker.
func leaks(out, secret string) bool {
	forms := []string{secret, marker, strconv.Quote(secret), strconv.QuoteToASCII(secret)}
	for _, f := range forms[2:] {
		forms = append(forms, f[1:len(f)-1])
	}
	for _, f := range forms {
		if f != "" && strings.Contains(out, f) {
			return true
		}
	}
	return false
}

// TestNoPasswordInOutput checks that neither the usage nor the errors print
// the password of a connection string given by $SHAWK_POSTGRES_DSN or by a
// flag, in a form that pgx hides and in forms that it does not.
func TestNoPasswordInOutput(t *testing.T) {
	for _, pw := range passwords {
		url := "postgres://shawk:" + pw + "@db.example.test:5432/shawk"
		badPort := "postgres://shawk:" + pw + "@db.example.test:bad/shawk"
		at := "postgres://shawk:x@" + pw + "@db.example.test:bad/shawk"
		spaces := "host=db.example.test password = " + pw + " port=x"
		// The host 127.0.0.1, the port 12 and the database pa...@x/y:
		// pgconn and the server quote the database.
		misparsed := "postgres://127.0.0.1:12/" + pw + "@x/y"
		refused := "postgres://shawk:" + pw + "@127.0.0.1:1/shawk"
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
			{"connection string as a separate duration", "", []string{"-timeout", url}, 2},
			{"key and value with spaces in the environment", spaces, nil, 1},
			{"key and value with spaces in the flag", "", []string{"-dsn", spaces}, 1},
			{"password with @ in the environment", at, nil, 1},
			{"password with @ in the flag", "", []string{"-dsn=" + at}, 1},
			{"invalid port in the flag", "", []string{"-dsn", badPort}, 1},
			{"connection string as -print", "", []string{"-print=" + url}, 1},
			{"connection string as -dsn-file", "", []string{"-dsn-file", url}, 1},
			{"password in the database", "", []string{"-timeout=5s", "-dsn", misparsed}, 1},
			{"connection refused", refused, []string{"-timeout=5s"}, 1},
			{"connection string as an argument", "", []string{"-list", url}, 0},
		}
		for _, tc := range cases {
			t.Run(strconv.Quote(pw)+"/"+tc.name, func(t *testing.T) {
				out, exit := command(t, tc.env, tc.args...)
				if leaks(out, pw) {
					t.Errorf("the output holds the password:\n%s", out)
				}
				if exit != tc.exit {
					t.Errorf("exit status %d, want %d:\n%s", exit, tc.exit, out)
				}
			})
		}
	}
}

// randomArgs returns a command line and a value of $SHAWK_POSTGRES_DSN
// built around secret, with connection strings that connect to no host
// but the local one, where the port 1 refuses them, or fail to parse.
func randomArgs(r *rand.Rand, secret string) ([]string, string) {
	dsns := []string{
		"postgres://shawk:" + secret + "@127.0.0.1:1/shawk",
		"postgres://shawk:x@" + secret + "@127.0.0.1:1/shawk",
		"postgres://127.0.0.1:1/" + secret + "@x/y",
		"postgresql://127.0.0.1:1/shawk?password=" + secret,
		"host=127.0.0.1 port=1 password=" + secret,
		"host=127.0.0.1 port=1 password = " + secret,
		"host=127.0.0.1 port=1 password='" + secret + "'",
		secret,
	}
	dsn := func() string { return dsns[r.IntN(len(dsns))] }
	// Every command line connects for at most 2 seconds; a later -timeout
	// below holds a connection string and is invalid.
	args := []string{"-timeout=2s"}
	for n := r.IntN(4); n > 0; n-- {
		switch r.IntN(17) {
		case 0:
			args = append(args, "-dsn="+dsn())
		case 1:
			args = append(args, "-dsn", dsn())
		case 2:
			args = append(args, "---dsn="+dsn())
		case 3:
			args = append(args, "-"+dsn())
		case 4:
			args = append(args, "-list="+dsn())
		case 5:
			args = append(args, "-timeout="+dsn())
		case 6:
			args = append(args, "-timeout", dsn())
		case 7:
			args = append(args, "-print="+dsn())
		case 8:
			args = append(args, "-dsn-file", dsn())
		case 9:
			args = append(args, "-dsn-file="+dsn())
		case 10:
			args = append(args, dsn())
		case 11:
			args = append(args, "-h")
		case 12:
			args = append(args, "-list")
		case 13:
			args = append(args, "-bogus")
		case 14:
			args = append(args, "-dsn")
		case 15:
			args = append(args, "-list="+secret, "-dsn="+dsn())
		default:
			args = append(args, "--"+secret+"="+dsn())
		}
	}
	env := ""
	if r.IntN(2) == 0 {
		env = dsn()
	}
	return args, env
}

// checkNoSecret runs the command in this process with a command line
// built around secret and fails if the output holds it.
func checkNoSecret(t *testing.T, r *rand.Rand, secret string) {
	t.Helper()
	args, env := randomArgs(r, secret)
	var out bytes.Buffer
	exit := run("shawk-migrate", args, func(k string) string {
		if k == "SHAWK_POSTGRES_DSN" {
			return env
		}
		return ""
	}, &out, &out)
	if leaks(out.String(), secret) {
		t.Fatalf("the output holds the secret %q, with the arguments %q and $SHAWK_POSTGRES_DSN %q:\n%s", secret, args, env, out.String())
	}
	if exit != 0 && exit != 1 && exit != 2 {
		t.Fatalf("exit status %d", exit)
	}
}

// TestRandomNoSecret checks random command lines built around random
// secrets.
func TestRandomNoSecret(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	alphabet := []rune("aZ09\"'\\%@:/?#&= \t\n\r$`{}[]\u00df\u00e9\u4e2d\u2028\x00\x7f\ufeff")
	n := 300
	if testing.Short() {
		n = 50
	}
	for range n {
		var b strings.Builder
		for k := r.IntN(12); k > 0; k-- {
			b.WriteRune(alphabet[r.IntN(len(alphabet))])
		}
		checkNoSecret(t, r, "Sq"+b.String()+marker)
	}
}

// FuzzNoSecret checks command lines built around secrets that the fuzzer
// chooses.
func FuzzNoSecret(f *testing.F) {
	for _, pw := range passwords {
		f.Add(strings.TrimSuffix(pw, marker), uint64(1))
	}
	f.Fuzz(func(t *testing.T, secret string, seed uint64) {
		checkNoSecret(t, rand.New(rand.NewPCG(seed, 0)), "Sq"+secret+marker)
	})
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
	for _, tc := range []struct{ args, want string }{
		{"-bogus", "flag provided but not defined (the argument is not shown)"},
		{"---dsn=x", "bad flag syntax (the argument is not shown)"},
		{"-timeout=xyz", "invalid value for flag -timeout (the value is not shown)"},
		{"-list=xyz", "invalid value for flag -list (the value is not shown)"},
		{"-dsn", "flag needs an argument: -dsn"},
		{"-dsn-file", "flag needs an argument: -dsn-file"},
	} {
		out, exit := command(t, "", tc.args)
		if exit != 2 || !strings.HasPrefix(out, tc.want+"\nUsage of ") {
			t.Errorf("%s: exit status %d and output %q, want 2 and %q then the usage", tc.args, exit, out, tc.want)
		}
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
