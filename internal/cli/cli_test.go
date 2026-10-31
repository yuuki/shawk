package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d":  30 * 24 * time.Hour,
		"2w":   14 * 24 * time.Hour,
		"12h":  12 * time.Hour,
		"90m":  90 * time.Minute,
		"1.5d": 36 * time.Hour,
	} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "-1d", "x", "-1h", "0s", "0d", "NaNd", "Infd", "1e300d", "5e4w"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) succeeded", in)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0B", 1023: "1023B", 1024: "1.0KiB", 1536: "1.5KiB", 5 << 30: "5.0GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Main(nil, &out, &errOut); code != 2 {
		t.Errorf("exit code without arguments = %d", code)
	}
	if code := Main([]string{"nope"}, &out, &errOut); code != 2 {
		t.Errorf("exit code of an unknown command = %d", code)
	}
	if code := Main([]string{"who-uses"}, &out, &errOut); code != 2 {
		t.Errorf("exit code without a target = %d", code)
	}
	if code := Main([]string{"can-i-remove", "db-01/nginx.service"}, &out, &errOut); code != 2 {
		t.Errorf("exit code of can-i-remove with a process = %d", code)
	}
	if code := Main([]string{"can-i-remove", "db-01", "-since", "-1h"}, &out, &errOut); code != 2 {
		t.Errorf("exit code of a negative window = %d", code)
	}
	if code := Main([]string{"version"}, &out, &errOut); code != 0 {
		t.Errorf("exit code of version = %d", code)
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte(" \n"), 0o600)
	if _, err := readToken(empty); err == nil {
		t.Error("an empty token file was accepted")
	}
	ok := filepath.Join(dir, "token")
	os.WriteFile(ok, []byte("s3cret\n"), 0o600)
	if tok, err := readToken(ok); err != nil || tok != "s3cret" {
		t.Errorf("readToken = %q, %v", tok, err)
	}
}
