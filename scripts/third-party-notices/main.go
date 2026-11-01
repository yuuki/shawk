// Command third-party-notices writes the license texts of the Go modules and
// of the Go standard library linked into binaries, which the release archives
// and packages ship next to them.
//
//	go run ./scripts/third-party-notices -o FILE DIR=PACKAGE...
//
// The packages are listed with their dependencies by go list in DIR, for
// linux/amd64 and linux/arm64. It fails when a module has no license file at
// its root, so that a new dependency cannot be shipped without its license.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Modules of this repository are covered by its own LICENSE and NOTICE.
const ownModule = "github.com/yuuki/shawk"

var licenseFile = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents|unlicense)([.\-_].*)?$`)

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

type pkg struct {
	ImportPath string
	Standard   bool
	Module     *module
}

func main() {
	out := flag.String("o", "", "output file")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: third-party-notices -o FILE DIR=PACKAGE...")
		os.Exit(2)
	}
	if err := run(*out, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "third-party-notices:", err)
		os.Exit(1)
	}
}

func run(out string, targets []string) error {
	mods := map[string]module{}
	for _, target := range targets {
		dir, pattern, ok := strings.Cut(target, "=")
		if !ok {
			return fmt.Errorf("%q is not DIR=PACKAGE", target)
		}
		for _, arch := range []string{"amd64", "arm64"} {
			if err := list(dir, pattern, arch, mods); err != nil {
				return fmt.Errorf("%s for %s: %w", target, arch, err)
			}
		}
	}

	var b bytes.Buffer
	b.WriteString("Third-party software linked into the binaries, with the texts of its licenses.\n")
	goroot, err := goEnv("GOROOT")
	if err != nil {
		return err
	}
	goversion, err := goEnv("GOVERSION")
	if err != nil {
		return err
	}
	if err := writeLicenses(&b, "Go standard library and runtime "+goversion, goroot); err != nil {
		return err
	}
	keys := make([]string, 0, len(mods))
	for k := range mods {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var missing []string
	for _, k := range keys {
		m := mods[k]
		if err := writeLicenses(&b, m.Path+" "+m.Version, m.Dir); err != nil {
			missing = append(missing, fmt.Sprintf("%s %s: %v", m.Path, m.Version, err))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("no license found for:\n  %s", strings.Join(missing, "\n  "))
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// list adds the modules of the packages pattern depends on.
func list(dir, pattern, arch string, mods map[string]module) error {
	cmd := exec.Command("go", "list", "-deps", "-json=ImportPath,Standard,Module", pattern)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Stderr = os.Stderr
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			return err
		}
		m := p.Module
		if p.Standard || m == nil || m.Main {
			continue
		}
		if m.Replace != nil {
			m = m.Replace
		}
		if strings.HasPrefix(m.Path, ownModule) || strings.HasPrefix(p.Module.Path, ownModule) {
			continue
		}
		if m.Dir == "" {
			return fmt.Errorf("module %s %s is not downloaded", m.Path, m.Version)
		}
		mods[m.Path+"@"+m.Version] = *m
	}
	return nil
}

// writeLicenses appends the license files at the root of dir.
func writeLicenses(b *bytes.Buffer, title, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var found bool
	for _, e := range entries {
		if e.IsDir() || !licenseFile.MatchString(e.Name()) {
			continue
		}
		text, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		found = true
		fmt.Fprintf(b, "\n%s\n%s (%s)\n%s\n\n", strings.Repeat("=", 78), title, e.Name(), strings.Repeat("-", 78))
		b.Write(bytes.TrimRight(text, "\n"))
		b.WriteByte('\n')
	}
	if !found {
		return errors.New("no license file")
	}
	return nil
}

func goEnv(name string) (string, error) {
	b, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}
