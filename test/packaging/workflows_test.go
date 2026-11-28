package packaging

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestWorkflowPackageInstalls: the package mirrors of the runners are slow
// at times, for up to half an hour, which took the time of the tests of
// whole jobs. Every step of the workflows that installs Debian packages
// does so with scripts/apt-install.sh, which limits and retries each run of
// apt-get, and has a time limit of its own, shorter than that of its job.
func TestWorkflowPackageInstalls(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(root, ".github/workflows/*.yml"))
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Jobs map[string]struct {
				TimeoutMinutes int `yaml:"timeout-minutes"`
				Steps          []struct {
					Name           string `yaml:"name"`
					Run            string `yaml:"run"`
					TimeoutMinutes int    `yaml:"timeout-minutes"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for name, job := range doc.Jobs {
			for _, s := range job.Steps {
				script := strings.Contains(s.Run, "scripts/apt-install.sh")
				if !script && !strings.Contains(s.Run, "apt-get") {
					continue
				}
				n++
				if !script {
					t.Errorf("%s: job %s, step %q runs apt-get rather than scripts/apt-install.sh", f, name, s.Name)
				}
				if s.TimeoutMinutes == 0 || s.TimeoutMinutes >= job.TimeoutMinutes {
					t.Errorf("%s: job %s, step %q: timeout-minutes %d, want one below the %d of the job",
						f, name, s.Name, s.TimeoutMinutes, job.TimeoutMinutes)
				}
			}
		}
	}
	if n < 2 {
		t.Errorf("only %d steps install packages", n)
	}
}

// TestAptInstallNextMirror: apt starts every download at the first mirror
// of the list of the runner image, also when that mirror is slow, as
// us-east-2.ec2.archive.ubuntu.com was for every attempt of the kernel jobs
// on 2026-11-24. After a failed install, scripts/apt-install.sh moves that
// mirror behind the others, so that the apt-get update and the install of
// the next attempt use another one. A fake apt-get fails every install and
// keeps the list each run sees.
func TestAptInstallNextMirror(t *testing.T) {
	for _, tc := range []struct {
		name, list string
		// The mirror apt tries first in each run: install, update,
		// install, update, install.
		first []string
		after string
	}{{
		// The list of the AWS image of the runners (actions/runner-images,
		// images/ubuntu/scripts/build/configure-apt-sources.sh).
		name: "runner",
		list: "http://us-east-2.ec2.archive.ubuntu.com/ubuntu/\tpriority:1\n" +
			"https://archive.ubuntu.com/ubuntu/\tpriority:2\n" +
			"https://security.ubuntu.com/ubuntu/\tpriority:3\n",
		first: []string{
			"http://us-east-2.ec2.archive.ubuntu.com/ubuntu/",
			"https://archive.ubuntu.com/ubuntu/", "https://archive.ubuntu.com/ubuntu/",
			"https://security.ubuntu.com/ubuntu/", "https://security.ubuntu.com/ubuntu/",
		},
		after: "http://us-east-2.ec2.archive.ubuntu.com/ubuntu/\tpriority:4\n" +
			"https://archive.ubuntu.com/ubuntu/\tpriority:5\n" +
			"https://security.ubuntu.com/ubuntu/\tpriority:3\n",
	}, {
		// Comments, other tags and mirrors without a priority stay.
		name:  "tags",
		list:  "# priority:0\nhttp://b/\tarch:amd64 priority:20\n\nhttp://a/\tpriority:10\nhttp://c/\n",
		first: []string{"http://a/", "http://b/", "http://b/", "http://a/", "http://a/"},
		after: "# priority:0\nhttp://b/\tarch:amd64 priority:22\n\nhttp://a/\tpriority:21\nhttp://c/\n",
	}, {
		// apt tries the mirrors of a list without priorities in a random
		// order.
		name:  "unordered",
		list:  "http://a/\nhttp://b/\n",
		first: []string{"http://a/", "http://a/", "http://a/", "http://a/", "http://a/"},
		after: "http://a/\nhttp://b/\n",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin, runs := filepath.Join(dir, "bin"), filepath.Join(dir, "runs")
			for _, d := range []string{bin, runs} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, script := range map[string]string{
				// sudo runs the command, without the time limit.
				"sudo": "#!/bin/sh\nif [ \"$1\" = timeout ]; then shift 2; fi\nexec \"$@\"\n",
				"dpkg": "#!/bin/sh\n",
				"apt-get": "#!/bin/sh\n" +
					"for a; do case $a in install|update) cmd=$a ;; esac; done\n" +
					"n=$(ls \"$APT_RUNS\" | wc -l | tr -d ' ')\n" +
					"cp \"$APT_MIRRORS\" \"$APT_RUNS/$n-$cmd\"\n" +
					"[ \"$cmd\" = update ]\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			list := filepath.Join(dir, "apt-mirrors.txt")
			if err := os.WriteFile(list, []byte(tc.list), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", filepath.Join(root, "scripts/apt-install.sh"), "qemu-system-x86")
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"APT_MIRRORS="+list, "APT_RUNS="+runs)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("apt-install.sh: %v, want exit status 1 after 3 failed installs:\n%s", err, out)
			}
			entries, err := os.ReadDir(runs)
			if err != nil {
				t.Fatal(err)
			}
			var got, want []string
			for _, e := range entries {
				b, err := os.ReadFile(filepath.Join(runs, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, e.Name()+" "+firstMirror(string(b)))
			}
			for i, m := range tc.first {
				want = append(want, fmt.Sprintf("%d-%s %s", i, []string{"install", "update"}[i%2], m))
			}
			if !slices.Equal(got, want) {
				t.Errorf("runs of apt-get and their first mirror:\n%s\nwant:\n%s",
					strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if b, err := os.ReadFile(list); err != nil || string(b) != tc.after {
				t.Errorf("list after the attempts: %q, %v, want %q", b, err, tc.after)
			}
		})
	}
}

// firstMirror returns the mirror of a list of apt's mirror method that apt
// tries first: the one of the lowest priority: tag, before those without
// one.
func firstMirror(list string) string {
	first, low := "", uint64(math.MaxUint64)
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		p := uint64(math.MaxUint64)
		for _, tag := range fields[1:] {
			if v, ok := strings.CutPrefix(tag, "priority:"); ok {
				p, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		if first == "" || p < low {
			first, low = fields[0], p
		}
	}
	return first
}
