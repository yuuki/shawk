package packaging

import (
	"os"
	"path/filepath"
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
