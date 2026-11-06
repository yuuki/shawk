package packaging

import (
	"bufio"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const root = "../.."

type nfpmContent struct {
	Src      string `yaml:"src"`
	Dst      string `yaml:"dst"`
	Packager string `yaml:"packager"`
}

// archiveFile is a file of an archive: a glob, or a src with options.
type archiveFile struct {
	Src         string `yaml:"src"`
	StripParent bool   `yaml:"strip_parent"`
}

func (f *archiveFile) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		f.Src = n.Value
		return nil
	}
	type plain archiveFile
	return n.Decode((*plain)(f))
}

type releaseConfig struct {
	Before struct {
		Hooks []string `yaml:"hooks"`
	} `yaml:"before"`
	Builds []struct {
		ID     string `yaml:"id"`
		Binary string `yaml:"binary"`
	} `yaml:"builds"`
	Archives []struct {
		ID    string        `yaml:"id"`
		IDs   []string      `yaml:"ids"`
		Files []archiveFile `yaml:"files"`
	} `yaml:"archives"`
	NFPMs []struct {
		ID          string        `yaml:"id"`
		IDs         []string      `yaml:"ids"`
		PackageName string        `yaml:"package_name"`
		Formats     []string      `yaml:"formats"`
		Bindir      string        `yaml:"bindir"`
		Contents    []nfpmContent `yaml:"contents"`
	} `yaml:"nfpms"`
}

func loadReleaseConfig(t *testing.T) releaseConfig {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var c releaseConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// generated reports whether a file is written by a before hook of the
// release, which the test cannot run; it fails the test for a file under
// build/ that no hook writes.
func generated(t *testing.T, c releaseConfig, file string) bool {
	t.Helper()
	if !strings.HasPrefix(file, "build/") {
		return false
	}
	if !slices.ContainsFunc(c.Before.Hooks, func(h string) bool { return strings.Contains(h, "-o "+file+" ") }) {
		t.Errorf("no before hook writes %s", file)
	}
	return true
}

// TestReleasePackages checks the archives and packages of .goreleaser.yml
// against the files they ship and the systemd units they install.
func TestReleasePackages(t *testing.T) {
	c := loadReleaseConfig(t)
	binaries := map[string]string{}
	for _, b := range c.Builds {
		binaries[b.ID] = b.Binary
	}
	archived := map[string][]string{} // files of the archive of each build
	for _, a := range c.Archives {
		var files []string
		for _, af := range a.Files {
			glob := af.Src
			if generated(t, c, glob) {
				if !af.StripParent {
					t.Errorf("archive %s: %s is not at the root of the archive", a.ID, glob)
				}
				files = append(files, glob)
				continue
			}
			m, _ := filepath.Glob(filepath.Join(root, glob))
			if len(m) == 0 {
				t.Errorf("archive %s: %s matches no file", a.ID, glob)
			}
			for _, f := range m {
				rel, _ := filepath.Rel(root, f)
				files = append(files, filepath.ToSlash(rel))
			}
		}
		for _, id := range a.IDs {
			archived[id] = append(archived[id], files...)
		}
	}
	for _, p := range c.NFPMs {
		installed := map[string]map[string]bool{"deb": {}, "rpm": {}}
		for _, id := range p.IDs {
			for _, f := range []string{"deb", "rpm"} {
				installed[f][path.Join(p.Bindir, binaries[id])] = true
			}
		}
		for _, ct := range p.Contents {
			if !generated(t, c, ct.Src) {
				if _, err := os.Stat(filepath.Join(root, ct.Src)); err != nil {
					t.Errorf("%s: %v", p.ID, err)
				}
			}
			for _, f := range []string{"deb", "rpm"} {
				if ct.Packager == "" || ct.Packager == f {
					installed[f][ct.Dst] = true
				}
			}
			// Tarball users install the examples the packages install.
			if strings.HasPrefix(ct.Src, "packaging/") && !strings.HasPrefix(ct.Src, "packaging/deb/") {
				for _, id := range p.IDs {
					if !slices.Contains(archived[id], ct.Src) {
						t.Errorf("%s: %s is not in the archive of %s", p.ID, ct.Src, id)
					}
				}
			}
		}
		// rpm keeps the license texts in /usr/share/licenses, deb its
		// copyright file and the notices in /usr/share/doc.
		doc, licenses := "/usr/share/doc/"+p.PackageName+"/", "/usr/share/licenses/"+p.PackageName+"/"
		want := map[string][]string{
			"deb": {doc + "copyright", doc + "THIRD_PARTY_NOTICES"},
			"rpm": {licenses + "LICENSE", licenses + "THIRD_PARTY_NOTICES"},
		}
		if p.PackageName == "shawk" {
			want["deb"] = append(want["deb"], doc+"NOTICE")
			want["rpm"] = append(want["rpm"], licenses+"NOTICE")
			texts, _ := filepath.Glob(filepath.Join(root, "LICENSES/*"))
			for _, f := range texts {
				want["rpm"] = append(want["rpm"], licenses+filepath.Base(f))
			}
		}
		for _, f := range p.Formats {
			for _, dst := range want[f] {
				if !installed[f][dst] {
					t.Errorf("%s %s: %s is not installed", p.ID, f, dst)
				}
			}
			for dst := range installed[f] {
				if f == "deb" && strings.HasPrefix(dst, "/usr/share/licenses/") || f == "rpm" && dst == doc+"copyright" {
					t.Errorf("%s %s: %s is installed", p.ID, f, dst)
				}
			}
		}
		// The units start an installed binary and read installed files.
		for _, ct := range p.Contents {
			if !strings.HasSuffix(ct.Dst, ".service") {
				continue
			}
			for key, v := range unitSettings(t, filepath.Join(root, ct.Src)) {
				var file string
				switch key {
				case "ExecStart":
					file, _, _ = strings.Cut(v, " ")
				case "EnvironmentFile":
					file = strings.TrimPrefix(v, "-")
				default:
					continue
				}
				if !installed["deb"][file] || !installed["rpm"][file] {
					t.Errorf("%s: %s=%s is not installed by the package", ct.Src, key, v)
				}
			}
		}
	}
}

// TestUnitsSandboxed checks that the systemd units keep their sandbox, and
// that the one of the agent still allows what the tracer needs.
func TestUnitsSandboxed(t *testing.T) {
	units, _ := filepath.Glob(filepath.Join(root, "packaging/systemd/*.service"))
	if len(units) != 2 {
		t.Fatalf("units = %v", units)
	}
	for _, u := range units {
		s := unitSettings(t, u)
		for k, want := range map[string]string{
			"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
			"ProtectKernelTunables": "yes", "ProtectControlGroups": "yes", "SystemCallArchitectures": "native",
			"SystemCallErrorNumber": "EPERM",
		} {
			if s[k] != want {
				t.Errorf("%s: %s=%s, want %s", u, k, s[k], want)
			}
		}
		for _, k := range []string{"CapabilityBoundingSet", "RestrictAddressFamilies", "RestrictNamespaces", "SystemCallFilter"} {
			if _, ok := s[k]; !ok {
				t.Errorf("%s: no %s", u, k)
			}
		}
		if filepath.Base(u) != "shawk-agent.service" {
			continue
		}
		// The agent reports ready from its main process once its programs
		// are attached; NOTIFY_SOCKET is a Unix socket.
		if s["Type"] != "notify" {
			t.Errorf("%s: Type=%s, want notify", u, s["Type"])
		}
		if s["NotifyAccess"] == "none" {
			t.Errorf("%s: NotifyAccess=none does not let the agent report ready", u)
		}
		for k, need := range map[string][]string{
			"CapabilityBoundingSet":   {"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"},
			"SystemCallFilter":        {"@system-service", "bpf", "perf_event_open", "setns"},
			"RestrictAddressFamilies": {"AF_INET", "AF_INET6", "AF_NETLINK", "AF_UNIX"},
			"RestrictNamespaces":      {"net"},
		} {
			for _, v := range need {
				if !slices.Contains(strings.Fields(s[k]), v) {
					t.Errorf("%s: %s does not have %s", u, k, v)
				}
			}
		}
	}
}

// unitSettings returns the settings of a unit. The values of a key given
// several times are joined with spaces, as systemd accumulates lists such as
// SystemCallFilter=; the units do not reset a list with an empty value.
func unitSettings(t *testing.T, file string) map[string]string {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: malformed line %q", file, line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if prev, ok := out[k]; ok && prev != "" {
			v = prev + " " + v
		}
		out[k] = v
	}
	return out
}

// TestUnitsVerify checks the units with systemd-analyze, which reports the
// settings it does not know, e.g. misspelt ones, which systemd ignores.
func TestUnitsVerify(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not available")
	}
	units, _ := filepath.Glob(filepath.Join(root, "packaging/systemd/*.service"))
	for _, u := range units {
		abs, err := filepath.Abs(u)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := exec.Command(analyze, "verify", abs).CombinedOutput()
		for _, line := range unitProblems(string(out), abs) {
			t.Errorf("%s: %s", filepath.Base(u), line)
		}
	}
}

// The lines of systemd-analyze verify that name what they concern: a file
// and a line of it, or a unit.
var (
	verifyFileLine = regexp.MustCompile(`^(/[^:]+):\d+: `)
	verifyUnitLine = regexp.MustCompile(`^([^\s/:]+\.(?:service|socket|device|mount|automount|swap|target|path|timer|slice|scope)): `)
)

// unitProblems returns the lines of the output of systemd-analyze verify of
// the unit file that concern it. systemd-analyze also loads the units of the
// host that the unit pulls in, and the drop-ins of the host for its name, and
// reports their problems, e.g. a PIDFile= under /var/run/ of munge.service on
// Rocky Linux 9 (#196): such a line starts with the path of another file or
// the name of another unit, and is left out. Lines that name neither are
// kept. "is not executable" is left out, since the binaries are not
// installed here.
func unitProblems(out, file string) []string {
	self, _ := os.Stat(file)
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || strings.Contains(line, "is not executable") {
			continue
		}
		if m := verifyFileLine.FindStringSubmatch(line); m != nil {
			if fi, err := os.Stat(m[1]); err != nil || self == nil || !os.SameFile(fi, self) {
				continue
			}
		} else if m := verifyUnitLine.FindStringSubmatch(line); m != nil && m[1] != filepath.Base(file) {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// TestUnitProblems checks that the problems of the units of the host, which
// systemd-analyze reports with those of the unit verified, are left out,
// and that those of the unit are kept, with systemd-analyze when the host
// has it.
func TestUnitProblems(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "shawk-agent.service")
	b, err := os.ReadFile(filepath.Join(root, "packaging/systemd/shawk-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	typo := strings.Replace(string(b), "\nProtectSystem=", "\nProtectSytem=", 1)
	if typo == string(b) {
		t.Fatal("no ProtectSystem= in shawk-agent.service")
	}
	if err := os.WriteFile(unit, []byte(typo), 0o644); err != nil {
		t.Fatal(err)
	}
	out := unit + ":40: Unknown key name 'ProtectSytem' in section 'Service', ignoring.\n" +
		"/usr/lib/systemd/system/munge.service:10: PIDFile= references a path below legacy directory /var/run/, updating /var/run/munge/munged.pid → /run/munge/munged.pid; please update the unit file accordingly.\n" +
		"/etc/systemd/system/shawk-agent.service.d/override.conf:2: Unknown key name 'Foo' in section 'Service', ignoring.\n" +
		"munge.service: Command /usr/sbin/munged is not executable: No such file or directory\n" +
		"foo@1.service: Service has more than one ExecStart= setting, which is only allowed for Type=oneshot services. Refusing.\n" +
		"shawk-agent.service: Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.\n" +
		"shawk-agent.service: Command /usr/bin/shawk is not executable: No such file or directory\n" +
		"Failed to start transaction: Unit sysinit.target not found.\n"
	want := []string{
		unit + ":40: Unknown key name 'ProtectSytem' in section 'Service', ignoring.",
		"shawk-agent.service: Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.",
		"Failed to start transaction: Unit sysinit.target not found.",
	}
	if got := unitProblems(out, unit); !slices.Equal(got, want) {
		t.Errorf("unitProblems =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not available")
	}
	// A unit of the host that warns, pulled in by network-online.target,
	// which shawk-agent.service wants, as munge.service is on Rocky Linux 9.
	host := filepath.Join(dir, "host")
	if err := os.MkdirAll(filepath.Join(host, "network-online.target.wants"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "hostwarn.service"),
		[]byte("[Service]\nExecStart=/bin/true\nBogus=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../hostwarn.service", filepath.Join(host, "network-online.target.wants/hostwarn.service")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(analyze, "verify", unit)
	// The trailing colon appends the default unit path.
	cmd.Env = append(os.Environ(), "SYSTEMD_UNIT_PATH="+host+":")
	raw, _ := cmd.CombinedOutput()
	if !strings.Contains(string(raw), "hostwarn.service") {
		t.Skipf("systemd-analyze did not load the unit of the host:\n%s", raw)
	}
	got := unitProblems(string(raw), unit)
	if len(got) != 1 || !strings.Contains(got[0], "ProtectSytem") {
		t.Errorf("unitProblems of\n%s= %q, want the misspelt ProtectSytem only", raw, got)
	}
}

// dep5 parses a machine-readable debian/copyright file into paragraphs of
// fields; continuation lines are kept with their leading space.
func dep5(t *testing.T, file string) []map[string]string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var paras []map[string]string
	for _, block := range strings.Split(strings.TrimSpace(string(b)), "\n\n") {
		p := map[string]string{}
		var last string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, " ") && last != "" {
				p[last] += "\n" + line
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				t.Fatalf("%s: malformed line %q", file, line)
			}
			last = k
			p[k] = strings.TrimSpace(v)
		}
		paras = append(paras, p)
	}
	return paras
}

// TestDebianCopyright checks the copyright files of the deb packages: the
// files they name exist, every license they use has its text, and every
// file of the BPF programs, which are not Apache-2.0, has its own paragraph.
func TestDebianCopyright(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(root, "packaging/deb/*.copyright"))
	if len(files) != 2 {
		t.Fatalf("copyright files = %v", files)
	}
	for _, file := range files {
		paras := dep5(t, file)
		if paras[0]["Format"] != "https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/" {
			t.Errorf("%s: no Format in the header", file)
		}
		texts := map[string]bool{}
		for _, p := range paras[1:] {
			if _, ok := p["Files"]; !ok {
				name, text, _ := strings.Cut(p["License"], "\n")
				texts[name] = text != ""
			}
		}
		var patterns []*regexp.Regexp
		for _, p := range paras[1:] {
			pats, ok := p["Files"]
			if !ok {
				continue
			}
			if p["Copyright"] == "" || p["License"] == "" {
				t.Errorf("%s: Files %s: no Copyright or License", file, pats)
			}
			for _, name := range regexp.MustCompile(` or | and |, `).Split(p["License"], -1) {
				if !texts[name] {
					t.Errorf("%s: no text of the license %s", file, name)
				}
			}
			for _, pat := range strings.Fields(pats) {
				if pat == "*" {
					continue
				}
				re := regexp.MustCompile("^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pat)) + "$")
				patterns = append(patterns, re)
				if m, _ := filepath.Glob(filepath.Join(root, pat)); len(m) == 0 {
					t.Errorf("%s: %s matches no file", file, pat)
				}
			}
		}
		// The binaries link third-party modules, whose licenses the
		// package ships next to the copyright file.
		pkg := strings.TrimSuffix(filepath.Base(file), ".copyright")
		if !strings.Contains(strings.Join(strings.Fields(paras[0]["Comment"]), " "), "/usr/share/doc/"+pkg+"/THIRD_PARTY_NOTICES") {
			t.Errorf("%s: the header does not refer to /usr/share/doc/%s/THIRD_PARTY_NOTICES", file, pkg)
		}
		if pkg != "shawk" {
			continue
		}
		bpf := []string{"internal/tracer/bpf_bpfel.o"}
		filepath.WalkDir(filepath.Join(root, "internal/tracer/bpf"), func(f string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, f)
			bpf = append(bpf, filepath.ToSlash(rel))
			return nil
		})
		for _, rel := range bpf {
			if !slices.ContainsFunc(patterns, func(re *regexp.Regexp) bool { return re.MatchString(rel) }) {
				t.Errorf("%s: %s is not covered by its own paragraph", file, rel)
			}
		}
	}
}
