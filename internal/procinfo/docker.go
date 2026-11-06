package procinfo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Docker keeps its state under its data root: --data-root on the command
// line of dockerd, else data-root in its configuration file
// (--config-file, /etc/docker/daemon.json by default), else
// /var/lib/docker. dockerd refuses to start with both.
const (
	dockerDefaultRoot   = "/var/lib/docker"
	dockerDefaultConfig = "/etc/docker/daemon.json"
	// dockerRootsTTL is how long the data roots are kept before they are
	// found again, so that a dockerd started or restarted with another
	// one is followed.
	dockerRootsTTL = time.Minute
)

// dockerDataRoots returns the data roots of the dockerd processes of the
// host, or, when none runs, that of the configuration file.
func (c *Containers) dockerDataRoots() []string {
	c.dockerMu.Lock()
	defer c.dockerMu.Unlock()
	if now := time.Now(); c.dockerRoots == nil || now.Sub(c.dockerRead) >= dockerRootsTTL {
		c.dockerRoots, c.dockerRead = c.findDockerRoots(), now
	}
	return c.dockerRoots
}

func (c *Containers) findDockerRoots() []string {
	var roots []string
	add := func(r string) {
		if !slices.Contains(roots, r) {
			roots = append(roots, r)
		}
	}
	for _, args := range c.dockerdArgs() {
		root, config := dockerdFlags(args)
		if root == "" {
			root = c.configDataRoot(config)
		}
		add(root)
	}
	if len(roots) == 0 {
		add(c.configDataRoot(""))
	}
	return roots
}

// configDataRoot returns data-root of a configuration file of dockerd
// (dockerDefaultConfig for ""), or dockerDefaultRoot.
func (c *Containers) configDataRoot(file string) string {
	if file == "" {
		file = dockerDefaultConfig
	}
	var cfg struct {
		DataRoot string `json:"data-root"`
	}
	if b := c.readFile(file); b != nil && json.Unmarshal(b, &cfg) == nil && filepath.IsAbs(cfg.DataRoot) {
		return filepath.Clean(cfg.DataRoot)
	}
	return dockerDefaultRoot
}

// dockerdArgs returns the command lines of the dockerd processes of the
// host: named dockerd, run by root with all its user ids, in the mount
// namespace of PID 1. Their paths are those the agent sees. Any user may
// name a process dockerd, and the root of a container may run one whose
// paths are of its own mount namespace; neither tells where the containers
// of the host are (#125). Nothing else of a command line is kept.
func (c *Containers) dockerdArgs() [][]string {
	hostMnt, err := os.Readlink(filepath.Join(c.root, "/proc/1/ns/mnt"))
	if err != nil {
		return nil
	}
	pids, err := os.ReadDir(filepath.Join(c.root, "/proc"))
	if err != nil {
		return nil
	}
	var out [][]string
	for _, e := range pids {
		pid := e.Name()
		if pid[0] < '1' || pid[0] > '9' || strings.TrimFunc(pid, isDigit) != "" {
			continue
		}
		dir := filepath.Join("/proc", pid)
		if comm := c.readFile(filepath.Join(dir, "comm")); strings.TrimSpace(string(comm)) != "dockerd" {
			continue
		}
		if !rootUIDs(c.readFile(filepath.Join(dir, "status"))) {
			continue
		}
		if mnt, err := os.Readlink(filepath.Join(c.root, dir, "ns/mnt")); err != nil || mnt != hostMnt {
			continue
		}
		cmdline := strings.TrimRight(string(c.readFile(filepath.Join(dir, "cmdline"))), "\x00")
		if cmdline != "" {
			out = append(out, strings.Split(cmdline, "\x00"))
		}
	}
	return out
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// rootUIDs tells whether the Uid line of /proc/PID/status has root as the
// real, effective, saved and file system user.
func rootUIDs(status []byte) bool {
	for line := range strings.SplitSeq(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			ids := strings.Fields(rest)
			return len(ids) == 4 && !slices.ContainsFunc(ids, func(id string) bool { return id != "0" })
		}
	}
	return false
}

// dockerdFlags returns the data root and the configuration file on the
// command line of dockerd, "" for those it does not give: --data-root, or
// -g and --graph before Docker 23, and --config-file, in the forms of
// pflag (--flag value, --flag=value, -g value, -g=value, -gvalue), the
// last one winning. Relative paths are left out.
func dockerdFlags(args []string) (dataRoot, configFile string) {
	for i := 1; i < len(args); i++ {
		a := args[i]
		var name, value string
		switch {
		case strings.HasPrefix(a, "--"):
			n, v, ok := strings.Cut(a[2:], "=")
			name, value = n, v
			if !ok && i+1 < len(args) && (n == "data-root" || n == "graph" || n == "config-file") {
				i++
				value = args[i]
			}
		case strings.HasPrefix(a, "-g"):
			name, value = "graph", strings.TrimPrefix(a[2:], "=")
			if value == "" && i+1 < len(args) {
				i++
				value = args[i]
			}
		default:
			continue
		}
		if !filepath.IsAbs(value) {
			continue
		}
		switch name {
		case "data-root", "graph":
			dataRoot = filepath.Clean(value)
		case "config-file":
			configFile = filepath.Clean(value)
		}
	}
	return dataRoot, configFile
}

// readDocker reads <data-root>/containers/<id>/config.v2.json, in each data
// root of dockerDataRoots.
func (c *Containers) readDocker(id string) *Container {
	name, labels, ok := c.dockerConfig(id)
	if !ok {
		return nil
	}
	ctr := &Container{Runtime: RuntimeDocker, ID: id, Name: name}
	dockerLabels(ctr, labels)
	if ctr.PodName != "" {
		ctr.Pod = c.dockerSandbox(ctr, labels)
	}
	return ctr
}

// dockerConfig reads the name and labels of a container of Docker.
func (c *Containers) dockerConfig(id string) (name string, labels map[string]string, ok bool) {
	var b []byte
	for _, root := range c.dockerDataRoots() {
		if b = c.readFile(filepath.Join(root, "containers", id, "config.v2.json")); b != nil {
			break
		}
	}
	if b == nil {
		return "", nil, false
	}
	var cfg struct {
		Name   string
		Config struct {
			Labels map[string]string
		}
	}
	if json.Unmarshal(b, &cfg) != nil {
		return "", nil, false
	}
	return strings.TrimPrefix(cfg.Name, "/"), cfg.Config.Labels, true
}

// criDockerdAnnotation prefixes the labels in which cri-dockerd keeps the
// annotations of a pod on its sandbox (core/helpers.go, makeLabels).
const criDockerdAnnotation = "annotation."

// dockerSandbox reads the labels and annotations of the pod of a container
// of cri-dockerd from its sandbox, k8s_POD_<pod>_<namespace>_<uid>_<attempt>,
// whose labels are those of the pod, and whose labels prefixed with
// annotation. are its annotations. The sandbox is named by the label
// io.kubernetes.sandbox.id of the container, and believed only with the
// name cri-dockerd gives the sandbox of the same pod.
func (c *Containers) dockerSandbox(ctr *Container, labels map[string]string) *PodMeta {
	f := strings.Split(ctr.Name, "_")
	name, sb := ctr.Name, labels
	if f[1] != "POD" {
		id := labels["io.kubernetes.sandbox.id"]
		if !containerIDHex.MatchString(id) {
			return nil
		}
		var ok bool
		if name, sb, ok = c.dockerConfig(id); !ok {
			return nil
		}
	}
	g := strings.Split(name, "_")
	if len(g) < 5 || g[0] != "k8s" || g[1] != "POD" || g[2] != f[2] || g[3] != f[3] || g[4] != f[4] {
		return nil
	}
	l, a := map[string]string{}, map[string]string{}
	for k, v := range sb {
		if k, ok := strings.CutPrefix(k, criDockerdAnnotation); ok {
			a[k] = v
		} else {
			l[k] = v
		}
	}
	return newPodMeta(l, a)
}

// composeIndex is the end of the name Docker Compose gives a container
// after its project and service: its number, or run-<id> for one-off
// containers of docker compose run.
var composeIndex = regexp.MustCompile(`^([0-9]+|run-[0-9a-f]+)$`)

// dockerLabels sets the pod or the Compose service of a container of Docker
// from its labels. Docker merges the labels of the image into those of the
// container, so an image could claim to be any pod or service; the labels
// are believed only when the name of the container, which whoever creates
// it chooses, is the one cri-dockerd or Compose gives it:
//
//	k8s_<container>_<pod>_<namespace>_<pod uid>_<attempt>   cri-dockerd
//	<project>-<service>-<number>, <project>_<service>_<number>  Compose
//
// A Compose service with container_name keeps its name, which is as stable.
// The tasks of a service of Docker Swarm are named
// <service>.<slot>.<task id>, the slot being the node of a global service,
// with the labels com.docker.swarm.* that Swarm sets over those of the
// image (#125).
func dockerLabels(ctr *Container, labels map[string]string) {
	if f := strings.Split(ctr.Name, "_"); len(f) >= 5 && f[0] == "k8s" &&
		f[2] == labels["io.kubernetes.pod.name"] && f[3] == labels["io.kubernetes.pod.namespace"] {
		ctr.PodName, ctr.PodNamespace, ctr.ContainerName = f[2], f[3], f[1]
		return
	}
	if service := swarmService(ctr.Name, labels); service != "" {
		ctr.SwarmService = service
		return
	}
	project, service := labels["com.docker.compose.project"], labels["com.docker.compose.service"]
	if project == "" || service == "" {
		return
	}
	for _, sep := range []string{"-", "_"} {
		if rest, ok := strings.CutPrefix(ctr.Name, project+sep+service+sep); ok && composeIndex.MatchString(rest) {
			ctr.ComposeProject, ctr.ComposeService = project, service
			return
		}
	}
}

// swarmTaskID matches the ids of the tasks of Docker Swarm, 128 random bits
// in base 36 padded to 25 characters (swarmkit identity.NewID).
var swarmTaskID = regexp.MustCompile(`^[0-9a-z]{25}$`)

// swarmService returns the service of Docker Swarm of a container named
// name with labels, or "" if it is not a task of a service: the name is
// <service>.<slot>.<task id> and com.docker.swarm.task.name, as swarmkit
// names the containers of its tasks.
func swarmService(name string, labels map[string]string) string {
	service, task := labels["com.docker.swarm.service.name"], labels["com.docker.swarm.task.id"]
	if service == "" || !swarmTaskID.MatchString(task) || labels["com.docker.swarm.task.name"] != name {
		return ""
	}
	slot, ok := strings.CutPrefix(name, service+".")
	if !ok {
		return ""
	}
	if slot, ok = strings.CutSuffix(slot, "."+task); !ok || slot == "" || strings.Contains(slot, ".") {
		return ""
	}
	return service
}
