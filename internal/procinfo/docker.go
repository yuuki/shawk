package procinfo

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// dockerDataRoot returns the data root of Docker: data-root in
// /etc/docker/daemon.json, or /var/lib/docker.
func (c *Containers) dockerDataRoot() string {
	c.dockerOnce.Do(func() {
		c.dockerRoot = "/var/lib/docker"
		var cfg struct {
			DataRoot string `json:"data-root"`
		}
		if b := c.readFile("/etc/docker/daemon.json"); b != nil && json.Unmarshal(b, &cfg) == nil &&
			filepath.IsAbs(cfg.DataRoot) {
			c.dockerRoot = filepath.Clean(cfg.DataRoot)
		}
	})
	return c.dockerRoot
}

// readDocker reads <data-root>/containers/<id>/config.v2.json.
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
	b := c.readFile(filepath.Join(c.dockerDataRoot(), "containers", id, "config.v2.json"))
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
func dockerLabels(ctr *Container, labels map[string]string) {
	if f := strings.Split(ctr.Name, "_"); len(f) >= 5 && f[0] == "k8s" &&
		f[2] == labels["io.kubernetes.pod.name"] && f[3] == labels["io.kubernetes.pod.namespace"] {
		ctr.PodName, ctr.PodNamespace, ctr.ContainerName = f[2], f[3], f[1]
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
