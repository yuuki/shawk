package procinfo

import (
	"encoding/json"
	"path/filepath"
)

// readCRIO reads the annotations of the OCI bundle of a container of CRI-O.
func (c *Containers) readCRIO(id string) *Container {
	for _, root := range []string{storageRoots[1], storageRoots[0]} {
		for _, p := range c.glob(filepath.Join(root, "*-containers", id, "userdata", "config.json")) {
			if ctr := c.crioBundle(id, p); ctr != nil {
				return ctr
			}
		}
	}
	return nil
}

// crioBundle reads the pod of a container from the annotations of its
// bundle, or returns nil if it is not the container of a pod, e.g. one of
// Podman, whose bundle is in the same directories.
func (c *Containers) crioBundle(id, path string) *Container {
	a := c.readBundle(path)
	if a["io.kubernetes.pod.name"] == "" {
		return nil
	}
	ctr := &Container{
		Runtime:       RuntimeCRIO,
		ID:            id,
		PodNamespace:  a["io.kubernetes.pod.namespace"],
		PodName:       a["io.kubernetes.pod.name"],
		ContainerName: a["io.kubernetes.container.name"],
	}
	ctr.Pod = c.crioSandbox(ctr, a)
	return ctr
}

// The annotations CRI-O sets on the bundles of its containers
// (pkg/annotations): the id of the sandbox of the pod, and on the bundle
// of the sandbox, the labels and annotations of the pod in JSON
// (server/sandbox_run_linux.go, setupSandboxAnnotations).
const (
	crioSandboxID   = "io.kubernetes.cri-o.SandboxID"
	crioLabels      = "io.kubernetes.cri-o.Labels"
	crioAnnotations = "io.kubernetes.cri-o.Annotations"
)

// crioSandbox reads the labels and annotations of the pod of a container
// of CRI-O from the bundle of its sandbox, which CRI-O saves in the
// directory of the sandbox even when it runs no infra container. The
// sandbox is believed only if its labels name the same pod.
func (c *Containers) crioSandbox(ctr *Container, a map[string]string) *PodMeta {
	sb := a
	if id := a[crioSandboxID]; id != ctr.ID {
		if !containerIDHex.MatchString(id) {
			return nil
		}
		sb = nil
		for _, root := range []string{storageRoots[1], storageRoots[0]} {
			for _, p := range c.glob(filepath.Join(root, "*-containers", id, "userdata", "config.json")) {
				if sb = c.readBundle(p); sb != nil {
					break
				}
			}
			if sb != nil {
				break
			}
		}
	}
	var labels, annotations map[string]string
	if json.Unmarshal([]byte(sb[crioLabels]), &labels) != nil ||
		labels["io.kubernetes.pod.name"] != ctr.PodName || labels["io.kubernetes.pod.namespace"] != ctr.PodNamespace {
		return nil
	}
	_ = json.Unmarshal([]byte(sb[crioAnnotations]), &annotations)
	return newPodMeta(labels, annotations)
}
