package procinfo

import (
	"os"
	"path/filepath"
)

// containerdTasks is where containerd keeps the OCI bundles of the running
// containers, one directory per namespace (k8s.io for Kubernetes).
const containerdTasks = "/run/containerd/io.containerd.runtime.v2.task"

// readContainerd reads the annotations of the OCI bundle of a container of
// containerd: those of the CRI plugin for Kubernetes, nerdctl/name for
// nerdctl. A bundle without them is not a container of containerd that has
// a name, such as a container of Docker (namespace moby), which Docker
// names.
func (c *Containers) readContainerd(id string) *Container {
	nss, err := os.ReadDir(filepath.Join(c.root, containerdTasks))
	if err != nil {
		return nil
	}
	for _, ns := range nss {
		a := c.readBundle(filepath.Join(containerdTasks, ns.Name(), id, "config.json"))
		if a == nil {
			continue
		}
		ctr := &Container{
			Runtime:       RuntimeContainerd,
			ID:            id,
			Name:          a["nerdctl/name"],
			PodNamespace:  a["io.kubernetes.cri.sandbox-namespace"],
			PodName:       a["io.kubernetes.cri.sandbox-name"],
			ContainerName: a["io.kubernetes.cri.container-name"],
		}
		if ctr.ContainerName == "" && a["io.kubernetes.cri.container-type"] == "sandbox" {
			ctr.ContainerName = "POD"
		}
		if ctr.Name == "" && ctr.PodName == "" {
			continue
		}
		if ctr.PodName != "" {
			ctr.Pod = c.containerdSandbox(ctr, ns.Name(), a)
		}
		return ctr
	}
	return nil
}

// containerdSandbox reads the annotations of the pod of a container of
// containerd from the bundle of its sandbox (io.kubernetes.cri.sandbox-id),
// which has those of the annotations of the pod that pod_annotations of
// the runtime handler lets through. containerd keeps the labels of the
// pod only in its metadata store, out of reach. The sandbox is believed
// only if it names the same pod.
func (c *Containers) containerdSandbox(ctr *Container, ns string, a map[string]string) *PodMeta {
	sb := a
	if a["io.kubernetes.cri.container-type"] != "sandbox" {
		id := a["io.kubernetes.cri.sandbox-id"]
		if !containerIDHex.MatchString(id) {
			return nil
		}
		if sb = c.readBundle(filepath.Join(containerdTasks, ns, id, "config.json")); sb == nil {
			return nil
		}
	}
	if sb["io.kubernetes.cri.sandbox-name"] != ctr.PodName || sb["io.kubernetes.cri.sandbox-namespace"] != ctr.PodNamespace {
		return nil
	}
	return newPodMeta(nil, sb)
}
