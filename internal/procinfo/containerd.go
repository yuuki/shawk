package procinfo

import (
	"os"
	"path/filepath"
)

// containerdTasks are where containerd keeps the OCI bundles of the running
// containers, one directory per namespace (k8s.io for Kubernetes), under
// its state directory: that of containerd, then those of the containerd
// that k3s and rke2 run (state /run/k3s/containerd), and of microk8s
// (state $SNAP_COMMON/run/containerd), which have their own (#125).
var containerdTasks = []string{
	"/run/containerd/io.containerd.runtime.v2.task",
	"/run/k3s/containerd/io.containerd.runtime.v2.task",
	"/var/snap/microk8s/common/run/containerd/io.containerd.runtime.v2.task",
}

// readContainerd reads the annotations of the OCI bundle of a container of
// containerd: those of the CRI plugin for Kubernetes, nerdctl/name for
// nerdctl. A bundle without them is not a container of containerd that has
// a name, such as a container of Docker (namespace moby), which Docker
// names.
func (c *Containers) readContainerd(id string) *Container {
	for _, tasks := range containerdTasks {
		if ctr := c.readContainerdTasks(tasks, id); ctr != nil {
			return ctr
		}
	}
	return nil
}

// readContainerdTasks reads the bundle of a container of the containerd
// whose bundles are in tasks.
func (c *Containers) readContainerdTasks(tasks, id string) *Container {
	nss, err := os.ReadDir(filepath.Join(c.root, tasks))
	if err != nil {
		return nil
	}
	for _, ns := range nss {
		a := c.readBundle(filepath.Join(tasks, ns.Name(), id, "config.json"))
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
			ctr.Pod = c.containerdSandbox(ctr, filepath.Join(tasks, ns.Name()), a)
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
// only if it names the same pod. ns is the directory of the namespace of
// the bundles.
func (c *Containers) containerdSandbox(ctr *Container, ns string, a map[string]string) *PodMeta {
	sb := a
	if a["io.kubernetes.cri.container-type"] != "sandbox" {
		id := a["io.kubernetes.cri.sandbox-id"]
		if !containerIDHex.MatchString(id) {
			return nil
		}
		if sb = c.readBundle(filepath.Join(ns, id, "config.json")); sb == nil {
			return nil
		}
	}
	if sb["io.kubernetes.cri.sandbox-name"] != ctr.PodName || sb["io.kubernetes.cri.sandbox-namespace"] != ctr.PodNamespace {
		return nil
	}
	return newPodMeta(nil, sb)
}
