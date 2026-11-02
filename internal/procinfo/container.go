package procinfo

import (
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Container runtimes, as Container.Runtime names them.
const (
	RuntimeDocker     = "docker"
	RuntimePodman     = "podman"
	RuntimeContainerd = "containerd"
	RuntimeCRIO       = "crio"
)

// Container is what the runtime of a container records about it on disk.
// Only ID and Runtime are set when its state could not be read.
type Container struct {
	Runtime string
	ID      string // the full id, as the cgroup names it
	// Name is the name of the container given by the user (Docker, Podman,
	// nerdctl), without the leading /.
	Name string
	// The service and project of a container of Docker Compose.
	ComposeProject, ComposeService string
	// The pod of a container of Kubernetes.
	PodNamespace, PodName, ContainerName string
}

// shortID is the length of the abbreviated id of a container, as docker ps
// shows it.
const shortID = 12

// Unit names a container after what stays the same when it is recreated:
// the namespace, workload and container of a pod of Kubernetes, the project
// and service of Docker Compose, or the name of the container. Without any
// of them, the name has the abbreviated id, which changes at every
// recreation.
//
//	k8s/default/web/nginx       a container nginx of a pod of the Deployment web
//	docker/shop/db              the service db of the Compose project shop
//	podman/redis                a container named redis
//	docker-0123456789ab         a container whose state could not be read
//
// The parts of the name come from the state of the container, which its
// owner or the author of its image may set, so each is limited to the
// characters of the names of containers and pods (see namePart).
func (c *Container) Unit() string {
	switch {
	case c.PodName != "":
		u := "k8s/" + namePart(c.podNamespace()) + "/" + namePart(PodWorkload(c.PodName))
		if c.ContainerName != "" {
			u += "/" + namePart(c.ContainerName)
		}
		return u
	case c.ComposeService != "":
		if c.ComposeProject == "" {
			return c.Runtime + "/" + namePart(c.ComposeService)
		}
		return c.Runtime + "/" + namePart(c.ComposeProject) + "/" + namePart(c.ComposeService)
	case c.Name != "":
		return c.Runtime + "/" + namePart(c.Name)
	}
	id := c.ID
	if len(id) > shortID {
		id = id[:shortID]
	}
	return c.Runtime + "-" + id
}

func (c *Container) podNamespace() string {
	if c.PodNamespace == "" {
		return "default"
	}
	return c.PodNamespace
}

// Workload returns the service of a container of Kubernetes, named as OBI
// names it from the metadata of the pod when the pod has no annotation or
// label that names its service: the workload that owns the pod in the
// namespace of the pod. It is zero for other containers, which OBI names
// after their executable.
func (c *Container) Workload() Service {
	if c == nil || c.PodName == "" {
		return Service{}
	}
	return Service{Name: namePart(PodWorkload(c.PodName)), Namespace: namePart(c.podNamespace())}
}

// maxNamePart bounds the length of a part of the name of a container: the
// names of pods and containers of Kubernetes have at most 63 characters,
// except the names of pods, which have at most 253.
const maxNamePart = 253

// namePart makes a part of a name taken from the state of a container safe
// to join with / into a unit or a Prometheus job: the characters the names
// of containers (Docker, Podman) and of objects of Kubernetes may have are
// kept, any other is replaced with _, and . and .. become _.
func namePart(s string) string {
	if len(s) > maxNamePart {
		s = s[:maxNamePart]
	}
	b := []byte(s)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '.' || ch == '-') {
			b[i] = '_'
		}
	}
	if s = string(b); s == "" || s == "." || s == ".." {
		return "_"
	}
	return s
}

// The suffixes Kubernetes appends to the names of the pods it creates, made
// of the characters of its random strings (k8s.io/apimachinery rand), which
// have no vowels and none of 0, 1 and 3:
//
//	<deployment>-<pod-template-hash>-<5>  pods of a ReplicaSet of a Deployment
//	<daemonset>-<5>, <job>-<5>            pods of a DaemonSet, a Job, a ReplicaSet
//	<cronjob>-<minutes>-<5>               pods of a Job of a CronJob
//	<statefulset>-<ordinal>               pods of a StatefulSet
var (
	podSuffix      = regexp.MustCompile(`-[bcdfghjklmnpqrstvwxz2456789]{5}$`)
	templateHash   = regexp.MustCompile(`-([bcdfghjklmnpqrstvwxz2456789]{6,10}|[0-9]{8,10})$`)
	generatedPart  = regexp.MustCompile(`^[0-9bcdfghjklmnpqrstvwxz]*$`)
	podOrdinal     = regexp.MustCompile(`-[0-9]+$`)
	containerIDHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// The API server truncates the prefix of a generated name to
// maxGeneratedPrefix characters before it appends the 5 random ones
// (k8s.io/apiserver/pkg/storage/names), so a generated name has at most
// maxGeneratedName.
const (
	maxGeneratedPrefix = 58
	maxGeneratedName   = maxGeneratedPrefix + 5
)

// PodWorkload guesses the name of the workload that owns a pod from the
// name of the pod, by removing the suffixes Kubernetes appends to the pods
// it creates, so that the pods of every rollout get the same name: web for
// web-5d8f7c9b6-x7z2k, node-exporter for node-exporter-x7z2k, db for db-0.
// The owner itself is known only to the API server, which the agent does
// not ask; a pod named by hand that ends like a generated one loses its
// end too.
//
// A generated name whose prefix was truncated has no - before its random
// characters: its prefix is cut at its last -, after which there is a part
// of the hash or of the minutes of the Job, or the end of a long name of a
// workload. The name is the same for every pod of the workload, though it
// may lack the end of the name of the workload.
func PodWorkload(pod string) string {
	if len(pod) == maxGeneratedName && pod[maxGeneratedPrefix-1] != '-' {
		prefix := pod[:maxGeneratedPrefix]
		if i := strings.LastIndexByte(prefix, '-'); i > 0 && generatedPart.MatchString(prefix[i+1:]) {
			prefix = prefix[:i]
		}
		return prefix
	}
	if loc := podSuffix.FindStringIndex(pod); loc != nil && loc[0] > 0 {
		base := pod[:loc[0]]
		if loc := templateHash.FindStringIndex(base); loc != nil && loc[0] > 0 {
			base = base[:loc[0]]
		}
		return base
	}
	if loc := podOrdinal.FindStringIndex(pod); loc != nil && loc[0] > 0 {
		return pod[:loc[0]]
	}
	return pod
}

// containerScope matches the scopes systemd creates for containers:
// docker-<id>.scope (Docker, cri-dockerd), libpod-<id>.scope (Podman),
// cri-containerd-<id>.scope (containerd), crio-<id>.scope (CRI-O) and
// nerdctl-<id>.scope (nerdctl). The cgroupfs driver of CRI-O names the
// cgroup crio-<id>, without .scope.
var containerScope = regexp.MustCompile(`^(docker|libpod|cri-containerd|crio|nerdctl)-([0-9a-f]{12,64})(\.scope)?$`)

// containerOf finds the container of the segment i of a cgroup path, or
// returns false if the segment is not the cgroup of a container. The
// cgroupfs drivers name the cgroup of a container by its bare id:
//
//	/docker/<id>                           Docker
//	/libpod_parent/libpod-<id>             Podman (its name is the scope's)
//	/kubepods/burstable/pod<uid>/<id>      kubelet, any runtime
func containerOf(parts []string, i int) (runtime, id string, ok bool) {
	p := parts[i]
	if m := containerScope.FindStringSubmatch(p); m != nil {
		switch m[1] {
		case "docker":
			return RuntimeDocker, m[2], true
		case "libpod":
			return RuntimePodman, m[2], true
		case "crio":
			return RuntimeCRIO, m[2], true
		}
		return RuntimeContainerd, m[2], true
	}
	if !containerIDHex.MatchString(p) || i == 0 {
		return "", "", false
	}
	switch parent := parts[i-1]; {
	case parent == "docker":
		return RuntimeDocker, p, true
	case strings.HasPrefix(parent, "pod"):
		for _, q := range parts[:i-1] {
			if strings.HasPrefix(q, "kubepods") {
				// The runtime is not in the path; Containers.Lookup
				// tries each.
				return "", p, true
			}
		}
	}
	return "", "", false
}

// containerTTL is how long the state of a container read from disk is
// kept after it was last used, and missTTL how long a container whose
// state could not be read is not read again.
const (
	containerTTL  = time.Hour
	missTTL       = time.Minute
	maxContainers = 10000
	// maxStateFile bounds the size of a state file read.
	maxStateFile = 16 << 20
)

// Containers reads the state the container runtimes keep on disk, and
// keeps what it read by container id. The APIs of the runtimes are on Unix
// sockets, which the systemd unit of the agent does not allow; their files
// tell the same names. Rootless containers keep their state in the home
// directory of their user, which the unit hides, and are named by id.
type Containers struct {
	// root is prepended to the paths of the state; replaced in tests.
	root string

	mu         sync.Mutex
	cache      map[string]containerEntry
	podman     podmanIndex
	dockerRoot string
}

type containerEntry struct {
	c     *Container
	found bool
	read  time.Time // when the state was read
	used  time.Time // when the container was last looked up
}

// podmanIndex holds the names of the containers of containers/storage,
// read again when one of its lists changes.
type podmanIndex struct {
	files map[string]fileStamp
	names map[string]string // id -> name
}

// fileStamp tells whether a file changed: a list is replaced by a new file
// (another inode), possibly of the same size within the resolution of the
// time of modification.
type fileStamp struct {
	mtime int64 // in nanoseconds
	size  int64
	ino   uint64
}

// NewContainers returns a reader of the state of the runtimes of the host.
func NewContainers() *Containers { return newContainers("") }

func newContainers(root string) *Containers {
	return &Containers{root: root, cache: map[string]containerEntry{}}
}

// Lookup returns the container of a runtime with an id. runtime is "" when
// the cgroup does not tell it; every runtime is tried then. found is false
// when its state cannot be read; the container then has only its id.
func (c *Containers) Lookup(runtime, id string) (ctr *Container, found bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.cache[id]; ok && (e.found || now.Sub(e.read) < missTTL) {
		e.used = now
		c.cache[id] = e
		return e.c, e.found
	}
	ctr, found = c.read(runtime, id)
	if len(c.cache) >= maxContainers {
		for k, e := range c.cache {
			if now.Sub(e.used) > containerTTL || !e.found {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= maxContainers {
			clear(c.cache)
		}
	}
	c.cache[id] = containerEntry{c: ctr, found: found, read: now, used: now}
	return ctr, found
}

// expire forgets the containers not looked up for containerTTL.
func (c *Containers) expire(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.cache {
		if now.Sub(e.used) > containerTTL {
			delete(c.cache, k)
		}
	}
}

func (c *Containers) read(runtime, id string) (*Container, bool) {
	readers := map[string]func(string) *Container{
		RuntimeDocker:     c.readDocker,
		RuntimePodman:     c.readPodman,
		RuntimeContainerd: c.readContainerd,
		RuntimeCRIO:       c.readCRIO,
	}
	if r, ok := readers[runtime]; ok {
		if ctr := r(id); ctr != nil {
			return ctr, true
		}
		return &Container{Runtime: runtime, ID: id}, false
	}
	for _, rt := range []string{RuntimeContainerd, RuntimeCRIO, RuntimeDocker, RuntimePodman} {
		if ctr := readers[rt](id); ctr != nil {
			return ctr, true
		}
	}
	return &Container{Runtime: runtimeOrAny(""), ID: id}, false
}

// glob returns the paths that match a pattern, without root.
func (c *Containers) glob(pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(c.root, pattern))
	for i := range m {
		m[i] = strings.TrimPrefix(m[i], c.root)
	}
	return m
}

func (c *Containers) readFile(path string) []byte {
	f, err := os.Open(filepath.Join(c.root, path))
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStateFile))
	if err != nil {
		return nil
	}
	return b
}

// dockerDataRoot returns the data root of Docker: data-root in
// /etc/docker/daemon.json, or /var/lib/docker.
func (c *Containers) dockerDataRoot() string {
	if c.dockerRoot != "" {
		return c.dockerRoot
	}
	c.dockerRoot = "/var/lib/docker"
	var cfg struct {
		DataRoot string `json:"data-root"`
	}
	if b := c.readFile("/etc/docker/daemon.json"); b != nil && json.Unmarshal(b, &cfg) == nil &&
		filepath.IsAbs(cfg.DataRoot) {
		c.dockerRoot = filepath.Clean(cfg.DataRoot)
	}
	return c.dockerRoot
}

// readDocker reads <data-root>/containers/<id>/config.v2.json.
func (c *Containers) readDocker(id string) *Container {
	b := c.readFile(filepath.Join(c.dockerDataRoot(), "containers", id, "config.v2.json"))
	if b == nil {
		return nil
	}
	var cfg struct {
		Name   string
		Config struct {
			Labels map[string]string
		}
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	ctr := &Container{Runtime: RuntimeDocker, ID: id, Name: strings.TrimPrefix(cfg.Name, "/")}
	dockerLabels(ctr, cfg.Config.Labels)
	return ctr
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

// storageRoots are the graph root of containers/storage used by Podman and
// CRI-O as root, then the run root, where CRI-O keeps the bundles and a
// transient store keeps its lists. The directories of the containers are
// named after the storage driver: overlay-containers, vfs-containers...
var storageRoots = []string{"/var/lib/containers/storage", "/run/containers/storage"}

// podmanNames returns the names of the containers of containers/storage
// by id: containers.json lists the containers, volatile-containers.json
// those removed when they stop (podman run --rm).
func (c *Containers) podmanNames() map[string]string {
	ix := &c.podman
	stamps := map[string]fileStamp{}
	for _, root := range storageRoots {
		for _, list := range []string{"containers.json", "volatile-containers.json"} {
			for _, p := range c.glob(filepath.Join(root, "*-containers", list)) {
				st, err := os.Stat(filepath.Join(c.root, p))
				if err != nil {
					continue
				}
				fs := fileStamp{mtime: st.ModTime().UnixNano(), size: st.Size()}
				if sys, ok := st.Sys().(*syscall.Stat_t); ok {
					fs.ino = sys.Ino
				}
				stamps[p] = fs
			}
		}
	}
	if ix.names != nil && maps.Equal(stamps, ix.files) {
		return ix.names
	}
	names := map[string]string{}
	for p := range stamps {
		var list []struct {
			ID    string   `json:"id"`
			Names []string `json:"names"`
		}
		if b := c.readFile(p); b != nil && json.Unmarshal(b, &list) == nil {
			for _, e := range list {
				if len(e.Names) > 0 {
					names[e.ID] = e.Names[0]
				}
			}
		}
	}
	ix.files, ix.names = stamps, names
	return names
}

// readPodman reads the name of a container from the lists of
// containers/storage, which also list the containers of CRI-O.
func (c *Containers) readPodman(id string) *Container {
	name, ok := c.podmanNames()[id]
	if !ok {
		return nil
	}
	ctr := &Container{Runtime: RuntimePodman, ID: id, Name: name}
	// The containers of CRI-O are in the same list; their bundle tells
	// their pod.
	if k := c.readCRIO(id); k != nil {
		return k
	}
	return ctr
}

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
	return &Container{
		Runtime:       RuntimeCRIO,
		ID:            id,
		PodNamespace:  a["io.kubernetes.pod.namespace"],
		PodName:       a["io.kubernetes.pod.name"],
		ContainerName: a["io.kubernetes.container.name"],
	}
}

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
		return ctr
	}
	return nil
}

// readBundle returns the annotations of the config.json of an OCI bundle,
// or nil if it cannot be read.
func (c *Containers) readBundle(path string) map[string]string {
	b := c.readFile(path)
	if b == nil {
		return nil
	}
	var spec struct {
		Annotations map[string]string `json:"annotations"`
	}
	if json.Unmarshal(b, &spec) != nil {
		return nil
	}
	if spec.Annotations == nil {
		return map[string]string{}
	}
	return spec.Annotations
}
