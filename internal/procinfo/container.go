package procinfo

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
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
	// Pod holds what the runtime keeps of the labels and annotations of
	// the pod; nil when it keeps none or they could not be read.
	Pod *PodMeta
}

// PodMeta holds the labels and annotations of a pod that name its service
// or tell its owner, as the runtime keeps them on disk. Labels is nil when
// the runtime does not keep them (containerd), Annotations when it keeps
// none of them.
type PodMeta struct {
	Labels, Annotations map[string]string
}

// The labels and annotations of a pod that OBI names its service from
// (pkg/kube/store.go, serviceNameNamespaceOwnerID), in its order, and
// those that tell the owner of the pod.
const (
	annotationServiceName      = "resource.opentelemetry.io/service.name"
	annotationServiceNamespace = "resource.opentelemetry.io/service.namespace"
	annotationConfigSource     = "kubernetes.io/config.source"
	labelPodTemplateHash       = "pod-template-hash"
)

var (
	serviceNameLabels      = []string{"app.kubernetes.io/instance", "app.kubernetes.io/name"}
	serviceNamespaceLabels = []string{"app.kubernetes.io/part-of"}
	jobNameLabels          = []string{"batch.kubernetes.io/job-name", "job-name"}
	podAnnotationKeys      = []string{annotationServiceName, annotationServiceNamespace, annotationConfigSource}
	podLabelKeys           = slices.Concat(serviceNameLabels, serviceNamespaceLabels, jobNameLabels,
		[]string{labelPodTemplateHash})
)

// newPodMeta keeps the labels and annotations of a pod that PodMeta holds,
// so that the cache of containers does not hold every label of every pod.
// It returns nil if there are none.
func newPodMeta(labels, annotations map[string]string) *PodMeta {
	pick := func(m map[string]string, keys []string) map[string]string {
		var out map[string]string
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if out == nil {
					out = map[string]string{}
				}
				out[k] = v
			}
		}
		return out
	}
	m := &PodMeta{Annotations: pick(annotations, podAnnotationKeys)}
	if labels != nil {
		m.Labels = pick(labels, podLabelKeys)
		if m.Labels == nil {
			m.Labels = map[string]string{}
		}
	}
	if m.Labels == nil && m.Annotations == nil {
		return nil
	}
	return m
}

// value returns the value of the first key the pod has, as OBI looks them
// up (valueFromMetadata): the annotation, then the labels in order. A key
// the pod has with an empty value ends the search, and OBI then falls
// back to the owner.
func (m *PodMeta) value(annotation string, labels []string) string {
	if m == nil {
		return ""
	}
	if v, ok := m.Annotations[annotation]; ok {
		return v
	}
	for _, k := range labels {
		if v, ok := m.Labels[k]; ok {
			return v
		}
	}
	return ""
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
// names it from the metadata of the pod (pkg/kube/store.go,
// serviceNameNamespaceOwnerID):
//
//   - the name is the annotation resource.opentelemetry.io/service.name,
//     then the label app.kubernetes.io/instance, then the label
//     app.kubernetes.io/name, then the owner of the pod (PodOwner);
//   - the namespace is the annotation
//     resource.opentelemetry.io/service.namespace, then the label
//     app.kubernetes.io/part-of, then the namespace of the pod.
//
// The labels and annotations are those the runtime keeps on disk (Pod);
// without them the name is the owner guessed from the name of the pod. It
// is zero for other containers, which OBI names after their executable.
func (c *Container) Workload() Service {
	if c == nil || c.PodName == "" {
		return Service{}
	}
	name := c.Pod.value(annotationServiceName, serviceNameLabels)
	if name == "" {
		name = c.PodOwner()
	}
	ns := c.Pod.value(annotationServiceNamespace, serviceNamespaceLabels)
	if ns == "" {
		ns = c.podNamespace()
	}
	return Service{Name: namePart(name), Namespace: namePart(ns)}
}

// PodOwner returns the name of the top owner of the pod of a container, as
// OBI names it (pkg/kube/kubecache/meta/types.go, ownersFrom), from the
// labels and annotations of the pod when the runtime keeps them:
//
//   - a static pod (annotation kubernetes.io/config.source other than api)
//     is owned by its Node, whose name ends the name of the pod;
//   - a pod of a Job (label batch.kubernetes.io/job-name or job-name) is
//     owned by a CronJob named after the Job cut at its last -, as OBI
//     assumes of every Job (data-load becomes data);
//   - a pod of a ReplicaSet of a Deployment (label pod-template-hash) is
//     owned by the Deployment, the name of the pod before -<hash>-.
//
// Otherwise the owner is guessed from the name of the pod (PodWorkload).
func (c *Container) PodOwner() string {
	if m := c.Pod; m != nil {
		if src, ok := m.Annotations[annotationConfigSource]; ok && src != "api" {
			if node := nodeName(); node != "" && strings.HasSuffix(c.PodName, "-"+node) {
				return node
			}
		}
		for _, k := range jobNameLabels {
			if job := m.Labels[k]; job != "" {
				if i := strings.LastIndexByte(job, '-'); i > 0 {
					return job[:i]
				}
				return job
			}
		}
		if h := m.Labels[labelPodTemplateHash]; h != "" {
			if i := strings.LastIndex(c.PodName, "-"+h+"-"); i > 0 {
				return c.PodName[:i]
			}
		}
	}
	return PodWorkload(c.PodName)
}

// nodeName returns the name of the Node of the host, which kubelet takes
// from the host name in lower case unless --hostname-override is set;
// replaced in tests.
var nodeName = sync.OnceValue(func() string {
	h, _ := os.Hostname()
	return strings.ToLower(h)
})

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

	// mu guards cache and reading only: files are read without it, so that
	// a lookup of a cached container does not wait for a read (#126).
	mu      sync.Mutex
	cache   map[string]containerEntry
	reading map[string]*containerRead

	podmanMu sync.Mutex // guards podman, read again when its lists change
	podman   podmanIndex

	dockerOnce sync.Once
	dockerRoot string
}

// containerRead is a read of the state of a container in flight, which
// lookups of the same id wait for instead of reading it again.
type containerRead struct {
	done  chan struct{}
	c     *Container
	found bool
}

type containerEntry struct {
	c     *Container
	found bool
	read  time.Time // when the state was read
	used  time.Time // when the container was last looked up
}

// NewContainers returns a reader of the state of the runtimes of the host.
func NewContainers() *Containers { return newContainers("") }

func newContainers(root string) *Containers {
	return &Containers{root: root, cache: map[string]containerEntry{}, reading: map[string]*containerRead{}}
}

// Lookup returns the container of a runtime with an id. runtime is "" when
// the cgroup does not tell it; every runtime is tried then. found is false
// when its state cannot be read; the container then has only its id.
// Lookups of the same id share one read; the files are read without
// holding the cache, so that lookups of other containers do not wait.
func (c *Containers) Lookup(runtime, id string) (ctr *Container, found bool) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.cache[id]; ok && (e.found || now.Sub(e.read) < missTTL) {
		e.used = now
		c.cache[id] = e
		c.mu.Unlock()
		return e.c, e.found
	}
	if rd, ok := c.reading[id]; ok {
		c.mu.Unlock()
		<-rd.done
		return rd.c, rd.found
	}
	rd := &containerRead{done: make(chan struct{})}
	c.reading[id] = rd
	c.mu.Unlock()

	rd.c, rd.found = c.read(runtime, id)

	c.mu.Lock()
	delete(c.reading, id)
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
	c.cache[id] = containerEntry{c: rd.c, found: rd.found, read: now, used: now}
	c.mu.Unlock()
	close(rd.done)
	return rd.c, rd.found
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
