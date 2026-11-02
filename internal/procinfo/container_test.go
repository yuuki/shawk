package procinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	id1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	id2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestPodWorkload(t *testing.T) {
	for pod, want := range map[string]string{
		"web-5d8f7c9b6-x7z2k":      "web",           // Deployment
		"web-api-7c6b5d4f8b-9mzqk": "web-api",       // Deployment with a dash
		"node-exporter-x7z2k":      "node-exporter", // DaemonSet
		"backup-29340000-tq8wz":    "backup",        // CronJob
		"db-0":                     "db",            // StatefulSet
		"kafka-broker-12":          "kafka-broker",
		"etcd-control-plane":       "etcd-control-plane", // static pod
		"nginx":                    "nginx",
		"migrate-abcde":            "migrate-abcde", // vowels are never generated
		"x7z2k":                    "x7z2k",
		"0":                        "0",
	} {
		if got := PodWorkload(pod); got != want {
			t.Errorf("PodWorkload(%q) = %q, want %q", pod, got, want)
		}
	}
}

func TestContainerUnit(t *testing.T) {
	for _, tc := range []struct {
		c    Container
		want string
	}{
		{Container{Runtime: RuntimeContainerd, ID: id1, PodNamespace: "shop", PodName: "cart-5d8f7c9b6-x7z2k", ContainerName: "app"}, "k8s/shop/cart/app"},
		{Container{Runtime: RuntimeCRIO, ID: id1, PodName: "cart-0"}, "k8s/default/cart"},
		{Container{Runtime: RuntimeDocker, ID: id1, Name: "shop-db-1", ComposeProject: "shop", ComposeService: "db"}, "docker/shop/db"},
		{Container{Runtime: RuntimeDocker, ID: id1, Name: "db-1", ComposeService: "db"}, "docker/db"},
		{Container{Runtime: RuntimePodman, ID: id1, Name: "redis"}, "podman/redis"},
		{Container{Runtime: RuntimeDocker, ID: id1}, "docker-0123456789ab"},
		{Container{Runtime: "container", ID: "0123"}, "container-0123"},
	} {
		if got := tc.c.Unit(); got != tc.want {
			t.Errorf("Unit of %+v = %q, want %q", tc.c, got, tc.want)
		}
	}
}

func TestCgroupContainer(t *testing.T) {
	for _, tc := range []struct {
		path string
		want containerRef
		ok   bool
	}{
		{"/system.slice/docker-" + id1 + ".scope", containerRef{RuntimeDocker, id1}, true},
		{"/docker/" + id1, containerRef{RuntimeDocker, id1}, true},
		{"/machine.slice/libpod-" + id1 + ".scope/container", containerRef{RuntimePodman, id1}, true},
		{"/libpod_parent/libpod-" + id1, containerRef{RuntimePodman, id1}, true},
		{"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-" + id1 + ".scope",
			containerRef{RuntimeContainerd, id1}, true},
		{"/kubepods.slice/kubepods-pod1234.slice/crio-" + id1 + ".scope", containerRef{RuntimeCRIO, id1}, true},
		{"/kubepods/burstable/pod0f1e-2d3c/crio-" + id1, containerRef{RuntimeCRIO, id1}, true},
		{"/kubepods/burstable/pod0f1e-2d3c/" + id1, containerRef{"", id1}, true},
		{"/kubepods/pod0f1e-2d3c/" + id1, containerRef{"", id1}, true},
		{"/kubelet/kubepods/besteffort/pod0f1e/" + id1, containerRef{"", id1}, true},
		{"/system.slice/nerdctl-" + id1 + ".scope", containerRef{RuntimeContainerd, id1}, true},
		// systemd in a container: the unit inside names the process.
		{"/system.slice/docker-" + id1 + ".scope/system.slice/nginx.service", containerRef{}, false},
		{"/system.slice/crio-conmon-" + id1 + ".scope", containerRef{}, false},
		{"/" + id1, containerRef{}, false},
		{"/system.slice/" + id1, containerRef{}, false},
		{"/system.slice/nginx.service", containerRef{}, false},
	} {
		got, ok := cgroupContainer(tc.path)
		if got != tc.want || ok != tc.ok {
			t.Errorf("cgroupContainer(%q) = %+v, %v, want %+v, %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func writeFile(t *testing.T, root, path, data string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestContainersDocker(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{
		"ID": "`+id1+`", "Name": "/shop-db-1",
		"Config": {"Image": "postgres:16", "Labels": {
			"com.docker.compose.project": "shop", "com.docker.compose.service": "db"}}}`)
	c := newContainers(root)
	got := c.Lookup(RuntimeDocker, id1)
	want := Container{Runtime: RuntimeDocker, ID: id1, Name: "shop-db-1", ComposeProject: "shop", ComposeService: "db"}
	if *got != want {
		t.Errorf("Lookup = %+v, want %+v", *got, want)
	}
	// Kept after the container is removed.
	os.RemoveAll(filepath.Join(root, "var/lib/docker/containers", id1))
	if got := c.Lookup(RuntimeDocker, id1); got.Unit() != "docker/shop/db" {
		t.Errorf("Lookup after removal = %+v", got)
	}
	// Unknown: named by id.
	if got := c.Lookup(RuntimeDocker, id2); got.Unit() != "docker-fedcba987654" || got.ID != id2 {
		t.Errorf("Lookup of an unknown container = %+v", got)
	}
	// Read again once a miss is old, even if it was used since.
	writeFile(t, root, "/var/lib/docker/containers/"+id2+"/config.v2.json", `{"Name": "/late", "Config": {}}`)
	if got := c.Lookup(RuntimeDocker, id2); got.Unit() != "docker-fedcba987654" {
		t.Errorf("Lookup within the miss TTL = %+v", got)
	}
	e := c.cache[id2]
	e.read = e.read.Add(-2 * missTTL)
	c.cache[id2] = e
	if got := c.Lookup(RuntimeDocker, id2); got.Unit() != "docker/late" {
		t.Errorf("Lookup after the miss TTL = %+v", got)
	}
}

func TestContainersDockerDataRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/docker/daemon.json", `{"data-root": "/srv/docker"}`)
	writeFile(t, root, "/srv/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	if got := newContainers(root).Lookup(RuntimeDocker, id1); got.Unit() != "docker/web" {
		t.Errorf("Lookup = %+v", got)
	}
}

func TestContainersCRIDockerd(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{
		"Name": "/k8s_app_cart-5d8f7c9b6-x7z2k_shop_uid_0",
		"Config": {"Labels": {"io.kubernetes.pod.name": "cart-5d8f7c9b6-x7z2k",
			"io.kubernetes.pod.namespace": "shop", "io.kubernetes.container.name": "app"}}}`)
	// The runtime is not in a cgroupfs path of kubelet: every one is tried.
	got := newContainers(root).Lookup("", id1)
	if got.Unit() != "k8s/shop/cart/app" || got.Workload() != (Service{"cart", "shop"}) {
		t.Errorf("Lookup = %+v", got)
	}
}

func TestContainersPodman(t *testing.T) {
	root := t.TempDir()
	list := `[{"id": "` + id1 + `", "names": ["redis"], "image": "x"},
		{"id": "` + id2 + `", "names": ["k8s_app_cart-0_shop_uid_0"]}]`
	writeFile(t, root, "/var/lib/containers/storage/overlay-containers/containers.json", list)
	writeFile(t, root, "/run/containers/storage/overlay-containers/"+id2+"/userdata/config.json", `{
		"annotations": {"io.kubernetes.pod.name": "cart-0", "io.kubernetes.pod.namespace": "shop",
			"io.kubernetes.container.name": "app"}}`)
	c := newContainers(root)
	if got := c.Lookup(RuntimePodman, id1); got.Unit() != "podman/redis" {
		t.Errorf("Lookup podman = %+v", got)
	}
	if got := c.Lookup(RuntimeCRIO, id2); got.Unit() != "k8s/shop/cart/app" || got.Runtime != RuntimeCRIO {
		t.Errorf("Lookup cri-o = %+v", got)
	}
	// A container created later is read from the list again.
	id3 := strings.Repeat("ab", 32)
	writeFile(t, root, "/var/lib/containers/storage/overlay-containers/containers.json",
		strings.Replace(list, "[", `[{"id": "`+id3+`", "names": ["new-one"]},`, 1))
	if got := c.Lookup(RuntimePodman, id3); got.Unit() != "podman/new-one" {
		t.Errorf("Lookup of a new podman container = %+v", got)
	}
}

func TestContainersContainerd(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, containerdTasks+"/k8s.io/"+id1+"/config.json", `{
		"annotations": {"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.sandbox-name": "web-5d8f7c9b6-x7z2k",
			"io.kubernetes.cri.sandbox-namespace": "default",
			"io.kubernetes.cri.container-name": "nginx"}}`)
	writeFile(t, root, containerdTasks+"/default/"+id2+"/config.json", `{
		"annotations": {"nerdctl/name": "proxy"}}`)
	c := newContainers(root)
	if got := c.Lookup("", id1); got.Unit() != "k8s/default/web/nginx" || got.Runtime != RuntimeContainerd {
		t.Errorf("Lookup k8s = %+v", got)
	}
	if got := c.Lookup(RuntimeContainerd, id2); got.Unit() != "containerd/proxy" || got.Workload() != (Service{}) {
		t.Errorf("Lookup nerdctl = %+v", got)
	}
}

func TestResolverUnit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	r := &Resolver{containers: newContainers(root), paths: map[uint64]string{}, learned: map[uint64]learnedPath{}}
	r.Learn(7, "/system.slice/docker-"+id1+".scope")
	// The state was read when the cgroup was created.
	os.RemoveAll(filepath.Join(root, "var/lib/docker/containers", id1))
	unit, ctr := r.Unit(7)
	if unit != "docker/web" || ctr == nil || ctr.ID != id1 {
		t.Errorf("Unit(7) = %q, %+v", unit, ctr)
	}
	r.Learn(8, "/system.slice/nginx.service")
	if unit, ctr := r.Unit(8); unit != "nginx.service" || ctr != nil {
		t.Errorf("Unit(8) = %q, %+v", unit, ctr)
	}
}
