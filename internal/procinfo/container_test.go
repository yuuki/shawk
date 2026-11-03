package procinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
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
		// Generated names whose prefix was truncated to 58 characters.
		"payments-reconciliation-service-worker-highprio-5d8f7c9b6fx7z2k": "payments-reconciliation-service-worker-highprio",
		"payments-reconciliation-service-worker-highprio-v2-5d8f7c9x7z2k": "payments-reconciliation-service-worker-highprio-v2",
		"nightly-warehouse-snapshot-export-for-analytics-team-29340x7z2k": "nightly-warehouse-snapshot-export-for-analytics-team",
		"a-very-long-daemonset-name-that-has-more-than-fifty-eight-x7z2k": "a-very-long-daemonset-name-that-has-more-than-fifty-eight",
		"0": "0",
	} {
		if got := PodWorkload(pod); got != want {
			t.Errorf("PodWorkload(%q) = %q, want %q", pod, got, want)
		}
	}
}

// The pods of a workload with a long name share the name of the workload.
func TestPodWorkloadTruncated(t *testing.T) {
	const alphabet = "bcdfghjklmnpqrstvwxz2456789"
	random := func(seed, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[(seed*7+i*13)%len(alphabet)]
		}
		return string(b)
	}
	generate := func(prefix string, seed int) string {
		if len(prefix) > maxGeneratedPrefix {
			prefix = prefix[:maxGeneratedPrefix]
		}
		return prefix + random(seed, 5)
	}
	for n := 40; n <= 70; n++ {
		owner := strings.TrimSuffix(("checkout-" + strings.Repeat("service-", 10))[:n], "-")
		var names [3]map[string]bool
		for i := range names {
			names[i] = map[string]bool{}
		}
		for seed := range 5 {
			hash := random(seed+100, 9)
			names[0][PodWorkload(generate(owner+"-"+hash+"-", seed))] = true
			names[1][PodWorkload(generate(owner+"-", seed))] = true
			names[2][PodWorkload(generate(owner+"-"+fmt.Sprint(29340000+seed)+"-", seed))] = true
		}
		for i, kind := range []string{"Deployment", "DaemonSet", "CronJob"} {
			if len(names[i]) != 1 {
				t.Errorf("%s of %d characters: names %v", kind, len(owner), names[i])
			}
		}
	}
}

func TestNamePart(t *testing.T) {
	for in, want := range map[string]string{
		"web-1":                  "web-1",
		"my_app.v2":              "my_app.v2",
		"../../etc/a":            ".._.._etc_a",
		"a/b\nc":                 "a_b_c",
		"":                       "_",
		".":                      "_",
		"..":                     "_",
		"caf\u00e9":              "caf__",
		strings.Repeat("x", 300): strings.Repeat("x", maxNamePart),
	} {
		if got := namePart(in); got != want {
			t.Errorf("namePart(%q) = %q, want %q", in, got, want)
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
		{Container{Runtime: RuntimeDocker, ID: id1, Name: "a/../b"}, "docker/a_.._b"},
		{Container{Runtime: RuntimeCRIO, ID: id1, PodNamespace: "kube/system", PodName: "x\ny"}, "k8s/kube_system/x_y"},
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
		refs := cgroupContainers(tc.path)
		var got containerRef
		if len(refs) > 0 {
			got = refs[0]
		}
		if ok := len(refs) > 0; got != tc.want || ok != tc.ok {
			t.Errorf("cgroupContainers(%q) = %+v, want %+v, %v", tc.path, refs, tc.want, tc.ok)
		}
	}
	nested := "/system.slice/docker-" + id1 + ".scope/docker/" + id2
	want := []containerRef{{RuntimeDocker, id2}, {RuntimeDocker, id1}}
	if got := cgroupContainers(nested); !slices.Equal(got, want) {
		t.Errorf("cgroupContainers(%q) = %+v, want %+v", nested, got, want)
	}
	if got := Unit(nested); got != "docker-0123456789ab" {
		t.Errorf("Unit(%q) = %q", nested, got)
	}
}

func writeFile(t testing.TB, root, path, data string) {
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
	got, _ := c.Lookup(RuntimeDocker, id1)
	want := Container{Runtime: RuntimeDocker, ID: id1, Name: "shop-db-1", ComposeProject: "shop", ComposeService: "db"}
	if *got != want {
		t.Errorf("Lookup = %+v, want %+v", *got, want)
	}
	// Kept after the container is removed.
	os.RemoveAll(filepath.Join(root, "var/lib/docker/containers", id1))
	if got, _ := c.Lookup(RuntimeDocker, id1); got.Unit() != "docker/shop/db" {
		t.Errorf("Lookup after removal = %+v", got)
	}
	// Unknown: named by id.
	if got, found := c.Lookup(RuntimeDocker, id2); got.Unit() != "docker-fedcba987654" || got.ID != id2 || found {
		t.Errorf("Lookup of an unknown container = %+v", got)
	}
	// Read again once a miss is old, even if it was used since.
	writeFile(t, root, "/var/lib/docker/containers/"+id2+"/config.v2.json", `{"Name": "/late", "Config": {}}`)
	if got, _ := c.Lookup(RuntimeDocker, id2); got.Unit() != "docker-fedcba987654" {
		t.Errorf("Lookup within the miss TTL = %+v", got)
	}
	e := c.cache[id2]
	e.read = e.read.Add(-2 * missTTL)
	c.cache[id2] = e
	if got, _ := c.Lookup(RuntimeDocker, id2); got.Unit() != "docker/late" {
		t.Errorf("Lookup after the miss TTL = %+v", got)
	}
}

func TestContainersDockerDataRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/docker/daemon.json", `{"data-root": "/srv/docker"}`)
	writeFile(t, root, "/srv/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	if got, _ := newContainers(root).Lookup(RuntimeDocker, id1); got.Unit() != "docker/web" {
		t.Errorf("Lookup = %+v", got)
	}
}

// Docker merges the labels of the image into those of the container: they
// name a pod or a Compose service only with the name cri-dockerd or Compose
// gives the container.
func TestContainersDockerImageLabels(t *testing.T) {
	root := t.TempDir()
	for i, tc := range []struct{ name, labels, want string }{
		{"/evil", `{"io.kubernetes.pod.name": "coredns-5d8f7c9b6-x7z2k", "io.kubernetes.pod.namespace": "kube-system",
			"io.kubernetes.container.name": "coredns"}`, "docker/evil"},
		{"/k8s_app_cart-0_shop_uid_0", `{"io.kubernetes.pod.name": "other", "io.kubernetes.pod.namespace": "shop"}`,
			"docker/k8s_app_cart-0_shop_uid_0"},
		{"/k8s_POD_cart-0_shop_uid_0", `{"io.kubernetes.pod.name": "cart-0", "io.kubernetes.pod.namespace": "shop",
			"io.kubernetes.docker.type": "podsandbox"}`, "k8s/shop/cart/POD"},
		{"/web", `{"com.docker.compose.project": "shop", "com.docker.compose.service": "db"}`, "docker/web"},
		{"/shop_db_1", `{"com.docker.compose.project": "shop", "com.docker.compose.service": "db"}`, "docker/shop/db"},
		{"/shop-db-run-0a1b2c3d4e5f", `{"com.docker.compose.project": "shop", "com.docker.compose.service": "db"}`,
			"docker/shop/db"},
		{"/shop-db-1", `{"com.docker.compose.project": "shop", "com.docker.compose.service": "../x"}`, "docker/shop-db-1"},
	} {
		id := fmt.Sprintf("%064x", i+1)
		writeFile(t, root, "/var/lib/docker/containers/"+id+"/config.v2.json",
			`{"Name": "`+tc.name+`", "Config": {"Labels": `+tc.labels+`}}`)
		if got, _ := newContainers(root).Lookup(RuntimeDocker, id); got.Unit() != tc.want {
			t.Errorf("%s: Unit = %q, want %q", tc.name, got.Unit(), tc.want)
		}
	}
}

func TestContainersCRIDockerd(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{
		"Name": "/k8s_app_cart-5d8f7c9b6-x7z2k_shop_0f1e2d3c_0",
		"Config": {"Labels": {"io.kubernetes.pod.name": "cart-5d8f7c9b6-x7z2k",
			"io.kubernetes.pod.namespace": "shop", "io.kubernetes.container.name": "app"}}}`)
	// The runtime is not in a cgroupfs path of kubelet: every one is tried.
	// Docker runs its containers with containerd, whose bundle has no name.
	writeFile(t, root, containerdTasks+"/moby/"+id1+"/config.json", `{"annotations": {}}`)
	got, _ := newContainers(root).Lookup("", id1)
	if got.Unit() != "k8s/shop/cart/app" || got.Workload() != (Service{"cart", "shop"}) || got.Runtime != RuntimeDocker {
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
	if got, _ := c.Lookup(RuntimePodman, id1); got.Unit() != "podman/redis" {
		t.Errorf("Lookup podman = %+v", got)
	}
	if got, _ := c.Lookup(RuntimeCRIO, id2); got.Unit() != "k8s/shop/cart/app" || got.Runtime != RuntimeCRIO {
		t.Errorf("Lookup cri-o = %+v", got)
	}
	// A container of podman run --rm is in volatile-containers.json, and
	// the directory is named after the storage driver.
	id4 := strings.Repeat("cd", 32)
	writeFile(t, root, "/var/lib/containers/storage/vfs-containers/volatile-containers.json",
		`[{"id": "`+id4+`", "names": ["tmp-job"]}]`)
	if got, _ := c.Lookup(RuntimePodman, id4); got.Unit() != "podman/tmp-job" {
		t.Errorf("Lookup of a volatile podman container = %+v", got)
	}
	// A container created later is read from the list again.
	id3 := strings.Repeat("ab", 32)
	writeFile(t, root, "/var/lib/containers/storage/overlay-containers/containers.json",
		strings.Replace(list, "[", `[{"id": "`+id3+`", "names": ["new-one"]},`, 1))
	if got, _ := c.Lookup(RuntimePodman, id3); got.Unit() != "podman/new-one" {
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
	id3 := strings.Repeat("ef", 32)
	writeFile(t, root, containerdTasks+"/default/"+id3+"/config.json", `{"annotations": {"other": "x"}}`)
	c := newContainers(root)
	if got, _ := c.Lookup("", id1); got.Unit() != "k8s/default/web/nginx" || got.Runtime != RuntimeContainerd {
		t.Errorf("Lookup k8s = %+v", got)
	}
	if got, _ := c.Lookup(RuntimeContainerd, id2); got.Unit() != "containerd/proxy" || got.Workload() != (Service{}) {
		t.Errorf("Lookup nerdctl = %+v", got)
	}
	if got, found := c.Lookup(RuntimeContainerd, id3); got.Unit() != "containerd-efefefefefef" || found {
		t.Errorf("Lookup of a container without a name = %+v, %v", got, found)
	}
}

func TestResolverUnit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	r := &Resolver{containers: newContainers(root), paths: map[uint64]string{}, learned: map[uint64]learnedPath{}}
	r.Learn(7, "/system.slice/docker-"+id1+".scope")
	r.reads.Wait()
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
	// Docker in the container web: the inner container is out of reach and
	// named after the outer one.
	r.Learn(9, "/system.slice/docker-"+id1+".scope/docker/"+id2)
	if unit, ctr := r.Unit(9); unit != "docker/web" || ctr.ID != id1 {
		t.Errorf("Unit(9) = %q, %+v", unit, ctr)
	}
	// Neither has state: named after the outer one, by id.
	id3 := strings.Repeat("ab", 32)
	r.Learn(10, "/system.slice/docker-"+id3+".scope/docker/"+id2)
	if unit, ctr := r.Unit(10); unit != "docker-abababababab" || ctr.ID != id3 {
		t.Errorf("Unit(10) = %q, %+v", unit, ctr)
	}
}

// A lookup does not wait for the read of another container, and waits for
// the read of the same one instead of reading it again (#126).
func TestLookupInFlight(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	c := newContainers(root)
	if got, _ := c.Lookup(RuntimeDocker, id1); got.Unit() != "docker/web" {
		t.Fatalf("Lookup = %+v", got)
	}
	// A slow read of id2 is in flight.
	rd := &containerRead{done: make(chan struct{})}
	c.mu.Lock()
	c.reading[id2] = rd
	c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if got, _ := c.Lookup(RuntimeDocker, id1); got.Unit() != "docker/web" {
			t.Errorf("Lookup of the cached container = %+v", got)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup of a cached container waited for the read of another")
	}
	joined := make(chan *Container)
	go func() {
		got, _ := c.Lookup(RuntimeDocker, id2)
		joined <- got
	}()
	want := &Container{Runtime: RuntimeDocker, ID: id2, Name: "db"}
	rd.c, rd.found = want, true
	close(rd.done)
	if got := <-joined; got != want {
		t.Errorf("Lookup during the read = %+v, want the result of the read", got)
	}
}

func TestLookupConcurrent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	writeFile(t, root, "/var/lib/containers/storage/overlay-containers/containers.json",
		`[{"id": "`+id2+`", "names": ["redis"]}]`)
	c := newContainers(root)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, want := id1, "docker/web"
			if i%2 == 1 {
				id, want = id2, "podman/redis"
			}
			if got, found := c.Lookup("", id); !found || got.Unit() != want {
				t.Errorf("Lookup(%s) = %+v, %v", id, got, found)
			}
		}()
	}
	wg.Wait()
}

// Learn does not wait for the reads it queues, and drops those that do not
// fit in the queue rather than blocking.
func TestLearnQueue(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{"Name": "/web", "Config": {}}`)
	r := &Resolver{containers: newContainers(root), paths: map[uint64]string{}, learned: map[uint64]learnedPath{}}
	// The worker starts after the burst, as if it were reading a large file.
	r.readerOnce.Do(func() { r.pending = make(chan string, maxPendingReads) })
	for i := range 3 * maxPendingReads {
		r.Learn(uint64(100+i), "/system.slice/docker-"+id1+".scope")
	}
	if got := r.ReadsDropped(); got != 2*maxPendingReads {
		t.Errorf("ReadsDropped = %d, want %d", got, 2*maxPendingReads)
	}
	go r.readQueued()
	r.reads.Wait()
	if unit, _ := r.Unit(100); unit != "docker/web" {
		t.Errorf("Unit(100) = %q", unit)
	}
	if got := r.CgroupPath(uint64(100 + 3*maxPendingReads - 1)); got != "/system.slice/docker-"+id1+".scope" {
		t.Errorf("the last path = %q", got)
	}
}

// BenchmarkLearn learns a burst of cgroups of containers of Podman on a
// host whose containers.json lists 5000 containers (#126). Learn only
// queues the reads, which a worker does; compare with the read itself in
// BenchmarkLookupPodman.
func BenchmarkLearn(b *testing.B) {
	root, ids := podmanHost(b, 5000)
	r := &Resolver{containers: newContainers(root), paths: map[uint64]string{}, learned: map[uint64]learnedPath{}}
	b.ResetTimer()
	for i := range b.N {
		r.Learn(uint64(i), "/machine.slice/libpod-"+ids[i%len(ids)]+".scope")
	}
	b.StopTimer()
	r.reads.Wait()
}

func BenchmarkLookupPodman(b *testing.B) {
	root, ids := podmanHost(b, 5000)
	b.ResetTimer()
	for i := range b.N {
		// A new reader each time: the list is read as when it changed.
		newContainers(root).Lookup(RuntimePodman, ids[i%len(ids)])
	}
}

func podmanHost(b *testing.B, n int) (string, []string) {
	root := b.TempDir()
	var list strings.Builder
	ids := make([]string, n)
	list.WriteString("[")
	for i := range n {
		ids[i] = fmt.Sprintf("%064x", i+1)
		if i > 0 {
			list.WriteString(",")
		}
		fmt.Fprintf(&list, `{"id": %q, "names": ["c%d"], "image": %q, "layer": %q, "metadata": %q}`,
			ids[i], i, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("m", 400))
	}
	list.WriteString("]")
	writeFile(b, root, "/var/lib/containers/storage/overlay-containers/containers.json", list.String())
	return root, ids
}
