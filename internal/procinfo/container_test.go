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
		refs, under := cgroupContainers(tc.path)
		if under != "" {
			t.Errorf("cgroupContainers(%q) is under %q", tc.path, under)
		}
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
	if got, _ := cgroupContainers(nested); !slices.Equal(got, want) {
		t.Errorf("cgroupContainers(%q) = %+v, want %+v", nested, got, want)
	}
	if got := Unit(nested); got != "docker-0123456789ab" {
		t.Errorf("Unit(%q) = %q", nested, got)
	}
}

// A unit above a container delegated its cgroups to a user, who may name
// one after any container of the host.
func TestCgroupContainerUnder(t *testing.T) {
	for _, tc := range []struct {
		path, under, unit string
	}{
		{"/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id1 + ".scope/container",
			"user@1000.service", "user@1000.service/podman-0123456789ab"},
		{"/user.slice/user-1000.slice/user@1000.service/app.slice/docker-" + id1 + ".scope",
			"user@1000.service", "user@1000.service/docker-0123456789ab"},
		{"/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service/docker-" + id1 + ".scope",
			"user@1000.service/foo.service", "user@1000.service/foo.service/docker-0123456789ab"},
		{"/system.slice/runner.service/docker/" + id1, "runner.service", "runner.service/docker-0123456789ab"},
		{"/user.slice/user-1000.slice/session-3.scope/docker-" + id1 + ".scope",
			"user-1000.slice/session.scope", "user-1000.slice/session.scope/docker-0123456789ab"},
	} {
		refs, under := cgroupContainers(tc.path)
		if len(refs) != 1 || refs[0].id != id1 || under != tc.under {
			t.Errorf("cgroupContainers(%q) = %+v, %q, want under %q", tc.path, refs, under, tc.under)
		}
		if got := Unit(tc.path); got != tc.unit {
			t.Errorf("Unit(%q) = %q, want %q", tc.path, got, tc.unit)
		}
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

// fakeProcess writes the files of /proc/PID that dockerdArgs reads: a
// process with comm, user id uid and the command line args, in the mount
// namespace mnt.
func fakeProcess(t *testing.T, root string, pid int, comm string, uid int, mnt string, args ...string) {
	t.Helper()
	dir := fmt.Sprintf("/proc/%d", pid)
	writeFile(t, root, dir+"/comm", comm+"\n")
	writeFile(t, root, dir+"/status", fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\nGid:\t0\t0\t0\t0\n", comm, uid, uid, uid, uid))
	writeFile(t, root, dir+"/cmdline", strings.Join(args, "\x00")+"\x00")
	if err := os.MkdirAll(filepath.Join(root, dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mnt, filepath.Join(root, dir, "ns/mnt")); err != nil {
		t.Fatal(err)
	}
}

// TestContainersDockerdDataRoot checks that the containers of Docker are
// found under the data root on the command line of dockerd (#125), or in
// the configuration file it names, for every dockerd of root in the mount
// namespace of PID 1, and not where another process named dockerd points.
func TestContainersDockerdDataRoot(t *testing.T) {
	root := t.TempDir()
	const host, other = "mnt:[4026531841]", "mnt:[4026532500]"
	fakeProcess(t, root, 1, "systemd", 0, host, "/sbin/init")
	fakeProcess(t, root, 812, "dockerd", 0, host, "/usr/bin/dockerd", "-H", "fd://", "--data-root", "/srv/docker")
	fakeProcess(t, root, 913, "dockerd", 0, host, "/usr/bin/dockerd", "--config-file=/etc/docker/d2.json", "-H", "unix:///run/d2.sock")
	writeFile(t, root, "/etc/docker/d2.json", `{"data-root": "/srv/d2"}`)
	// daemon.json is not that of the dockerd processes.
	writeFile(t, root, "/etc/docker/daemon.json", `{"data-root": "/srv/unused"}`)
	// A user's process, and the dockerd of a container.
	fakeProcess(t, root, 2001, "dockerd", 1000, host, "dockerd", "--data-root=/var/tmp/evil")
	fakeProcess(t, root, 2002, "dockerd", 0, other, "dockerd", "--data-root=/var/tmp/evil")
	ids := map[string]string{"/srv/docker": "web", "/srv/d2": "db", "/var/tmp/evil": "forged", "/srv/unused": "unused"}
	idOf := map[string]string{}
	var i int
	for dir, name := range ids {
		i++
		id := fmt.Sprintf("%064x", i)
		idOf[name] = id
		writeFile(t, root, dir+"/containers/"+id+"/config.v2.json", `{"Name": "/`+name+`", "Config": {}}`)
	}
	c := newContainers(root)
	if got := c.dockerDataRoots(); !slices.Equal(got, []string{"/srv/docker", "/srv/d2"}) {
		t.Errorf("data roots = %q", got)
	}
	for name, want := range map[string]string{"web": "docker/web", "db": "docker/db",
		"forged": "docker-" + idOf["forged"][:shortID], "unused": "docker-" + idOf["unused"][:shortID]} {
		if got, _ := c.Lookup(RuntimeDocker, idOf[name]); got.Unit() != want {
			t.Errorf("%s: Unit = %q, want %q", name, got.Unit(), want)
		}
	}

	// The data roots are found again after dockerRootsTTL: dockerd was
	// restarted with daemon.json alone.
	os.RemoveAll(filepath.Join(root, "proc/812"))
	os.RemoveAll(filepath.Join(root, "proc/913"))
	if got := c.dockerDataRoots(); !slices.Equal(got, []string{"/srv/docker", "/srv/d2"}) {
		t.Errorf("data roots within the TTL = %q", got)
	}
	c.dockerRead = c.dockerRead.Add(-dockerRootsTTL)
	if got := c.dockerDataRoots(); !slices.Equal(got, []string{"/srv/unused"}) {
		t.Errorf("data roots after the TTL = %q", got)
	}
}

func TestDockerdFlags(t *testing.T) {
	for _, tc := range []struct {
		args         []string
		root, config string
	}{
		{[]string{"dockerd"}, "", ""},
		{[]string{"dockerd", "--data-root", "/a"}, "/a", ""},
		{[]string{"dockerd", "--data-root=/a/../b/", "--config-file", "/etc/c.json"}, "/b", "/etc/c.json"},
		{[]string{"dockerd", "-g", "/a"}, "/a", ""},
		{[]string{"dockerd", "-g=/a"}, "/a", ""},
		{[]string{"dockerd", "-g/a"}, "/a", ""},
		{[]string{"dockerd", "--graph", "/a", "--data-root", "/b"}, "/b", ""},
		{[]string{"dockerd", "--data-root", "relative", "--config-file=x.json"}, "", ""},
		{[]string{"dockerd", "-H", "fd://", "--debug", "--data-root"}, "", ""},
		{[]string{"/usr/bin/dockerd", "--data-root", "/a", "-G", "docker"}, "/a", ""},
	} {
		root, config := dockerdFlags(tc.args)
		if root != tc.root || config != tc.config {
			t.Errorf("dockerdFlags(%q) = %q, %q, want %q, %q", tc.args, root, config, tc.root, tc.config)
		}
	}
}

// TestContainersDockerSwarm checks that the containers of the tasks of a
// service of Docker Swarm are named after the service (#125), and that the
// labels of Swarm, which an image may carry too, name a service only with
// the name Swarm gives the container.
func TestContainersDockerSwarm(t *testing.T) {
	root := t.TempDir()
	const task, node = "3x2ke8c1k0gsdmhwx1w4vjp2u", "q6ymazaxr8gn5yqvzvm7d6o1i"
	swarm := func(service, name string) string {
		return `{"com.docker.swarm.service.name": "` + service + `", "com.docker.swarm.task.id": "` + task +
			`", "com.docker.swarm.task.name": "` + name + `", "com.docker.swarm.task": ""}`
	}
	for i, tc := range []struct{ name, labels, want string }{
		{"/shop_web.1." + task, swarm("shop_web", "shop_web.1."+task), "docker/swarm/shop_web"},
		{"/shop_web.12." + task, swarm("shop_web", "shop_web.12."+task), "docker/swarm/shop_web"},
		// A task of a global service, on a node.
		{"/agent." + node + "." + task, swarm("agent", "agent."+node+"."+task), "docker/swarm/agent"},
		// Labels of an image: the name is not that of a task.
		{"/web", swarm("shop_web", "shop_web.1."+task), "docker/web"},
		{"/shop_web.1." + task, swarm("shop_web", "web"), "docker/shop_web.1." + task},
		{"/shop_web.1." + task, swarm("shop", "shop_web.1."+task), "docker/shop_web.1." + task},
		{"/shop_web.1.x." + task, swarm("shop_web", "shop_web.1.x."+task), "docker/shop_web.1.x." + task},
		{"/shop_web.1.short", strings.ReplaceAll(swarm("shop_web", "shop_web.1.short"), task, "short"),
			"docker/shop_web.1.short"},
	} {
		id := fmt.Sprintf("%064x", i+1)
		writeFile(t, root, "/var/lib/docker/containers/"+id+"/config.v2.json",
			`{"Name": "`+tc.name+`", "Config": {"Labels": `+tc.labels+`}}`)
		if got, _ := newContainers(root).Lookup(RuntimeDocker, id); got.Unit() != tc.want {
			t.Errorf("%s: Unit = %q, want %q", tc.name, got.Unit(), tc.want)
		}
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
	writeFile(t, root, containerdTasks[0]+"/moby/"+id1+"/config.json", `{"annotations": {}}`)
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

// TestContainersContainerdDistributions checks that the containers of the
// containerd of k3s and rke2, and of microk8s, are read from their state
// directories, with the sandbox of their pod (#125).
func TestContainersContainerdDistributions(t *testing.T) {
	for _, tasks := range containerdTasks[1:] {
		root := t.TempDir()
		writeFile(t, root, tasks+"/k8s.io/"+id1+"/config.json", `{
			"annotations": {"io.kubernetes.cri.container-type": "container",
				"io.kubernetes.cri.sandbox-id": "`+id2+`",
				"io.kubernetes.cri.sandbox-name": "web-5d8f7c9b6-x7z2k",
				"io.kubernetes.cri.sandbox-namespace": "shop",
				"io.kubernetes.cri.container-name": "nginx"}}`)
		writeFile(t, root, tasks+"/k8s.io/"+id2+"/config.json", `{
			"annotations": {"io.kubernetes.cri.container-type": "sandbox",
				"io.kubernetes.cri.sandbox-name": "web-5d8f7c9b6-x7z2k",
				"io.kubernetes.cri.sandbox-namespace": "shop",
				"resource.opentelemetry.io/service.name": "storefront"}}`)
		got, found := newContainers(root).Lookup("", id1)
		if !found || got.Unit() != "k8s/shop/web/nginx" || got.Workload() != (Service{"storefront", "shop"}) {
			t.Errorf("%s: Lookup = %+v, %t", tasks, got, found)
		}
	}
}

func TestContainersContainerd(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, containerdTasks[0]+"/k8s.io/"+id1+"/config.json", `{
		"annotations": {"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.sandbox-name": "web-5d8f7c9b6-x7z2k",
			"io.kubernetes.cri.sandbox-namespace": "default",
			"io.kubernetes.cri.container-name": "nginx"}}`)
	writeFile(t, root, containerdTasks[0]+"/default/"+id2+"/config.json", `{
		"annotations": {"nerdctl/name": "proxy"}}`)
	id3 := strings.Repeat("ef", 32)
	writeFile(t, root, containerdTasks[0]+"/default/"+id3+"/config.json", `{"annotations": {"other": "x"}}`)
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

// A user, or a container allowed to write its cgroups, can make a cgroup
// named after a container of the host: the process in it is not named
// after that container.
func TestResolverUnitForged(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", `{"Name": "/db", "Config": {}}`)
	r := &Resolver{containers: newContainers(root), paths: map[uint64]string{}, learned: map[uint64]learnedPath{}}
	for i, tc := range []struct{ path, unit, id string }{
		{"/user.slice/user-1000.slice/user@1000.service/app.slice/docker-" + id1 + ".scope",
			"user@1000.service/docker-0123456789ab", id1},
		{"/system.slice/runner.service/docker-" + id1 + ".scope", "runner.service/docker-0123456789ab", id1},
		// Inside the container id2, which has no state: named after it.
		{"/system.slice/docker-" + id2 + ".scope/docker-" + id1 + ".scope", "docker-fedcba987654", id2},
		// The container of the host itself.
		{"/system.slice/docker-" + id1 + ".scope", "docker/db", id1},
	} {
		id := uint64(20 + i)
		r.Learn(id, tc.path)
		r.reads.Wait()
		unit, ctr := r.Unit(id)
		if unit != tc.unit || ctr == nil || ctr.ID != tc.id {
			t.Errorf("Unit(%q) = %q, %+v, want %q", tc.path, unit, ctr, tc.unit)
		}
	}
}

func TestContainerWorkload(t *testing.T) {
	defer func(f func() string) { nodeName = f }(nodeName)
	nodeName = func() string { return "node-1" }
	pod := func(name string, labels, annotations map[string]string) *Container {
		return &Container{Runtime: RuntimeCRIO, ID: id1, PodNamespace: "shop", PodName: name,
			Pod: newPodMeta(labels, annotations)}
	}
	for _, tc := range []struct {
		name string
		c    *Container
		want Service
	}{
		{"no metadata", pod("cart-5d8f7c9b6-x7z2k", nil, nil), Service{"cart", "shop"}},
		{"Helm chart", pod("ingress-nginx-controller-5d8f7c9b6-x7z2k", map[string]string{
			"app.kubernetes.io/instance": "ingress-nginx", "app.kubernetes.io/name": "ingress-nginx",
			"app.kubernetes.io/part-of": "ingress-nginx", "pod-template-hash": "5d8f7c9b6",
		}, nil), Service{"ingress-nginx", "ingress-nginx"}},
		{"instance before name", pod("x-0", map[string]string{
			"app.kubernetes.io/instance": "prod-db", "app.kubernetes.io/name": "postgresql"}, nil),
			Service{"prod-db", "shop"}},
		{"name", pod("x-0", map[string]string{"app.kubernetes.io/name": "postgresql"}, nil),
			Service{"postgresql", "shop"}},
		{"annotation before labels", pod("x-0", map[string]string{"app.kubernetes.io/name": "postgresql"},
			map[string]string{annotationServiceName: "orders", annotationServiceNamespace: "eu"}),
			Service{"orders", "eu"}},
		{"empty annotation ends the search", pod("x-0", map[string]string{"app.kubernetes.io/name": "postgresql"},
			map[string]string{annotationServiceName: ""}), Service{"x", "shop"}},
		{"Deployment", pod("web-api-7c6b5d4f8b-9mzqk", map[string]string{"pod-template-hash": "7c6b5d4f8b"}, nil),
			Service{"web-api", "shop"}},
		{"Job owned by a CronJob", pod("backup-29340000-tq8wz", map[string]string{
			"batch.kubernetes.io/job-name": "backup-29340000", "job-name": "backup-29340000"}, nil),
			Service{"backup", "shop"}},
		{"Job", pod("data-load-tq8wz", map[string]string{"job-name": "data-load"}, nil), Service{"data", "shop"}},
		{"Job without -", pod("migrate-tq8wz", map[string]string{"job-name": "migrate"}, nil), Service{"migrate", "shop"}},
		{"static pod", pod("kube-apiserver-node-1", map[string]string{"component": "kube-apiserver"},
			map[string]string{annotationConfigSource: "file"}), Service{"node-1", "shop"}},
		{"static pod of another node", pod("etcd-node-2", map[string]string{},
			map[string]string{annotationConfigSource: "file"}), Service{"etcd-node", "shop"}}, // guessed from the name
		{"pod of the API server", pod("web-node-1", map[string]string{},
			map[string]string{annotationConfigSource: "api"}), Service{"web-node", "shop"}},
		{"unsafe annotation", pod("x-0", nil, map[string]string{annotationServiceName: "a/b c"}),
			Service{"a_b_c", "shop"}},
		{"not a pod", &Container{Runtime: RuntimeDocker, ID: id1, Name: "web"}, Service{}},
	} {
		if got := tc.c.Workload(); got != tc.want {
			t.Errorf("%s: Workload = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestNewPodMeta(t *testing.T) {
	if m := newPodMeta(nil, map[string]string{"io.kubernetes.cri.sandbox-name": "x"}); m != nil {
		t.Errorf("newPodMeta without keys = %+v", m)
	}
	m := newPodMeta(map[string]string{"app.kubernetes.io/name": "a", "other": "b"}, nil)
	if len(m.Labels) != 1 || m.Annotations != nil {
		t.Errorf("newPodMeta = %+v", m)
	}
}

// cri-dockerd keeps the labels and annotations of a pod on its sandbox.
func TestContainersCRIDockerdPodMeta(t *testing.T) {
	root := t.TempDir()
	sandbox := id2
	writeFile(t, root, "/var/lib/docker/containers/"+sandbox+"/config.v2.json", `{
		"Name": "/k8s_POD_cart-5d8f7c9b6-x7z2k_shop_0f1e2d3c_0",
		"Config": {"Labels": {"io.kubernetes.pod.name": "cart-5d8f7c9b6-x7z2k",
			"io.kubernetes.pod.namespace": "shop", "io.kubernetes.docker.type": "podsandbox",
			"app.kubernetes.io/name": "cart-app",
			"annotation.resource.opentelemetry.io/service.namespace": "store"}}}`)
	container := `{
		"Name": "/k8s_app_cart-5d8f7c9b6-x7z2k_shop_%s_0",
		"Config": {"Labels": {"io.kubernetes.pod.name": "cart-5d8f7c9b6-x7z2k",
			"io.kubernetes.pod.namespace": "shop", "io.kubernetes.container.name": "app",
			"io.kubernetes.sandbox.id": "` + sandbox + `"}}}`
	writeFile(t, root, "/var/lib/docker/containers/"+id1+"/config.v2.json", fmt.Sprintf(container, "0f1e2d3c"))
	c := newContainers(root)
	if got, _ := c.Lookup(RuntimeDocker, id1); got.Workload() != (Service{"cart-app", "store"}) {
		t.Errorf("Workload of the container = %+v", got.Workload())
	}
	if got, _ := c.Lookup(RuntimeDocker, sandbox); got.Workload() != (Service{"cart-app", "store"}) {
		t.Errorf("Workload of the sandbox = %+v", got.Workload())
	}
	// The sandbox of another pod is not believed.
	id3 := strings.Repeat("ab", 32)
	writeFile(t, root, "/var/lib/docker/containers/"+id3+"/config.v2.json", fmt.Sprintf(container, "other"))
	if got, _ := c.Lookup(RuntimeDocker, id3); got.Pod != nil || got.Workload() != (Service{"cart", "shop"}) {
		t.Errorf("Workload with the sandbox of another pod = %+v", got.Workload())
	}
}

// CRI-O keeps the labels and annotations of a pod in JSON on the bundle of
// its sandbox.
func TestContainersCRIOPodMeta(t *testing.T) {
	root := t.TempDir()
	sandbox := id2
	writeFile(t, root, "/var/lib/containers/storage/overlay-containers/"+sandbox+"/userdata/config.json", `{
		"annotations": {"io.kubernetes.pod.name": "data-load-tq8wz", "io.kubernetes.pod.namespace": "batch",
			"io.kubernetes.container.name": "POD", "io.kubernetes.cri-o.SandboxID": "`+sandbox+`",
			"io.kubernetes.cri-o.Labels": "{\"io.kubernetes.pod.name\":\"data-load-tq8wz\",\"io.kubernetes.pod.namespace\":\"batch\",\"job-name\":\"data-load\"}",
			"io.kubernetes.cri-o.Annotations": "{\"resource.opentelemetry.io/service.namespace\":\"etl\"}"}}`)
	writeFile(t, root, "/run/containers/storage/overlay-containers/"+id1+"/userdata/config.json", `{
		"annotations": {"io.kubernetes.pod.name": "data-load-tq8wz", "io.kubernetes.pod.namespace": "batch",
			"io.kubernetes.container.name": "load", "io.kubernetes.cri-o.SandboxID": "`+sandbox+`",
			"io.kubernetes.cri-o.Labels": "{\"io.kubernetes.pod.name\":\"data-load-tq8wz\",\"io.kubernetes.pod.namespace\":\"batch\"}"}}`)
	c := newContainers(root)
	for _, id := range []string{id1, sandbox} {
		if got, _ := c.Lookup(RuntimeCRIO, id); got.Workload() != (Service{"data", "etl"}) {
			t.Errorf("Workload of %s = %+v", got.ContainerName, got.Workload())
		}
	}
	// Without its sandbox, the owner is guessed from the name.
	id3 := strings.Repeat("ab", 32)
	writeFile(t, root, "/run/containers/storage/overlay-containers/"+id3+"/userdata/config.json", `{
		"annotations": {"io.kubernetes.pod.name": "data-load-tq8wz", "io.kubernetes.pod.namespace": "batch",
			"io.kubernetes.cri-o.SandboxID": "`+strings.Repeat("cd", 32)+`"}}`)
	if got, _ := c.Lookup(RuntimeCRIO, id3); got.Pod != nil || got.Workload() != (Service{"data-load", "batch"}) {
		t.Errorf("Workload without a sandbox = %+v", got.Workload())
	}
}

// containerd keeps the annotations of a pod that pod_annotations lets
// through on the bundle of its sandbox, and not its labels.
func TestContainersContainerdPodMeta(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, containerdTasks[0]+"/k8s.io/"+id2+"/config.json", `{
		"annotations": {"io.kubernetes.cri.container-type": "sandbox",
			"io.kubernetes.cri.sandbox-name": "web-5d8f7c9b6-x7z2k",
			"io.kubernetes.cri.sandbox-namespace": "default",
			"resource.opentelemetry.io/service.name": "frontend"}}`)
	writeFile(t, root, containerdTasks[0]+"/k8s.io/"+id1+"/config.json", `{
		"annotations": {"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.sandbox-id": "`+id2+`",
			"io.kubernetes.cri.sandbox-name": "web-5d8f7c9b6-x7z2k",
			"io.kubernetes.cri.sandbox-namespace": "default",
			"io.kubernetes.cri.container-name": "nginx"}}`)
	c := newContainers(root)
	for _, id := range []string{id1, id2} {
		got, _ := c.Lookup(RuntimeContainerd, id)
		if got.Workload() != (Service{"frontend", "default"}) || got.Pod.Labels != nil {
			t.Errorf("Workload of %s = %+v, %+v", got.ContainerName, got.Workload(), got.Pod)
		}
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
