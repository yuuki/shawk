package procinfo

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"syscall"
)

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

// storageRoots are the graph root of containers/storage used by Podman and
// CRI-O as root, then the run root, where CRI-O keeps the bundles and a
// transient store keeps its lists. The directories of the containers are
// named after the storage driver: overlay-containers, vfs-containers...
var storageRoots = []string{"/var/lib/containers/storage", "/run/containers/storage"}

// podmanNames returns the names of the containers of containers/storage
// by id: containers.json lists the containers, volatile-containers.json
// those removed when they stop (podman run --rm).
func (c *Containers) podmanNames() map[string]string {
	c.podmanMu.Lock()
	defer c.podmanMu.Unlock()
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
