package tracer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// A socket iterator only walks the sockets of the network namespace of the
// thread that opens it, so the iterators are opened once per namespace.

// netnsDirs are the directories where ip netns, CNI plugins and docker keep
// network namespaces with bind mounts. /var/run is mostly a link to /run.
var netnsDirs = []string{"/run/netns", "/var/run/netns", "/run/docker/netns"}

// maxNetNSPaths bounds the paths kept for each network namespace.
const maxNetNSPaths = 4

// fileID identifies a file by its device and its inode. A network namespace
// is identified so by the files of nsfs that open it.
type fileID struct {
	dev, ino uint64
}

func fileIDOf(st *unix.Stat_t) fileID {
	return fileID{dev: st.Dev, ino: st.Ino}
}

// netnsRef is a network namespace and the paths that opened it when it was
// listed, preferred first.
type netnsRef struct {
	id    fileID
	paths []string
}

// inode returns the inode of the namespace, by which the BPF programs know
// it.
func (ns *netnsRef) inode() uint32 {
	return uint32(ns.id.ino)
}

// listNetNS returns the network namespaces of the host: those kept by bind
// mounts (ip netns, docker) and those of all processes. With only set, it
// returns that namespace alone.
func listNetNS(only uint32) []netnsRef {
	return findNetNS("/proc", netnsDirs, only)
}

// findNetNS returns the network namespaces kept by bind mounts in dirs and
// those of the processes of procDir, a mount of procfs.
//
// A bind mount keeps its namespace until it is unmounted, while the path of
// a process stops opening its namespace when the process exits, and opens
// another one if its PID is reused. The paths of a namespace are therefore
// those of bind mounts first, then those of the processes with the lowest
// PIDs, which mostly started first, like the init of a container, and live
// as long as the namespace. At most maxNetNSPaths are kept.
func findNetNS(procDir string, dirs []string, only uint32) []netnsRef {
	var (
		refs []netnsRef
		idx  = map[fileID]int{}
	)
	add := func(path string) {
		var st unix.Stat_t
		if unix.Stat(path, &st) != nil || (only != 0 && uint32(st.Ino) != only) {
			return
		}
		id := fileIDOf(&st)
		i, ok := idx[id]
		if !ok {
			idx[id] = len(refs)
			refs = append(refs, netnsRef{id: id, paths: []string{path}})
			return
		}
		if len(refs[i].paths) < maxNetNSPaths {
			refs[i].paths = append(refs[i].paths, path)
		}
	}
	// A directory may have several names, through a link.
	listed := map[fileID]bool{}
	for _, dir := range dirs {
		var st unix.Stat_t
		if unix.Stat(dir, &st) != nil || listed[fileIDOf(&st)] {
			continue
		}
		listed[fileIDOf(&st)] = true
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				add(filepath.Join(dir, e.Name()))
			}
		}
	}
	add(filepath.Join(procDir, "self", "ns", "net"))
	for _, pid := range listPIDs(procDir) {
		add(filepath.Join(procDir, strconv.Itoa(pid), "ns", "net"))
	}
	return refs
}

// listPIDs returns the PIDs of the processes of procDir, lowest first.
func listPIDs(procDir string) []int {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

// walkAllNetNS opens the socket iterators in every network namespace and
// passes them to read, one namespace at a time, so that the files it holds
// do not grow with the number of namespaces. It returns the namespaces it
// could not open, which may have gone away since they were listed.
//
// The iterators walk the namespace of the thread that opens them, which is
// not always that of the process: a thread may have entered another
// namespace and stayed there, e.g. the main thread of the process, which Go
// never terminates. The namespace of the thread is therefore compared, on a
// thread locked for the walk.
func (t *Tracer) walkAllNetNS(read func(io.Reader) error) (map[uint32]bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var (
		skipped map[uint32]bool
		st      unix.Stat_t
	)
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return nil, fmt.Errorf("finding the network namespace: %w", err)
	}
	for _, ns := range listNetNS(t.opts.NetNS) {
		var (
			rcs []io.ReadCloser
			err error
		)
		if ns.id == fileIDOf(&st) {
			if rcs, err = openIters(t.iterTCP, t.iterUDP); err != nil {
				return nil, err
			}
		} else if rcs, err = openInNetNS(&ns, t.iterTCP, t.iterUDP); err != nil {
			t.log.Debug("skipping network namespace", "netns", ns.inode(), "error", err)
			if skipped == nil {
				skipped = map[uint32]bool{}
			}
			skipped[ns.inode()] = true
			continue
		}
		if err := readAll(rcs, read); err != nil {
			return nil, err
		}
	}
	return skipped, nil
}

// readAll passes the readers to read, in order, and closes them.
func readAll(rcs []io.ReadCloser, read func(io.Reader) error) error {
	defer closeAll(rcs)
	for _, rc := range rcs {
		if err := read(rc); err != nil {
			return err
		}
	}
	return nil
}

// openIters opens the iterators in the current network namespace.
func openIters(its ...*link.Iter) ([]io.ReadCloser, error) {
	var rcs []io.ReadCloser
	for _, it := range its {
		rc, err := it.Open()
		if err != nil {
			closeAll(rcs)
			return nil, fmt.Errorf("opening iterator: %w", err)
		}
		rcs = append(rcs, rc)
	}
	return rcs, nil
}

// openNetNS opens the first path of ns that still opens the namespace: the
// process of a path may have exited since the namespace was listed, and its
// PID may be that of a process in another namespace now. The namespace is
// checked on the opened file, which keeps it.
func openNetNS(ns *netnsRef) (*os.File, error) {
	var errs []error
	for _, path := range ns.paths {
		f, err := os.Open(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			f.Close()
			errs = append(errs, fmt.Errorf("stat %s: %w", path, err))
			continue
		}
		if fileIDOf(&st) != ns.id {
			f.Close()
			errs = append(errs, fmt.Errorf("%s opens network namespace %d now", path, st.Ino))
			continue
		}
		return f, nil
	}
	return nil, fmt.Errorf("no path opens network namespace %d: %w", ns.inode(), errors.Join(errs...))
}

// openInNetNS opens the iterators inside the network namespace ns. The
// returned readers walk that namespace wherever they are read.
func openInNetNS(ns *netnsRef, its ...*link.Iter) ([]io.ReadCloser, error) {
	type result struct {
		rcs []io.ReadCloser
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			// A thread that could not return to its namespace is discarded
			// by exiting the goroutine while it is still locked.
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer orig.Close()
		target, err := openNetNS(ns)
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("entering %s: %w", target.Name(), err)}
			return
		}
		var (
			rcs     []io.ReadCloser
			openErr error
		)
		for _, it := range its {
			rc, err := it.Open()
			if err != nil {
				openErr = err
				break
			}
			rcs = append(rcs, rc)
		}
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
			restored = false
		}
		if openErr != nil {
			closeAll(rcs)
			rcs = nil
		}
		ch <- result{rcs: rcs, err: openErr}
	}()
	r := <-ch
	return r.rcs, r.err
}

func closeAll(rcs []io.ReadCloser) {
	for _, rc := range rcs {
		rc.Close()
	}
}
