package tracer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// A socket iterator only walks the sockets of the network namespace of the
// thread that opens it, so the iterators are opened once per namespace.

// netnsRef is a network namespace and a path that opens it.
type netnsRef struct {
	inode uint32
	path  string
}

// listNetNS returns the network namespaces of the host: those of all
// processes and those kept by bind mounts (ip netns, docker). With only set,
// it returns that namespace alone.
func listNetNS(only uint32) []netnsRef {
	var (
		refs []netnsRef
		seen = map[uint32]bool{}
	)
	add := func(path string) {
		var st unix.Stat_t
		if unix.Stat(path, &st) != nil {
			return
		}
		ino := uint32(st.Ino)
		if seen[ino] || (only != 0 && ino != only) {
			return
		}
		seen[ino] = true
		refs = append(refs, netnsRef{inode: ino, path: path})
	}
	add("/proc/self/ns/net")
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				add(filepath.Join("/proc", e.Name(), "ns", "net"))
			}
		}
	}
	for _, dir := range []string{"/run/netns", "/run/docker/netns"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				add(filepath.Join(dir, e.Name()))
			}
		}
	}
	return refs
}

// openInNetNS opens the iterators inside the network namespace at path. The
// returned readers walk that namespace wherever they are read.
func openInNetNS(path string, its ...*link.Iter) ([]io.ReadCloser, error) {
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
		target, err := os.Open(path)
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("entering %s: %w", path, err)}
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
