package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// workload is a loopback workload of netbench:
//
//	tcp_rr    persistent TCP connections; a transaction writes size bytes
//	          and reads them back, two messages on each side
//	tcp_crr   a TCP connection per transaction: connect, write, read, close
//	udp_rr    a datagram of size bytes sent and echoed
//	fail      connects to target that fail; the client waits for each with
//	          poll(2), sleeping (-wait poll) or spinning (-wait spin), then
//	          reads SO_ERROR
//
// The threads of the transactions make raw system calls on blocking
// sockets, each on an OS thread of its own, so that they behave as those of
// a C program and the Go scheduler stays out of the measurement.
type workload struct {
	mode   string
	pairs  int
	secs   float64
	size   int
	target string
	wait   string
}

func (w *workload) flags(fs *flag.FlagSet) {
	fs.StringVar(&w.mode, "mode", "tcp_rr", "tcp_rr, tcp_crr, udp_rr or fail")
	fs.IntVar(&w.pairs, "pairs", 8, "pairs of client and server threads")
	fs.Float64Var(&w.secs, "secs", 5, "duration in seconds")
	fs.IntVar(&w.size, "size", 64, "bytes of a message")
	fs.StringVar(&w.target, "target", "10.99.0.2:9", "address that fail connects to")
	fs.StringVar(&w.wait, "wait", "poll", "how fail waits for a connect: poll or spin")
}

func (w *workload) args() []string {
	return []string{"-mode", w.mode, "-pairs", strconv.Itoa(w.pairs), "-secs", fmt.Sprint(w.secs),
		"-size", strconv.Itoa(w.size), "-target", w.target, "-wait", w.wait}
}

type benchOut struct {
	Ops    uint64            `json:"ops"`
	Secs   float64           `json:"secs"`
	Errnos map[string]uint64 `json:"errnos,omitempty"`
}

// counter is a per-thread count of transactions on a cache line of its own.
type counter struct {
	n atomic.Uint64
	_ [56]byte
}

func runNetbench(args []string) error {
	fs := flag.NewFlagSet("netbench", flag.ExitOnError)
	var w workload
	w.flags(fs)
	fs.Parse(args)

	var (
		stop   atomic.Bool
		counts = make([]counter, w.pairs)
		wg     sync.WaitGroup
		client func(i int) error
		errnos sync.Map
	)
	// Every thread holds a P while it blocks in a raw system call, which
	// a collection could not stop: the workload allocates little, and
	// does not collect.
	runtime.GOMAXPROCS(2*w.pairs + 4)
	debug.SetGCPercent(-1)
	switch w.mode {
	case "tcp_rr":
		port, err := tcpServer(w.pairs, w.size, false)
		if err != nil {
			return err
		}
		client = func(i int) error { return tcpRRClient(port, w.size, &stop, &counts[i].n) }
	case "tcp_crr":
		port, err := tcpServer(w.pairs, w.size, true)
		if err != nil {
			return err
		}
		client = func(i int) error { return tcpCRRClient(port, w.size, &stop, &counts[i].n) }
	case "udp_rr":
		client = func(i int) error {
			port, err := udpServer(w.size)
			if err != nil {
				return err
			}
			return udpRRClient(port, w.size, &stop, &counts[i].n)
		}
	case "fail":
		ap, err := netip.ParseAddrPort(w.target)
		if err != nil {
			return err
		}
		runtime.GOMAXPROCS(runtime.NumCPU())
		client = func(i int) error { return failClient(ap, w.wait == "spin", &stop, &counts[i].n, &errnos) }
	default:
		return fmt.Errorf("unknown mode %s", w.mode)
	}

	errc := make(chan error, w.pairs)
	start := time.Now()
	for i := range w.pairs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			if err := client(i); err != nil {
				errc <- err
				stop.Store(true)
			}
		}()
	}
	time.Sleep(time.Duration(w.secs * float64(time.Second)))
	stop.Store(true)
	elapsed := time.Since(start)
	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		return err
	}
	out := benchOut{Secs: elapsed.Seconds()}
	for i := range counts {
		out.Ops += counts[i].n.Load()
	}
	errnos.Range(func(k, v any) bool {
		if out.Errnos == nil {
			out.Errnos = map[string]uint64{}
		}
		out.Errnos[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return json.NewEncoder(os.Stdout).Encode(&out)
}

func sys(trap, a1, a2, a3 uintptr) (uintptr, error) {
	r, _, e := unix.RawSyscall(trap, a1, a2, a3)
	if e != 0 {
		return r, e
	}
	return r, nil
}

func sys6(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, error) {
	r, _, e := unix.RawSyscall6(trap, a1, a2, a3, a4, a5, a6)
	if e != 0 {
		return r, e
	}
	return r, nil
}

func readFull(fd int, b []byte) error {
	for got := 0; got < len(b); {
		n, err := sys(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[got])), uintptr(len(b)-got))
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("connection closed")
		}
		got += int(n)
	}
	return nil
}

func writeAll(fd int, b []byte) error {
	_, err := sys(unix.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return err
}

func loopback(port int) *unix.SockaddrInet4 {
	return &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
}

func localPort(fd int) (int, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	return sa.(*unix.SockaddrInet4).Port, nil
}

// tcpServer listens on loopback. Without crr it accepts n persistent
// connections and echoes on each with a thread of its own; with crr, n
// threads accept connections and make one transaction on each.
func tcpServer(n, size int, crr bool) (int, error) {
	lfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	if err := unix.Bind(lfd, loopback(0)); err != nil {
		return 0, err
	}
	if err := unix.Listen(lfd, 4096); err != nil {
		return 0, err
	}
	port, err := localPort(lfd)
	if err != nil {
		return 0, err
	}
	serve := func(fd int) {
		buf := make([]byte, size)
		unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		for {
			if readFull(fd, buf) != nil || writeAll(fd, buf) != nil {
				break
			}
			if crr {
				break
			}
		}
		unix.Close(fd)
	}
	if !crr {
		go func() {
			for range n {
				fd, _, err := unix.Accept4(lfd, unix.SOCK_CLOEXEC)
				if err != nil {
					return
				}
				go func() {
					runtime.LockOSThread()
					serve(fd)
				}()
			}
		}()
		return port, nil
	}
	for range n {
		go func() {
			runtime.LockOSThread()
			for {
				fd, err := sys(unix.SYS_ACCEPT4, uintptr(lfd), 0, 0)
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if err != nil {
					return
				}
				serve(int(fd))
			}
		}()
	}
	return port, nil
}

func dialTCP(port int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	sa := unix.RawSockaddrInet4{Family: unix.AF_INET, Port: uint16(port>>8 | port<<8&0xff00), Addr: [4]byte{127, 0, 0, 1}}
	if _, err := sys(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); err != nil {
		unix.Close(fd)
		return 0, err
	}
	unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	return fd, nil
}

func tcpRRClient(port, size int, stop *atomic.Bool, n *atomic.Uint64) error {
	fd, err := dialTCP(port)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	buf := make([]byte, size)
	for !stop.Load() {
		if err := writeAll(fd, buf); err != nil {
			return err
		}
		if err := readFull(fd, buf); err != nil {
			return err
		}
		n.Add(1)
	}
	return nil
}

func tcpCRRClient(port, size int, stop *atomic.Bool, n *atomic.Uint64) error {
	buf := make([]byte, size)
	for !stop.Load() {
		fd, err := dialTCP(port)
		if err != nil {
			if errors.Is(err, unix.EADDRNOTAVAIL) {
				continue
			}
			return err
		}
		if err := writeAll(fd, buf); err != nil {
			unix.Close(fd)
			return err
		}
		if err := readFull(fd, buf); err != nil {
			unix.Close(fd)
			return err
		}
		unix.Close(fd)
		n.Add(1)
	}
	return nil
}

// udpServer echoes the datagrams sent to its port with a thread of its own.
func udpServer(size int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	if err := unix.Bind(fd, loopback(0)); err != nil {
		return 0, err
	}
	port, err := localPort(fd)
	if err != nil {
		return 0, err
	}
	go func() {
		runtime.LockOSThread()
		buf := make([]byte, size)
		var from unix.RawSockaddrInet4
		for {
			fromlen := uint32(unsafe.Sizeof(from))
			n, err := sys6(unix.SYS_RECVFROM, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0,
				uintptr(unsafe.Pointer(&from)), uintptr(unsafe.Pointer(&fromlen)))
			if err != nil {
				return
			}
			if _, err := sys6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), n, 0,
				uintptr(unsafe.Pointer(&from)), uintptr(fromlen)); err != nil {
				return
			}
		}
	}()
	return port, nil
}

func udpRRClient(port, size int, stop *atomic.Bool, n *atomic.Uint64) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, loopback(port)); err != nil {
		return err
	}
	buf := make([]byte, size)
	for !stop.Load() {
		if err := writeAll(fd, buf); err != nil {
			return err
		}
		if _, err := sys(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); err != nil {
			return err
		}
		n.Add(1)
	}
	return nil
}

// failClient connects to target over and over, and counts the errors that
// SO_ERROR gives.
func failClient(target netip.AddrPort, spin bool, stop *atomic.Bool, n *atomic.Uint64, errnos *sync.Map) error {
	sa := &unix.SockaddrInet4{Port: int(target.Port()), Addr: target.Addr().As4()}
	for !stop.Load() {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			return err
		}
		// One retransmission, so that a dropped SYN fails within 3 s.
		unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_SYNCNT, 1)
		err = unix.Connect(fd, sa)
		var revents int16
		if errors.Is(err, unix.EINPROGRESS) {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			timeout := 5000
			if spin {
				timeout = 0
			}
			// An attempt is never abandoned, so that each ends with the
			// error the kernel gives it.
			for {
				k, err := unix.Poll(fds, timeout)
				if errors.Is(err, unix.EINTR) || (err == nil && k == 0) {
					continue
				}
				break
			}
			revents = fds[0].Revents
			v, gerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if gerr != nil {
				err = gerr
			} else {
				err = unix.Errno(v)
			}
		}
		name := "0"
		var errno unix.Errno
		if errors.As(err, &errno) {
			name = unix.ErrnoName(errno)
		}
		// No error after poll(2) reported the socket: what it reported,
		// and the state of the connection.
		if errno == 0 && revents != 0 {
			state := -1
			if info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
				state = int(info.State)
			}
			name = fmt.Sprintf("none(revents=%#x,state=%d)", revents, state)
		}
		unix.Close(fd)
		v, _ := errnos.LoadOrStore(name, new(atomic.Uint64))
		v.(*atomic.Uint64).Add(1)
		n.Add(1)
	}
	return nil
}
