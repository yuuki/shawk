//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The ports of the workload: rank j of a peer node listens on
// peerPortBase+j, and rank i of the node on rankPortBase+i.
const (
	peerPortBase = 20000
	rankPortBase = 30000
)

// targets are the servers a rank connects to: ports of ranks of the peer
// nodes, from first to first+peers-1. Rank i connects to the ranks
// (i+k) mod peerRanks, k < ports, of every peer node, so that ports=1 is a
// rank talking to the same rank on every other node and ports=peerRanks a
// rank talking to all of them (all to all), each connection made by one
// side as MPI does.
type targets struct {
	first     netip.Addr
	peers     int
	ports     int
	peerRanks int
}

func (t *targets) flags(fs *flag.FlagSet) {
	fs.Func("peer-first", "address of the first peer node (default 10.98.0.1)", func(s string) error {
		a, err := netip.ParseAddr(s)
		t.first = a
		return err
	})
	t.first = netip.MustParseAddr("10.98.0.1")
	fs.IntVar(&t.peers, "peers", 189, "peer nodes")
	fs.IntVar(&t.ports, "ports", 1, "ranks of every peer node each rank connects to")
	fs.IntVar(&t.peerRanks, "peer-ranks", 128, "ranks per peer node, which listen on ports 20000 and on")
}

func (t *targets) args() []string {
	return []string{"-peer-first", t.first.String(), "-peers", strconv.Itoa(t.peers),
		"-ports", strconv.Itoa(t.ports), "-peer-ranks", strconv.Itoa(t.peerRanks)}
}

// peerAddrs returns the addresses of n peer nodes from first on.
func peerAddrs(first netip.Addr, n int) []netip.Addr {
	addrs := make([]netip.Addr, 0, n)
	for a := first; len(addrs) < n; a = a.Next() {
		addrs = append(addrs, a)
	}
	return addrs
}

func (t *targets) list(rank int) []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range peerAddrs(t.first, t.peers) {
		for k := range t.ports {
			out = append(out, netip.AddrPortFrom(a, uint16(peerPortBase+(rank+k)%t.peerRanks)))
		}
	}
	return out
}

// runMesh runs the ranks of the node, in jobs of cgroups like those of
// Slurm (job_ID/step_0/user/task_N), and short jobs at a rate.
func runMesh(args []string) error {
	fs := flag.NewFlagSet("mesh", flag.ExitOnError)
	var t targets
	t.flags(fs)
	var (
		ranks      = fs.Int("ranks", 128, "ranks of the node")
		jobs       = fs.Int("jobs", 1, "concurrent jobs the ranks are spread over")
		inbound    = fs.Bool("in", false, "every rank listens, and every peer node connects to it (run peer with -in-ranks)")
		cgroot     = fs.String("cgroup", "", "directory of the cgroup v2 hierarchy under which the jobs are made (required)")
		hold       = fs.Duration("hold", time.Hour, "how long the ranks keep their connections")
		traffic    = fs.Duration("traffic", 5*time.Second, "how often every rank writes 8 bytes on each connection; 0 never")
		shortRate  = fs.Float64("short-rate", 0, "short jobs started per minute")
		shortRanks = fs.Int("short-ranks", 4, "ranks of a short job")
		shortPeers = fs.Int("short-peers", 8, "peer nodes a short job talks to")
		shortLen   = fs.Duration("short-secs", 10*time.Second, "how long a short job runs")
		ready      = fs.String("ready", "", "file created once all ranks are connected")
	)
	fs.Parse(args)
	if *cgroot == "" {
		return errors.New("-cgroup is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *hold)
	defer cancel()
	if err := os.MkdirAll(*cgroot, 0o755); err != nil {
		return err
	}

	var started []*job
	defer func() {
		for _, j := range started {
			j.stop()
		}
	}()
	per := (*ranks + *jobs - 1) / *jobs
	for id := 1; id <= *jobs; id++ {
		n := min(per, *ranks-(id-1)*per)
		if n <= 0 {
			break
		}
		j := &job{root: filepath.Join(*cgroot, fmt.Sprintf("job_%d", id))}
		started = append(started, j)
		for i := range n {
			rank := (id-1)*per + i
			ra := []string{"-id", strconv.Itoa(rank), "-traffic", traffic.String()}
			if *inbound {
				ra = append(ra, "-listen", strconv.Itoa(rankPortBase+rank))
			}
			if err := j.start(i, append(ra, t.args()...)); err != nil {
				return err
			}
		}
	}
	for _, j := range started {
		if err := j.waitReady(ctx); err != nil {
			return err
		}
	}
	logf("mesh: %d ranks connected", *ranks)
	if *ready != "" {
		if err := os.WriteFile(*ready, nil, 0o644); err != nil {
			return err
		}
	}

	var wg sync.WaitGroup
	if *shortRate > 0 {
		st := t
		st.peers = min(*shortPeers, t.peers)
		every := time.Duration(float64(time.Minute) / *shortRate)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for id := 1000000; ; id++ {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			case <-tick.C:
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				j := &job{root: filepath.Join(*cgroot, fmt.Sprintf("job_%d", id))}
				defer j.stop()
				for i := range *shortRanks {
					ra := append([]string{"-id", strconv.Itoa(i), "-traffic", "1s", "-hold", shortLen.String()}, st.args()...)
					if err := j.start(i, ra); err != nil {
						logf("short job %d: %v", id, err)
						return
					}
				}
				j.wait()
			}()
		}
	}
	<-ctx.Done()
	return nil
}

// job is a job of Slurm: its ranks, each in the cgroup of a task.
type job struct {
	root  string
	cmds  []*exec.Cmd
	ready []*bufio.Reader
	dirs  []string
}

func (j *job) start(task int, args []string) error {
	dir := filepath.Join(j.root, "step_0", "user", fmt.Sprintf("task_%d", task))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	j.dirs = append(j.dirs, dir)
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	cmd := exec.Command("/proc/self/exe", append([]string{"rank"}, args...)...)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd, Pdeathsig: syscall.SIGKILL}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting rank in %s: %w", dir, err)
	}
	j.cmds = append(j.cmds, cmd)
	j.ready = append(j.ready, bufio.NewReader(out))
	return nil
}

// waitReady waits until every rank connected.
func (j *job) waitReady(ctx context.Context) error {
	for i, r := range j.ready {
		done := make(chan error, 1)
		go func() {
			_, err := r.ReadString('\n')
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("rank %d of %s did not connect: %w", i, j.root, err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (j *job) wait() {
	for _, c := range j.cmds {
		c.Wait()
	}
}

// stop kills the ranks and removes the cgroups of the job.
func (j *job) stop() {
	for _, c := range j.cmds {
		if c.ProcessState == nil {
			c.Process.Signal(syscall.SIGTERM)
		}
	}
	j.wait()
	for _, d := range j.dirs {
		for p := d; p != filepath.Dir(j.root); p = filepath.Dir(p) {
			// Fails while other tasks are left under a parent.
			if os.Remove(p) != nil {
				break
			}
		}
	}
}

// runRank is a rank of mesh: it connects to its targets, accepts on its
// port, and writes on its connections every -traffic.
func runRank(args []string) error {
	fs := flag.NewFlagSet("rank", flag.ExitOnError)
	var t targets
	t.flags(fs)
	var (
		id      = fs.Int("id", 0, "rank")
		listen  = fs.Int("listen", 0, "port to accept connections on; 0 none")
		hold    = fs.Duration("hold", 24*time.Hour, "how long the connections are kept")
		traffic = fs.Duration("traffic", 5*time.Second, "how often 8 bytes are written on each connection; 0 never")
		short   = fs.Bool("short", false, "make the connections at every -traffic, write and close them: short connections")
	)
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *hold)
	defer cancel()

	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	if *listen != 0 {
		ln, err := listenBacklog(netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(*listen)))
		if err != nil {
			return err
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}
		}()
	}
	var d net.Dialer
	servers := t.list(*id)
	made := make([]net.Conn, len(servers))
	dial := func() error {
		for i, ap := range servers {
			c, err := dialRetry(ctx, &d, "", ap)
			if err != nil {
				return fmt.Errorf("rank %d: %w", *id, err)
			}
			made[i] = c
		}
		return nil
	}
	closeMade := func() {
		for _, c := range made {
			c.Close()
		}
	}
	if err := dial(); err != nil {
		return err
	}
	if *short {
		closeMade()
	}
	fmt.Println("ready")

	msg := make([]byte, 8)
	var tick <-chan time.Time
	if *traffic > 0 {
		tk := time.NewTicker(*traffic)
		defer tk.Stop()
		tick = tk.C
	}
	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, c := range conns {
				c.Close()
			}
			mu.Unlock()
			closeMade()
			return nil
		case <-tick:
			if *short {
				if err := dial(); err != nil {
					return err
				}
			}
			mu.Lock()
			cs := append(conns[:len(conns):len(conns)], made...)
			mu.Unlock()
			for _, c := range cs {
				c.Write(msg)
			}
			if *short {
				closeMade()
			}
		}
	}
}

// runPeer serves the ports of the ranks of the peer nodes on all addresses,
// reading the connections until they close, and with -in-ranks connects from
// every peer address to every rank of the node.
func runPeer(args []string) error {
	fs := flag.NewFlagSet("peer", flag.ExitOnError)
	var (
		ranks   = fs.Int("peer-ranks", 128, "ranks per peer node: ports 20000 and on are served")
		first   = fs.String("peer-first", "10.98.0.1", "address of the first peer node")
		peers   = fs.Int("peers", 189, "peer nodes, for -in-ranks")
		node    = fs.String("node", "10.97.0.1", "address of the node, for -in-ranks")
		inRanks = fs.Int("in-ranks", 0, "ranks of the node every peer node connects to")
		traffic = fs.Duration("traffic", 5*time.Second, "how often 8 bytes are written on each connection made; 0 never")
		ready   = fs.String("ready", "", "file created once listening, and again (.in) once the connections to the node are made")
	)
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	for j := range *ranks {
		ln, err := listenBacklog(netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(peerPortBase+j)))
		if err != nil {
			return err
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						logf("peer: accepting on %s: %v", ln.Addr(), err)
					}
					return
				}
				// Read until the rank closes, so that the connections of
				// short jobs do not pile up in CLOSE_WAIT.
				go func() {
					io.Copy(io.Discard, c)
					c.Close()
				}()
			}
		}()
	}
	if *ready != "" {
		os.WriteFile(*ready, nil, 0o644)
	}
	var made []net.Conn
	if *inRanks > 0 {
		dst, err := netip.ParseAddr(*node)
		if err != nil {
			return err
		}
		src, err := netip.ParseAddr(*first)
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		var errOnce sync.Once
		var firstErr error
		addrs := peerAddrs(src, *peers)
		made = make([]net.Conn, len(addrs)**inRanks)
		for pi, a := range addrs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 0))}
				for i := range *inRanks {
					c, err := dialRetry(ctx, &d, a.String(), netip.AddrPortFrom(dst, uint16(rankPortBase+i)))
					if err != nil {
						errOnce.Do(func() { firstErr = err })
						return
					}
					made[pi**inRanks+i] = c
				}
			}()
		}
		wg.Wait()
		if firstErr != nil {
			return firstErr
		}
		logf("peer: %d connections to the node", len(made))
		if *ready != "" {
			os.WriteFile(*ready+".in", nil, 0o644)
		}
	}
	msg := make([]byte, 8)
	var tick <-chan time.Time
	if *traffic > 0 && len(made) > 0 {
		tk := time.NewTicker(*traffic)
		defer tk.Stop()
		tick = tk.C
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
			for _, c := range made {
				c.Write(msg)
			}
		}
	}
}

func listenBacklog(ap netip.AddrPort) (net.Listener, error) {
	lc := net.ListenConfig{}
	return lc.Listen(context.Background(), "tcp4", ap.String())
}

// dialRetry connects to ap, retrying for a minute while it refuses, e.g.
// before the rank listens.
func dialRetry(ctx context.Context, d *net.Dialer, src string, ap netip.AddrPort) (net.Conn, error) {
	deadline := time.Now().Add(time.Minute)
	for {
		c, err := d.DialContext(ctx, "tcp4", ap.String())
		if err == nil {
			return c, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil, fmt.Errorf("connecting from %s to %s: %w", src, ap, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
