package agent

import (
	"sync"
	"time"

	"github.com/yuuki/shawk/internal/otlp"
	"github.com/yuuki/shawk/internal/procinfo"
)

// identities resolves the process identity of flows and listeners: the
// executable and the service name, which are read from /proc.
type identities struct {
	fallback procinfo.Fallback
	ttl      time.Duration
	// Reads of /proc in the current interval, by PID.
	byPID map[uint32]procRead
	// The latest identity of each unit and comm, for flows whose process
	// exited before it could be read, such as short-lived batch jobs.
	latest map[unitComm]latestIdentity
	// Readers of /proc; replaced in tests.
	exe  func(pid uint32) string
	comm func(pid uint32) string
	env  func(pid uint32) (map[string]string, bool)
	// budget bounds the time spent reading /proc in an interval.
	budget time.Duration
}

// procReadBudget bounds the time spent reading /proc for the processes of
// an interval, and procReaders how many are read at once. A read of the
// environment of a process can block while the process is stuck; such
// reads time out (procinfo.OTelEnv), and the processes left when the
// budget is spent keep their latest identity.
const (
	procReadBudget = time.Second
	procReaders    = 8
)

type procRead struct {
	exe  string
	comm string
	env  map[string]string
	// complete is false when the environment could not be read in time.
	complete bool
}

type unitComm struct{ unit, comm string }

type latestIdentity struct {
	proc otlp.Process
	at   time.Time
}

func newIdentities(fb procinfo.Fallback, ttl time.Duration) *identities {
	return &identities{
		fallback: fb,
		ttl:      ttl,
		latest:   map[unitComm]latestIdentity{},
		exe:      procinfo.Exe,
		comm:     procinfo.Comm,
		env:      procinfo.OTelEnv,
		budget:   procReadBudget,
	}
}

// beginInterval forgets the reads of the previous interval, since PIDs may
// have been reused.
func (r *identities) beginInterval() { r.byPID = map[uint32]procRead{} }

// prefetch reads /proc for the processes of an interval, several at once
// and within the budget, so that a few stuck processes do not delay the
// export. Processes not read in time are marked incomplete.
func (r *identities) prefetch(pids []uint32) {
	var todo []uint32
	queued := map[uint32]bool{}
	for _, pid := range pids {
		if _, ok := r.byPID[pid]; ok || pid == 0 || queued[pid] {
			continue
		}
		queued[pid] = true
		todo = append(todo, pid)
	}
	if len(todo) == 0 {
		return
	}
	type result struct {
		pid uint32
		p   procRead
	}
	// Buffered, so that readers still running after the budget never block.
	results := make(chan result, len(todo))
	jobs := make(chan uint32)
	stop := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(stop) })
	go func() {
		defer close(jobs)
		for _, pid := range todo {
			select {
			case jobs <- pid:
			case <-stop:
				return
			}
		}
	}()
	for range min(procReaders, len(todo)) {
		go func() {
			for pid := range jobs {
				results <- result{pid, r.readNow(pid)}
			}
		}()
	}
	deadline := time.NewTimer(r.budget)
	defer deadline.Stop()
	for range todo {
		select {
		case res := <-results:
			r.byPID[res.pid] = res.p
		case <-deadline.C:
			once.Do(func() { close(stop) })
			for _, pid := range todo {
				if _, ok := r.byPID[pid]; !ok {
					r.byPID[pid] = procRead{}
				}
			}
			return
		}
	}
}

func (r *identities) read(pid uint32) procRead {
	if pid == 0 {
		return procRead{complete: true}
	}
	if p, ok := r.byPID[pid]; ok {
		return p
	}
	p := r.readNow(pid)
	r.byPID[pid] = p
	return p
}

// readNow reads the executable, the command name and the environment of a
// process.
func (r *identities) readNow(pid uint32) procRead {
	p := procRead{exe: r.exe(pid), complete: true}
	if p.exe != "" {
		p.comm = r.comm(pid)
		p.env, p.complete = r.env(pid)
	}
	return p
}

// resolve returns the identity of the process pid with comm in unit.
func (r *identities) resolve(pid uint32, comm, unit string, now time.Time) otlp.Process {
	k := unitComm{unit, comm}
	p := r.read(pid)
	if p.comm != "" && p.comm != comm {
		// The flow was seen up to an interval ago; the PID now belongs to
		// another process (the tracer reports the command name of the main
		// thread, as /proc/PID/comm does).
		p = procRead{}
	}
	if p.exe == "" || !p.complete {
		if l, ok := r.latest[k]; ok {
			l.at = now
			r.latest[k] = l
			return l.proc
		}
	}
	svc := procinfo.ServiceName(p.env, p.exe, comm, unit, r.fallback)
	proc := otlp.Process{Unit: unit, Comm: comm, Exe: p.exe, Service: svc.Name, ServiceNamespace: svc.Namespace}
	if p.exe != "" && p.complete {
		r.latest[k] = latestIdentity{proc: proc, at: now}
	}
	return proc
}

// expire forgets identities not used for the TTL.
func (r *identities) expire(now time.Time) {
	for k, l := range r.latest {
		if now.Sub(l.at) > r.ttl {
			delete(r.latest, k)
		}
	}
}
