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
	latest map[identityKey]latestIdentity
	// Readers of /proc; replaced in tests.
	exe  func(pid uint32) string
	comm func(pid uint32) string
	env  func(pid uint32) (map[string]string, bool)
	// cgroup reads the path of the cgroup of a process.
	cgroup func(pid uint32) string
	// stuck tells how many reads of environments hang; replaced in tests.
	stuck func() procinfo.EnvironReads
	// budget bounds the time spent reading /proc in an interval.
	budget time.Duration
}

// procReadBudget bounds the time spent reading /proc for the processes of
// an interval, and procReaders how many are read at once. A read of the
// environment of a process can block while the process is stuck; such
// reads time out, and once procinfo.MaxEnvironReads hang no read starts
// (procinfo.OTelEnv). The processes not read in time, and those left when
// the budget is spent, keep their latest identity.
const (
	procReadBudget = time.Second
	procReaders    = 8
)

type procRead struct {
	exe  string
	comm string
	// cgroup is the path of the cgroup of the process when it was read.
	cgroup string
	env    map[string]string
	// complete is false when the environment could not be read in time;
	// noEnv tells that it was not asked for.
	complete, noEnv bool
}

// identityKey keys the latest identities. The processes of a Slurm job are
// keyed by their cgroup too, so that the identity of a process of a job is
// filled in only from its own step: the units of jobs are shared by every
// job of every user (procinfo.SlurmJob).
type identityKey struct {
	unit, comm string
	cgroup     uint64
}

func newIdentityKey(unit, comm string, cgroupID uint64) identityKey {
	k := identityKey{unit: unit, comm: comm}
	if procinfo.SlurmJob(unit) {
		k.cgroup = cgroupID
	}
	return k
}

type latestIdentity struct {
	proc otlp.Process
	at   time.Time
}

func newIdentities(fb procinfo.Fallback, ttl time.Duration) *identities {
	return &identities{
		fallback: fb,
		ttl:      ttl,
		latest:   map[identityKey]latestIdentity{},
		exe:      procinfo.Exe,
		comm:     procinfo.Comm,
		env:      procinfo.OTelEnv,
		cgroup:   procinfo.CgroupOf,
		stuck:    procinfo.StuckEnvironReads,
		budget:   procReadBudget,
	}
}

// beginInterval forgets the reads of the previous interval, since PIDs may
// have been reused.
func (r *identities) beginInterval() { r.byPID = map[uint32]procRead{} }

// procRequest asks for the identity of a process; env tells whether its
// environment names it, which it does not in the cgroup of a Slurm job.
type procRequest struct {
	pid uint32
	env bool
}

// prefetch reads /proc for the processes of an interval, several at once
// and within the budget, so that a few stuck processes do not delay the
// export. Processes not read in time are marked incomplete. The
// environment of a process is read if one of its requests uses it.
func (r *identities) prefetch(reqs []procRequest) {
	var todo []uint32
	env := map[uint32]bool{}
	for _, q := range reqs {
		if _, ok := r.byPID[q.pid]; ok || q.pid == 0 {
			continue
		}
		e, queued := env[q.pid]
		env[q.pid] = e || q.env
		if !queued {
			todo = append(todo, q.pid)
		}
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
				results <- result{pid, r.readNow(pid, env[pid])}
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

// read returns the reads of a process, reading /proc if the interval has
// not, with its environment if env is true.
func (r *identities) read(pid uint32, env bool) procRead {
	if pid == 0 {
		return procRead{complete: true}
	}
	if p, ok := r.byPID[pid]; ok && (!p.noEnv || !env) {
		return p
	}
	p := r.readNow(pid, env)
	r.byPID[pid] = p
	return p
}

// readNow reads the executable, the command name, the cgroup and, if env is
// true, the environment of a process.
func (r *identities) readNow(pid uint32, env bool) procRead {
	p := procRead{exe: r.exe(pid), complete: true}
	if p.exe != "" {
		p.comm = r.comm(pid)
		p.cgroup = r.cgroup(pid)
		if env {
			p.env, p.complete = r.env(pid)
		} else {
			p.noEnv = true
		}
	}
	return p
}

// flowCgroup is the cgroup of a flow or a listener: its id, and its path,
// "" if it is not known.
type flowCgroup struct {
	id   uint64
	path string
}

// resolve returns the identity of the process pid with comm in the cgroup
// cg of unit, which is the unit of the container ctr if it is not nil.
//
// The OTEL_ variables of the processes of Slurm jobs are not read: any user
// could name a job after a service of the cluster, such as slurmctld, so
// they are named after their executable onwards. What /proc tells of a PID
// is not used when the process is now in another cgroup and one of them is
// that of a job: the PID was reused by a process of another job, or the
// process was moved, e.g. by pam_slurm_adopt. When the cgroup of the flow
// is not known, the cgroup the process is in tells whether it is in a job;
// its identity is then not kept, since its unit is not known. A process
// whose cgroup cannot be read is taken as it is.
func (r *identities) resolve(pid uint32, comm string, cg flowCgroup, unit string, ctr *procinfo.Container, now time.Time) otlp.Process {
	k := newIdentityKey(unit, comm, cg.id)
	job := procinfo.SlurmJob(unit)
	keep := true
	p := r.read(pid, !job)
	if p.comm != "" && p.comm != comm {
		// The flow was seen up to an interval ago; the PID now belongs to
		// another process (the tracer reports the command name of the main
		// thread, as /proc/PID/comm does).
		p = procRead{}
	}
	if p.exe != "" && p.cgroup != "" {
		inJob := procinfo.SlurmJob(procinfo.Unit(p.cgroup))
		switch {
		case cg.path == "" && inJob:
			job, keep = true, false
		case cg.path != "" && p.cgroup != cg.path && (job || inJob):
			p = procRead{}
		}
	}
	if job {
		// The environment is not used, whether or not it was read.
		p.env, p.complete = nil, true
	}
	if keep && (p.exe == "" || !p.complete) {
		if l, ok := r.latest[k]; ok {
			l.at = now
			r.latest[k] = l
			// The unit is shared by the replicas of a container and by the
			// containers that replace it; the container is that of the
			// cgroup of the flow.
			proc := l.proc
			proc.ContainerID = ""
			if ctr != nil {
				proc.ContainerID = ctr.ID
			}
			return proc
		}
	}
	svc := procinfo.ServiceName(p.env, p.exe, comm, unit, ctr.Workload(), r.fallback)
	proc := otlp.Process{Unit: unit, Comm: comm, Exe: p.exe, Service: svc.Name, ServiceNamespace: svc.Namespace}
	if ctr != nil {
		proc.ContainerID = ctr.ID
	}
	if keep && p.exe != "" && p.complete {
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
