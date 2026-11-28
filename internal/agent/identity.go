package agent

import (
	"strings"
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
	// Readers of /proc; replaced in tests. open opens the directory of a
	// process, through which its executable, command name and cgroup are
	// read.
	open func(pid uint32) (procDir, bool)
	env  func(pid uint32) (map[string]string, bool)
	// users reads the user id of a process and the cgroup it is in, which
	// the processes of Slurm jobs carry; nil reads none.
	users func(pid uint32) (uid uint32, cgroupID uint64, ok bool)
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

// procDir is the directory of a process in /proc, opened once
// (procinfo.Proc): what is read through it is of that process, and the reads
// fail once it has exited, rather than read a process that took its PID.
type procDir interface {
	Exe() string
	Comm() (string, bool)
	Cgroup() (string, bool)
	Close() error
}

// openProc opens the directory of a process in /proc, or returns false if
// the process is gone.
func openProc(pid uint32) (procDir, bool) {
	p, err := procinfo.OpenProc(pid)
	if err != nil {
		return nil, false
	}
	return p, true
}

type procRead struct {
	exe  string
	comm string
	// cgroup is the path of the cgroup of the process when it was read, and
	// job tells that it is the cgroup of a Slurm job.
	cgroup string
	job    bool
	env    map[string]string
	// uid is the effective user id if hasUID, read with uidCgroup, the
	// cgroup the process was in.
	uid       uint32
	uidCgroup uint64
	hasUID    bool
	// complete is false when the environment could not be read in time;
	// noEnv tells that it was not read.
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

// newIdentities returns a resolver of identities; users reads the user ids
// of the processes of Slurm jobs, nil none.
func newIdentities(fb procinfo.Fallback, ttl time.Duration, users func(uint32) (uint32, uint64, bool)) *identities {
	return &identities{
		fallback: fb,
		ttl:      ttl,
		users:    users,
		latest:   map[identityKey]latestIdentity{},
		open:     openProc,
		env:      procinfo.OTelEnv,
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
	todo, env := r.unread(reqs)
	if len(todo) == 0 {
		return
	}
	results, stop := r.startReaders(todo, env)
	defer stop()
	deadline := time.NewTimer(r.budget)
	defer deadline.Stop()
	for range todo {
		select {
		case res := <-results:
			r.byPID[res.pid] = res.p
		case <-deadline.C:
			for _, pid := range todo {
				if _, ok := r.byPID[pid]; !ok {
					r.byPID[pid] = procRead{}
				}
			}
			return
		}
	}
}

// unread returns the processes of the requests that the interval has not
// read, each once, and whether a request of each uses its environment.
func (r *identities) unread(reqs []procRequest) (todo []uint32, env map[uint32]bool) {
	env = map[uint32]bool{}
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
	return todo, env
}

// pidRead is what a reader read of a process.
type pidRead struct {
	pid uint32
	p   procRead
}

// startReaders starts the readers of /proc, at most procReaders, which read
// the processes of todo, with the environment of those env tells, and send
// what they read. stop keeps them from starting to read the processes left;
// a read that hangs goes on.
func (r *identities) startReaders(todo []uint32, env map[uint32]bool) (results <-chan pidRead, stop func()) {
	// Buffered, so that readers still running after the budget never block.
	out := make(chan pidRead, len(todo))
	jobs := make(chan uint32)
	stopped := make(chan struct{})
	go func() {
		defer close(jobs)
		for _, pid := range todo {
			select {
			case jobs <- pid:
			case <-stopped:
				return
			}
		}
	}()
	for range min(procReaders, len(todo)) {
		go func() {
			for pid := range jobs {
				out <- pidRead{pid, r.readNow(pid, env[pid])}
			}
		}()
	}
	return out, func() { close(stopped) }
}

// read returns the reads of a process, reading /proc if the interval has
// not, with its environment if env is true and the process is not in a job.
func (r *identities) read(pid uint32, env bool) procRead {
	if pid == 0 {
		return procRead{complete: true}
	}
	if p, ok := r.byPID[pid]; ok && (!p.noEnv || !env || p.job) {
		return p
	}
	p := r.readNow(pid, env)
	r.byPID[pid] = p
	return p
}

// readNow reads the executable, the command name, the cgroup and, if env is
// true, the environment of a process. The first three are read through one
// open /proc/PID, so that they are of one process; a process that exited
// before all were read is taken as one that exited before it was read. The
// environment of a process in the cgroup of a Slurm job is not read,
// whatever the cgroup of its flow: it names nothing, and its read could hang
// on a parallel file system and hold a slot of the reads of the other
// processes. The environment is read by its path, so a process that exited,
// executed another executable or changed its cgroup while it was read, as
// when its PID was reused, is incomplete.
//
// If users are read, so are the user id of the process and its cgroup,
// whether or not the environment is: a process that pam_slurm_adopt moved
// into a job is asked for with its environment for the sockets it opened
// before, and carries its user on the flows of the cgroup it is in now.
func (r *identities) readNow(pid uint32, env bool) procRead {
	p := procRead{complete: true}
	d, ok := r.open(pid)
	if !ok {
		return p
	}
	defer d.Close()
	exe := d.Exe()
	if exe == "" {
		return p
	}
	comm, okComm := d.Comm()
	cgroup, okCgroup := d.Cgroup()
	if !okComm || !okCgroup {
		// The process exited after its executable was read: the executable
		// cannot be checked against the flow.
		return p
	}
	p.exe, p.comm, p.cgroup = exe, comm, cgroup
	p.job = procinfo.SlurmJob(procinfo.Unit(p.cgroup))
	if env && !p.job {
		p.env, p.complete = r.env(pid)
		if p.complete {
			if cg, ok := d.Cgroup(); !ok || cg != p.cgroup || d.Exe() != p.exe {
				p.env, p.complete = nil, false
			}
		}
	} else {
		p.noEnv = true
	}
	if r.users != nil {
		p.uid, p.uidCgroup, p.hasUID = r.users(pid)
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
// process was moved, e.g. by pam_slurm_adopt. The cgroup of a flow whose
// path is not known is learned from its process when the process is still
// in it (Agent.process); otherwise a process now in a job is not taken for
// the process of the flow, nor is its latest identity, since the unit of
// the flow is not known. A process whose cgroup is not in the hierarchy of
// the agent (cgroup v1, another cgroup namespace) is taken as it is.
//
// With users, a process of a Slurm job carries its user id as read in this
// interval, if it was read in the cgroup of the flow: the user id and the
// cgroup are read together, after the checks above, and a process of
// another job with the same comm may take the PID in between. A user id
// that could not be read is unknown: it is never taken from the latest
// identity, which the processes of the step share.
func (r *identities) resolve(pid uint32, comm string, cg flowCgroup, unit string, ctr *procinfo.Container, now time.Time) otlp.Process {
	k := newIdentityKey(unit, comm, cg.id)
	job := procinfo.SlurmJob(unit)
	keep := true
	p := r.read(pid, !job)
	switch {
	case p.exe == "" || p.comm == comm:
		// Nothing was read of the process, or it has the command name of
		// the flow: an executable is used only with the command name read
		// with it.
	case systemdChild(comm, p.comm):
		// The child that systemd forked for a service, which connected the
		// standard output of the service to journald, executed it: the
		// flow is the service's.
		comm = p.comm
	default:
		// The flow was seen up to an interval ago; the PID now belongs to
		// another process (the tracer reports the command name of the main
		// thread, as /proc/PID/comm does).
		p = procRead{}
	}
	if p.exe != "" && p.cgroup != "" {
		switch {
		case cg.path == "" && p.job:
			// The process is in a job, and not in the cgroup of the flow
			// (Agent.process): another process of a job took the PID, or
			// the process was moved into a job.
			p, keep = procRead{}, false
		case cg.path != "" && p.cgroup != cg.path && (job || p.job):
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
			r.setUser(&proc, p, cg.id)
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
	r.setUser(&proc, p, cg.id)
	return proc
}

// systemdChild reports whether a flow of comm was opened by the child that
// systemd forks to execute a service, and which now runs procComm: systemd
// names the child after the executable in parentheses, "(cron)", until it
// executes it, and connects the standard output of the service to journald
// before. Command names are cut to 15 bytes, the closing parenthesis first.
func systemdChild(comm, procComm string) bool {
	name, ok := strings.CutPrefix(comm, "(")
	name = strings.TrimSuffix(name, ")")
	return ok && name != "" && strings.HasPrefix(procComm, name)
}

// setUser sets the user id of a process of a Slurm job in the cgroup
// cgroupID to the one read, if it was read in that cgroup.
func (r *identities) setUser(proc *otlp.Process, p procRead, cgroupID uint64) {
	proc.UserID, proc.HasUserID = 0, false
	if p.hasUID && p.uidCgroup == cgroupID && cgroupID != 0 && procinfo.SlurmJob(proc.Unit) {
		proc.UserID, proc.HasUserID = p.uid, true
	}
}

// expire forgets identities not used for the TTL.
func (r *identities) expire(now time.Time) {
	for k, l := range r.latest {
		if now.Sub(l.at) > r.ttl {
			delete(r.latest, k)
		}
	}
}
