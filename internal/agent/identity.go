package agent

import (
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
	exe func(pid uint32) string
	env func(pid uint32) map[string]string
}

type procRead struct {
	exe string
	env map[string]string
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
		env:      procinfo.OTelEnv,
	}
}

// beginInterval forgets the reads of the previous interval, since PIDs may
// have been reused.
func (r *identities) beginInterval() { r.byPID = map[uint32]procRead{} }

func (r *identities) read(pid uint32) procRead {
	if pid == 0 {
		return procRead{}
	}
	if p, ok := r.byPID[pid]; ok {
		return p
	}
	p := procRead{exe: r.exe(pid)}
	if p.exe != "" {
		p.env = r.env(pid)
	}
	r.byPID[pid] = p
	return p
}

// resolve returns the identity of the process pid with comm in unit.
func (r *identities) resolve(pid uint32, comm, unit string, now time.Time) otlp.Process {
	k := unitComm{unit, comm}
	p := r.read(pid)
	if p.exe == "" {
		if l, ok := r.latest[k]; ok {
			l.at = now
			r.latest[k] = l
			return l.proc
		}
	}
	svc := procinfo.ServiceName(p.env, p.exe, comm, unit, r.fallback)
	proc := otlp.Process{Unit: unit, Comm: comm, Exe: p.exe, Service: svc.Name, ServiceNamespace: svc.Namespace}
	if p.exe != "" {
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
