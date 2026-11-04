package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// watchOut is what watch prints for a window.
type watchOut struct {
	Label  string  `json:"label,omitempty"`
	Window int     `json:"window"`
	CPU    float64 `json:"cpu_ms"`     // CPU time of the process in the window, in ticks of 10 ms
	Busy   float64 `json:"busy_ms"`    // wall time of its bursts of activity
	Burst  float64 `json:"longest_ms"` // the longest burst
	Bursts int     `json:"bursts"`
	RSS    float64 `json:"rss_mib"` // the largest VmRSS sampled
	HWM    float64 `json:"hwm_mib"` // VmHWM at the end of the window
}

// runWatch samples a process and prints it per window of fixed length: its
// CPU time from /proc/PID/stat (which keeps that of the threads that
// exited, in ticks of the clock), and its bursts of activity, found from the
// run time of its threads in their schedstat (in nanoseconds). A burst is a
// run of samples in which the process ran, with pauses shorter than -gap:
// the collection and export of an interval of the agent, or a write of the
// connector. A burst that spans the end of a window is split there.
func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	var (
		pid    = fs.Int("pid", 0, "process")
		every  = fs.Duration("every", 5*time.Millisecond, "sampling period")
		window = fs.Duration("window", 15*time.Second, "window of an output line")
		gap    = fs.Duration("gap", 100*time.Millisecond, "longest pause within a burst")
		count  = fs.Int("count", 8, "windows")
		label  = fs.String("label", "", "label of the output lines")
	)
	fs.Parse(args)
	if *pid == 0 {
		return fmt.Errorf("-pid is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	tick := time.NewTicker(*every)
	defer tick.Stop()

	var (
		o                 = watchOut{Label: *label}
		end               = time.Now().Add(*window)
		run, _            = procCPU(*pid)
		total, _          = procTotal(*pid)
		lastT             = time.Now()
		burstStart, ranAt time.Time
	)
	closeBurst := func(at time.Time) {
		if !burstStart.IsZero() {
			d := at.Sub(burstStart)
			o.Busy += ms(d)
			o.Burst = max(o.Burst, ms(d))
			o.Bursts++
			burstStart = time.Time{}
		}
	}
	for o.Window < *count {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		now := time.Now()
		r, err := procCPU(*pid)
		if err != nil {
			return err
		}
		// A thread that exited takes its run time with it: the sum may
		// fall, which is not activity.
		if r > run {
			if burstStart.IsZero() || now.Sub(ranAt) > *gap {
				closeBurst(ranAt)
				burstStart = lastT
			}
			ranAt = now
		}
		run, lastT = r, now
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", *pid)); err == nil {
			o.RSS = max(o.RSS, statusKiB(b, "VmRSS:")/1024)
			o.HWM = statusKiB(b, "VmHWM:") / 1024
		}
		if now.After(end) {
			if !burstStart.IsZero() && now.Sub(ranAt) <= *gap {
				// Split the burst at the end of the window.
				closeBurst(now)
				burstStart = now
			} else {
				closeBurst(ranAt)
			}
			t, err := procTotal(*pid)
			if err != nil {
				return err
			}
			o.CPU = ms(t - total)
			total = t
			emit(o)
			o = watchOut{Label: *label, Window: o.Window + 1}
			end = end.Add(*window)
		}
	}
	return nil
}

// procTotal reads the user and system time of a process, including its
// threads that exited, from /proc/PID/stat.
func procTotal(pid int) (time.Duration, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("process %d is gone", pid)
	}
	// The command, in parentheses, may hold spaces.
	f := bytes.Fields(b[bytes.LastIndexByte(b, ')')+1:])
	if len(f) < 13 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat", pid)
	}
	// utime and stime are fields 14 and 15, the 12th and 13th after the
	// command, in ticks of 100 Hz (USER_HZ).
	u, _ := strconv.ParseInt(string(f[11]), 10, 64)
	s, _ := strconv.ParseInt(string(f[12]), 10, 64)
	return time.Duration(u+s) * 10 * time.Millisecond, nil
}

// procCPU sums the run time of the threads of a process.
func procCPU(pid int) (time.Duration, error) {
	paths, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/schedstat", pid))
	if err != nil || len(paths) == 0 {
		return 0, fmt.Errorf("process %d is gone", pid)
	}
	var sum time.Duration
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue // the thread exited
		}
		f := bytes.Fields(b)
		if len(f) > 0 {
			n, _ := strconv.ParseInt(string(f[0]), 10, 64)
			sum += time.Duration(n)
		}
	}
	return sum, nil
}

// statusKiB returns a field of /proc/PID/status in KiB.
func statusKiB(b []byte, field string) float64 {
	i := bytes.Index(b, []byte(field))
	if i < 0 {
		return 0
	}
	f := bytes.Fields(b[i+len(field):])
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(string(f[0]), 64)
	return n
}
