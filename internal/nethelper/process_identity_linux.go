//go:build linux

package nethelper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// processIdentity binds a numeric PID to one Linux process lifetime. A pidfd is
// retained when supported. The /proc start-time check remains mandatory so the
// fallback on older or restricted kernels is still safe against PID reuse.
type processIdentity struct {
	pid       int
	startTime uint64
	pidfd     int
}

func openProcessIdentity(pid int) (*processIdentity, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("pid must be positive")
	}
	before, err := procStartTime(pid)
	if err != nil {
		return nil, err
	}
	pidfd, pidfdErr := unix.PidfdOpen(pid, 0)
	if pidfdErr == nil {
		unix.CloseOnExec(pidfd)
	} else if errors.Is(pidfdErr, unix.ESRCH) {
		return nil, fmt.Errorf("process %d exited while capturing identity: %w", pid, pidfdErr)
	} else {
		// pidfd_open may be unavailable or denied by an older/restricted kernel.
		// PID plus /proc start time is the supported fail-closed fallback.
		pidfd = -1
	}
	after, err := procStartTime(pid)
	if err != nil {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return nil, err
	}
	if before != after {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return nil, fmt.Errorf("process %d identity changed while being captured", pid)
	}
	return &processIdentity{pid: pid, startTime: before, pidfd: pidfd}, nil
}

func (p *processIdentity) clone() (*processIdentity, error) {
	if p == nil || p.pid <= 0 || p.startTime == 0 {
		return nil, fmt.Errorf("process identity is unavailable")
	}
	out := &processIdentity{pid: p.pid, startTime: p.startTime, pidfd: -1}
	if p.pidfd >= 0 {
		fd, err := unix.Dup(p.pidfd)
		if err != nil {
			return nil, fmt.Errorf("duplicate pidfd: %w", err)
		}
		unix.CloseOnExec(fd)
		out.pidfd = fd
	}
	if err := out.validate(); err != nil {
		out.close()
		return nil, err
	}
	return out, nil
}

func (p *processIdentity) validate() error {
	if p == nil || p.pid <= 0 || p.startTime == 0 {
		return fmt.Errorf("stable process identity is unavailable")
	}
	if p.pidfd >= 0 {
		fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 0)
		if err != nil {
			return fmt.Errorf("poll pidfd: %w", err)
		}
		if n != 0 || fds[0].Revents != 0 {
			return fmt.Errorf("registered supervisor process has exited")
		}
	}
	got, err := procStartTime(p.pid)
	if err != nil {
		return fmt.Errorf("revalidate process start time: %w", err)
	}
	if got != p.startTime {
		return fmt.Errorf("registered supervisor pid was reused")
	}
	return nil
}

func (p *processIdentity) alive() bool {
	return p != nil && p.validate() == nil
}

func (p *processIdentity) close() {
	if p != nil && p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
		p.pidfd = -1
	}
}

func procStartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("pid must be positive")
	}
	path := filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	// comm is parenthesized and may itself contain spaces or ')'. Fields after
	// the final ')' begin with field 3 (state); starttime is field 22, index 19.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+1 >= len(data) {
		return 0, fmt.Errorf("malformed %s", path)
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("start time is missing from %s", path)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse start time from %s: %w", path, err)
	}
	if start == 0 {
		return 0, fmt.Errorf("start time in %s is zero", path)
	}
	return start, nil
}
