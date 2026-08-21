//go:build linux

package leakcheck

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func prepareResourceTracking() error {
	// The Go runtime creates its process-lifetime epoll and event descriptors
	// lazily. Initialize them before the baseline so subsequent count changes
	// represent descriptors owned by the package under test.
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		return fmt.Errorf("initialize runtime network poller: %w", err)
	}
	return listener.Close()
}

type resourceSnapshot struct {
	fileDescriptors map[string]int
	children        map[int]struct{}
	mounts          map[string]int
}

func snapshotResources() (resourceSnapshot, error) {
	fds, err := snapshotFileDescriptors()
	if err != nil {
		return resourceSnapshot{}, err
	}
	children, err := snapshotChildren()
	if err != nil {
		return resourceSnapshot{}, err
	}
	mounts, err := snapshotMounts()
	if err != nil {
		return resourceSnapshot{}, err
	}
	return resourceSnapshot{fileDescriptors: fds, children: children, mounts: mounts}, nil
}

func snapshotFileDescriptors() (map[string]int, error) {
	fdRoot := filepath.Join(string(filepath.Separator), "proc", "self", "fd")
	entries, err := os.ReadDir(fdRoot)
	if err != nil {
		return nil, fmt.Errorf("read file descriptors: %w", err)
	}
	result := make(map[string]int, len(entries))
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdRoot, entry.Name()))
		if err != nil {
			// The directory descriptor used by os.ReadDir can disappear before
			// Readlink observes it; all other failures are meaningful.
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read file descriptor %s: %w", entry.Name(), err)
		}
		result[target]++
	}
	return result, nil
}

func snapshotChildren() (map[int]struct{}, error) {
	taskRoot := filepath.Join(string(filepath.Separator), "proc", "self", "task")
	tasks, err := os.ReadDir(taskRoot)
	if err != nil {
		return nil, fmt.Errorf("read process tasks: %w", err)
	}
	result := make(map[int]struct{})
	for _, task := range tasks {
		contents, err := os.ReadFile(filepath.Join(taskRoot, task.Name(), "children"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read children for task %s: %w", task.Name(), err)
		}
		for _, field := range strings.Fields(string(contents)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("parse child pid %q: %w", field, err)
			}
			result[pid] = struct{}{}
		}
	}
	return result, nil
}

func snapshotMounts() (map[string]int, error) {
	contents, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "self", "mountinfo"))
	if err != nil {
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}
	result := make(map[string]int)
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			result[fields[4]]++
		}
	}
	return result, nil
}

func diffResources(baseline, current resourceSnapshot) []string {
	var leaked []string
	for target, count := range current.fileDescriptors {
		for extra := count - baseline.fileDescriptors[target]; extra > 0; extra-- {
			leaked = append(leaked, "file descriptor: "+target)
		}
	}
	for pid := range current.children {
		if _, existed := baseline.children[pid]; !existed {
			leaked = append(leaked, fmt.Sprintf("child process: pid %d", pid))
		}
	}
	for mount, count := range current.mounts {
		for extra := count - baseline.mounts[mount]; extra > 0; extra-- {
			leaked = append(leaked, "mount: "+mount)
		}
	}
	return leaked
}
