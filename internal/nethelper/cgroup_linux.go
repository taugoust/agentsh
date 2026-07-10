//go:build linux

package nethelper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type kernelCgroupResolver struct{}

func defaultCgroupResolver() CgroupResolver { return kernelCgroupResolver{} }

func (kernelCgroupResolver) CgroupPathForPID(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("pid must be positive")
	}
	path := filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "cgroup")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		// Unified cgroup v2 format is "0::/path". Ignore legacy v1 lines.
		if parts[0] != "0" || parts[1] != "" {
			continue
		}
		rel := strings.TrimSpace(parts[2])
		if rel == "" || rel == string(filepath.Separator) {
			return cgroupV2Root(), nil
		}
		return filepath.Join(cgroupV2Root(), strings.TrimPrefix(rel, string(filepath.Separator))), nil
	}
	return "", fmt.Errorf("unified cgroup v2 entry not found in %s", path)
}

func (kernelCgroupResolver) CanonicalCgroupPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("cgroup path is empty")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("cgroup path must be absolute for kernel authorization")
	}
	cleaned := filepath.Clean(path)
	root := cgroupV2Root()
	if !pathInSubtree(root, cleaned, true) {
		return "", fmt.Errorf("cgroup path %s is outside %s", cleaned, root)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve cgroup path %s: %w", cleaned, err)
	}
	resolved = filepath.Clean(resolved)
	if !pathInSubtree(root, resolved, true) {
		return "", fmt.Errorf("cgroup path %s is outside %s", resolved, root)
	}
	if resolved != cleaned {
		return "", fmt.Errorf("cgroup path %s must not contain symlink components", cleaned)
	}
	var statfs unix.Statfs_t
	if err := unix.Statfs(resolved, &statfs); err != nil {
		return "", fmt.Errorf("inspect cgroup filesystem for %s: %w", resolved, err)
	}
	if uint64(statfs.Type) != uint64(unix.CGROUP2_SUPER_MAGIC) {
		return "", fmt.Errorf("cgroup path %s is not on the unified cgroup v2 filesystem", resolved)
	}
	return resolved, nil
}

func (r kernelCgroupResolver) SameCgroupPath(a, b string) (bool, error) {
	ca, err := r.CanonicalCgroupPath(a)
	if err != nil {
		return false, err
	}
	cb, err := r.CanonicalCgroupPath(b)
	if err != nil {
		return false, err
	}
	ai, err := os.Stat(ca)
	if err != nil {
		return false, fmt.Errorf("stat cgroup %s: %w", ca, err)
	}
	bi, err := os.Stat(cb)
	if err != nil {
		return false, fmt.Errorf("stat cgroup %s: %w", cb, err)
	}
	return os.SameFile(ai, bi), nil
}

func (r kernelCgroupResolver) CgroupPathContains(parent, child string) (bool, error) {
	cp, err := r.CanonicalCgroupPath(parent)
	if err != nil {
		return false, err
	}
	cc, err := r.CanonicalCgroupPath(child)
	if err != nil {
		return false, err
	}
	return pathInSubtree(cp, cc, false), nil
}

func (r kernelCgroupResolver) CgroupID(path string) (uint64, error) {
	canonical, err := r.CanonicalCgroupPath(path)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", canonical, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Ino == 0 {
		return 0, fmt.Errorf("cgroup id is unavailable for %s", canonical)
	}
	return stat.Ino, nil
}

func (r kernelCgroupResolver) CgroupPopulated(path string) (bool, error) {
	canonical, err := r.CanonicalCgroupPath(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	eventsPath := filepath.Join(canonical, "cgroup.events")
	data, err := os.ReadFile(eventsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", eventsPath, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			switch fields[1] {
			case "0":
				return false, nil
			case "1":
				return true, nil
			default:
				return false, fmt.Errorf("invalid populated value %q in %s", fields[1], eventsPath)
			}
		}
	}
	return false, fmt.Errorf("populated field is missing from %s", eventsPath)
}

func cgroupV2Root() string {
	return filepath.Join(string(filepath.Separator), "sys", "fs", "cgroup")
}
