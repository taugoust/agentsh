//go:build linux

package overlay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	StateActive   = "active"
	StateAccepted = "accepted"
	StateRejected = "rejected"
	StateClosed   = "closed"
)

var ErrInactive = errors.New("overlay workspace is not active")

type Options struct {
	BaseDir     string
	Excludes    []string
	AcceptChown bool
}

type Workspace struct {
	mu sync.Mutex

	ID        string
	Real      string
	Upper     string
	Work      string
	Merged    string
	OwnerUID  int
	OwnerGID  int
	Excludes  []string
	CreatedAt time.Time
	State     string

	acceptChown bool
}

func Create(ctx context.Context, id string, real string, opts Options) (*Workspace, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("session id is required")
	}
	if strings.TrimSpace(real) == "" {
		return nil, fmt.Errorf("workspace is required")
	}
	if strings.TrimSpace(opts.BaseDir) == "" {
		return nil, fmt.Errorf("overlay base dir is required")
	}

	realAbs, err := filepath.Abs(real)
	if err != nil {
		return nil, fmt.Errorf("workspace abs: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(realAbs); err == nil {
		realAbs = resolved
	}
	st, err := os.Stat(realAbs)
	if err != nil {
		return nil, fmt.Errorf("workspace stat: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("workspace must be a directory")
	}

	uid, gid := owner(st)
	baseAbs, err := filepath.Abs(opts.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("overlay base abs: %w", err)
	}
	paths := []string{realAbs, baseAbs}
	for _, p := range paths {
		if strings.Contains(p, ",") {
			return nil, fmt.Errorf("overlay paths containing comma are not supported: %s", p)
		}
	}

	sessionDir := filepath.Join(baseAbs, id)
	upper := filepath.Join(sessionDir, "upper")
	work := filepath.Join(sessionDir, "work")
	merged := filepath.Join(sessionDir, "merged")
	for _, p := range []string{upper, work, merged} {
		if strings.Contains(p, ",") {
			return nil, fmt.Errorf("overlay paths containing comma are not supported: %s", p)
		}
	}

	if err := os.MkdirAll(sessionDir, 0o711); err != nil {
		return nil, fmt.Errorf("create overlay session dir: %w", err)
	}
	if err := os.Chmod(sessionDir, 0o711); err != nil {
		return nil, fmt.Errorf("chmod overlay session dir: %w", err)
	}
	if err := os.MkdirAll(upper, 0o755); err != nil {
		return nil, fmt.Errorf("create upperdir: %w", err)
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}
	if err := os.MkdirAll(merged, 0o755); err != nil {
		return nil, fmt.Errorf("create merged dir: %w", err)
	}
	if err := os.Chown(upper, uid, gid); err != nil {
		return nil, fmt.Errorf("chown upperdir: %w", err)
	}
	if err := os.Chown(merged, uid, gid); err != nil {
		return nil, fmt.Errorf("chown merged dir: %w", err)
	}
	if err := os.Chmod(upper, 0o755); err != nil {
		return nil, fmt.Errorf("chmod upperdir: %w", err)
	}
	if err := os.Chmod(merged, 0o755); err != nil {
		return nil, fmt.Errorf("chmod merged dir: %w", err)
	}
	if err := os.Chmod(work, 0o700); err != nil {
		return nil, fmt.Errorf("chmod workdir: %w", err)
	}

	excludes := cleanExcludes(opts.Excludes)
	if len(excludes) == 0 {
		excludes = []string{".git", ".direnv"}
	}
	if err := materializeUpperDirs(realAbs, upper, uid, gid, excludes); err != nil {
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("materialize upper dirs: %w", err)
	}

	mountOpts := strings.Join([]string{
		"lowerdir=" + realAbs,
		"upperdir=" + upper,
		"workdir=" + work,
	}, ",")
	cmd := exec.CommandContext(ctx, "mount", "-t", "overlay", "overlay", "-o", mountOpts, merged)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("mount overlay: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return &Workspace{
		ID:          id,
		Real:        realAbs,
		Upper:       upper,
		Work:        work,
		Merged:      merged,
		OwnerUID:    uid,
		OwnerGID:    gid,
		Excludes:    excludes,
		CreatedAt:   time.Now().UTC(),
		State:       StateActive,
		acceptChown: opts.AcceptChown,
	}, nil
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return nil, ErrInactive
	}
	args := []string{"-ruN"}
	for _, ex := range w.Excludes {
		args = append(args, "--exclude="+ex)
	}
	args = append(args, w.Real, w.Merged)
	cmd := exec.CommandContext(ctx, "diff", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case 1:
			return out, nil
		case 2:
			// GNU diff uses exit code 2 for trouble. During review of live/virtiofs
			// workspaces a file can disappear while diff is walking both trees; treat
			// that specific race as non-fatal so the user can retry or proceed.
			if strings.Contains(string(out), "No such file or directory") {
				return out, nil
			}
		}
	}
	return out, fmt.Errorf("diff overlay: %w: %s", err, strings.TrimSpace(string(out)))
}

func (w *Workspace) Accept(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return ErrInactive
	}
	args := []string{"-a", "--delete"}
	for _, ex := range w.Excludes {
		args = append(args, "--exclude="+ex)
	}
	if w.acceptChown && w.OwnerUID >= 0 && w.OwnerGID >= 0 {
		args = append(args, "--chown="+strconv.Itoa(w.OwnerUID)+":"+strconv.Itoa(w.OwnerGID))
	}
	args = append(args, withTrailingSeparator(w.Merged), withTrailingSeparator(w.Real))
	cmd := exec.CommandContext(ctx, "rsync", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		var ee *exec.ExitError
		// rsync exit code 24 means files vanished while being transferred. That can
		// happen on live/virtiofs workspaces during accept and is not a failed
		// policy or copy decision; keep accepting the overlay and clean it up.
		if !errors.As(err, &ee) || ee.ExitCode() != 24 {
			return fmt.Errorf("accept overlay: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := w.unmountLocked(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Dir(w.Upper)); err != nil {
		return fmt.Errorf("remove overlay dir: %w", err)
	}
	w.State = StateAccepted
	return nil
}

func (w *Workspace) Reject(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return nil
	}
	if err := w.unmountLocked(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Dir(w.Upper)); err != nil {
		return fmt.Errorf("remove overlay dir: %w", err)
	}
	w.State = StateRejected
	return nil
}

func (w *Workspace) Close(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return nil
	}
	if err := w.unmountLocked(ctx); err != nil {
		return err
	}
	w.State = StateClosed
	return nil
}

func (w *Workspace) unmountLocked(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "umount", w.Merged)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Treat already-unmounted as success when mountpoint says it is not mounted.
		check := exec.CommandContext(ctx, "mountpoint", "-q", w.Merged)
		if check.Run() != nil {
			return nil
		}
		return fmt.Errorf("unmount overlay: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func owner(info fs.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return os.Getuid(), os.Getgid()
}

func materializeUpperDirs(realRoot, upperRoot string, uid, gid int, excludes []string) error {
	excludeSet := make(map[string]struct{}, len(excludes))
	for _, ex := range excludes {
		ex = filepath.Clean(strings.Trim(ex, string(filepath.Separator)))
		if ex != "." && ex != "" {
			excludeSet[ex] = struct{}{}
		}
	}

	return filepath.WalkDir(realRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Live virtiofs workspaces can race with user changes. Skip unreadable or
			// vanished subtrees rather than failing overlay creation for one path.
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(realRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.Clean(rel)
		if shouldSkipUpperDir(rel, excludeSet) {
			return filepath.SkipDir
		}
		mode := fs.FileMode(0o755)
		if info, statErr := d.Info(); statErr == nil {
			mode = info.Mode().Perm()
			if mode == 0 {
				mode = 0o755
			}
		}
		target := filepath.Join(upperRoot, rel)
		if err := os.MkdirAll(target, mode); err != nil {
			return err
		}
		if err := os.Chown(target, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
		return nil
	})
}

func shouldSkipUpperDir(rel string, excludeSet map[string]struct{}) bool {
	for ex := range excludeSet {
		if rel == ex || strings.HasPrefix(rel, ex+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func cleanExcludes(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, ex := range in {
		ex = strings.TrimSpace(ex)
		ex = strings.Trim(ex, string(filepath.Separator))
		if ex == "" {
			continue
		}
		if _, ok := seen[ex]; ok {
			continue
		}
		seen[ex] = struct{}{}
		out = append(out, ex)
	}
	return out
}

func withTrailingSeparator(path string) string {
	sep := string(filepath.Separator)
	if strings.HasSuffix(path, sep) {
		return path
	}
	var b bytes.Buffer
	b.WriteString(path)
	b.WriteString(sep)
	return b.String()
}
