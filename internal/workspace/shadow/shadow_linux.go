//go:build linux

package shadow

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

var ErrInactive = errors.New("shadow workspace is not active")

type Options struct {
	BaseDir        string
	DiffExcludes   []string
	AcceptExcludes []string
	AcceptChown    bool
}

type Workspace struct {
	mu sync.Mutex

	ID        string
	Real      string
	Work      string
	OwnerUID  int
	OwnerGID  int
	CreatedAt time.Time
	State     string

	diffExcludes   []string
	acceptExcludes []string
	acceptChown    bool
}

func Create(ctx context.Context, id string, real string, opts Options) (*Workspace, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("session id is required")
	}
	if strings.TrimSpace(real) == "" {
		return nil, fmt.Errorf("workspace is required")
	}
	if strings.TrimSpace(opts.BaseDir) == "" {
		return nil, fmt.Errorf("shadow base dir is required")
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
		return nil, fmt.Errorf("shadow base abs: %w", err)
	}
	sessionDir := filepath.Join(baseAbs, id)
	work := filepath.Join(sessionDir, "work")
	for _, p := range []string{realAbs, baseAbs, work} {
		if strings.Contains(p, ",") {
			return nil, fmt.Errorf("shadow paths containing comma are not supported: %s", p)
		}
	}
	if err := os.RemoveAll(sessionDir); err != nil {
		return nil, fmt.Errorf("remove old shadow dir: %w", err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, fmt.Errorf("create shadow workdir: %w", err)
	}
	if err := os.Chown(work, uid, gid); err != nil {
		return nil, fmt.Errorf("chown shadow workdir: %w", err)
	}

	excludes := cleanExcludes(opts.DiffExcludes)
	if len(excludes) == 0 {
		excludes = []string{".git", ".direnv"}
	}
	acceptExcludes := cleanExcludes(opts.AcceptExcludes)
	if len(acceptExcludes) == 0 {
		acceptExcludes = []string{".git", ".direnv"}
	}

	args := []string{"-a", "--delete", "--chown=" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid)}
	args = append(args, withTrailingSeparator(realAbs), withTrailingSeparator(work))
	cmd := exec.CommandContext(ctx, "rsync", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("copy shadow workspace: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return &Workspace{
		ID:             id,
		Real:           realAbs,
		Work:           work,
		OwnerUID:       uid,
		OwnerGID:       gid,
		CreatedAt:      time.Now().UTC(),
		State:          StateActive,
		diffExcludes:   excludes,
		acceptExcludes: acceptExcludes,
		acceptChown:    opts.AcceptChown,
	}, nil
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return nil, ErrInactive
	}
	args := []string{"-ruN"}
	for _, ex := range w.diffExcludes {
		args = append(args, "--exclude="+ex)
	}
	args = append(args, w.Real, w.Work)
	cmd := exec.CommandContext(ctx, "diff", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return out, nil
	}
	return out, fmt.Errorf("diff shadow workspace: %w: %s", err, strings.TrimSpace(string(out)))
}

func (w *Workspace) Accept(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return ErrInactive
	}
	args := []string{"-a", "--delete"}
	for _, ex := range w.acceptExcludes {
		args = append(args, "--exclude="+ex)
	}
	if w.acceptChown && w.OwnerUID >= 0 && w.OwnerGID >= 0 {
		args = append(args, "--chown="+strconv.Itoa(w.OwnerUID)+":"+strconv.Itoa(w.OwnerGID))
	}
	args = append(args, withTrailingSeparator(w.Work), withTrailingSeparator(w.Real))
	cmd := exec.CommandContext(ctx, "rsync", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 24 {
			return fmt.Errorf("accept shadow workspace: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := os.RemoveAll(filepath.Dir(w.Work)); err != nil {
		return fmt.Errorf("remove shadow dir: %w", err)
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
	if err := os.RemoveAll(filepath.Dir(w.Work)); err != nil {
		return fmt.Errorf("remove shadow dir: %w", err)
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
	w.State = StateClosed
	return nil
}

func owner(info fs.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return os.Getuid(), os.Getgid()
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
