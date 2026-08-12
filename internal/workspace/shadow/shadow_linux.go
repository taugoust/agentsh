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

	"github.com/agentsh/agentsh/internal/workspace/cleanup"
	"github.com/agentsh/agentsh/internal/workspace/runtimebin"
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

type RootSpec struct {
	Name string
	Path string
}

type Root struct {
	Name string
	Real string
	Work string
}

type Workspace struct {
	mu sync.Mutex

	ID        string
	Real      string
	Work      string
	Home      string
	Tmp       string
	Roots     []Root
	OwnerUID  int
	OwnerGID  int
	CreatedAt time.Time
	State     string

	diffExcludes    []string
	acceptExcludes  []string
	acceptChown     bool
	diffExecutable  string
	rsyncExecutable string
}

func Create(ctx context.Context, id string, real string, opts Options) (*Workspace, error) {
	return CreateMulti(ctx, id, []RootSpec{{Path: real}}, opts)
}

func CreateMulti(ctx context.Context, id string, specs []RootSpec, opts Options) (*Workspace, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("session id is required")
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("at least one workspace root is required")
	}
	if strings.TrimSpace(opts.BaseDir) == "" {
		return nil, fmt.Errorf("shadow base dir is required")
	}

	roots := make([]Root, 0, len(specs))
	seenNames := map[string]struct{}{}
	seenReal := map[string]struct{}{}
	ownerUID, ownerGID := -1, -1
	for i, spec := range specs {
		realAbs, err := filepath.Abs(spec.Path)
		if err != nil {
			return nil, fmt.Errorf("workspace root %q abs: %w", spec.Path, err)
		}
		if resolved, err := filepath.EvalSymlinks(realAbs); err == nil {
			realAbs = resolved
		}
		st, err := os.Stat(realAbs)
		if err != nil {
			return nil, fmt.Errorf("workspace root %q stat: %w", spec.Path, err)
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("workspace root %q must be a directory", spec.Path)
		}
		if i == 0 {
			ownerUID, ownerGID = owner(st)
		}
		if _, ok := seenReal[realAbs]; ok {
			return nil, fmt.Errorf("duplicate workspace root path: %s", realAbs)
		}
		seenReal[realAbs] = struct{}{}

		name := cleanRootName(spec.Name)
		if name == "" {
			name = cleanRootName(filepath.Base(realAbs))
		}
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
			return nil, fmt.Errorf("invalid workspace root name %q", spec.Name)
		}
		if _, ok := seenNames[name]; ok {
			return nil, fmt.Errorf("duplicate workspace root name %q; use explicit names", name)
		}
		seenNames[name] = struct{}{}
		roots = append(roots, Root{Name: name, Real: realAbs})
	}

	baseAbs, err := filepath.Abs(opts.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("shadow base abs: %w", err)
	}
	sessionDir := filepath.Join(baseAbs, id)
	work := filepath.Join(sessionDir, "work")
	home := filepath.Join(sessionDir, "home")
	tmp := filepath.Join(sessionDir, "tmp")
	for _, p := range []string{baseAbs, work, home, tmp} {
		if strings.Contains(p, ",") {
			return nil, fmt.Errorf("shadow paths containing comma are not supported: %s", p)
		}
	}
	for _, root := range roots {
		if strings.Contains(root.Real, ",") {
			return nil, fmt.Errorf("shadow paths containing comma are not supported: %s", root.Real)
		}
	}

	// Resolve lifecycle dependencies before creating or removing any session
	// state. Hermetic builds return absolute paths from their packaged runtime
	// closure and do not depend on the detached supervisor's ambient PATH.
	rsyncExecutable, err := runtimebin.Resolve("rsync")
	if err != nil {
		return nil, fmt.Errorf("resolve shadow workspace rsync: %w", err)
	}
	diffExecutable, err := runtimebin.Resolve("diff")
	if err != nil {
		return nil, fmt.Errorf("resolve shadow workspace diff: %w", err)
	}

	if err := cleanup.RemoveAllWritable(sessionDir); err != nil {
		return nil, fmt.Errorf("remove old shadow dir: %w", err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, fmt.Errorf("create shadow workdir: %w", err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("create shadow home: %w", err)
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("create shadow tmp: %w", err)
	}
	for _, dir := range []string{work, home, tmp} {
		if err := os.Chown(dir, ownerUID, ownerGID); err != nil {
			return nil, fmt.Errorf("chown shadow dir %s: %w", dir, err)
		}
	}

	excludes := cleanExcludes(opts.DiffExcludes)
	if len(excludes) == 0 {
		excludes = []string{".git", ".direnv"}
	}
	acceptExcludes := cleanExcludes(opts.AcceptExcludes)
	if len(acceptExcludes) == 0 {
		acceptExcludes = []string{".git", ".direnv"}
	}

	multi := len(roots) > 1 || strings.TrimSpace(specs[0].Name) != ""
	for i := range roots {
		dest := work
		if multi {
			dest = filepath.Join(work, roots[i].Name)
			if err := os.MkdirAll(dest, 0o755); err != nil {
				_ = cleanup.RemoveAllWritable(sessionDir)
				return nil, fmt.Errorf("create shadow root %s: %w", roots[i].Name, err)
			}
			if err := os.Chown(dest, ownerUID, ownerGID); err != nil {
				_ = cleanup.RemoveAllWritable(sessionDir)
				return nil, fmt.Errorf("chown shadow root %s: %w", roots[i].Name, err)
			}
		}
		args := []string{"-a", "--delete", "--chown=" + strconv.Itoa(ownerUID) + ":" + strconv.Itoa(ownerGID)}
		args = append(args, withTrailingSeparator(roots[i].Real), withTrailingSeparator(dest))
		cmd := exec.CommandContext(ctx, rsyncExecutable, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			if !isRsyncVanished(err) {
				_ = cleanup.RemoveAllWritable(sessionDir)
				return nil, fmt.Errorf("copy shadow workspace root %s: %w: %s", roots[i].Name, err, strings.TrimSpace(string(out)))
			}
		}
		roots[i].Work = dest
	}

	return &Workspace{
		ID:              id,
		Real:            roots[0].Real,
		Work:            work,
		Home:            home,
		Tmp:             tmp,
		Roots:           roots,
		OwnerUID:        ownerUID,
		OwnerGID:        ownerGID,
		CreatedAt:       time.Now().UTC(),
		State:           StateActive,
		diffExcludes:    excludes,
		acceptExcludes:  acceptExcludes,
		acceptChown:     opts.AcceptChown,
		diffExecutable:  diffExecutable,
		rsyncExecutable: rsyncExecutable,
	}, nil
}

// OpenMulti reopens an already materialized retained shadow workspace without
// copying from the real roots or deleting any shadow data. expected is the
// durable identity captured after the original CreateMulti completed.
func OpenMulti(ctx context.Context, id string, specs []RootSpec, opts Options, expected []Root, createdAt time.Time) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" || len(specs) == 0 || strings.TrimSpace(opts.BaseDir) == "" {
		return nil, fmt.Errorf("retained shadow identity is incomplete")
	}
	if len(expected) != len(specs) || len(expected) == 0 {
		return nil, fmt.Errorf("retained shadow root identity is incomplete")
	}

	baseAbs, err := filepath.Abs(opts.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("shadow base abs: %w", err)
	}
	sessionDir := filepath.Join(baseAbs, id)
	work := filepath.Join(sessionDir, "work")
	home := filepath.Join(sessionDir, "home")
	tmp := filepath.Join(sessionDir, "tmp")
	for _, dir := range []string{sessionDir, work, home, tmp} {
		info, statErr := os.Lstat(dir)
		if statErr != nil {
			return nil, fmt.Errorf("retained shadow path %s: %w", dir, statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("retained shadow path %s must be a real directory", dir)
		}
	}

	roots := make([]Root, 0, len(specs))
	seenNames := make(map[string]struct{}, len(specs))
	seenReal := make(map[string]struct{}, len(specs))
	ownerUID, ownerGID := -1, -1
	multi := len(specs) > 1 || strings.TrimSpace(specs[0].Name) != ""
	for i, spec := range specs {
		realAbs, absErr := filepath.Abs(spec.Path)
		if absErr != nil {
			return nil, fmt.Errorf("workspace root %q abs: %w", spec.Path, absErr)
		}
		if resolved, resolveErr := filepath.EvalSymlinks(realAbs); resolveErr == nil {
			realAbs = resolved
		}
		info, statErr := os.Stat(realAbs)
		if statErr != nil || !info.IsDir() {
			if statErr != nil {
				return nil, fmt.Errorf("workspace root %q stat: %w", spec.Path, statErr)
			}
			return nil, fmt.Errorf("workspace root %q must be a directory", spec.Path)
		}
		if i == 0 {
			ownerUID, ownerGID = owner(info)
		}
		if _, duplicate := seenReal[realAbs]; duplicate {
			return nil, fmt.Errorf("duplicate workspace root path: %s", realAbs)
		}
		seenReal[realAbs] = struct{}{}
		name := cleanRootName(spec.Name)
		if name == "" {
			name = cleanRootName(filepath.Base(realAbs))
		}
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
			return nil, fmt.Errorf("invalid workspace root name %q", spec.Name)
		}
		if _, duplicate := seenNames[name]; duplicate {
			return nil, fmt.Errorf("duplicate workspace root name %q", name)
		}
		seenNames[name] = struct{}{}
		rootWork := work
		if multi {
			rootWork = filepath.Join(work, name)
		}
		workInfo, workErr := os.Lstat(rootWork)
		if workErr != nil || !workInfo.IsDir() || workInfo.Mode()&os.ModeSymlink != 0 {
			if workErr != nil {
				return nil, fmt.Errorf("retained shadow root %s: %w", name, workErr)
			}
			return nil, fmt.Errorf("retained shadow root %s is not a real directory", name)
		}
		want := expected[i]
		if want.Name != name || filepath.Clean(want.Real) != filepath.Clean(realAbs) || filepath.Clean(want.Work) != filepath.Clean(rootWork) {
			return nil, fmt.Errorf("retained shadow root %d identity mismatch", i)
		}
		roots = append(roots, Root{Name: name, Real: realAbs, Work: rootWork})
	}

	rsyncExecutable, err := runtimebin.Resolve("rsync")
	if err != nil {
		return nil, fmt.Errorf("resolve shadow workspace rsync: %w", err)
	}
	diffExecutable, err := runtimebin.Resolve("diff")
	if err != nil {
		return nil, fmt.Errorf("resolve shadow workspace diff: %w", err)
	}
	diffExcludes := cleanExcludes(opts.DiffExcludes)
	if len(diffExcludes) == 0 {
		diffExcludes = []string{".git", ".direnv"}
	}
	acceptExcludes := cleanExcludes(opts.AcceptExcludes)
	if len(acceptExcludes) == 0 {
		acceptExcludes = []string{".git", ".direnv"}
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	return &Workspace{
		ID: id, Real: roots[0].Real, Work: work, Home: home, Tmp: tmp, Roots: roots,
		OwnerUID: ownerUID, OwnerGID: ownerGID, CreatedAt: createdAt.UTC(), State: StateActive,
		diffExcludes: diffExcludes, acceptExcludes: acceptExcludes, acceptChown: opts.AcceptChown,
		diffExecutable: diffExecutable, rsyncExecutable: rsyncExecutable,
	}, nil
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return nil, ErrInactive
	}
	roots := w.Roots
	if len(roots) == 0 {
		roots = []Root{{Name: filepath.Base(w.Real), Real: w.Real, Work: w.Work}}
	}
	diffExecutable, err := workspaceExecutable(w.diffExecutable, "diff")
	if err != nil {
		return nil, fmt.Errorf("resolve shadow workspace diff: %w", err)
	}
	rsyncExecutable, err := workspaceExecutable(w.rsyncExecutable, "rsync")
	if err != nil {
		return nil, fmt.Errorf("resolve shadow workspace rsync: %w", err)
	}
	var combined bytes.Buffer
	for _, root := range roots {
		if len(roots) > 1 {
			fmt.Fprintf(&combined, "diff --shadow-root %s\n", root.Name)
		}
		args := []string{"-ruN", "--no-dereference"}
		for _, ex := range w.diffExcludes {
			args = append(args, "--exclude="+ex)
		}
		args = append(args, root.Real, root.Work)
		cmd := exec.CommandContext(ctx, diffExecutable, args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			combined.Write(out)
			continue
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			combined.Write(out)
			continue
		}
		if errors.As(err, &ee) && ee.ExitCode() == 2 {
			planArgs := []string{"-a", "--delete", "--dry-run", "--itemize-changes"}
			for _, ex := range w.diffExcludes {
				planArgs = append(planArgs, "--exclude="+ex)
			}
			planArgs = append(planArgs, withTrailingSeparator(root.Work), withTrailingSeparator(root.Real))
			planOut, planErr := exec.CommandContext(ctx, rsyncExecutable, planArgs...).CombinedOutput()
			if planErr == nil {
				fmt.Fprintf(&combined, "Itemized shadow Apply plan for root %s (unified diff unavailable):\n", root.Name)
				combined.Write(planOut)
				continue
			}
			return combined.Bytes(), fmt.Errorf("diff shadow workspace root %s: %w: %s; itemized fallback: %v: %s", root.Name, err, strings.TrimSpace(string(out)), planErr, strings.TrimSpace(string(planOut)))
		}
		return combined.Bytes(), fmt.Errorf("diff shadow workspace root %s: %w: %s", root.Name, err, strings.TrimSpace(string(out)))
	}
	return combined.Bytes(), nil
}

func (w *Workspace) Accept(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return ErrInactive
	}
	rsyncExecutable, err := workspaceExecutable(w.rsyncExecutable, "rsync")
	if err != nil {
		return fmt.Errorf("resolve shadow workspace rsync: %w", err)
	}
	roots := w.Roots
	if len(roots) == 0 {
		roots = []Root{{Name: filepath.Base(w.Real), Real: w.Real, Work: w.Work}}
	}
	for _, root := range roots {
		args := []string{"-a", "--delete"}
		for _, ex := range w.acceptExcludes {
			args = append(args, "--exclude="+ex)
		}
		if w.acceptChown && w.OwnerUID >= 0 && w.OwnerGID >= 0 {
			args = append(args, "--chown="+strconv.Itoa(w.OwnerUID)+":"+strconv.Itoa(w.OwnerGID))
		}
		args = append(args, withTrailingSeparator(root.Work), withTrailingSeparator(root.Real))
		cmd := exec.CommandContext(ctx, rsyncExecutable, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			if !isRsyncVanished(err) {
				return fmt.Errorf("accept shadow workspace root %s: %w: %s", root.Name, err, strings.TrimSpace(string(out)))
			}
		}
	}
	if err := cleanup.RemoveAllWritable(filepath.Dir(w.Work)); err != nil {
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
	if err := cleanup.RemoveAllWritable(filepath.Dir(w.Work)); err != nil {
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

func workspaceExecutable(configured, name string) (string, error) {
	if strings.TrimSpace(configured) != "" {
		return configured, nil
	}
	return runtimebin.Resolve(name)
}

func isRsyncVanished(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 24
}

func owner(info fs.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return os.Getuid(), os.Getgid()
}

func cleanRootName(name string) string {
	name = strings.TrimSpace(name)
	name = filepath.Clean(name)
	if name == "." {
		return ""
	}
	return name
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
