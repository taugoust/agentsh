//go:build linux

package shadow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

var (
	ErrInactive    = errors.New("shadow workspace is not active")
	ErrStaleReview = errors.New("shadow workspace review is stale")
)

const (
	reviewSchemaVersion       = 1
	reviewFileName            = "review.json"
	finalizationSchemaVersion = 3
	finalizationFileName      = "finalization.json"

	FinalizationAccept   = "accept"
	FinalizationReject   = "reject"
	FinalizationPrepared = "prepared"
	FinalizationApplying = "applying"
	FinalizationApplied  = "applied"
)

type Review struct {
	SchemaVersion int       `json:"schema_version"`
	Generation    uint64    `json:"generation"`
	Hash          string    `json:"hash"`
	BaseHash      string    `json:"base_hash"`
	ShadowHash    string    `json:"shadow_hash"`
	DiffHash      string    `json:"diff_hash"`
	CreatedAt     time.Time `json:"created_at"`
	Diff          []byte    `json:"-"`
}

type Finalization struct {
	SchemaVersion    int       `json:"schema_version"`
	ID               string    `json:"finalization_id"`
	Action           string    `json:"action"`
	Phase            string    `json:"phase"`
	ReviewGeneration uint64    `json:"review_generation,omitempty"`
	ReviewHash       string    `json:"review_hash,omitempty"`
	BaseHash         string    `json:"base_hash,omitempty"`
	ShadowHash       string    `json:"shadow_hash,omitempty"`
	DiffHash         string    `json:"diff_hash,omitempty"`
	SnapshotDir      string    `json:"snapshot_dir,omitempty"`
	AcceptExcludes   []string  `json:"accept_excludes,omitempty"`
	AcceptChown      bool      `json:"accept_chown,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	AppliedAt        time.Time `json:"applied_at,omitempty"`
}

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
	latestReview    Review
	finalization    *Finalization
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
	if err := validateNonOverlappingRoots(roots, sessionDir); err != nil {
		return nil, err
	}
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
	excludes = reviewExcludes(excludes, acceptExcludes)

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
	if err := validateNonOverlappingRoots(roots, sessionDir); err != nil {
		return nil, err
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
	diffExcludes = reviewExcludes(diffExcludes, acceptExcludes)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	workspace := &Workspace{
		ID: id, Real: roots[0].Real, Work: work, Home: home, Tmp: tmp, Roots: roots,
		OwnerUID: ownerUID, OwnerGID: ownerGID, CreatedAt: createdAt.UTC(), State: StateActive,
		diffExcludes: diffExcludes, acceptExcludes: acceptExcludes, acceptChown: opts.AcceptChown,
		diffExecutable: diffExecutable, rsyncExecutable: rsyncExecutable,
	}
	if err := workspace.loadReviewLocked(); err != nil {
		return nil, err
	}
	if err := workspace.loadFinalizationLocked(); err != nil {
		return nil, err
	}
	return workspace, nil
}

// OpenMaterialized binds an already staged single-root workspace to the
// journaled shadow review/finalization machinery without copying or deleting
// either tree. The caller owns lifecycle cleanup for the materialized work root.
func OpenMaterialized(ctx context.Context, id, real, work string, opts Options, createdAt time.Time) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" || strings.ContainsRune(id, filepath.Separator) {
		return nil, fmt.Errorf("materialized shadow session identity is invalid")
	}
	realAbs, err := filepath.Abs(real)
	if err != nil {
		return nil, err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(realAbs); resolveErr == nil {
		realAbs = resolved
	}
	workAbs, err := filepath.Abs(work)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(workAbs) != workAbs || realAbs == workAbs || pathContains(realAbs, workAbs) || pathContains(workAbs, realAbs) {
		return nil, fmt.Errorf("materialized shadow paths are invalid or overlap")
	}
	realInfo, err := os.Lstat(realAbs)
	if err != nil || !realInfo.IsDir() || realInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("materialized shadow real root is not a direct directory")
	}
	workInfo, err := os.Lstat(workAbs)
	if err != nil || !workInfo.IsDir() || workInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("materialized shadow work root is not a direct directory")
	}
	rsyncExecutable, err := runtimebin.Resolve("rsync")
	if err != nil {
		return nil, fmt.Errorf("resolve materialized shadow rsync: %w", err)
	}
	diffExecutable, err := runtimebin.Resolve("diff")
	if err != nil {
		return nil, fmt.Errorf("resolve materialized shadow diff: %w", err)
	}
	diffExcludes := cleanExcludes(opts.DiffExcludes)
	if len(diffExcludes) == 0 {
		diffExcludes = []string{".git", ".direnv"}
	}
	acceptExcludes := cleanExcludes(opts.AcceptExcludes)
	if len(acceptExcludes) == 0 {
		acceptExcludes = []string{".git", ".direnv"}
	}
	diffExcludes = reviewExcludes(diffExcludes, acceptExcludes)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	ownerUID, ownerGID := owner(realInfo)
	name := cleanRootName(filepath.Base(realAbs))
	if name == "" {
		name = "workspace"
	}
	workspace := &Workspace{
		ID: id, Real: realAbs, Work: workAbs,
		Roots:    []Root{{Name: name, Real: realAbs, Work: workAbs}},
		OwnerUID: ownerUID, OwnerGID: ownerGID, CreatedAt: createdAt.UTC(), State: StateActive,
		diffExcludes: diffExcludes, acceptExcludes: acceptExcludes, acceptChown: opts.AcceptChown,
		diffExecutable: diffExecutable, rsyncExecutable: rsyncExecutable,
	}
	if err := workspace.loadReviewLocked(); err != nil {
		return nil, err
	}
	if err := workspace.loadFinalizationLocked(); err != nil {
		return nil, err
	}
	return workspace, nil
}

func (w *Workspace) reviewPath() string {
	return filepath.Join(filepath.Dir(w.Work), reviewFileName)
}

func (w *Workspace) finalizationPath() string {
	return filepath.Join(filepath.Dir(w.Work), finalizationFileName)
}

func (w *Workspace) finalizationSnapshotDir() string {
	return filepath.Join(filepath.Dir(w.Work), "finalization-snapshot")
}

func persistPrivateJSON(path, prefix string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, prefix)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(encoded, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := dirHandle.Sync()
	closeErr := dirHandle.Close()
	return errors.Join(syncErr, closeErr)
}

func (w *Workspace) persistReviewLocked(review Review) error {
	persisted := review
	persisted.Diff = nil
	if err := persistPrivateJSON(w.reviewPath(), ".review-*.json", persisted); err != nil {
		return fmt.Errorf("persist shadow review: %w", err)
	}
	return nil
}

func (w *Workspace) persistFinalizationValueLocked(finalization *Finalization) error {
	if finalization == nil {
		return fmt.Errorf("shadow finalization is absent")
	}
	if err := persistPrivateJSON(w.finalizationPath(), ".finalization-*.json", finalization); err != nil {
		return fmt.Errorf("persist shadow finalization: %w", err)
	}
	return nil
}

func (w *Workspace) persistFinalizationLocked() error {
	return w.persistFinalizationValueLocked(w.finalization)
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func reviewDigest(generation uint64, baseHash, shadowHash, diffHash string) (string, error) {
	payload := struct {
		SchemaVersion int    `json:"schema_version"`
		Generation    uint64 `json:"generation"`
		BaseHash      string `json:"base_hash"`
		ShadowHash    string `json:"shadow_hash"`
		DiffHash      string `json:"diff_hash"`
	}{reviewSchemaVersion, generation, baseHash, shadowHash, diffHash}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func (w *Workspace) loadReviewLocked() error {
	data, err := os.ReadFile(w.reviewPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read retained shadow review: %w", err)
	}
	var review Review
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&review); err != nil {
		return fmt.Errorf("decode retained shadow review: %w", err)
	}
	expected, digestErr := reviewDigest(review.Generation, review.BaseHash, review.ShadowHash, review.DiffHash)
	if review.SchemaVersion != reviewSchemaVersion || review.Generation == 0 || !validSHA256Digest(review.Hash) ||
		!validSHA256Digest(review.BaseHash) || !validSHA256Digest(review.ShadowHash) || !validSHA256Digest(review.DiffHash) || digestErr != nil || expected != review.Hash {
		return fmt.Errorf("retained shadow review is invalid")
	}
	w.latestReview = review
	return nil
}

func (w *Workspace) loadFinalizationLocked() error {
	data, err := os.ReadFile(w.finalizationPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read retained shadow finalization: %w", err)
	}
	var finalization Finalization
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&finalization); err != nil {
		return fmt.Errorf("decode retained shadow finalization: %w", err)
	}
	if (finalization.SchemaVersion < 1 || finalization.SchemaVersion > 2) && finalization.SchemaVersion != finalizationSchemaVersion {
		return fmt.Errorf("retained shadow finalization has unsupported schema")
	}
	if finalization.SchemaVersion < finalizationSchemaVersion && finalization.Action == FinalizationAccept && finalization.SnapshotDir == "" {
		finalization.SnapshotDir = w.finalizationSnapshotDir()
		if finalization.Phase != FinalizationApplied {
			_, shadowHash, hashErr := w.treeHashesLocked(context.Background())
			if hashErr != nil || shadowHash != finalization.ShadowHash {
				return fmt.Errorf("legacy shadow finalization cannot be safely migrated")
			}
			if finalization.Phase == FinalizationPrepared {
				baseHash, _, hashErr := w.treeHashesLocked(context.Background())
				if hashErr != nil || baseHash != finalization.BaseHash {
					return fmt.Errorf("legacy shadow finalization base changed before migration")
				}
			}
			if err := w.createFinalizationSnapshotLocked(context.Background()); err != nil {
				return err
			}
		}
	}
	if finalization.SchemaVersion < finalizationSchemaVersion {
		if finalization.Action == FinalizationAccept && finalization.Phase != FinalizationApplied {
			w.finalization = &finalization
			snapshotHash, hashErr := w.snapshotHashLocked(context.Background())
			if hashErr != nil || snapshotHash != finalization.ShadowHash {
				return fmt.Errorf("legacy shadow finalization semantics changed before migration")
			}
		}
		finalization.AcceptExcludes = append([]string(nil), w.acceptExcludes...)
		finalization.AcceptChown = w.acceptChown
		finalization.SchemaVersion = finalizationSchemaVersion
		w.finalization = &finalization
		if err := w.persistFinalizationLocked(); err != nil {
			return err
		}
	}
	if finalization.SchemaVersion != finalizationSchemaVersion || strings.TrimSpace(finalization.ID) == "" ||
		(finalization.Action != FinalizationAccept && finalization.Action != FinalizationReject) ||
		(finalization.Phase != FinalizationPrepared && finalization.Phase != FinalizationApplying && finalization.Phase != FinalizationApplied) || finalization.CreatedAt.IsZero() {
		return fmt.Errorf("retained shadow finalization is invalid")
	}
	if finalization.Action == FinalizationAccept && (finalization.ReviewGeneration == 0 || finalization.ReviewHash == "" || finalization.ShadowHash == "" ||
		!filepath.IsAbs(finalization.SnapshotDir) || filepath.Clean(finalization.SnapshotDir) != finalization.SnapshotDir || finalization.SnapshotDir != w.finalizationSnapshotDir()) {
		return fmt.Errorf("retained shadow accept finalization is incomplete")
	}
	if finalization.Action == FinalizationAccept {
		expected, digestErr := reviewDigest(finalization.ReviewGeneration, finalization.BaseHash, finalization.ShadowHash, finalization.DiffHash)
		if digestErr != nil || expected != finalization.ReviewHash || w.latestReview.Generation != finalization.ReviewGeneration || w.latestReview.Hash != finalization.ReviewHash ||
			w.latestReview.BaseHash != finalization.BaseHash || w.latestReview.ShadowHash != finalization.ShadowHash || w.latestReview.DiffHash != finalization.DiffHash {
			return fmt.Errorf("retained shadow finalization does not match its review")
		}
	}
	if finalization.Action == FinalizationAccept {
		w.acceptExcludes = append([]string(nil), finalization.AcceptExcludes...)
		w.acceptChown = finalization.AcceptChown
	}
	w.finalization = &finalization
	switch finalization.Phase {
	case FinalizationApplied:
		if finalization.Action == FinalizationAccept {
			w.State = StateAccepted
		} else {
			w.State = StateRejected
		}
	default:
		w.State = StateActive
	}
	return nil
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) {
	review, err := w.Review(ctx)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), review.Diff...), nil
}

func (w *Workspace) Review(ctx context.Context) (Review, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive || w.finalization != nil {
		return Review{}, ErrInactive
	}
	baseHash, shadowHash, err := w.treeHashesLocked(ctx)
	if err != nil {
		return Review{}, err
	}
	out, err := w.diffLocked(ctx)
	if err != nil {
		return Review{}, err
	}
	verifiedBase, verifiedShadow, err := w.treeHashesLocked(ctx)
	if err != nil {
		return Review{}, err
	}
	if verifiedBase != baseHash || verifiedShadow != shadowHash {
		return Review{}, fmt.Errorf("%w: workspace changed while review was generated", ErrStaleReview)
	}
	diffSum := sha256.Sum256(out)
	generation := w.latestReview.Generation + 1
	createdAt := time.Now().UTC()
	diffHash := "sha256:" + hex.EncodeToString(diffSum[:])
	hash, digestErr := reviewDigest(generation, baseHash, shadowHash, diffHash)
	if digestErr != nil {
		return Review{}, digestErr
	}
	review := Review{
		SchemaVersion: reviewSchemaVersion, Generation: generation,
		Hash: hash, BaseHash: baseHash,
		ShadowHash: shadowHash, DiffHash: diffHash, CreatedAt: createdAt,
		Diff: append([]byte(nil), out...),
	}
	if err := w.persistReviewLocked(review); err != nil {
		return Review{}, err
	}
	w.latestReview = review
	return review, nil
}

func (w *Workspace) diffLocked(ctx context.Context) ([]byte, error) {
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

func (w *Workspace) workspaceRootsLocked() []Root {
	if len(w.Roots) > 0 {
		return w.Roots
	}
	return []Root{{Name: filepath.Base(w.Real), Real: w.Real, Work: w.Work}}
}

func (w *Workspace) hashRootSetLocked(ctx context.Context, pathFor func(Root) string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	hasher := sha256.New()
	for _, root := range w.workspaceRootsLocked() {
		if _, err := fmt.Fprintf(hasher, "root\x00%s\x00", root.Name); err != nil {
			return "", err
		}
		if err := hashTree(ctx, hasher, pathFor(root), w.acceptExcludes); err != nil {
			return "", fmt.Errorf("hash workspace root %s: %w", root.Name, err)
		}
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func (w *Workspace) treeHashesLocked(ctx context.Context) (string, string, error) {
	baseHash, err := w.hashRootSetLocked(ctx, func(root Root) string { return root.Real })
	if err != nil {
		return "", "", fmt.Errorf("hash real workspace: %w", err)
	}
	shadowHash, err := w.hashRootSetLocked(ctx, func(root Root) string { return root.Work })
	if err != nil {
		return "", "", fmt.Errorf("hash shadow workspace: %w", err)
	}
	return baseHash, shadowHash, nil
}

func (w *Workspace) snapshotRoot(root Root) string {
	return filepath.Join(w.finalizationSnapshotDir(), root.Name)
}

func (w *Workspace) snapshotHashLocked(ctx context.Context) (string, error) {
	return w.hashRootSetLocked(ctx, w.snapshotRoot)
}

func hashTree(ctx context.Context, hasher io.Writer, root string, excludes []string) error {
	writeField := func(kind string, value []byte) error {
		if _, err := fmt.Fprintf(hasher, "%d:%s%d:", len(kind), kind, len(value)); err != nil {
			return err
		}
		_, err := hasher.Write(value)
		return err
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		first, _, _ := strings.Cut(rel, string(filepath.Separator))
		if slices.Contains(excludes, first) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		kind := "file"
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			kind = "symlink"
		case info.IsDir():
			kind = "dir"
		case !info.Mode().IsRegular():
			kind = "other"
		}
		if err := writeField("path", []byte(filepath.ToSlash(rel))); err != nil {
			return err
		}
		if err := writeField("kind", []byte(kind)); err != nil {
			return err
		}
		if err := writeField("mode", []byte(strconv.FormatUint(uint64(info.Mode()), 8))); err != nil {
			return err
		}
		switch kind {
		case "file":
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			contentHash := sha256.New()
			_, copyErr := io.Copy(contentHash, file)
			closeErr := file.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return err
			}
			return writeField("content-sha256", contentHash.Sum(nil))
		case "symlink":
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return writeField("target", []byte(target))
		}
		return nil
	})
}

func (w *Workspace) Accept(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.latestReview.Generation == 0 {
		return ErrStaleReview
	}
	if w.finalization == nil {
		return fmt.Errorf("shadow accept requires a prepared finalization")
	}
	return w.applyFinalizationLocked(ctx, w.finalization.ID)
}

func (w *Workspace) ValidateReview(ctx context.Context, generation uint64, hash string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.validateReviewLocked(ctx, generation, hash)
}

func (w *Workspace) validateReviewLocked(ctx context.Context, generation uint64, hash string) error {
	if w.State != StateActive || w.finalization != nil {
		return ErrInactive
	}
	if generation == 0 || generation != w.latestReview.Generation || hash == "" || hash != w.latestReview.Hash {
		return ErrStaleReview
	}
	baseHash, shadowHash, err := w.treeHashesLocked(ctx)
	if err != nil {
		return err
	}
	if baseHash != w.latestReview.BaseHash || shadowHash != w.latestReview.ShadowHash {
		return ErrStaleReview
	}
	return nil
}

func (w *Workspace) createFinalizationSnapshotLocked(ctx context.Context) error {
	snapshotDir := w.finalizationSnapshotDir()
	if err := cleanup.RemoveAllWritable(snapshotDir); err != nil {
		return fmt.Errorf("remove stale finalization snapshot: %w", err)
	}
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return fmt.Errorf("create finalization snapshot: %w", err)
	}
	rsyncExecutable, err := workspaceExecutable(w.rsyncExecutable, "rsync")
	if err != nil {
		return err
	}
	for _, root := range w.workspaceRootsLocked() {
		destination := w.snapshotRoot(root)
		if err := os.MkdirAll(destination, 0o700); err != nil {
			return err
		}
		args := []string{"-a", "--delete", "--fsync"}
		for _, excluded := range w.acceptExcludes {
			args = append(args, "--exclude="+excluded)
		}
		args = append(args, withTrailingSeparator(root.Work), withTrailingSeparator(destination))
		if output, err := exec.CommandContext(ctx, rsyncExecutable, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("snapshot shadow workspace root %s: %w: %s", root.Name, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (w *Workspace) PrepareAccept(ctx context.Context, finalizationID string, generation uint64, hash string) (Finalization, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if strings.TrimSpace(finalizationID) == "" {
		return Finalization{}, fmt.Errorf("shadow finalization id is required")
	}
	if w.finalization != nil {
		if w.finalization.ID == finalizationID && w.finalization.Action == FinalizationAccept && w.finalization.ReviewGeneration == generation && w.finalization.ReviewHash == hash {
			return *w.finalization, nil
		}
		return Finalization{}, fmt.Errorf("a different shadow finalization is already prepared")
	}
	if err := w.validateReviewLocked(ctx, generation, hash); err != nil {
		return Finalization{}, err
	}
	if err := w.createFinalizationSnapshotLocked(ctx); err != nil {
		return Finalization{}, err
	}
	snapshotHash, err := w.snapshotHashLocked(ctx)
	if err != nil || snapshotHash != w.latestReview.ShadowHash {
		_ = cleanup.RemoveAllWritable(w.finalizationSnapshotDir())
		if err != nil {
			return Finalization{}, err
		}
		return Finalization{}, ErrStaleReview
	}
	finalization := &Finalization{
		SchemaVersion: finalizationSchemaVersion, ID: finalizationID, Action: FinalizationAccept, Phase: FinalizationPrepared,
		ReviewGeneration: generation, ReviewHash: hash, BaseHash: w.latestReview.BaseHash,
		ShadowHash: w.latestReview.ShadowHash, DiffHash: w.latestReview.DiffHash, SnapshotDir: w.finalizationSnapshotDir(),
		AcceptExcludes: append([]string(nil), w.acceptExcludes...), AcceptChown: w.acceptChown, CreatedAt: time.Now().UTC(),
	}
	w.finalization = finalization
	if err := w.persistFinalizationLocked(); err != nil {
		w.finalization = nil
		_ = cleanup.RemoveAllWritable(w.finalizationSnapshotDir())
		return Finalization{}, err
	}
	return *finalization, nil
}

func (w *Workspace) PrepareReject(ctx context.Context, finalizationID string) (Finalization, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Finalization{}, err
	}
	if strings.TrimSpace(finalizationID) == "" {
		return Finalization{}, fmt.Errorf("shadow finalization id is required")
	}
	if w.finalization != nil {
		if w.finalization.ID == finalizationID && w.finalization.Action == FinalizationReject {
			return *w.finalization, nil
		}
		return Finalization{}, fmt.Errorf("a different shadow finalization is already prepared")
	}
	if w.State != StateActive {
		return Finalization{}, ErrInactive
	}
	finalization := &Finalization{SchemaVersion: finalizationSchemaVersion, ID: finalizationID, Action: FinalizationReject, Phase: FinalizationPrepared, CreatedAt: time.Now().UTC()}
	w.finalization = finalization
	if err := w.persistFinalizationLocked(); err != nil {
		w.finalization = nil
		return Finalization{}, err
	}
	return *finalization, nil
}

func (w *Workspace) PendingFinalization() (Finalization, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finalization == nil {
		return Finalization{}, false
	}
	return *w.finalization, true
}

func (w *Workspace) ApplyFinalization(ctx context.Context, finalizationID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.applyFinalizationLocked(ctx, finalizationID)
}

func (w *Workspace) ResumeFinalization(ctx context.Context, finalizationID string) error {
	return w.ApplyFinalization(ctx, finalizationID)
}

func (w *Workspace) applyFinalizationLocked(ctx context.Context, finalizationID string) error {
	if w.finalization == nil || w.finalization.ID != finalizationID {
		return fmt.Errorf("shadow finalization identity mismatch")
	}
	if w.finalization.Phase == FinalizationApplied {
		return nil
	}
	if w.finalization.Action == FinalizationAccept {
		snapshotHash, err := w.snapshotHashLocked(ctx)
		if err != nil || snapshotHash != w.finalization.ShadowHash {
			if err != nil {
				return err
			}
			return fmt.Errorf("immutable reviewed snapshot is stale")
		}
		if w.finalization.Phase == FinalizationPrepared {
			baseHash, err := w.hashRootSetLocked(ctx, func(root Root) string { return root.Real })
			if err != nil {
				return err
			}
			if baseHash != w.finalization.BaseHash {
				return ErrStaleReview
			}
		}
	}
	applying := *w.finalization
	applying.Phase = FinalizationApplying
	if err := w.persistFinalizationValueLocked(&applying); err != nil {
		return err
	}
	w.finalization = &applying
	switch w.finalization.Action {
	case FinalizationReject:
		w.State = StateRejected
	case FinalizationAccept:
		if err := w.applyAcceptLocked(ctx); err != nil {
			return err
		}
		w.State = StateAccepted
	default:
		return fmt.Errorf("unsupported shadow finalization action %q", w.finalization.Action)
	}
	applied := *w.finalization
	applied.Phase = FinalizationApplied
	applied.AppliedAt = time.Now().UTC()
	if err := w.persistFinalizationValueLocked(&applied); err != nil {
		return err
	}
	w.finalization = &applied
	return nil
}

func (w *Workspace) applyAcceptLocked(ctx context.Context) error {
	rsyncExecutable, err := workspaceExecutable(w.rsyncExecutable, "rsync")
	if err != nil {
		return fmt.Errorf("resolve shadow workspace rsync: %w", err)
	}
	roots := w.workspaceRootsLocked()
	for _, root := range roots {
		args := []string{"-a", "--delete", "--fsync"}
		for _, ex := range w.acceptExcludes {
			args = append(args, "--exclude="+ex)
		}
		if w.acceptChown && w.OwnerUID >= 0 && w.OwnerGID >= 0 {
			args = append(args, "--chown="+strconv.Itoa(w.OwnerUID)+":"+strconv.Itoa(w.OwnerGID))
		}
		args = append(args, withTrailingSeparator(w.snapshotRoot(root)), withTrailingSeparator(root.Real))
		cmd := exec.CommandContext(ctx, rsyncExecutable, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("accept shadow workspace root %s: %w: %s", root.Name, err, strings.TrimSpace(string(out)))
		}
	}
	baseHash, err := w.hashRootSetLocked(ctx, func(root Root) string { return root.Real })
	if err != nil {
		return err
	}
	snapshotHash, err := w.snapshotHashLocked(ctx)
	if err != nil {
		return err
	}
	if baseHash != w.finalization.ShadowHash || snapshotHash != w.finalization.ShadowHash {
		return fmt.Errorf("accepted workspace verification failed")
	}
	return nil
}

func (w *Workspace) AcceptReviewed(ctx context.Context, generation uint64, hash string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finalization == nil || w.finalization.Action != FinalizationAccept || w.finalization.ReviewGeneration != generation || w.finalization.ReviewHash != hash {
		return ErrStaleReview
	}
	return w.applyFinalizationLocked(ctx, w.finalization.ID)
}

func (w *Workspace) Reject(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateActive {
		return nil
	}
	if w.finalization != nil {
		return w.applyFinalizationLocked(ctx, w.finalization.ID)
	}
	w.State = StateRejected
	return nil
}

func (w *Workspace) CleanupFinalized() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.State != StateAccepted && w.State != StateRejected {
		return ErrInactive
	}
	if w.finalization == nil || w.finalization.Phase != FinalizationApplied {
		return fmt.Errorf("shadow finalization is not durably applied")
	}
	if err := cleanup.RemoveAllWritable(filepath.Dir(w.Work)); err != nil {
		return fmt.Errorf("remove finalized shadow dir: %w", err)
	}
	return nil
}

func (w *Workspace) StateValue() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.State
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

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func validateNonOverlappingRoots(roots []Root, sessionDir string) error {
	for i, root := range roots {
		if root.Real == sessionDir || pathContains(root.Real, sessionDir) || pathContains(sessionDir, root.Real) {
			return fmt.Errorf("shadow session directory overlaps workspace root %s", root.Real)
		}
		for j := i + 1; j < len(roots); j++ {
			other := roots[j].Real
			if root.Real == other || pathContains(root.Real, other) || pathContains(other, root.Real) {
				return fmt.Errorf("workspace roots overlap: %s and %s", root.Real, other)
			}
		}
	}
	return nil
}

func cleanRootName(name string) string {
	name = strings.TrimSpace(name)
	name = filepath.Clean(name)
	if name == "." {
		return ""
	}
	return name
}

func reviewExcludes(diffExcludes, acceptExcludes []string) []string {
	out := make([]string, 0, len(diffExcludes))
	for _, excluded := range diffExcludes {
		if slices.Contains(acceptExcludes, excluded) {
			out = append(out, excluded)
		}
	}
	return out
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
