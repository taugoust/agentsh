package gitdraft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

const (
	baselineRef = "refs/pi-auto/baseline"
	resultRef   = "refs/pi-auto/result"
	stateSchema = 1
)

type GuestWorkspace struct {
	SessionID  string
	Workspace  string
	VolumeRoot string
	Git        string
}

type state struct {
	SchemaVersion int    `json:"schema_version"`
	SessionID     string `json:"session_id"`
	InputSHA256   string `json:"input_sha256"`
	Baseline      string `json:"baseline"`
	Sealing       bool   `json:"sealing,omitempty"`
	Result        string `json:"result,omitempty"`
	ResultSHA256  string `json:"result_sha256,omitempty"`
	ResultSize    int64  `json:"result_size,omitempty"`
}

func (g GuestWorkspace) Import(ctx context.Context, transfer guestcontrol.ArtifactTransfer, source io.Reader) error {
	if err := g.validate(); err != nil {
		return err
	}
	if transfer.Kind != guestcontrol.ArtifactKindGitInputBundle || transfer.Validate() != nil || source == nil {
		return fmt.Errorf("Git Draft input artifact is invalid")
	}
	controlDir := filepath.Join(g.VolumeRoot, ".agentsh-draft")
	if err := os.Mkdir(controlDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Mkdir(filepath.Join(g.VolumeRoot, ".agentsh-home"), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if existing, err := g.readState(); err == nil {
		if existing.InputSHA256 == transfer.SHA256 && existing.SessionID == g.SessionID {
			return g.verifyRepository(ctx, existing.Baseline)
		}
		return fmt.Errorf("Git Draft volume already contains a different input")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	bundlePath := filepath.Join(controlDir, "input.bundle")
	temporary, err := os.OpenFile(bundlePath+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporary.Name())
		}
	}()
	hasher := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(temporary, hasher), source, transfer.Size)
	if copyErr == nil && written == transfer.Size {
		copyErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err := errors.Join(copyErr, closeErr); err != nil || written != transfer.Size {
		return fmt.Errorf("receive Git Draft input: %w", err)
	}
	if digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); digest != transfer.SHA256 {
		return fmt.Errorf("Git Draft input digest mismatch")
	}
	if err := os.Rename(temporary.Name(), bundlePath); err != nil {
		return err
	}
	published = true
	if err := syncDir(controlDir); err != nil {
		return err
	}

	baseline, err := g.bundleBaseline(ctx, bundlePath)
	if err != nil {
		return err
	}
	if entries, err := os.ReadDir(g.Workspace); err != nil {
		return err
	} else if len(entries) != 0 {
		return fmt.Errorf("Git Draft workspace is not empty before initialization")
	}
	if _, err := g.git(ctx, g.Workspace, "init", "--quiet"); err != nil {
		return err
	}
	if _, err := g.git(ctx, g.Workspace, "fetch", "--quiet", "--no-tags", bundlePath, baselineRef+":"+baselineRef); err != nil {
		return err
	}
	if _, err := g.git(ctx, g.Workspace, "checkout", "--quiet", "-b", "pi-auto-draft", baseline); err != nil {
		return err
	}
	if _, err := g.git(ctx, g.Workspace, "reset", "--hard", "--quiet", baseline); err != nil {
		return err
	}
	for key, value := range map[string]string{
		"user.name": "Pi Auto", "user.email": "pi-auto@localhost", "commit.gpgSign": "false", "core.hooksPath": "/dev/null",
	} {
		if _, err := g.git(ctx, g.Workspace, "config", "--local", key, value); err != nil {
			return err
		}
	}
	record := state{SchemaVersion: stateSchema, SessionID: g.SessionID, InputSHA256: transfer.SHA256, Baseline: baseline}
	if err := writeState(filepath.Join(controlDir, "state.json"), record); err != nil {
		return err
	}
	return g.verifyRepository(ctx, baseline)
}

func (g GuestWorkspace) BeginSeal() error {
	if err := g.validate(); err != nil {
		return err
	}
	record, err := g.readState()
	if err != nil {
		return err
	}
	if record.Sealing {
		return nil
	}
	record.Sealing = true
	return writeState(filepath.Join(g.VolumeRoot, ".agentsh-draft", "state.json"), record)
}

func (g GuestWorkspace) Sealing() (bool, error) {
	record, err := g.readState()
	if err != nil {
		return false, err
	}
	return record.Sealing, nil
}

func (g GuestWorkspace) Seal(ctx context.Context) (guestcontrol.ArtifactTransfer, *os.File, error) {
	if err := g.validate(); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	record, err := g.readState()
	if err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	if !record.Sealing {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("Git Draft sealing intent is not durable")
	}
	resultPath := filepath.Join(g.VolumeRoot, ".agentsh-draft", "result.bundle")
	if record.Result != "" {
		file, err := os.Open(resultPath)
		if err != nil {
			return guestcontrol.ArtifactTransfer{}, nil, err
		}
		transfer := guestcontrol.ArtifactTransfer{Kind: guestcontrol.ArtifactKindGitResultBundle, SHA256: record.ResultSHA256, Size: record.ResultSize, BaselineCommit: record.Baseline, ResultCommit: record.Result}
		if err := verifyFile(file, transfer); err != nil {
			_ = file.Close()
			return guestcontrol.ArtifactTransfer{}, nil, err
		}
		return transfer, file, nil
	}
	if err := g.verifyRepository(ctx, record.Baseline); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	head, err := g.git(ctx, g.Workspace, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	head = strings.TrimSpace(head)
	if !validOID(head) {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("Git Draft HEAD object ID is invalid")
	}
	if _, err := g.git(ctx, g.Workspace, "merge-base", "--is-ancestor", record.Baseline, head); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("Git Draft history no longer descends from its baseline: %w", err)
	}
	if _, err := g.git(ctx, g.Workspace, "add", "-A", "--", "."); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	tree, err := g.git(ctx, g.Workspace, "write-tree")
	if err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	commitEnv := []string{
		"GIT_AUTHOR_NAME=AgentSH", "GIT_AUTHOR_EMAIL=agentsh@localhost",
		"GIT_COMMITTER_NAME=AgentSH", "GIT_COMMITTER_EMAIL=agentsh@localhost",
	}
	result, err := g.gitEnv(ctx, g.Workspace, commitEnv, "commit-tree", strings.TrimSpace(tree), "-p", head, "-m", "pi-auto result "+g.SessionID)
	if err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	result = strings.TrimSpace(result)
	if !validOID(result) {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("Git Draft result object ID is invalid")
	}
	if _, err := g.git(ctx, g.Workspace, "update-ref", resultRef, result); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	temporary := resultPath + ".tmp"
	_ = os.Remove(temporary)
	if _, err := g.git(ctx, g.Workspace, "bundle", "create", temporary, resultRef, "^"+record.Baseline); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	file, err := os.Open(temporary)
	if err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	transfer, err := describeFile(file, guestcontrol.ArtifactKindGitResultBundle)
	_ = file.Close()
	if err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	transfer.BaselineCommit = record.Baseline
	transfer.ResultCommit = result
	if err := os.Rename(temporary, resultPath); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	record.Sealing = true
	record.Result, record.ResultSHA256, record.ResultSize = result, transfer.SHA256, transfer.Size
	if err := writeState(filepath.Join(g.VolumeRoot, ".agentsh-draft", "state.json"), record); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, err
	}
	file, err = os.Open(resultPath)
	return transfer, file, err
}

func (g GuestWorkspace) bundleBaseline(ctx context.Context, path string) (string, error) {
	output, err := g.git(ctx, g.Workspace, "bundle", "list-heads", path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		return "", fmt.Errorf("Git Draft input must contain exactly one baseline ref")
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 2 || fields[1] != baselineRef || !validOID(fields[0]) {
		return "", fmt.Errorf("Git Draft input baseline ref is invalid")
	}
	return fields[0], nil
}

func (g GuestWorkspace) verifyRepository(ctx context.Context, baseline string) error {
	got, err := g.git(ctx, g.Workspace, "rev-parse", "--verify", baseline+"^{commit}")
	if err != nil || strings.TrimSpace(got) != baseline {
		return fmt.Errorf("Git Draft baseline repository verification failed: %w", err)
	}
	return nil
}

func (g GuestWorkspace) validate() error {
	if !strings.HasPrefix(g.SessionID, "session-") || !cleanAbsolute(g.Workspace) || !cleanAbsolute(g.VolumeRoot) || !cleanAbsolute(g.Git) || g.Workspace == g.VolumeRoot {
		return fmt.Errorf("Git Draft guest workspace configuration is invalid")
	}
	rel, relErr := filepath.Rel(g.VolumeRoot, g.Workspace)
	inside := relErr == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	if !inside {
		// Production exposes the volume's workspace subdirectory at the fixed
		// guest path through a bind mount. Prove that alias by exact inode/device
		// identity instead of trusting a lexically unrelated mountpoint.
		expected := filepath.Join(g.VolumeRoot, "workspace")
		workspaceInfo, workspaceErr := os.Lstat(g.Workspace)
		expectedInfo, expectedErr := os.Lstat(expected)
		if workspaceErr != nil || expectedErr != nil || !workspaceInfo.IsDir() || !expectedInfo.IsDir() ||
			workspaceInfo.Mode()&os.ModeSymlink != 0 || expectedInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(workspaceInfo, expectedInfo) {
			return fmt.Errorf("Git Draft workspace is outside its volume")
		}
	}
	return nil
}

func (g GuestWorkspace) readState() (state, error) {
	path := filepath.Join(g.VolumeRoot, ".agentsh-draft", "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return state{}, err
	}
	var record state
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.SchemaVersion != stateSchema || record.SessionID != g.SessionID || !validOID(record.Baseline) {
		return state{}, fmt.Errorf("Git Draft state is invalid")
	}
	resultPresent := record.Result != "" || record.ResultSHA256 != "" || record.ResultSize != 0
	if resultPresent && (!record.Sealing || !validOID(record.Result) || record.Result == record.Baseline || !validSHA256(record.ResultSHA256) || record.ResultSize <= 0) {
		return state{}, fmt.Errorf("Git Draft result state is invalid")
	}
	return record, nil
}

func (g GuestWorkspace) git(ctx context.Context, directory string, args ...string) (string, error) {
	return g.gitEnv(ctx, directory, nil, args...)
}

func (g GuestWorkspace) gitEnv(ctx context.Context, directory string, extra []string, args ...string) (string, error) {
	fixed := []string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false"}
	cmd := exec.CommandContext(ctx, g.Git, append(fixed, args...)...)
	cmd.Dir = directory
	cmd.Env = append([]string{"HOME=" + filepath.Join(g.VolumeRoot, ".agentsh-home"), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1", "LC_ALL=C"}, extra...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("trusted Git operation %q failed: %s", args[0], bounded(string(output)))
	}
	return string(output), nil
}

func writeState(path string, record state) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := tmp.Write(append(data, '\n'))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func describeFile(file *os.File, kind string) (guestcontrol.ArtifactTransfer, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return guestcontrol.ArtifactTransfer{}, err
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, io.LimitReader(file, guestcontrol.MaxArtifactTransferBytes+1))
	if err != nil || size > guestcontrol.MaxArtifactTransferBytes {
		return guestcontrol.ArtifactTransfer{}, fmt.Errorf("Git Draft artifact exceeds its limit")
	}
	_, _ = file.Seek(0, io.SeekStart)
	return guestcontrol.ArtifactTransfer{Kind: kind, SHA256: "sha256:" + hex.EncodeToString(hasher.Sum(nil)), Size: size}, nil
}

func verifyFile(file *os.File, transfer guestcontrol.ArtifactTransfer) error {
	got, err := describeFile(file, transfer.Kind)
	if err != nil || got.Kind != transfer.Kind || got.SHA256 != transfer.SHA256 || got.Size != transfer.Size || transfer.Validate() != nil {
		return fmt.Errorf("Git Draft result artifact integrity check failed")
	}
	return nil
}

func syncDir(path string) error {
	handle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}
func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
func validOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
func bounded(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if len(value) > 2048 {
		value = value[:2048]
	}
	return value
}
