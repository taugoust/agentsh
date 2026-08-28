package gitdraft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type InputReport struct {
	SchemaVersion  int    `json:"schema_version"`
	Repository     string `json:"repository"`
	Branch         string `json:"branch"`
	BaselineCommit string `json:"baseline_commit"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
}

func PrepareInputBundle(ctx context.Context, git, repository, output string) (InputReport, error) {
	if !cleanAbsolute(git) || !cleanAbsolute(repository) || !cleanAbsolute(output) || pathsOverlap(repository, output) {
		return InputReport{}, fmt.Errorf("Git Draft input preparation paths are invalid")
	}
	resolved, err := filepath.EvalSymlinks(repository)
	if err != nil {
		return InputReport{}, err
	}
	if resolved != repository {
		return InputReport{}, fmt.Errorf("Git Draft repository path must be canonical")
	}
	home, err := os.MkdirTemp("", "agentsh-git-prepare-home-*")
	if err != nil {
		return InputReport{}, err
	}
	defer os.RemoveAll(home)
	run := func(dir string, allowNoMatch bool, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, git, append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-c", "protocol.file.allow=always"}, args...)...)
		cmd.Dir = dir
		cmd.Env = []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1", "LC_ALL=C"}
		data, runErr := cmd.CombinedOutput()
		if allowNoMatch {
			if exit, ok := runErr.(*exec.ExitError); ok && exit.ExitCode() == 1 {
				return string(data), nil
			}
		}
		if runErr != nil {
			return "", fmt.Errorf("trusted Git preparation %q failed: %s", args[0], bounded(string(data)))
		}
		return string(data), nil
	}
	root, err := run(repository, false, "rev-parse", "--show-toplevel")
	if err != nil || strings.TrimSpace(root) != repository {
		return InputReport{}, fmt.Errorf("selected path is not one exact Git repository root")
	}
	gitDir, err := run(repository, false, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return InputReport{}, err
	}
	commonDir, err := run(repository, false, "rev-parse", "--git-common-dir")
	if err != nil {
		return InputReport{}, err
	}
	commonDir = strings.TrimSpace(commonDir)
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(repository, commonDir)
	}
	commonDir, _ = filepath.Abs(commonDir)
	if filepath.Clean(strings.TrimSpace(gitDir)) != filepath.Clean(commonDir) {
		return InputReport{}, fmt.Errorf("linked Git worktrees are unsupported for autonomous Drafts")
	}
	status, err := run(repository, false, "status", "--porcelain=v2", "--untracked-files=all", "--ignored=matching")
	if err != nil {
		return InputReport{}, err
	}
	if strings.TrimSpace(status) != "" {
		return InputReport{}, fmt.Errorf("autonomous Drafts require a clean repository without untracked or ignored files")
	}
	sparse, _ := run(repository, true, "config", "--bool", "core.sparseCheckout")
	if strings.TrimSpace(sparse) == "true" {
		return InputReport{}, fmt.Errorf("sparse checkout is unsupported for autonomous Drafts")
	}
	index, err := run(repository, false, "ls-files", "--stage")
	if err != nil {
		return InputReport{}, err
	}
	for _, line := range strings.Split(index, "\n") {
		if strings.HasPrefix(line, "160000 ") {
			return InputReport{}, fmt.Errorf("submodules are unsupported for autonomous Drafts")
		}
	}
	lfs, err := run(repository, true, "grep", "-I", "-n", "-E", `filter[[:space:]]*=[[:space:]]*lfs`, "HEAD", "--", ".gitattributes", ":(glob)**/.gitattributes")
	if err != nil {
		return InputReport{}, err
	}
	if strings.TrimSpace(lfs) != "" {
		return InputReport{}, fmt.Errorf("Git LFS attributes are unsupported for autonomous Drafts")
	}
	branch, err := run(repository, false, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || strings.TrimSpace(branch) == "" {
		return InputReport{}, fmt.Errorf("autonomous Drafts require a checked-out branch")
	}
	branch = strings.TrimSpace(branch)
	baseline, err := run(repository, false, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return InputReport{}, err
	}
	baseline = strings.TrimSpace(baseline)
	if !validOID(baseline) {
		return InputReport{}, fmt.Errorf("Git baseline object ID is invalid")
	}

	parent := filepath.Dir(output)
	work, err := os.MkdirTemp(parent, ".agentsh-git-input-*")
	if err != nil {
		return InputReport{}, err
	}
	defer os.RemoveAll(work)
	bare := filepath.Join(work, "repository.git")
	if err := os.Mkdir(bare, 0o700); err != nil {
		return InputReport{}, err
	}
	if _, err := run(bare, false, "init", "--quiet", "--bare"); err != nil {
		return InputReport{}, err
	}
	if _, err := run(bare, false, "fetch", "--quiet", "--no-tags", repository, baseline+":"+baselineRef); err != nil {
		return InputReport{}, err
	}
	bundle := filepath.Join(work, "input.bundle")
	if _, err := run(bare, false, "bundle", "create", bundle, baselineRef); err != nil {
		return InputReport{}, err
	}
	if err := os.Chmod(bundle, 0o600); err != nil {
		return InputReport{}, err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return InputReport{}, fmt.Errorf("Git input bundle output already exists")
		}
		return InputReport{}, err
	}
	if err := os.Link(bundle, output); err != nil {
		return InputReport{}, err
	}
	if err := syncDir(parent); err != nil {
		_ = os.Remove(output)
		return InputReport{}, err
	}
	file, err := os.Open(output)
	if err != nil {
		return InputReport{}, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return InputReport{}, err
	}
	return InputReport{SchemaVersion: 1, Repository: repository, Branch: branch, BaselineCommit: baseline, SHA256: "sha256:" + hex.EncodeToString(hasher.Sum(nil)), Size: size}, nil
}

func pathsOverlap(left, right string) bool {
	rel, err := filepath.Rel(left, right)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
