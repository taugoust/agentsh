package gitdraft

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func VerifyResultBundles(ctx context.Context, git string, inputBundle, resultBundle *os.File, baseline, result string) error {
	if !cleanAbsolute(git) || inputBundle == nil || resultBundle == nil || !validOID(baseline) || !validOID(result) || baseline == result {
		return fmt.Errorf("Git Draft verification identity is invalid")
	}
	temporary, err := os.MkdirTemp("", "agentsh-git-draft-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	inputPath := filepath.Join(string(filepath.Separator), "proc", "self", "fd", "3")
	resultPath := filepath.Join(string(filepath.Separator), "proc", "self", "fd", "4")
	run := func(args ...string) (string, error) {
		if _, err := inputBundle.Seek(0, 0); err != nil {
			return "", err
		}
		if _, err := resultBundle.Seek(0, 0); err != nil {
			return "", err
		}
		cmd := exec.CommandContext(ctx, git, append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false"}, args...)...)
		cmd.Dir = temporary
		cmd.ExtraFiles = []*os.File{inputBundle, resultBundle}
		cmd.Env = []string{"HOME=" + temporary, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1", "LC_ALL=C"}
		output, runErr := cmd.CombinedOutput()
		if runErr != nil {
			return "", fmt.Errorf("trusted Git verification %q failed: %s", args[0], bounded(string(output)))
		}
		return string(output), nil
	}
	if _, err := run("init", "--quiet", "--bare"); err != nil {
		return err
	}
	inputHeads, err := run("bundle", "list-heads", inputPath)
	if err != nil {
		return err
	}
	if fields := strings.Fields(strings.TrimSpace(inputHeads)); len(fields) != 2 || fields[0] != baseline || fields[1] != baselineRef {
		return fmt.Errorf("Git Draft input bundle baseline identity changed")
	}
	if _, err := run("fetch", "--quiet", "--no-tags", inputPath, baselineRef+":"+baselineRef); err != nil {
		return err
	}
	if _, err := run("bundle", "verify", resultPath); err != nil {
		return err
	}
	resultHeads, err := run("bundle", "list-heads", resultPath)
	if err != nil {
		return err
	}
	if fields := strings.Fields(strings.TrimSpace(resultHeads)); len(fields) != 2 || fields[0] != result || fields[1] != resultRef {
		return fmt.Errorf("Git Draft result bundle has unexpected heads")
	}
	if _, err := run("fetch", "--quiet", "--no-tags", resultPath, resultRef+":"+resultRef); err != nil {
		return err
	}
	if _, err := run("merge-base", "--is-ancestor", baselineRef, resultRef); err != nil {
		return fmt.Errorf("Git Draft result history does not descend from its baseline: %w", err)
	}
	commits, err := run("rev-list", "--count", baselineRef+".."+resultRef)
	if err != nil || strings.TrimSpace(commits) == "0" {
		return fmt.Errorf("Git Draft result history is empty: %w", err)
	}
	if got, err := run("rev-parse", "--verify", resultRef+"^{commit}"); err != nil || strings.TrimSpace(got) != result {
		return fmt.Errorf("Git Draft result commit verification failed: %w", err)
	}
	return nil
}
