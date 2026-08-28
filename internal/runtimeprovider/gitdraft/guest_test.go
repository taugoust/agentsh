package gitdraft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func TestGuestWorkspaceImportsAndSealsExactGitBundles(t *testing.T) {
	git := os.Getenv("AGENTSH_TEST_GIT")
	if git == "" {
		var err error
		git, err = exec.LookPath("git")
		if err != nil {
			t.Skip("git is unavailable in this test environment")
		}
	}
	ctx := context.Background()
	source := t.TempDir()
	runTestGit(t, git, source, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, git, source, "add", "README.md")
	runTestGitEnv(t, git, source, []string{"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.invalid"}, "commit", "--quiet", "-m", "baseline")
	baseline := strings.TrimSpace(runTestGit(t, git, source, "rev-parse", "HEAD"))
	inputPath := filepath.Join(t.TempDir(), "input.bundle")
	prepared, err := PrepareInputBundle(ctx, git, source, inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.BaselineCommit != baseline || prepared.Size <= 0 || prepared.SHA256 == "" {
		t.Fatalf("prepared input = %+v", prepared)
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	transfer := testTransfer(guestcontrol.ArtifactKindGitInputBundle, input)

	volume := t.TempDir()
	workspace := filepath.Join(volume, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	draft := GuestWorkspace{SessionID: "session-11111111-1111-4111-8111-111111111111", Workspace: workspace, VolumeRoot: volume, Git: git}
	if err := draft.Import(ctx, transfer, bytes.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(workspace, "README.md")); err != nil || string(data) != "baseline\n" {
		t.Fatalf("imported README = %q, %v", data, err)
	}
	if err := draft.Import(ctx, transfer, bytes.NewReader(input)); err != nil {
		t.Fatalf("idempotent import: %v", err)
	}

	if branch := strings.TrimSpace(runTestGit(t, git, workspace, "branch", "--show-current")); branch != "pi-auto-draft" {
		t.Fatalf("draft branch = %q", branch)
	}
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("committed result\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, git, workspace, "add", "README.md")
	runTestGit(t, git, workspace, "commit", "--quiet", "-m", "agent commit")
	agentCommit := strings.TrimSpace(runTestGit(t, git, workspace, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("result\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(workspace, "README.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "new.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := draft.BeginSeal(); err != nil {
		t.Fatal(err)
	}
	if sealing, err := draft.Sealing(); err != nil || !sealing {
		t.Fatalf("sealing intent = %t, %v", sealing, err)
	}
	resultTransfer, resultFile, err := draft.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resultBytes, err := io.ReadAll(resultFile)
	_ = resultFile.Close()
	expectedResultBytes := testTransfer(guestcontrol.ArtifactKindGitResultBundle, resultBytes)
	if err != nil || resultTransfer.Kind != expectedResultBytes.Kind || resultTransfer.SHA256 != expectedResultBytes.SHA256 || resultTransfer.Size != expectedResultBytes.Size ||
		resultTransfer.BaselineCommit != baseline || resultTransfer.ResultCommit == "" {
		t.Fatalf("result artifact = %+v, %v", resultTransfer, err)
	}
	secondTransfer, secondFile, err := draft.Seal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, _ := io.ReadAll(secondFile)
	_ = secondFile.Close()
	if secondTransfer != resultTransfer || !bytes.Equal(secondBytes, resultBytes) {
		t.Fatal("repeated seal changed the immutable result")
	}

	verify := t.TempDir()
	runTestGit(t, git, verify, "init", "--quiet")
	runTestGit(t, git, verify, "fetch", "--quiet", inputPath, baselineRef+":"+baselineRef)
	resultPath := filepath.Join(t.TempDir(), "result.bundle")
	if err := os.WriteFile(resultPath, resultBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	inputFile, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	verifyResultFile, err := os.Open(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResultBundles(ctx, git, inputFile, verifyResultFile, resultTransfer.BaselineCommit, resultTransfer.ResultCommit); err != nil {
		t.Fatal(err)
	}
	_ = inputFile.Close()
	_ = verifyResultFile.Close()
	runTestGit(t, git, verify, "fetch", "--quiet", resultPath, resultRef+":"+resultRef)
	parent := strings.TrimSpace(runTestGit(t, git, verify, "rev-parse", resultRef+"^"))
	if parent != agentCommit {
		t.Fatalf("result parent = %s, want preserved agent commit %s", parent, agentCommit)
	}
	if count := strings.TrimSpace(runTestGit(t, git, verify, "rev-list", "--count", baseline+".."+resultRef)); count != "2" {
		t.Fatalf("result history count = %s, want 2", count)
	}
	mode := strings.Fields(runTestGit(t, git, verify, "ls-tree", resultRef, "README.md"))[0]
	if mode != "100755" {
		t.Fatalf("result executable mode = %s", mode)
	}
}

func TestGuestWorkspaceRejectsSubstitutedInput(t *testing.T) {
	git := os.Getenv("AGENTSH_TEST_GIT")
	if git == "" {
		var err error
		git, err = exec.LookPath("git")
		if err != nil {
			t.Skip("git is unavailable")
		}
	}
	volume := t.TempDir()
	workspace := filepath.Join(volume, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	draft := GuestWorkspace{SessionID: "session-11111111-1111-4111-8111-111111111111", Workspace: workspace, VolumeRoot: volume, Git: git}
	transfer := testTransfer(guestcontrol.ArtifactKindGitInputBundle, []byte("expected"))
	if err := draft.Import(context.Background(), transfer, strings.NewReader("wrong!!!")); err == nil {
		t.Fatal("substituted input was accepted")
	}
}

func testTransfer(kind string, data []byte) guestcontrol.ArtifactTransfer {
	sum := sha256.Sum256(data)
	return guestcontrol.ArtifactTransfer{Kind: kind, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(data))}
}
func runTestGit(t *testing.T, git, dir string, args ...string) string {
	return runTestGitEnv(t, git, dir, nil, args...)
}
func runTestGitEnv(t *testing.T, git, dir string, extra []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}
