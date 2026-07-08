package api

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestAddExecveApprovalHints_AppendsStderrAndSuggestions(t *testing.T) {
	blockedOps := []types.Event{
		{
			Type:        "execve",
			Filename:    "/nix/store/abc-getent/bin/getent",
			RawFilename: "/run/current-system/sw/bin/getent",
			Argv:        []string{"getent", "hosts", "matebook.local"},
			Policy: &types.PolicyInfo{
				Decision:          types.DecisionApprove,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "approve-unknown-nix-store-executables",
				Message:           "approval timeout",
			},
		},
	}
	stderr := []byte("orig\n")
	stderrTotal := int64(len(stderr))

	newStderr, newTotal, suggestions := addExecveApprovalHints(blockedOps, stderr, stderrTotal)

	if !strings.Contains(string(newStderr), "nested exec approval timed out") {
		t.Fatalf("stderr hint missing approval timeout: %s", string(newStderr))
	}
	if !strings.Contains(string(newStderr), "getent hosts matebook.local") {
		t.Fatalf("stderr hint missing argv: %s", string(newStderr))
	}
	if newTotal <= stderrTotal {
		t.Fatalf("stderrTotal not incremented: old=%d new=%d", stderrTotal, newTotal)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].Action != "retry_after_approval" {
		t.Fatalf("unexpected suggestion action: %s", suggestions[0].Action)
	}
}

func TestAddSoftDeleteHints_AppendsStderrAndSuggestions(t *testing.T) {
	fileOps := []types.Event{
		{Type: "file_soft_deleted", Path: "/workspace/a.txt", Fields: map[string]any{"trash_token": "tok123"}},
	}
	stderr := []byte("orig\n")
	stderrTotal := int64(len(stderr))

	newStderr, newTotal, suggestions := addSoftDeleteHints(fileOps, stderr, stderrTotal)

	if !strings.Contains(string(newStderr), "restore with: agentsh trash restore tok123") {
		t.Fatalf("stderr hint missing restore command: %s", string(newStderr))
	}
	if newTotal <= stderrTotal {
		t.Fatalf("stderrTotal not incremented: old=%d new=%d", stderrTotal, newTotal)
	}
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].Command != "agentsh trash restore tok123" {
		t.Fatalf("unexpected suggestion command: %s", suggestions[0].Command)
	}
}
