//go:build linux

package shadow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedAcceptBindsReviewAndReopensPending(t *testing.T) {
	realRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(realRoot, "value.txt"), []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseDir := t.TempDir()
	workspace, err := Create(context.Background(), "prepared-accept", realRoot, Options{BaseDir: baseDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Work, "value.txt"), []byte("draft\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	review, err := workspace.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := workspace.PrepareAccept(context.Background(), "finalization-one", review.Generation, review.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Phase != FinalizationPrepared {
		t.Fatalf("phase=%q", intent.Phase)
	}
	if _, err := workspace.Review(context.Background()); err == nil {
		t.Fatal("review advanced after finalization was prepared")
	}
	reopened, err := OpenMulti(context.Background(), workspace.ID, []RootSpec{{Path: realRoot}}, Options{BaseDir: baseDir}, workspace.Roots, workspace.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := reopened.PendingFinalization()
	if !ok || pending.ID != intent.ID || pending.Phase != FinalizationPrepared {
		t.Fatalf("pending=%+v ok=%v", pending, ok)
	}
	if err := reopened.ResumeFinalization(context.Background(), intent.ID); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(realRoot, "value.txt")); err != nil || string(data) != "draft\n" {
		t.Fatalf("accepted data=%q err=%v", data, err)
	}
}

func TestPreparedRejectIsDurableAndIdempotent(t *testing.T) {
	realRoot := t.TempDir()
	baseDir := t.TempDir()
	workspace, err := Create(context.Background(), "prepared-reject", realRoot, Options{BaseDir: baseDir})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := workspace.PrepareReject(context.Background(), "finalization-reject")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenMulti(context.Background(), workspace.ID, []RootSpec{{Path: realRoot}}, Options{BaseDir: baseDir}, workspace.Roots, workspace.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.ResumeFinalization(context.Background(), intent.ID); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ResumeFinalization(context.Background(), intent.ID); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if reopened.StateValue() != StateRejected {
		t.Fatalf("state=%q", reopened.StateValue())
	}
	if err := reopened.CleanupFinalized(); err != nil {
		t.Fatal(err)
	}
}
