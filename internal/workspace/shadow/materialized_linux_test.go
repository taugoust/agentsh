//go:build linux

package shadow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaterializedWorkspaceUsesJournaledConflictRefusingAccept(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	work := filepath.Join(root, "runtime", "workspace")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "guest.txt"), []byte("guest\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	workspace, err := OpenMaterialized(context.Background(), "session-materialized", real, work, Options{}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	review, err := workspace.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "base.txt"), []byte("host changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.PrepareAccept(context.Background(), "finalization-conflict", review.Generation, review.Hash); !errors.Is(err, ErrStaleReview) {
		t.Fatalf("PrepareAccept after host drift error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(real, "guest.txt")); !os.IsNotExist(err) {
		t.Fatalf("guest content was applied despite conflict: %v", err)
	}
}

func TestMaterializedWorkspacePersistsAndResumesAccept(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	work := filepath.Join(root, "runtime", "workspace")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "base.txt"), []byte("guest replacement\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	createdAt := time.Now().UTC()
	workspace, err := OpenMaterialized(context.Background(), "session-materialized", real, work, Options{}, createdAt)
	if err != nil {
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
		t.Fatalf("prepared phase = %q", intent.Phase)
	}

	reopened, err := OpenMaterialized(context.Background(), "session-materialized", real, work, Options{}, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := reopened.PendingFinalization()
	if !ok || pending.ID != intent.ID || pending.Phase != FinalizationPrepared {
		t.Fatalf("pending finalization = %#v, %v", pending, ok)
	}
	if err := reopened.ResumeFinalization(context.Background(), intent.ID); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(real, "base.txt"))
	if err != nil || string(content) != "guest replacement\n" {
		t.Fatalf("accepted content = %q, %v", content, err)
	}

	completed, err := OpenMaterialized(context.Background(), "session-materialized", real, work, Options{}, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	finalized, ok := completed.PendingFinalization()
	if !ok || finalized.Phase != FinalizationApplied || completed.StateValue() != StateAccepted {
		t.Fatalf("completed finalization = %#v, state=%q", finalized, completed.StateValue())
	}
	if err := completed.ResumeFinalization(context.Background(), intent.ID); err != nil {
		t.Fatalf("idempotent resume: %v", err)
	}
}
