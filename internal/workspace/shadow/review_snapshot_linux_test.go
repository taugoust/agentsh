//go:build linux

package shadow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedReviewTamperingFailsRecovery(t *testing.T) {
	realRoot := t.TempDir()
	baseDir := t.TempDir()
	workspace, err := Create(context.Background(), "tampered-review", realRoot, Options{BaseDir: baseDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Review(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(workspace.reviewPath())
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"base_hash": "sha256:`, `"base_hash": "sha256:0`, 1))
	if err := os.WriteFile(workspace.reviewPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMulti(context.Background(), workspace.ID, []RootSpec{{Path: realRoot}}, Options{BaseDir: baseDir}, workspace.Roots, workspace.CreatedAt); err == nil {
		t.Fatal("tampered retained review was accepted")
	}
}

func TestPreparedAcceptRefusesRealChangeBeforeMutation(t *testing.T) {
	realRoot := t.TempDir()
	value := filepath.Join(realRoot, "value.txt")
	if err := os.WriteFile(value, []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workspace, err := Create(context.Background(), "real-precondition", realRoot, Options{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Work, "value.txt"), []byte("reviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	review, err := workspace.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := workspace.PrepareAccept(context.Background(), "real-precondition-finalization", review.Generation, review.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(value, []byte("external\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := workspace.ApplyFinalization(context.Background(), intent.ID); !errors.Is(err, ErrStaleReview) {
		t.Fatalf("ApplyFinalization error=%v", err)
	}
	data, err := os.ReadFile(value)
	if err != nil || string(data) != "external\n" {
		t.Fatalf("real workspace was mutated before stale check: %q %v", data, err)
	}
}

func TestPreparedRejectsOverlappingWorkspaceTopology(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateMulti(context.Background(), "nested", []RootSpec{{Name: "parent", Path: parent}, {Name: "child", Path: child}}, Options{BaseDir: t.TempDir()}); err == nil {
		t.Fatal("nested workspace roots were accepted")
	}
	baseInsideReal := filepath.Join(parent, "shadow-state")
	if _, err := Create(context.Background(), "overlap", parent, Options{BaseDir: baseInsideReal}); err == nil {
		t.Fatal("shadow state inside real workspace was accepted")
	}
}

func TestPreparedAcceptUsesImmutableReviewedSnapshot(t *testing.T) {
	realRoot := t.TempDir()
	value := filepath.Join(realRoot, "value.txt")
	if err := os.WriteFile(value, []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workspace, err := Create(context.Background(), "immutable-snapshot", realRoot, Options{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	workValue := filepath.Join(workspace.Work, "value.txt")
	if err := os.WriteFile(workValue, []byte("reviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	review, err := workspace.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := workspace.PrepareAccept(context.Background(), "immutable-finalization", review.Generation, review.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workValue, []byte("unreviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := workspace.ApplyFinalization(context.Background(), intent.ID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(value)
	if err != nil || string(data) != "reviewed\n" {
		t.Fatalf("accepted content=%q err=%v", data, err)
	}
}
