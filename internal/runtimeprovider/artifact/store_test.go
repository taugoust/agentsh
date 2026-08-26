//go:build linux

package artifact

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSessionID = "session-11111111-1111-4111-8111-111111111111"

func newTestStore(t *testing.T, maxBytes int64) (*Store, string) {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), testSessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(stateDir, testSessionID, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return store, stateDir
}

func TestStorePublishesAndReopensCompleteBundle(t *testing.T) {
	store, _ := newTestStore(t, 1024)
	descriptor, err := store.Put(context.Background(), KindGitInputBundle, strings.NewReader("bundle data"))
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.SessionID != testSessionID || descriptor.Kind != KindGitInputBundle || descriptor.Size != int64(len("bundle data")) || !descriptor.Complete {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	file, reopened, err := store.Open(context.Background(), descriptor.ArtifactID, KindGitInputBundle)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "bundle data" || reopened != descriptor {
		t.Fatalf("reopened = %#v, content = %q", reopened, content)
	}
	listed, err := store.List()
	if err != nil || len(listed) != 1 || listed[0] != descriptor {
		t.Fatalf("List = %#v, %v", listed, err)
	}
	if info, err := os.Stat(store.dataPath(descriptor.ArtifactID)); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("content permissions = %v, %v", info, err)
	}
}

func TestStoreOverflowPublishesNothing(t *testing.T) {
	store, _ := newTestStore(t, 4)
	if _, err := store.Put(context.Background(), KindGitResultBundle, strings.NewReader("12345")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Put error = %v, want ErrTooLarge", err)
	}
	assertNoPublishedArtifacts(t, store)
}

func TestStoreCancellationPublishesNothing(t *testing.T) {
	store, _ := newTestStore(t, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(ctx, KindGitInputBundle, strings.NewReader("data")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put error = %v, want context cancellation", err)
	}
	assertNoPublishedArtifacts(t, store)
}

func TestStoreRejectsTamperedContentAndDescriptor(t *testing.T) {
	t.Run("content", func(t *testing.T) {
		store, _ := newTestStore(t, 1024)
		descriptor, err := store.Put(context.Background(), KindGitResultBundle, strings.NewReader("original"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.dataPath(descriptor.ArtifactID), []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		if file, _, err := store.Open(context.Background(), descriptor.ArtifactID, KindGitResultBundle); !errors.Is(err, ErrCorrupt) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("descriptor", func(t *testing.T) {
		store, _ := newTestStore(t, 1024)
		descriptor, err := store.Put(context.Background(), KindGitResultBundle, strings.NewReader("original"))
		if err != nil {
			t.Fatal(err)
		}
		path := store.descriptorPath(descriptor.ArtifactID)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, []byte("{}\n")...)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if file, _, err := store.Open(context.Background(), descriptor.ArtifactID, KindGitResultBundle); !errors.Is(err, ErrInvalid) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("Open error = %v, want ErrInvalid", err)
		}
	})
}

func TestStoreRejectsReplacementAndCrossKindAccess(t *testing.T) {
	store, _ := newTestStore(t, 1024)
	descriptor, err := store.Put(context.Background(), KindGitInputBundle, strings.NewReader("input"))
	if err != nil {
		t.Fatal(err)
	}
	if file, _, err := store.Open(context.Background(), descriptor.ArtifactID, KindGitResultBundle); !errors.Is(err, ErrInvalid) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("cross-kind Open error = %v, want ErrInvalid", err)
	}
	path := store.dataPath(descriptor.ArtifactID)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(store.descriptorPath(descriptor.ArtifactID)), path); err != nil {
		t.Fatal(err)
	}
	if file, _, err := store.Open(context.Background(), descriptor.ArtifactID, KindGitInputBundle); !errors.Is(err, ErrCorrupt) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("replacement Open error = %v, want ErrCorrupt", err)
	}
}

func TestStoreDeleteIsIdempotentAndIdentityBound(t *testing.T) {
	store, _ := newTestStore(t, 1024)
	descriptor, err := store.Put(context.Background(), KindGitResultBundle, strings.NewReader("result"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(descriptor.ArtifactID, KindGitInputBundle); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-kind Delete error = %v, want ErrInvalid", err)
	}
	if err := store.Delete(descriptor.ArtifactID, KindGitResultBundle); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(descriptor.ArtifactID, KindGitResultBundle); err != nil {
		t.Fatalf("repeated Delete: %v", err)
	}
	if _, err := os.Lstat(store.dataPath(descriptor.ArtifactID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact content survived Delete: %v", err)
	}
}

func TestStoreReconcilesOrphanAndInterruptedDelete(t *testing.T) {
	store, stateDir := newTestStore(t, 1024)
	orphanID := "22222222-2222-4222-8222-222222222222"
	if err := os.WriteFile(store.dataPath(orphanID), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := store.Put(context.Background(), KindGitResultBundle, strings.NewReader("result"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(store.descriptorPath(descriptor.ArtifactID), store.tombstonePath(descriptor.ArtifactID)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(stateDir, testSessionID, 1024); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{store.dataPath(orphanID), store.dataPath(descriptor.ArtifactID), store.tombstonePath(descriptor.ArtifactID)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("reconciliation retained %s: %v", path, err)
		}
	}
}

func TestNewStoreRejectsUnboundAndSymlinkState(t *testing.T) {
	root := t.TempDir()
	unbound := filepath.Join(root, "different")
	if err := os.Mkdir(unbound, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(unbound, testSessionID, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbound NewStore error = %v", err)
	}
	direct := filepath.Join(root, testSessionID)
	if err := os.Mkdir(direct, 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(t.TempDir(), testSessionID)
	if err := os.Symlink(direct, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(linkRoot, testSessionID, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink NewStore error = %v", err)
	}

	intermediateState := filepath.Join(t.TempDir(), testSessionID)
	if err := os.Mkdir(intermediateState, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(intermediateState, "runtime")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(intermediateState, testSessionID, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("intermediate symlink NewStore error = %v", err)
	}
}

func assertNoPublishedArtifacts(t *testing.T, store *Store) {
	t.Helper()
	entries, err := os.ReadDir(store.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != ".lock" {
			t.Fatalf("operation left artifact file %s", entry.Name())
		}
	}
}
