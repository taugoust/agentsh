//go:build linux

package externalrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCIDLeasesAreDurableAndConcurrent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cid-leases")
	const count = 16
	leases := make(chan CIDLease, count)
	errorsCh := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			lease, err := AllocateCID(context.Background(), root, "session-concurrent-"+strings.Repeat("x", index+1), 41000, 41015)
			if err != nil {
				errorsCh <- err
				return
			}
			leases <- lease
		}(index)
	}
	group.Wait()
	close(leases)
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}

	seen := make(map[uint32]CIDLease, count)
	for lease := range leases {
		if _, exists := seen[lease.CID]; exists {
			t.Fatalf("CID %d was leased more than once", lease.CID)
		}
		seen[lease.CID] = lease
		if err := VerifyCIDLease(context.Background(), root, lease, 41000, 41015); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != count {
		t.Fatalf("allocated %d CIDs, want %d", len(seen), count)
	}
	if _, err := AllocateCID(context.Background(), root, "session-exhausted", 41000, 41015); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhausted allocation error = %v", err)
	}
	for _, lease := range seen {
		if err := ReleaseCID(context.Background(), root, lease, 41000, 41015); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCIDLeaseReleaseRequiresExactIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cid-leases")
	lease, err := AllocateCID(context.Background(), root, "session-exact", 42000, 42000)
	if err != nil {
		t.Fatal(err)
	}
	wrong := lease
	wrong.LeaseID = strings.Repeat("9", 64)
	if err := ReleaseCID(context.Background(), root, wrong, 42000, 42000); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("wrong lease release error = %v", err)
	}
	if err := VerifyCIDLease(context.Background(), root, lease, 42000, 42000); err != nil {
		t.Fatalf("wrong release removed the exact lease: %v", err)
	}
	if err := ReleaseCID(context.Background(), root, lease, 42000, 42000); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCIDLease(context.Background(), root, lease, 42000, 42000); err == nil {
		t.Fatal("released CID lease still verifies")
	}
}

func TestCIDLeaseRejectsUnsafeRootAndHonorsLockCancellation(t *testing.T) {
	unsafeRoot := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := AllocateCID(context.Background(), unsafeRoot, "session-unsafe", 43000, 43001); err == nil {
		t.Fatal("CID allocator accepted a non-private lease root")
	}

	root := filepath.Join(t.TempDir(), "cid-leases")
	lock, dir, err := acquireCIDLock(context.Background(), root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	defer dir.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := AllocateCID(ctx, root, "session-cancelled", 43000, 43001); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended allocation error = %v", err)
	}
}
