package session

import (
	"context"
	"testing"
	"time"
)

func TestOutputArtifact_DirenvEnvironmentAtomicOwnership(t *testing.T) {
	s := &Session{}
	generation, changed := s.ReplaceDirenvEnvironment(map[string]string{"PATH": "one", "DEV": "yes"})
	if !changed || generation != 1 {
		t.Fatalf("first replace = (%d,%v)", generation, changed)
	}
	snapshot, gotGeneration := s.DirenvEnvironment()
	snapshot["DEV"] = "mutated"
	again, _ := s.DirenvEnvironment()
	if gotGeneration != 1 || again["DEV"] != "yes" {
		t.Fatalf("private snapshot aliased or generation wrong: %#v generation=%d", again, gotGeneration)
	}
	generation, changed = s.ReplaceDirenvEnvironment(map[string]string{"PATH": "one", "DEV": "yes"})
	if changed || generation != 1 {
		t.Fatalf("unchanged replace = (%d,%v)", generation, changed)
	}
	generation, changed = s.ReplaceDirenvEnvironment(map[string]string{"PATH": "two"})
	if !changed || generation != 2 {
		t.Fatalf("replacement = (%d,%v)", generation, changed)
	}
	if snap := s.Snapshot(); snap.ID != "" {
		t.Fatalf("unexpected snapshot mutation: %#v", snap)
	}
}

func TestOutputArtifact_DirenvLockExecContextTimesOutWithoutInterleaving(t *testing.T) {
	s := &Session{}
	unlock := s.LockExec()
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if secondUnlock, err := s.LockExecContext(ctx); err == nil {
		secondUnlock()
		t.Fatal("concurrent admission unexpectedly succeeded")
	}
}
