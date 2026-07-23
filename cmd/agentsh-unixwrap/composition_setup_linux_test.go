//go:build linux && cgo

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishCompositionSetupRejectsSurvivingPoolPaths(t *testing.T) {
	state := &compositionSetupState{poolRoot: filepath.Join(t.TempDir(), "survivor")}
	if err := os.Mkdir(state.poolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishCompositionSetup(state); err == nil || !strings.Contains(err.Error(), "survived pre-enforcement cleanup") {
		t.Fatalf("publish survivor error = %v", err)
	}
}

func TestCompositionSetupCleanupRetainsFailedPathsForRetry(t *testing.T) {
	poolRoot := filepath.Join(t.TempDir(), ".agentsh-composition-pool-retry")
	slot := filepath.Join(poolRoot, "slot")
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(slot, "blocker")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := &compositionSetupState{poolRoot: poolRoot, poolSlots: []string{slot}}
	if err := state.cleanupPoolPaths(); err == nil {
		t.Fatal("non-empty construction slot was removed")
	}
	if state.poolRoot != poolRoot || len(state.poolSlots) != 1 || state.poolSlots[0] != slot {
		t.Fatalf("failed cleanup forgot surviving paths: %+v", state)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := state.cleanupPoolPaths(); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if state.poolRoot != "" || len(state.poolSlots) != 0 {
		t.Fatalf("successful cleanup retained paths: %+v", state)
	}
}

func TestCompositionSetupCleanupRemovesPoolNames(t *testing.T) {
	parent := t.TempDir()
	poolRoot := filepath.Join(parent, ".agentsh-composition-pool-test")
	if err := os.Mkdir(poolRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	state := &compositionSetupState{poolRoot: poolRoot}
	for index := 0; index < 3; index++ {
		slot := filepath.Join(poolRoot, string(rune('a'+index)))
		if err := os.Mkdir(slot, 0o700); err != nil {
			t.Fatal(err)
		}
		state.poolSlots = append(state.poolSlots, slot)
	}
	if err := state.cleanupPoolPaths(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(poolRoot); !os.IsNotExist(err) {
		t.Fatalf("pool root remains after cleanup: %v", err)
	}
	if err := state.cleanupPoolPaths(); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
}
