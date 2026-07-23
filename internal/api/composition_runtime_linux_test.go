//go:build linux

package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestCompositionRuntimePreflightAcceptsExistingStaticRoot(t *testing.T) {
	root := t.TempDir()
	app := &App{cfg: &config.Config{}}
	app.cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = root
	evidence, err := app.CompositionRuntimePreflight()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mode != "static" || evidence.ScratchRoot != root || evidence.LeaseID != "" {
		t.Fatalf("evidence = %+v", evidence)
	}
}

func TestCompositionRuntimeAutoRequiresProtectedLeaseMetadata(t *testing.T) {
	app := &App{cfg: &config.Config{}, nethelperBinding: &nethelperBindingState{}}
	app.cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = config.CompositionScratchRootAuto
	_, err := app.CompositionRuntimePreflight()
	if err == nil || !strings.Contains(err.Error(), "active ephemeral helper lease") {
		t.Fatalf("preflight error = %v", err)
	}
}

func TestValidateLeaseCompositionScratchRootRejectsArbitraryPath(t *testing.T) {
	runtimeDir := t.TempDir()
	path := filepath.Join(t.TempDir(), "composition")
	if err := validateLeaseCompositionScratchRoot(path, runtimeDir); err == nil {
		t.Fatal("arbitrary composition path accepted")
	}
}
