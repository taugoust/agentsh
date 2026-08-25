package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/externalrunner"
)

func TestVerifyRuntimeWorkspaceBaselineReportsHostDrift(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-33333333-3333-4333-8333-333333333333"
	stateDir := filepath.Join(root, "sessions", sessionID)
	source := filepath.Join(root, "project")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file.txt"), []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	layout, err := externalrunner.HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.HostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	baseline, err := externalrunner.CaptureWorkspaceBaseline(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := externalrunner.WriteWorkspaceBaseline(layout.BaselinePath, baseline); err != nil {
		t.Fatal(err)
	}
	manifest := runtimeprovider.NewManifest(runtimeprovider.Request{
		Provider:  externalrunner.ProviderName,
		Profile:   "pi-linux-qemu-v1",
		SessionID: sessionID,
		StateDir:  stateDir,
	}, time.Now().UTC())
	manifest.State = runtimeprovider.StateFailed
	manifest.CleanupComplete = true
	if err := runtimeprovider.WriteManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}

	report, err := verifyRuntimeWorkspaceBaseline(context.Background(), sessionID, stateDir, source)
	if err != nil || !report.Clean || len(report.Drift) != 0 {
		t.Fatalf("clean report = %#v, %v", report, err)
	}
	if err := os.WriteFile(filepath.Join(source, "file.txt"), []byte("host changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err = verifyRuntimeWorkspaceBaseline(context.Background(), sessionID, stateDir, source)
	if err != nil || report.Clean || len(report.Drift) != 1 {
		t.Fatalf("drift report = %#v, %v", report, err)
	}
	if _, err := verifyRuntimeWorkspaceBaseline(context.Background(), sessionID, stateDir, filepath.Join(root, "other")); err == nil {
		t.Fatal("wrong source identity was accepted")
	}
}
