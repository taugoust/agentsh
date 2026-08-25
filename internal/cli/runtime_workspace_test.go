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

func TestApplyReviewedRuntimeWorkspaceJournalsAndResumes(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-44444444-4444-4444-8444-444444444444"
	stateDir := filepath.Join(root, "sessions", sessionID)
	source := filepath.Join(root, "project")
	layout, err := externalrunner.HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.WorkspaceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.HostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := externalrunner.CaptureWorkspaceBaseline(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := externalrunner.WriteWorkspaceBaseline(layout.BaselinePath, baseline); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.WorkspaceDir, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.WorkspaceDir, "guest.txt"), []byte("guest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeStoppedExternalManifest(t, sessionID, stateDir)

	report, err := applyReviewedRuntimeWorkspace(context.Background(), sessionID, stateDir, source)
	if err != nil || !report.Applied || report.Phase != "applied" || report.FinalizationID == "" {
		t.Fatalf("Apply report = %#v, %v", report, err)
	}
	if content, err := os.ReadFile(filepath.Join(source, "guest.txt")); err != nil || string(content) != "guest\n" {
		t.Fatalf("applied content = %q, %v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(layout.RuntimeDir, "finalization.json")); err != nil {
		t.Fatalf("durable finalization journal: %v", err)
	}
	repeated, err := applyReviewedRuntimeWorkspace(context.Background(), sessionID, stateDir, source)
	if err != nil || !repeated.Applied || repeated.FinalizationID != report.FinalizationID {
		t.Fatalf("idempotent Apply report = %#v, %v", repeated, err)
	}
}

func TestApplyReviewedRuntimeWorkspaceRefusesHostDrift(t *testing.T) {
	root := t.TempDir()
	sessionID := "session-55555555-5555-4555-8555-555555555555"
	stateDir := filepath.Join(root, "sessions", sessionID)
	source := filepath.Join(root, "project")
	layout, err := externalrunner.HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.WorkspaceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.HostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, err := externalrunner.CaptureWorkspaceBaseline(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := externalrunner.WriteWorkspaceBaseline(layout.BaselinePath, baseline); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.WorkspaceDir, "base.txt"), []byte("guest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "base.txt"), []byte("host changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeStoppedExternalManifest(t, sessionID, stateDir)

	if _, err := applyReviewedRuntimeWorkspace(context.Background(), sessionID, stateDir, source); err == nil {
		t.Fatal("Apply accepted host drift")
	}
	if content, err := os.ReadFile(filepath.Join(source, "base.txt")); err != nil || string(content) != "host changed\n" {
		t.Fatalf("host drift was overwritten: %q, %v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(layout.RuntimeDir, "finalization.json")); !os.IsNotExist(err) {
		t.Fatalf("finalization was prepared after drift: %v", err)
	}
}

func writeStoppedExternalManifest(t *testing.T, sessionID, stateDir string) {
	t.Helper()
	manifest := runtimeprovider.NewManifest(runtimeprovider.Request{
		Provider:  externalrunner.ProviderName,
		Profile:   "pi-linux-qemu-v1",
		SessionID: sessionID,
		StateDir:  stateDir,
	}, time.Now().UTC())
	manifest.State = runtimeprovider.StateStopped
	manifest.Identity = runtimeprovider.Identity{
		ContractVersion:    runtimeprovider.ContractVersion,
		Provider:           externalrunner.ProviderName,
		Profile:            "pi-linux-qemu-v1",
		SessionID:          sessionID,
		Generation:         1,
		IncarnationID:      "11111111-1111-4111-8111-111111111111",
		OwnerPID:           123,
		OwnerStartIdentity: "start",
		BootID:             "boot",
	}
	manifest.Endpoint = runtimeprovider.Endpoint{Transport: "unix", Address: filepath.Join(stateDir, "supervisor.sock")}
	manifest.CleanupComplete = true
	if err := runtimeprovider.WriteManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
}

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
