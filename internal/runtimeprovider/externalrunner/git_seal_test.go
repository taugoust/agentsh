//go:build linux

package externalrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
)

type fakeGitSealControl struct {
	data  []byte
	calls int
}

func (c *fakeGitSealControl) ExportArtifact(_ context.Context, kind string, destination io.Writer) (guestcontrol.ArtifactTransfer, error) {
	c.calls++
	if _, err := destination.Write(c.data); err != nil {
		return guestcontrol.ArtifactTransfer{}, err
	}
	sum := sha256.Sum256(c.data)
	return guestcontrol.ArtifactTransfer{
		Kind: kind, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(c.data)),
		BaselineCommit: strings.Repeat("1", 40), ResultCommit: strings.Repeat("2", 40),
	}, nil
}

func TestSealGitDraftPersistsExactResultAndIsIdempotent(t *testing.T) {
	stateDir, request, profile, guestManifest := prepareV2HostMonitorFixture(t)
	writeReadyProviderFixture(t, stateDir, request, profile, guestManifest)
	status, err := ReadHostMonitorStatus(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	providerManifest := runtimeprovider.Manifest{
		SchemaVersion: runtimeprovider.ManifestSchemaVersion, ContractVersion: runtimeprovider.ContractVersion,
		Provider: ProviderName, Profile: profile.Name, SessionID: request.SessionID, StateDir: stateDir,
		State: runtimeprovider.StateReady, CreatedAt: now, UpdatedAt: now, CleanupIntentKnown: true,
		Identity: runtimeprovider.Identity{
			ContractVersion: runtimeprovider.ContractVersion, Provider: ProviderName, Profile: profile.Name, SessionID: request.SessionID,
			Generation: status.Guest.Generation, IncarnationID: status.Guest.IncarnationID,
			OwnerPID: status.Monitor.PID, OwnerStartIdentity: status.Monitor.StartIdentity, BootID: status.Monitor.BootID,
		},
		Endpoint: *status.Endpoint,
	}
	if err := runtimeprovider.WriteManifest(stateDir, providerManifest); err != nil {
		t.Fatal(err)
	}
	control := &fakeGitSealControl{data: []byte("sealed result bundle")}
	previousControl := newGitSealControl
	previousVerify := verifyGitSealResult
	newGitSealControl = func(guestcontrol.Manifest) (gitSealControl, error) { return control, nil }
	verifyGitSealResult = func(context.Context, *os.File, *os.File, string, string) error { return nil }
	defer func() { newGitSealControl = previousControl; verifyGitSealResult = previousVerify }()

	// The delivery copy is guest-visible and therefore untrusted. Corrupting it
	// after readiness must not alter the host-authoritative manifest used to seal.
	layout := HostMonitorLayoutMust(stateDir)
	if err := os.WriteFile(layout.GuestManifestDelivery, []byte("guest-controlled\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := SealGitDraft(context.Background(), request.SessionID, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if first.BaselineCommit != strings.Repeat("1", 40) || first.ResultCommit != strings.Repeat("2", 40) || first.ResultArtifact.Kind != artifact.KindGitResultBundle {
		t.Fatalf("sealed result = %+v", first)
	}
	exportPath := filepath.Join(t.TempDir(), "result.bundle")
	exportedRecord, err := ExportGitDraftResult(context.Background(), request.SessionID, stateDir, exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if exportedRecord != first {
		t.Fatalf("exported record = %+v", exportedRecord)
	}
	if exportedData, err := os.ReadFile(exportPath); err != nil || string(exportedData) != string(control.data) {
		t.Fatalf("exported data = %q, %v", exportedData, err)
	}

	second, err := SealGitDraft(context.Background(), request.SessionID, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if second != first || control.calls != 1 {
		t.Fatalf("idempotent seal = %+v calls=%d", second, control.calls)
	}
	store, err := artifact.NewStore(stateDir, request.SessionID, guestcontrol.MaxArtifactTransferBytes)
	if err != nil {
		t.Fatal(err)
	}
	file, descriptor, err := store.Open(context.Background(), first.ResultArtifact.ArtifactID, artifact.KindGitResultBundle)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(file)
	_ = file.Close()
	if descriptor != first.ResultArtifact || string(data) != string(control.data) {
		t.Fatalf("persisted result = %+v %q", descriptor, data)
	}

	stoppedStatus := status
	stoppedStatus.Revision++
	stoppedStatus.State = HostMonitorStopped
	stoppedStatus.UpdatedAt = time.Now().UTC()
	stoppedStatus.RunnerExit = &HostRunnerExit{ExitCode: 0}
	stoppedStatus.RunnerReaped = true
	stoppedStatus.RelayClosed = true
	stoppedStatus.VolumeClosed = true
	if err := writeHostMonitorStatus(HostMonitorLayoutMust(stateDir).StatusPath, stoppedStatus); err != nil {
		t.Fatal(err)
	}
	providerManifest.State = runtimeprovider.StateStopped
	providerManifest.CleanupComplete = true
	providerManifest.CleanupPending = false
	if err := runtimeprovider.WriteManifest(stateDir, providerManifest); err != nil {
		t.Fatal(err)
	}
	deletedVolumes := 0
	previousDelete := deleteGitDraftVolume
	deleteGitDraftVolume = func(context.Context, WorkspaceVolumeRequest, string) error { deletedVolumes++; return nil }
	defer func() { deleteGitDraftVolume = previousDelete }()
	terminal, err := FinalizeGitDraftStorage(context.Background(), request.SessionID, stateDir, "applied")
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Complete || !terminal.VolumeDeleted || !terminal.ArtifactsDeleted || deletedVolumes != 1 {
		t.Fatalf("terminal = %+v deletes=%d", terminal, deletedVolumes)
	}
	if _, err := FinalizeGitDraftStorage(context.Background(), request.SessionID, stateDir, "applied"); err != nil {
		t.Fatalf("repeated finalization: %v", err)
	}
	if _, err := FinalizeGitDraftStorage(context.Background(), request.SessionID, stateDir, "discarded"); err == nil {
		t.Fatal("conflicting terminal intent was accepted")
	}
}
