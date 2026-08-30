//go:build linux

package externalrunner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func TestRecoverV3RotatesEgressIdentityAndArchivesGeneration(t *testing.T) {
	stateDir, request, profile, oldManifest := prepareV3HostMonitorFixture(t)
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	status := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersionV3, Revision: 2, MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: profile.Name, ExternalProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest, VolumeID: request.VolumeID,
		State: HostMonitorStopped, CreatedAt: now, UpdatedAt: now,
		Monitor:    HostProcessIdentity{PID: 999999, StartIdentity: "dead-monitor", BootID: "dead-boot"},
		Runner:     &HostProcessIdentity{PID: 999998, ProcessGroup: 999998, StartIdentity: "dead-runner", BootID: "dead-boot"},
		RunnerExit: &HostRunnerExit{ExitCode: 0}, RunnerReaped: true, RelayClosed: true, VolumeClosed: true, EgressBrokerClosed: true,
	}
	if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(ProviderOptions{
		Enabled: true, Profiles: map[string]string{profile.Name: request.ProfileFile}, CIDLeaseRoot: request.CIDLeaseRoot,
		MonitorExecutable: filepath.Join(t.TempDir(), "missing-agentsh"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.recoverV2(context.Background(), request.SessionID, stateDir, profile.Name); err == nil {
		t.Fatal("recovery unexpectedly launched a missing monitor")
	}
	next, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	var nextManifest guestcontrol.Manifest
	if err := readStrictPrivateJSON(layout.GuestManifest, &nextManifest); err != nil {
		t.Fatal(err)
	}
	if next.ExpectedGuestGeneration != request.ExpectedGuestGeneration+1 || next.EgressPort != request.EgressPort || nextManifest.EgressPort != next.EgressPort ||
		nextManifest.EgressToken == oldManifest.EgressToken || nextManifest.EgressToken == "" {
		t.Fatalf("recovered v3 identity request=%+v manifest=%+v", next, nextManifest)
	}
	archive := filepath.Join(layout.RuntimeDir, "generations", "generation-00000000000000000001")
	if _, err := os.Stat(filepath.Join(archive, "host", HostMonitorRequestName)); err != nil {
		t.Fatalf("archived request: %v", err)
	}
}

func TestRecoverV2DurablyArchivesGenerationBeforeRelaunch(t *testing.T) {
	stateDir, request, profile, _ := prepareV2HostMonitorFixture(t)
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	status := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersionV2, Revision: 2, MonitorID: request.MonitorID, SessionID: request.SessionID,
		Profile: profile.Name, ExternalProfileDigest: profile.ProfileDigest, GuestProfileDigest: profile.Guest.ProfileDigest, VolumeID: request.VolumeID,
		State: HostMonitorStopped, CreatedAt: now, UpdatedAt: now,
		Monitor:    HostProcessIdentity{PID: 999999, StartIdentity: "dead-monitor", BootID: "dead-boot"},
		Runner:     &HostProcessIdentity{PID: 999998, ProcessGroup: 999998, StartIdentity: "dead-runner", BootID: "dead-boot"},
		RunnerExit: &HostRunnerExit{ExitCode: 0}, RunnerReaped: true, RelayClosed: true, VolumeClosed: true,
	}
	if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(ProviderOptions{
		Enabled: true, Profiles: map[string]string{profile.Name: request.ProfileFile}, CIDLeaseRoot: request.CIDLeaseRoot,
		MonitorExecutable: filepath.Join(t.TempDir(), "missing-agentsh"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.recoverV2(context.Background(), request.SessionID, stateDir, profile.Name); err == nil {
		t.Fatal("recovery unexpectedly launched a missing monitor")
	}
	next, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if next.ExpectedGuestGeneration != request.ExpectedGuestGeneration+1 || next.VolumeID != request.VolumeID || next.CIDLease != request.CIDLease || next.InputArtifact == nil || *next.InputArtifact != *request.InputArtifact {
		t.Fatalf("next generation request = %+v", next)
	}
	archive := filepath.Join(layout.RuntimeDir, "generations", "generation-00000000000000000001")
	if _, err := os.Stat(filepath.Join(archive, "host", HostMonitorRequestName)); err != nil {
		t.Fatalf("archived request: %v", err)
	}
	if _, err := os.Stat(filepath.Join(layout.RuntimeDir, v2RecoveryRecordName)); err != nil {
		t.Fatalf("recovery transaction: %v", err)
	}
	if _, err := provider.recoverV2(context.Background(), request.SessionID, stateDir, profile.Name); err == nil {
		t.Fatal("retry unexpectedly launched a missing monitor")
	}
	retried, err := ReadHostMonitorRequest(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if retried.MonitorID != next.MonitorID || retried.ExpectedGuestGeneration != next.ExpectedGuestGeneration {
		t.Fatal("retry replaced the durable next-generation identity")
	}
}
