//go:build linux

package externalrunner

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestProviderPreflightAndStartRejectV2UntilHostMonitorIntegration(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("external runner provider preflight is x86_64-only")
	}
	profile := testProfile(t)
	profile.Schema = ProfileSchemaV2
	profile.Name = "pi-linux-qemu-v2"
	profile.WorkspaceVolume = &WorkspaceVolumeSpec{
		Model: WorkspaceVolumeModel, Format: WorkspaceVolumeFormat, Filesystem: WorkspaceVolumeFilesystem,
		RunnerFD: WorkspaceVolumeRunnerFD, VirtualSizeBytes: 8 << 30,
	}
	profilePath := writeProfile(t, profile)
	provider, err := NewProvider(ProviderOptions{
		Enabled: true, Profiles: map[string]string{profile.Name: profilePath},
		CIDLeaseRoot: filepath.Join(t.TempDir(), "cid-leases"), MonitorExecutable: filepath.Join(t.TempDir(), "agentsh"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "session-11111111-1111-4111-8111-111111111111"
	request := runtimeprovider.Request{
		SessionID: sessionID, Provider: ProviderName, Profile: profile.Name,
		StateDir: filepath.Join(t.TempDir(), sessionID),
		Session: types.CreateSessionRequest{
			ID: sessionID, Workspace: t.TempDir(), WorkspaceMode: string(types.WorkspaceModeShadow), Policy: profile.Guest.Policy,
		},
	}
	if _, err := provider.Preflight(context.Background(), request); err == nil || !strings.Contains(err.Error(), "host-monitor integration") {
		t.Fatalf("v2 Preflight error = %v", err)
	}
	if instance, err := provider.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "host-monitor integration") {
		if instance != nil {
			_ = instance.Destroy(context.Background())
		}
		t.Fatalf("v2 Start error = %v", err)
	}
}

func TestExactHostMonitorStatusTerminalAcceptsReapedTerminalStatus(t *testing.T) {
	for _, state := range []HostMonitorState{HostMonitorStopped, HostMonitorFailed} {
		t.Run(string(state), func(t *testing.T) {
			monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
			status := HostMonitorStatus{
				State:        state,
				Monitor:      monitor,
				RunnerReaped: true,
				RelayClosed:  true,
			}
			if !exactHostMonitorStatusTerminal(status, monitor) {
				t.Fatal("exact terminal teardown evidence was not accepted")
			}
			wrongMonitor := monitor
			wrongMonitor.StartIdentity = "replacement"
			if exactHostMonitorStatusTerminal(status, wrongMonitor) {
				t.Fatal("terminal evidence for a different monitor identity was accepted")
			}
		})
	}
}

func TestExactHostMonitorStatusTerminalRejectsIncompleteCleanup(t *testing.T) {
	monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
	status := HostMonitorStatus{
		State:        HostMonitorFailed,
		Monitor:      monitor,
		RunnerReaped: true,
		RelayClosed:  false,
	}
	if exactHostMonitorStatusTerminal(status, monitor) {
		t.Fatal("terminal evidence with an open relay was accepted")
	}
}
