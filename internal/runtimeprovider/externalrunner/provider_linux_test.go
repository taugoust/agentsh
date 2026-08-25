//go:build linux

package externalrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExactHostMonitorTerminalEvidenceAcceptsReapedTerminalStatus(t *testing.T) {
	for _, state := range []HostMonitorState{HostMonitorStopped, HostMonitorFailed} {
		t.Run(string(state), func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "session-11111111-1111-4111-8111-111111111111")
			layout, err := HostMonitorPaths(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(layout.HostDir, 0o700); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
			runner := HostProcessIdentity{PID: 202, ProcessGroup: 202, StartIdentity: "runner-start", BootID: "boot-id"}
			status := HostMonitorStatus{
				SchemaVersion: HostMonitorSchemaVersion,
				Revision:      5,
				MonitorID:     "0123456789abcdef0123456789abcdef",
				SessionID:     filepath.Base(stateDir),
				State:         state,
				CreatedAt:     now,
				UpdatedAt:     now,
				Monitor:       monitor,
				Runner:        &runner,
				RunnerExit:    &HostRunnerExit{ExitCode: 0},
				RunnerReaped:  true,
				RelayClosed:   true,
			}
			if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
				t.Fatal(err)
			}
			if !exactHostMonitorTerminalEvidence(stateDir, monitor) {
				t.Fatal("exact terminal teardown evidence was not accepted")
			}
			wrongMonitor := monitor
			wrongMonitor.StartIdentity = "replacement"
			if exactHostMonitorTerminalEvidence(stateDir, wrongMonitor) {
				t.Fatal("terminal evidence for a different monitor identity was accepted")
			}
		})
	}
}

func TestExactHostMonitorTerminalEvidenceRejectsIncompleteCleanup(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "session-22222222-2222-4222-8222-222222222222")
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.HostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	monitor := HostProcessIdentity{PID: 101, StartIdentity: "monitor-start", BootID: "boot-id"}
	runner := HostProcessIdentity{PID: 202, ProcessGroup: 202, StartIdentity: "runner-start", BootID: "boot-id"}
	status := HostMonitorStatus{
		SchemaVersion: HostMonitorSchemaVersion,
		Revision:      4,
		MonitorID:     "0123456789abcdef0123456789abcdef",
		SessionID:     filepath.Base(stateDir),
		State:         HostMonitorFailed,
		CreatedAt:     now,
		UpdatedAt:     now,
		Monitor:       monitor,
		Runner:        &runner,
		RunnerExit:    &HostRunnerExit{ExitCode: -1, Signaled: true},
		RunnerReaped:  true,
		RelayClosed:   false,
	}
	if err := writeHostMonitorStatus(layout.StatusPath, status); err != nil {
		t.Fatal(err)
	}
	if exactHostMonitorTerminalEvidence(stateDir, monitor) {
		t.Fatal("terminal evidence with an open relay was accepted")
	}
}
