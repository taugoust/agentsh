//go:build linux

package externalrunner

import "testing"

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
