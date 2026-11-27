package events

import (
	"testing"
)

func TestEventTypes(t *testing.T) {
	// Verify all event types have categories
	for _, et := range AllEventTypes {
		if _, ok := EventCategory[et]; !ok {
			t.Errorf("Event type %q has no category", et)
		}
	}
}

func TestEventCategory(t *testing.T) {
	tests := []struct {
		eventType EventType
		category  string
	}{
		{EventFileOpen, "file"},
		{EventNetConnect, "network"},
		{EventProcessSpawn, "process"},
		{EventShellInvoke, "shell"},
		{EventCommandRedirect, "command"},
		{EventResourceLimitSet, "resource"},
		{EventUnixSocketConnect, "ipc"},
	}

	for _, tt := range tests {
		if got := EventCategory[tt.eventType]; got != tt.category {
			t.Errorf("EventCategory[%q] = %q, want %q", tt.eventType, got, tt.category)
		}
	}
}

func TestBaseEvent(t *testing.T) {
	event := BaseEvent{
		Hostname:  "test-host",
		MachineID: "machine-123",
		OS:        "linux",
		Arch:      "amd64",
		Type:      EventFileOpen,
		Category:  "file",
		PID:       1234,
		SessionID: "session-123",
	}

	if event.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want test-host", event.Hostname)
	}
	if event.Type != EventFileOpen {
		t.Errorf("Type = %q, want file_open", event.Type)
	}
}

func TestShellInvokeEvent(t *testing.T) {
	event := ShellInvokeEvent{
		Shell:       "bash",
		InvokedAs:   "/bin/bash",
		Args:        []string{"-c", "echo hello"},
		Mode:        "command",
		Command:     "echo hello",
		Intercepted: true,
		Strategy:    "binary_replace",
	}

	if event.Shell != "bash" {
		t.Errorf("Shell = %q, want bash", event.Shell)
	}
	if !event.Intercepted {
		t.Error("Intercepted should be true")
	}
}

func TestResourceLimits(t *testing.T) {
	limits := ResourceLimits{
		MaxMemoryMB:     2048,
		CPUQuotaPercent: 80,
		MaxProcesses:    100,
	}

	if limits.MaxMemoryMB != 2048 {
		t.Errorf("MaxMemoryMB = %d, want 2048", limits.MaxMemoryMB)
	}
	if limits.CPUQuotaPercent != 80 {
		t.Errorf("CPUQuotaPercent = %d, want 80", limits.CPUQuotaPercent)
	}
}

func TestProcessSpawnEvent(t *testing.T) {
	event := ProcessSpawnEvent{
		ChildPID:  1235,
		ChildComm: "node",
		ParentPID: 1234,
		Depth:     2,
		Expected:  true,
	}

	if event.ChildPID != 1235 {
		t.Errorf("ChildPID = %d, want 1235", event.ChildPID)
	}
	if event.Depth != 2 {
		t.Errorf("Depth = %d, want 2", event.Depth)
	}
}

func TestUnixSocketEvent(t *testing.T) {
	event := UnixSocketEvent{
		Operation:  "connect",
		SocketType: "stream",
		Path:       "/var/run/docker.sock",
		Service:    "docker",
		Method:     "seccomp",
	}

	if event.Path != "/var/run/docker.sock" {
		t.Errorf("Path = %q, want /var/run/docker.sock", event.Path)
	}
	if event.Service != "docker" {
		t.Errorf("Service = %q, want docker", event.Service)
	}
}
