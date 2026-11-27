package session

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestSessionState_IsTerminal(t *testing.T) {
	tests := []struct {
		state    types.SessionState
		terminal bool
	}{
		{types.SessionStatePending, false},
		{types.SessionStateStarting, false},
		{types.SessionStateRunning, false},
		{types.SessionStatePaused, false},
		{types.SessionStateTerminating, false},
		{types.SessionStateCompleted, true},
		{types.SessionStateFailed, true},
		{types.SessionStateTimedOut, true},
		{types.SessionStateKilled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsTerminal(); got != tt.terminal {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.terminal)
			}
		})
	}
}

func TestSessionState_IsActive(t *testing.T) {
	tests := []struct {
		state  types.SessionState
		active bool
	}{
		{types.SessionStatePending, false},
		{types.SessionStateStarting, true},
		{types.SessionStateRunning, true},
		{types.SessionStateBusy, true},
		{types.SessionStatePaused, false},
		{types.SessionStateTerminating, false},
		{types.SessionStateCompleted, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsActive(); got != tt.active {
				t.Errorf("IsActive() = %v, want %v", got, tt.active)
			}
		})
	}
}

func TestSession_Stats(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Initial stats should be zero
	stats := s.Stats()
	if stats.FileReads != 0 || stats.FileWrites != 0 {
		t.Error("expected zero initial stats")
	}

	// Increment stats
	s.IncrementFileReads(100)
	s.IncrementFileReads(50)
	s.IncrementFileWrites(200)

	stats = s.Stats()
	if stats.FileReads != 2 {
		t.Errorf("FileReads = %d, want 2", stats.FileReads)
	}
	if stats.BytesRead != 150 {
		t.Errorf("BytesRead = %d, want 150", stats.BytesRead)
	}
	if stats.FileWrites != 1 {
		t.Errorf("FileWrites = %d, want 1", stats.FileWrites)
	}
	if stats.BytesWritten != 200 {
		t.Errorf("BytesWritten = %d, want 200", stats.BytesWritten)
	}
}

func TestSession_UpdateStats(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s.UpdateStats(func(stats *types.SessionStats) {
		stats.NetworkConns = 5
		stats.DNSQueries = 10
		stats.CommandsExecuted = 20
	})

	stats := s.Stats()
	if stats.NetworkConns != 5 {
		t.Errorf("NetworkConns = %d, want 5", stats.NetworkConns)
	}
	if stats.DNSQueries != 10 {
		t.Errorf("DNSQueries = %d, want 10", stats.DNSQueries)
	}
	if stats.CommandsExecuted != 20 {
		t.Errorf("CommandsExecuted = %d, want 20", stats.CommandsExecuted)
	}
}

func TestSession_IncrementCounters(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s.IncrementNetworkConns()
	s.IncrementNetworkConns()
	s.IncrementBlockedOps()
	s.IncrementCommandsExecuted()
	s.IncrementCommandsExecuted()
	s.IncrementCommandsExecuted()
	s.IncrementCommandsFailed()

	stats := s.Stats()
	if stats.NetworkConns != 2 {
		t.Errorf("NetworkConns = %d, want 2", stats.NetworkConns)
	}
	if stats.BlockedOps != 1 {
		t.Errorf("BlockedOps = %d, want 1", stats.BlockedOps)
	}
	if stats.CommandsExecuted != 3 {
		t.Errorf("CommandsExecuted = %d, want 3", stats.CommandsExecuted)
	}
	if stats.CommandsFailed != 1 {
		t.Errorf("CommandsFailed = %d, want 1", stats.CommandsFailed)
	}
}
