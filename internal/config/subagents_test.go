package config

import (
	"strings"
	"testing"
	"time"
)

func TestSubagents_DefaultTimeoutIsTwoHours(t *testing.T) {
	cfg, err := loadFromString(t, "sessions: {}\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Sessions.Subagents.DefaultTimeout; got != DefaultSubagentTimeoutString {
		t.Fatalf("sessions.subagents.default_timeout = %q, want %q", got, DefaultSubagentTimeoutString)
	}
	if got := cfg.Sessions.Subagents.DefaultTimeoutDuration(); got != 2*time.Hour {
		t.Fatalf("default timeout duration = %s, want %s", got, 2*time.Hour)
	}
	if got := cfg.Sessions.Subagents.ExecConcurrency(); got != 1 {
		t.Fatalf("default exec concurrency = %d, want fail-closed value 1", got)
	}
}

func TestSubagents_ParsesCustomDefaultTimeout(t *testing.T) {
	cfg, err := loadFromString(t, "sessions:\n  subagents:\n    default_timeout: 45m\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Sessions.Subagents.DefaultTimeoutDuration(); got != 45*time.Minute {
		t.Fatalf("default timeout duration = %s, want %s", got, 45*time.Minute)
	}
}

func TestSubagents_ParsesAndValidatesExecConcurrency(t *testing.T) {
	cfg, err := loadFromString(t, "sessions:\n  subagents:\n    max_exec_concurrency: 4\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Sessions.Subagents.ExecConcurrency(); got != 4 {
		t.Fatalf("exec concurrency = %d, want 4", got)
	}

	for _, value := range []string{"-1", "5"} {
		t.Run(value, func(t *testing.T) {
			_, err := loadFromString(t, "sessions:\n  subagents:\n    max_exec_concurrency: "+value+"\n")
			if err == nil || !strings.Contains(err.Error(), "sessions.subagents.max_exec_concurrency must be between 1 and 4") {
				t.Fatalf("Load error = %v", err)
			}
		})
	}
}

func TestSubagents_RejectsInvalidDefaultTimeout(t *testing.T) {
	for _, value := range []string{"invalid", "0s", "-1s"} {
		t.Run(value, func(t *testing.T) {
			_, err := loadFromString(t, "sessions:\n  subagents:\n    default_timeout: "+value+"\n")
			if err == nil {
				t.Fatalf("Load succeeded with subagent timeout %q", value)
			}
			if !strings.Contains(err.Error(), "sessions.subagents.default_timeout must be a positive duration") {
				t.Fatalf("Load error = %q", err)
			}
		})
	}
}
