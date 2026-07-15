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
