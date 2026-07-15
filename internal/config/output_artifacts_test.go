package config

import (
	"strings"
	"testing"
)

func TestOutputArtifacts_DefaultMaxBytes(t *testing.T) {
	cfg, err := loadFromString(t, "sessions: {}\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Sessions.OutputArtifacts.MaxBytes; got != DefaultOutputArtifactMaxBytes {
		t.Fatalf("sessions.output_artifacts.max_bytes = %d, want %d", got, DefaultOutputArtifactMaxBytes)
	}
}

func TestOutputArtifacts_ParsesInt64MaxBytes(t *testing.T) {
	const want int64 = 5 * 1024 * 1024 * 1024
	cfg, err := loadFromString(t, "sessions:\n  output_artifacts:\n    max_bytes: 5368709120\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Sessions.OutputArtifacts.MaxBytes; got != want {
		t.Fatalf("sessions.output_artifacts.max_bytes = %d, want %d", got, want)
	}
}

func TestOutputArtifacts_RejectsNegativeMaxBytes(t *testing.T) {
	_, err := loadFromString(t, "sessions:\n  output_artifacts:\n    max_bytes: -1\n")
	if err == nil {
		t.Fatal("Load succeeded with a negative output artifact limit")
	}
	if !strings.Contains(err.Error(), "sessions.output_artifacts.max_bytes must be > 0") {
		t.Fatalf("Load error = %q", err)
	}
}
