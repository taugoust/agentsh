package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicyValidateCommandTimeoutMinimum(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		wantErr bool
	}{
		{name: "omitted or zero keeps fallback semantics"},
		{name: "negative keeps existing non-positive fallback semantics", timeout: -time.Nanosecond},
		{name: "sub-millisecond positive is rejected", timeout: 999 * time.Microsecond, wantErr: true},
		{name: "one millisecond is accepted", timeout: time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := Policy{
				Version: 1,
				Name:    "command-timeout-validation",
				ResourceLimits: ResourceLimits{
					CommandTimeout: duration{Duration: test.timeout},
				},
			}
			err := p.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestPolicyLoadRejectsSubMillisecondCommandTimeout(t *testing.T) {
	for _, value := range []string{"1ns", "500us", "999us"} {
		t.Run(value, func(t *testing.T) {
			document := []byte("version: 1\nname: command-timeout-load\nresource_limits:\n  command_timeout: " + value + "\n")
			if _, err := LoadFromBytes(document); err == nil {
				t.Fatalf("LoadFromBytes accepted command_timeout %s", value)
			}
		})
	}
	for _, value := range []string{"0s", "1ms"} {
		t.Run("accept_"+value, func(t *testing.T) {
			document := []byte("version: 1\nname: command-timeout-load\nresource_limits:\n  command_timeout: " + value + "\n")
			if _, err := LoadFromBytes(document); err != nil {
				t.Fatalf("LoadFromBytes rejected command_timeout %s: %v", value, err)
			}
		})
	}
}

func TestEngine_Limits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yml")
	if err := os.WriteFile(path, []byte(`
version: 1
name: test
file_rules: []
network_rules: []
command_rules: []
resource_limits:
  command_timeout: 12s
  session_timeout: 34m
  idle_timeout: 56m
`), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	lim := e.Limits()
	if lim.CommandTimeout != 12*time.Second {
		t.Fatalf("command_timeout: expected 12s, got %s", lim.CommandTimeout)
	}
	if lim.SessionTimeout != 34*time.Minute {
		t.Fatalf("session_timeout: expected 34m, got %s", lim.SessionTimeout)
	}
	if lim.IdleTimeout != 56*time.Minute {
		t.Fatalf("idle_timeout: expected 56m, got %s", lim.IdleTimeout)
	}
}
