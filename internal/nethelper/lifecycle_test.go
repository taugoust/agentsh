package nethelper

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapResultRuntimeAndExpiryValidation(t *testing.T) {
	started := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	runtimeLimit := MaximumBootstrapRuntime
	result := BootstrapResult{
		ProtocolVersion: CurrentProtocolVersion, BootstrapSchemaVersion: BootstrapSchemaVersion,
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", UID: 1000, GID: 100,
		UnitName: "agentsh-nethelper.service", SocketPath: filepath.Join(string(filepath.Separator), "run", "helper.sock"),
		CredentialFile: filepath.Join(string(filepath.Separator), "run", "credential"),
		PinRoot:        filepath.Join(string(filepath.Separator), "sys", "fs", "bpf", "pins"),
		ResultFile:     filepath.Join(string(filepath.Separator), "run", "bootstrap.json"),
		StartedAt:      started, ExpiresAt: started.Add(runtimeLimit), RuntimeSeconds: int64(runtimeLimit / time.Second),
	}
	if err := result.Validate(started.Add(time.Hour)); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	result.ExpiresAt = result.ExpiresAt.Add(time.Second)
	if err := result.Validate(started.Add(time.Hour)); err == nil {
		t.Fatal("inconsistent expiry accepted")
	}
}

func TestBootstrapResultSoftLeaseIsExplicitlyNegotiated(t *testing.T) {
	started := time.Now().UTC().Truncate(time.Second)
	base := BootstrapResult{ProtocolVersion: 1, BootstrapSchemaVersion: BootstrapSchemaVersion,
		LeaseID: "lease-11111111-1111-4111-8111-111111111111", UnitName: "helper.service",
		SocketPath: filepath.Join(string(filepath.Separator), "run", "helper.sock"), CredentialFile: filepath.Join(string(filepath.Separator), "run", "credential"),
		PinRoot: filepath.Join(string(filepath.Separator), "sys", "fs", "bpf", "pins"), ResultFile: filepath.Join(string(filepath.Separator), "run", "bootstrap.json"),
		StartedAt: started, ExpiresAt: started.Add(192 * time.Hour), RuntimeSeconds: int64((192 * time.Hour) / time.Second)}
	if err := base.Validate(started); err != nil {
		t.Fatalf("runtime-only metadata rejected: %v", err)
	}
	base.SoftLeaseSeconds = int64((49 * time.Hour) / time.Second)
	base.RenewalRequired = true
	if err := base.Validate(started); err != nil {
		t.Fatalf("negotiated metadata rejected: %v", err)
	}
	base.RenewalRequired = false
	if err := base.Validate(started); err == nil {
		t.Fatal("uncommitted soft lease accepted")
	}
}

func TestDefaultBootstrapRuntimeRemainsThirteenHours(t *testing.T) {
	if DefaultBootstrapRuntime != 13*time.Hour {
		t.Fatalf("default runtime=%s", DefaultBootstrapRuntime)
	}
}
