package nethelper

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	BootstrapSchemaVersion  = 3
	DefaultBootstrapRuntime = 13 * time.Hour
	MaximumBootstrapRuntime = 192 * time.Hour
	EphemeralSoftLease      = 49 * time.Hour
)

var LifecycleCapabilities = []string{"instance_status", "renew_instance", "attest_composition_runtime"}

type BootstrapResult struct {
	ProtocolVersion        int       `json:"protocol_version"`
	BootstrapSchemaVersion int       `json:"bootstrap_schema_version"`
	LeaseID                string    `json:"lease_id"`
	UID                    uint32    `json:"uid"`
	GID                    uint32    `json:"gid"`
	UnitName               string    `json:"unit_name"`
	SocketPath             string    `json:"socket_path"`
	CredentialFile         string    `json:"credential_file"`
	PinRoot                string    `json:"pin_root"`
	ResultFile             string    `json:"result_file"`
	CompositionScratchRoot string    `json:"composition_scratch_root"`
	StartedAt              time.Time `json:"started_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	RuntimeSeconds         int64     `json:"runtime_seconds"`
	SoftLeaseSeconds       int64     `json:"soft_lease_seconds,omitempty"`
	RenewalRequired        bool      `json:"renewal_required,omitempty"`
}

func (r BootstrapResult) Validate(now time.Time) error {
	if r.ProtocolVersion != CurrentProtocolVersion {
		return fmt.Errorf("bootstrap protocol_version=%d, want %d", r.ProtocolVersion, CurrentProtocolVersion)
	}
	if r.BootstrapSchemaVersion < BootstrapSchemaVersion {
		return fmt.Errorf("bootstrap_schema_version=%d does not support helper rebinding", r.BootstrapSchemaVersion)
	}
	if err := ValidateEphemeralLeaseID(strings.TrimSpace(r.LeaseID)); err != nil {
		return err
	}
	if strings.TrimSpace(r.UnitName) == "" || strings.ContainsAny(r.UnitName, `/\\`) {
		return fmt.Errorf("bootstrap unit_name is invalid")
	}
	for name, path := range map[string]string{
		"socket_path": r.SocketPath, "credential_file": r.CredentialFile,
		"pin_root": r.PinRoot, "result_file": r.ResultFile,
		"composition_scratch_root": r.CompositionScratchRoot,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("bootstrap %s must be absolute and canonical", name)
		}
	}
	if r.StartedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.StartedAt) {
		return fmt.Errorf("bootstrap timestamps are invalid")
	}
	if r.RuntimeSeconds <= 0 || r.RuntimeSeconds > int64(MaximumBootstrapRuntime/time.Second) {
		return fmt.Errorf("bootstrap runtime_seconds is outside the supported bound")
	}
	if r.SoftLeaseSeconds < 0 || r.SoftLeaseSeconds > r.RuntimeSeconds || (r.RenewalRequired != (r.SoftLeaseSeconds > 0)) {
		return fmt.Errorf("bootstrap soft lease negotiation is inconsistent")
	}
	if !r.StartedAt.Add(time.Duration(r.RuntimeSeconds) * time.Second).Equal(r.ExpiresAt) {
		return fmt.Errorf("bootstrap expires_at is inconsistent with started_at and runtime_seconds")
	}
	if !now.IsZero() {
		if r.StartedAt.After(now.Add(time.Minute)) {
			return fmt.Errorf("bootstrap creation time is implausibly in the future")
		}
		if !now.Before(r.ExpiresAt) {
			return fmt.Errorf("bootstrap helper hard expiry has passed")
		}
	}
	return nil
}
