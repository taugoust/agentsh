package externalrunner

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
)

const cidLeaseSchemaVersion = 1

type CIDLease struct {
	SchemaVersion int       `json:"schema_version"`
	CID           uint32    `json:"cid"`
	SessionID     string    `json:"session_id"`
	LeaseID       string    `json:"lease_id"`
	CreatedAt     time.Time `json:"created_at"`
}

func (l CIDLease) Validate(cidMin, cidMax uint32) error {
	if l.SchemaVersion != cidLeaseSchemaVersion {
		return fmt.Errorf("external runner CID lease schema version %d is unsupported", l.SchemaVersion)
	}
	if l.CID < cidMin || l.CID > cidMax || l.CID < 3 || l.CID == ^uint32(0) {
		return fmt.Errorf("external runner CID lease is outside its operator range")
	}
	if err := runtimeprovider.ValidateName(l.SessionID); err != nil || !strings.HasPrefix(l.SessionID, "session-") {
		return fmt.Errorf("external runner CID lease session identity is invalid")
	}
	if !validHexSecret(l.LeaseID) {
		return fmt.Errorf("external runner CID lease identity is invalid")
	}
	if l.CreatedAt.IsZero() {
		return fmt.Errorf("external runner CID lease creation time is missing")
	}
	return nil
}

func AllocateCID(ctx context.Context, root, sessionID string, cidMin, cidMax uint32) (CIDLease, error) {
	if err := validateCIDLeaseRequest(root, sessionID, cidMin, cidMax); err != nil {
		return CIDLease{}, err
	}
	return allocateCID(ctx, root, sessionID, cidMin, cidMax)
}

func VerifyCIDLease(ctx context.Context, root string, lease CIDLease, cidMin, cidMax uint32) error {
	if err := validateCIDLeaseRoot(root); err != nil {
		return err
	}
	if err := lease.Validate(cidMin, cidMax); err != nil {
		return err
	}
	return verifyCID(ctx, root, lease, cidMin, cidMax)
}

func ReleaseCID(ctx context.Context, root string, lease CIDLease, cidMin, cidMax uint32) error {
	if err := validateCIDLeaseRoot(root); err != nil {
		return err
	}
	if err := lease.Validate(cidMin, cidMax); err != nil {
		return err
	}
	return releaseCID(ctx, root, lease, cidMin, cidMax)
}

func validateCIDLeaseRequest(root, sessionID string, cidMin, cidMax uint32) error {
	if err := validateCIDLeaseRoot(root); err != nil {
		return err
	}
	if err := runtimeprovider.ValidateName(sessionID); err != nil || !strings.HasPrefix(sessionID, "session-") {
		return fmt.Errorf("external runner CID session identity is invalid")
	}
	if cidMin < 3 || cidMax == ^uint32(0) || cidMin > cidMax || cidMax-cidMin > 65535 {
		return fmt.Errorf("external runner CID allocation range is invalid")
	}
	return nil
}

func validHexSecret(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateCIDLeaseRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) == string(filepath.Separator) {
		return fmt.Errorf("external runner CID lease root must be clean and absolute")
	}
	return nil
}
