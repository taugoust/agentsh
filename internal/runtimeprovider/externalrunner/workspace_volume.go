package externalrunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/google/uuid"
)

const (
	WorkspaceVolumeManifestSchemaVersion = 1
	WorkspaceVolumeManifestName          = "manifest.json"
	WorkspaceVolumeImageName             = "workspace.qcow2"

	workspaceVolumeCreateIntentName = "create-intent.json"
	workspaceVolumeManifestMaxBytes = 64 * 1024
)

var (
	ErrWorkspaceVolumeUnsupported = errors.New("external runner workspace volumes are supported only on Linux")
	ErrWorkspaceVolumeInvalid     = errors.New("invalid external runner workspace volume")
	ErrWorkspaceVolumeNotFound    = errors.New("external runner workspace volume not found")
	ErrWorkspaceVolumeExists      = errors.New("external runner workspace volume already exists")
	ErrWorkspaceVolumeCorrupt     = errors.New("external runner workspace volume integrity check failed")
)

// WorkspaceVolumeRequest carries the immutable operator and session binding
// used by create, reopen, and delete. ProfileFileSHA256 is the hash returned by
// ReadProfileSnapshot, not the profile's separately pinned payload digest.
type WorkspaceVolumeRequest struct {
	StateDir          string
	SessionID         string
	Profile           Profile
	ProfileFileSHA256 string
}

// WorkspaceVolumeImageIdentity binds the manifest to the exact published image
// inode and the immutable part of its qcow2 header. A full-file digest cannot
// identify mutable block contents: every reopen instead performs bounded
// qemu-img structural validation, which detects truncation and invalid in-place
// replacement. The provider integration must add and verify the ext4 UUID after
// trusted guest formatting to complete mutable filesystem identity.
type WorkspaceVolumeImageIdentity struct {
	FileName     string `json:"file_name"`
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	HeaderSHA256 string `json:"header_sha256"`
}

// WorkspaceVolumeManifest is private provider state. The image path is fixed by
// layout and deliberately is not persisted as a caller-controlled host path.
// This foundation validates a mutable image structurally; it does not format
// the guest filesystem or claim content identity before ext4 UUID binding.
type WorkspaceVolumeManifest struct {
	SchemaVersion     int                          `json:"schema_version"`
	Complete          bool                         `json:"complete"`
	SessionID         string                       `json:"session_id"`
	Provider          string                       `json:"provider"`
	Profile           string                       `json:"profile"`
	ProfileSchema     string                       `json:"profile_schema"`
	ProfileDigest     string                       `json:"profile_digest"`
	ProfileFileSHA256 string                       `json:"profile_file_sha256"`
	VolumeID          string                       `json:"volume_id"`
	WorkspaceVolume   WorkspaceVolumeSpec          `json:"workspace_volume"`
	Image             WorkspaceVolumeImageIdentity `json:"image"`
	CreatedAt         time.Time                    `json:"created_at"`
}

// WorkspaceVolume holds the only mutable image descriptor admitted by an
// exclusive cross-process lease. Close releases both; it never deletes volume
// state.
type WorkspaceVolume struct {
	Manifest WorkspaceVolumeManifest
	Image    *os.File

	lock      io.Closer
	closeOnce sync.Once
	closeErr  error
}

func (v *WorkspaceVolume) RunnerFD() int {
	if v == nil {
		return 0
	}
	return v.Manifest.WorkspaceVolume.RunnerFD
}

func (v *WorkspaceVolume) Close() error {
	if v == nil {
		return nil
	}
	v.closeOnce.Do(func() {
		var imageErr error
		if v.Image != nil {
			imageErr = v.Image.Close()
		}
		var lockErr error
		if v.lock != nil {
			lockErr = v.lock.Close()
		}
		v.closeErr = errors.Join(imageErr, lockErr)
	})
	return v.closeErr
}

func (r WorkspaceVolumeRequest) validate() error {
	if err := runtimeprovider.ValidateName(r.SessionID); err != nil || !strings.HasPrefix(r.SessionID, "session-") {
		return fmt.Errorf("%w: session identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if !filepath.IsAbs(r.StateDir) || filepath.Clean(r.StateDir) != r.StateDir || filepath.Base(r.StateDir) != r.SessionID {
		return fmt.Errorf("%w: state directory is not bound to the exact session", ErrWorkspaceVolumeInvalid)
	}
	if err := r.Profile.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrWorkspaceVolumeInvalid, err)
	}
	if r.Profile.Schema != ProfileSchemaV2 || r.Profile.WorkspaceVolume == nil {
		return fmt.Errorf("%w: workspace volumes require an external runner v2 profile", ErrWorkspaceVolumeInvalid)
	}
	if !validSHA256(r.ProfileFileSHA256) {
		return fmt.Errorf("%w: operator profile hash is invalid", ErrWorkspaceVolumeInvalid)
	}
	return nil
}

func (m WorkspaceVolumeManifest) Validate() error {
	if m.SchemaVersion != WorkspaceVolumeManifestSchemaVersion || !m.Complete {
		return fmt.Errorf("%w: manifest is incomplete or uses an unsupported schema", ErrWorkspaceVolumeInvalid)
	}
	if err := runtimeprovider.ValidateName(m.SessionID); err != nil || !strings.HasPrefix(m.SessionID, "session-") {
		return fmt.Errorf("%w: manifest session identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if m.Provider != ProviderName {
		return fmt.Errorf("%w: manifest provider is invalid", ErrWorkspaceVolumeInvalid)
	}
	if err := runtimeprovider.ValidateName(m.Profile); err != nil || m.ProfileSchema != ProfileSchemaV2 || !validSHA256(m.ProfileDigest) || !validSHA256(m.ProfileFileSHA256) {
		return fmt.Errorf("%w: manifest profile binding is invalid", ErrWorkspaceVolumeInvalid)
	}
	if !canonicalWorkspaceVolumeUUID(m.VolumeID) {
		return fmt.Errorf("%w: manifest volume identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if err := m.WorkspaceVolume.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrWorkspaceVolumeInvalid, err)
	}
	if m.Image.FileName != WorkspaceVolumeImageName || m.Image.Inode == 0 || !validSHA256(m.Image.HeaderSHA256) {
		return fmt.Errorf("%w: manifest image identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if m.CreatedAt.IsZero() || m.CreatedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return fmt.Errorf("%w: manifest creation time is invalid", ErrWorkspaceVolumeInvalid)
	}
	return nil
}

func (m WorkspaceVolumeManifest) matches(request WorkspaceVolumeRequest, volumeID string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.SessionID != request.SessionID || m.Provider != request.Profile.Provider || m.Profile != request.Profile.Name ||
		m.ProfileSchema != request.Profile.Schema || m.ProfileDigest != request.Profile.ProfileDigest ||
		m.ProfileFileSHA256 != request.ProfileFileSHA256 || request.Profile.WorkspaceVolume == nil ||
		m.WorkspaceVolume != *request.Profile.WorkspaceVolume {
		return fmt.Errorf("%w: manifest does not match its session and operator profile", ErrWorkspaceVolumeInvalid)
	}
	if volumeID != "" && m.VolumeID != volumeID {
		return fmt.Errorf("%w: volume identity mismatch", ErrWorkspaceVolumeInvalid)
	}
	return nil
}

func canonicalWorkspaceVolumeUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.Version() == 4 && parsed.Variant() == uuid.RFC4122 && parsed.String() == value
}

// CreateWorkspaceVolume atomically publishes or reopens the exact blank
// session qcow2 named by the caller-provided volume ID. Retrying the same exact
// create transaction is idempotent. It does not mount, attach, format, stage,
// or materialize host workspace content.
func CreateWorkspaceVolume(ctx context.Context, request WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
	return createWorkspaceVolume(ctx, request, volumeID)
}

// OpenWorkspaceVolume reopens only the exact volume ID under the same immutable
// session and operator-profile binding used at creation.
func OpenWorkspaceVolume(ctx context.Context, request WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
	return openWorkspaceVolume(ctx, request, volumeID)
}

// DeleteWorkspaceVolume is the only API that removes a published workspace
// volume. It is idempotent for an already-removed exact volume ID.
func DeleteWorkspaceVolume(ctx context.Context, request WorkspaceVolumeRequest, volumeID string) error {
	return deleteWorkspaceVolume(ctx, request, volumeID)
}
