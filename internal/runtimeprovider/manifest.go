package runtimeprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const manifestFileName = "runtime-provider.json"

var ErrManifestInvalid = errors.New("invalid runtime-provider manifest")

type Manifest struct {
	SchemaVersion   int       `json:"schema_version"`
	ContractVersion int       `json:"contract_version"`
	Provider        string    `json:"provider"`
	Profile         string    `json:"profile"`
	SessionID       string    `json:"session_id"`
	StateDir        string    `json:"state_dir"`
	State           State     `json:"state"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Identity        Identity  `json:"identity,omitempty"`
	Endpoint        Endpoint  `json:"endpoint,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	CleanupComplete bool      `json:"cleanup_complete,omitempty"`
	// CleanupPending distinguishes provider cleanup debt from an ordinary
	// recoverable runtime failure in schema-v1 manifests.
	CleanupPending bool `json:"cleanup_pending,omitempty"`
}

func ManifestPath(stateDir string) string {
	return filepath.Join(stateDir, manifestFileName)
}

func NewManifest(request Request, now time.Time) Manifest {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	return Manifest{
		SchemaVersion:   ManifestSchemaVersion,
		ContractVersion: ContractVersion,
		Provider:        request.Provider,
		Profile:         request.Profile,
		SessionID:       request.SessionID,
		StateDir:        request.StateDir,
		State:           StateProvisioning,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %d", ErrManifestInvalid, m.SchemaVersion)
	}
	if m.ContractVersion != ContractVersion {
		return fmt.Errorf("%w: unsupported contract_version %d", ErrManifestInvalid, m.ContractVersion)
	}
	if !validName(m.Provider) || !validName(m.Profile) || !validName(m.SessionID) || filepath.Base(m.SessionID) != m.SessionID {
		return fmt.Errorf("%w: provider, profile, or session identity is invalid", ErrManifestInvalid)
	}
	if !filepath.IsAbs(m.StateDir) || filepath.Clean(m.StateDir) != m.StateDir || filepath.Base(m.StateDir) != m.SessionID {
		return fmt.Errorf("%w: state directory is not bound to the exact session", ErrManifestInvalid)
	}
	if m.CreatedAt.IsZero() || m.UpdatedAt.IsZero() || m.UpdatedAt.Before(m.CreatedAt) {
		return fmt.Errorf("%w: timestamps are invalid", ErrManifestInvalid)
	}
	switch m.State {
	case StateProvisioning, StateRecovering, StateReady, StateDegraded, StateStopping, StateStopped, StateFailed:
	default:
		return fmt.Errorf("%w: unsupported state %q", ErrManifestInvalid, m.State)
	}
	identityPresent := m.Identity.ContractVersion != 0 || m.Identity.Provider != "" || m.Identity.Profile != "" || m.Identity.SessionID != "" || m.Identity.Generation != 0 || m.Identity.IncarnationID != "" || m.Identity.OwnerPID != 0 || m.Identity.OwnerStartIdentity != "" || m.Identity.BootID != ""
	endpointPresent := m.Endpoint.Transport != "" || m.Endpoint.Address != ""
	if identityPresent {
		if err := m.Identity.ValidateComplete(); err != nil {
			return fmt.Errorf("%w: %v", ErrManifestInvalid, err)
		}
		if m.Identity.Provider != m.Provider || m.Identity.Profile != m.Profile || m.Identity.SessionID != m.SessionID {
			return fmt.Errorf("%w: manifest and runtime identities differ", ErrManifestInvalid)
		}
	}
	if endpointPresent {
		if err := m.Endpoint.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrManifestInvalid, err)
		}
	}
	if m.State == StateReady || m.State == StateDegraded || m.State == StateStopping || m.State == StateStopped {
		if !identityPresent || !endpointPresent {
			return fmt.Errorf("%w: state %s requires complete identity and endpoint", ErrManifestInvalid, m.State)
		}
	}
	if m.CleanupPending && m.CleanupComplete {
		return fmt.Errorf("%w: cleanup cannot be pending and complete", ErrManifestInvalid)
	}
	if strings.ContainsAny(m.LastError, "\x00") || len(m.LastError) > 4096 {
		return fmt.Errorf("%w: last_error is invalid", ErrManifestInvalid)
	}
	return nil
}

func WriteManifest(stateDir string, manifest Manifest) error {
	if err := validateManifestStateDir(stateDir, manifest); err != nil {
		return err
	}
	manifest.UpdatedAt = time.Now().UTC()
	if manifest.CreatedAt.IsZero() {
		manifest.CreatedAt = manifest.UpdatedAt
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runtime-provider manifest: %w", err)
	}
	if err := atomicWritePrivateFile(ManifestPath(stateDir), append(data, '\n')); err != nil {
		return fmt.Errorf("write runtime-provider manifest: %w", err)
	}
	return nil
}

func ReadManifest(stateDir string) (Manifest, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return Manifest{}, fmt.Errorf("%w: state directory must be clean and absolute", ErrManifestInvalid)
	}
	path := ManifestPath(stateDir)
	data, err := readProtectedRegularFile(path, 1<<20)
	if err != nil {
		return Manifest{}, fmt.Errorf("read runtime-provider manifest at %s: %w", path, err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w at %s: %v", ErrManifestInvalid, path, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, fmt.Errorf("%w at %s: %v", ErrManifestInvalid, path, err)
	}
	if err := validateManifestStateDir(stateDir, manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w at %s", err, path)
	}
	return manifest, nil
}

func validateManifestStateDir(stateDir string, manifest Manifest) error {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return fmt.Errorf("%w: state directory must be clean and absolute", ErrManifestInvalid)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if stateDir != manifest.StateDir {
		return fmt.Errorf("%w: manifest state directory does not match its storage directory", ErrManifestInvalid)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("trailing JSON value")
}

func atomicWritePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

func readProtectedRegularFile(path string, maxBytes int64) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("protected file has unsafe type or permissions")
	}
	if pathInfo.Size() < 0 || pathInfo.Size() > maxBytes {
		return nil, fmt.Errorf("protected file exceeds %d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("protected file identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("protected file exceeds %d bytes", maxBytes)
	}
	return data, nil
}
