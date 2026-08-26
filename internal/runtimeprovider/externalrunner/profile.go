package externalrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
)

const (
	ProviderName    = runtimeprovider.ExternalRunnerProvider
	ProfileSchemaV1 = "io.agentsh.microvm-external-runner-profile/v1"
	ProfileSchemaV2 = "io.agentsh.microvm-external-runner-profile/v2"

	// ProfileSchema remains the legacy schema so existing profile producers and
	// callers retain their v1 behavior unless they explicitly select v2.
	ProfileSchema = ProfileSchemaV1

	WorkspaceVolumeModel      = "session-qcow2-ext4-v1"
	WorkspaceVolumeFormat     = "qcow2"
	WorkspaceVolumeFilesystem = "ext4"
	WorkspaceVolumeRunnerFD   = 4

	WorkspaceVolumeMinVirtualSizeBytes int64 = 1 << 30
	WorkspaceVolumeMaxVirtualSizeBytes int64 = 256 << 30

	maxProfileBytes = 64 * 1024
)

type Profile struct {
	Schema          string               `json:"schema"`
	ProfileDigest   string               `json:"profile_digest"`
	Name            string               `json:"name"`
	Provider        string               `json:"provider"`
	Status          string               `json:"status"`
	System          string               `json:"system"`
	Runner          Runner               `json:"runner"`
	Guest           Guest                `json:"guest"`
	VSock           VSock                `json:"vsock"`
	Network         Network              `json:"network"`
	Timeouts        Timeouts             `json:"timeouts"`
	WorkspaceVolume *WorkspaceVolumeSpec `json:"workspace_volume,omitempty"`
}

type Runner struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	ProcessModel string `json:"process_model"`
}

type Guest struct {
	ProfileDigest  string `json:"profile_digest"`
	Policy         string `json:"policy"`
	Workspace      string `json:"workspace"`
	Protocol       int    `json:"protocol_version"`
	ControlPort    uint32 `json:"control_port"`
	SupervisorPort uint32 `json:"supervisor_port"`
}

type VSock struct {
	CIDMin uint32 `json:"cid_min"`
	CIDMax uint32 `json:"cid_max"`
}

type Network struct {
	Transport                 string `json:"transport"`
	Enforcement               string `json:"enforcement"`
	RequireReadyBeforePublish bool   `json:"require_ready_before_publish"`
}

type Timeouts struct {
	ReadinessSeconds        int `json:"readiness_seconds"`
	GracefulShutdownSeconds int `json:"graceful_shutdown_seconds"`
}

// WorkspaceVolumeSpec is the complete v2 operator contract for the private
// session workspace block device. AgentSH does not infer or default any field.
type WorkspaceVolumeSpec struct {
	Model            string `json:"model"`
	Format           string `json:"format"`
	Filesystem       string `json:"filesystem"`
	RunnerFD         int    `json:"runner_fd"`
	VirtualSizeBytes int64  `json:"virtual_size_bytes"`
}

func (s WorkspaceVolumeSpec) Validate() error {
	if s.Model != WorkspaceVolumeModel || s.Format != WorkspaceVolumeFormat || s.Filesystem != WorkspaceVolumeFilesystem || s.RunnerFD != WorkspaceVolumeRunnerFD {
		return fmt.Errorf("external runner workspace volume contract is unsupported")
	}
	if s.VirtualSizeBytes < WorkspaceVolumeMinVirtualSizeBytes || s.VirtualSizeBytes > WorkspaceVolumeMaxVirtualSizeBytes {
		return fmt.Errorf("external runner workspace volume virtual size is outside the supported range")
	}
	return nil
}

func ReadProfile(path string) (Profile, error) {
	profile, _, err := ReadProfileSnapshot(path)
	return profile, err
}

// ReadProfileSnapshot parses and hashes the same opened profile bytes so a
// launch request can bind one immutable operator-profile snapshot.
func ReadProfileSnapshot(path string) (Profile, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Profile{}, "", fmt.Errorf("external runner profile path must be clean and absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return Profile{}, "", fmt.Errorf("inspect external runner profile: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 || before.Size() > maxProfileBytes {
		return Profile{}, "", fmt.Errorf("external runner profile has unsafe type, permissions, or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return Profile{}, "", fmt.Errorf("open external runner profile: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Profile{}, "", fmt.Errorf("stat external runner profile: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return Profile{}, "", fmt.Errorf("external runner profile identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
	if err != nil {
		return Profile{}, "", fmt.Errorf("read external runner profile snapshot: %w", err)
	}
	if len(data) > maxProfileBytes {
		return Profile{}, "", fmt.Errorf("external runner profile snapshot exceeds limit")
	}
	// workspace_volume was not a v1 field. Reject it before decoding into the
	// shared Go type so adding v2 does not make any formerly-invalid v1 profile
	// valid, including a field whose JSON value is null.
	var envelope struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Profile{}, "", fmt.Errorf("decode external runner profile: %w", err)
	}
	if envelope.Schema == ProfileSchemaV1 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return Profile{}, "", fmt.Errorf("decode external runner profile: %w", err)
		}
		// encoding/json matches object names to struct fields without regard to
		// case. Preserve the v1 unknown-field contract for every spelling that
		// the newly-added v2 field would otherwise accept, including null.
		for name := range fields {
			if strings.EqualFold(name, "workspace_volume") {
				return Profile{}, "", fmt.Errorf("decode external runner profile: json: unknown field %q", name)
			}
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, "", fmt.Errorf("decode external runner profile: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Profile{}, "", fmt.Errorf("decode external runner profile: %w", err)
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, "", err
	}
	sum := sha256.Sum256(data)
	return profile, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (p Profile) Validate() error {
	switch p.Schema {
	case ProfileSchemaV1:
		if p.WorkspaceVolume != nil {
			return fmt.Errorf("external runner v1 profile cannot define a workspace volume")
		}
		if p.Guest.Protocol != guestcontrol.ProtocolVersionV2 {
			return fmt.Errorf("external runner v1 profile requires guest protocol version %d", guestcontrol.ProtocolVersionV2)
		}
	case ProfileSchemaV2:
		if p.WorkspaceVolume == nil {
			return fmt.Errorf("external runner v2 profile requires a workspace volume")
		}
		if err := p.WorkspaceVolume.Validate(); err != nil {
			return err
		}
		if p.Guest.Protocol != guestcontrol.ProtocolVersionV3 {
			return fmt.Errorf("external runner v2 profile requires guest protocol version %d", guestcontrol.ProtocolVersionV3)
		}
	default:
		return fmt.Errorf("external runner profile schema %q is unsupported", p.Schema)
	}
	if err := runtimeprovider.ValidateName(p.Name); err != nil {
		return fmt.Errorf("external runner profile name: %w", err)
	}
	if p.Provider != ProviderName {
		return fmt.Errorf("external runner profile provider %q is unsupported", p.Provider)
	}
	if !validSHA256(p.ProfileDigest) || !validSHA256(p.Runner.SHA256) || !validSHA256(p.Guest.ProfileDigest) {
		return fmt.Errorf("external runner profile digest is invalid")
	}
	if p.System != "x86_64-linux" {
		return fmt.Errorf("external runner profile system %q is unsupported", p.System)
	}
	if !filepath.IsAbs(p.Runner.Path) || filepath.Clean(p.Runner.Path) != p.Runner.Path || strings.ContainsAny(p.Runner.Path, "\x00\r\n") || p.Runner.ProcessModel != "direct-exec" {
		return fmt.Errorf("external runner executable path is invalid")
	}
	if err := runtimeprovider.ValidateName(p.Guest.Policy); err != nil {
		return fmt.Errorf("external runner guest policy: %w", err)
	}
	if !filepath.IsAbs(p.Guest.Workspace) || filepath.Clean(p.Guest.Workspace) != p.Guest.Workspace || p.Guest.Workspace == string(filepath.Separator) {
		return fmt.Errorf("external runner guest workspace is invalid")
	}
	if !validPort(p.Guest.ControlPort) || !validPort(p.Guest.SupervisorPort) || p.Guest.ControlPort == p.Guest.SupervisorPort {
		return fmt.Errorf("external runner guest VSOCK ports are invalid or reused")
	}
	if p.VSock.CIDMin < 3 || p.VSock.CIDMax == ^uint32(0) || p.VSock.CIDMin > p.VSock.CIDMax || p.VSock.CIDMax-p.VSock.CIDMin > 65535 {
		return fmt.Errorf("external runner VSOCK CID range is invalid")
	}
	if p.Network.Transport != "qemu-user" {
		return fmt.Errorf("external runner network transport %q is unsupported", p.Network.Transport)
	}
	switch p.Status {
	case "diagnostic":
		if p.Network.Enforcement != "disabled-bringup" || p.Network.RequireReadyBeforePublish {
			return fmt.Errorf("diagnostic external runner profile has inconsistent network admission")
		}
	case "strict":
		if p.Network.Enforcement != "strict" || !p.Network.RequireReadyBeforePublish {
			return fmt.Errorf("strict external runner profile has inconsistent network admission")
		}
	default:
		return fmt.Errorf("external runner profile status %q is unsupported", p.Status)
	}
	if !validTimeout(p.Timeouts.ReadinessSeconds) || !validTimeout(p.Timeouts.GracefulShutdownSeconds) {
		return fmt.Errorf("external runner profile timeout is invalid")
	}
	return nil
}

func (p Profile) ReadinessTimeout() time.Duration {
	return time.Duration(p.Timeouts.ReadinessSeconds) * time.Second
}

func (p Profile) GracefulShutdownTimeout() time.Duration {
	return time.Duration(p.Timeouts.GracefulShutdownSeconds) * time.Second
}

func (p Profile) VerifyRunner() error {
	if err := p.Validate(); err != nil {
		return err
	}
	info, err := os.Lstat(p.Runner.Path)
	if err != nil {
		return fmt.Errorf("inspect external runner executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("external runner executable has unsafe type or permissions")
	}
	file, err := os.Open(p.Runner.Path)
	if err != nil {
		return fmt.Errorf("open external runner executable: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Mode().Perm()&0o022 != 0 {
		_ = file.Close()
		return fmt.Errorf("external runner executable identity changed while opening")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("hash external runner executable: %w", err)
	}
	got := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if got != p.Runner.SHA256 {
		return fmt.Errorf("external runner executable digest mismatch")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func validPort(port uint32) bool    { return port >= 1024 && port <= 65535 }
func validTimeout(seconds int) bool { return seconds >= 1 && seconds <= 600 }

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("trailing JSON value")
}
