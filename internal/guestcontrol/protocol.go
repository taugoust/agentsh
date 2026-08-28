package guestcontrol

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// ProtocolVersionV2 is retained for already-created legacy sessions. It
	// predates workspace-volume identity and must never carry a VolumeID.
	ProtocolVersionV2 = 2
	// ProtocolVersionV3 binds the authenticated guest to one exact workspace
	// volume. ProtocolVersion is the version used for new current manifests.
	ProtocolVersionV3 = 3
	ProtocolVersion   = ProtocolVersionV3

	MaxMessageBytes = 64 * 1024
)

type Manifest struct {
	ProtocolVersion    int    `json:"protocol_version"`
	SessionID          string `json:"session_id"`
	LaunchNonce        string `json:"launch_nonce"`
	ControlToken       string `json:"control_token"`
	SupervisorToken    string `json:"supervisor_token"`
	Profile            string `json:"profile"`
	ProfileDigest      string `json:"profile_digest"`
	Policy             string `json:"policy"`
	Workspace          string `json:"workspace"`
	VSockCID           uint32 `json:"vsock_cid"`
	VSockPort          uint32 `json:"vsock_port"`
	SupervisorPort     uint32 `json:"supervisor_port"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	VolumeID           string `json:"volume_id,omitempty"`
}

func (m Manifest) Validate(workspace, expectedProfile, expectedProfileDigest string, allowedPolicies []string) error {
	switch m.ProtocolVersion {
	case ProtocolVersionV2:
		if m.VolumeID != "" {
			return fmt.Errorf("guest control protocol version 2 cannot carry a volume identity")
		}
	case ProtocolVersionV3:
		if !canonicalVolumeID(m.VolumeID) {
			return fmt.Errorf("guest control volume identity is invalid")
		}
	default:
		return fmt.Errorf("guest control protocol version %d is unsupported", m.ProtocolVersion)
	}
	if err := validateSessionID(m.SessionID); err != nil {
		return err
	}
	if !validHexSecret(m.LaunchNonce) {
		return fmt.Errorf("guest control launch nonce is invalid")
	}
	if !validHexSecret(m.ControlToken) || !validHexSecret(m.SupervisorToken) || secretEqual(m.ControlToken, m.SupervisorToken) {
		return fmt.Errorf("guest control tokens are invalid or reused")
	}
	if !validName(m.Profile) || !validName(m.Policy) {
		return fmt.Errorf("guest control profile or policy is invalid")
	}
	if m.Profile != expectedProfile || m.ProfileDigest != expectedProfileDigest {
		return fmt.Errorf("guest control profile identity does not match the compiled guest profile")
	}
	if !strings.HasPrefix(m.ProfileDigest, "sha256:") || len(m.ProfileDigest) != len("sha256:")+64 || !validHex(m.ProfileDigest[len("sha256:"):]) {
		return fmt.Errorf("guest control profile digest is invalid")
	}
	workspace = filepath.Clean(workspace)
	if !filepath.IsAbs(workspace) || m.Workspace != workspace {
		return fmt.Errorf("guest control workspace does not match the operator-owned mount")
	}
	if !slices.Contains(allowedPolicies, m.Policy) {
		return fmt.Errorf("guest control policy %q is not operator-allowed", m.Policy)
	}
	if m.VSockCID < 3 || m.VSockCID == ^uint32(0) {
		return fmt.Errorf("guest control VSOCK CID is invalid")
	}
	if m.VSockPort < 1024 || m.VSockPort > 65535 || m.SupervisorPort < 1024 || m.SupervisorPort > 65535 || m.SupervisorPort == m.VSockPort {
		return fmt.Errorf("guest control VSOCK ports are invalid or reused")
	}
	if m.ExpectedGeneration == 0 {
		return fmt.Errorf("guest control expected generation is missing")
	}
	return nil
}

func ReadManifest(path, workspace, expectedProfile, expectedProfileDigest string, allowedPolicies []string) (Manifest, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Manifest{}, fmt.Errorf("guest control manifest path must be clean and absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect guest control manifest: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 || before.Size() > MaxMessageBytes {
		return Manifest{}, fmt.Errorf("guest control manifest has unsafe type, permissions, or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open guest control manifest: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Manifest{}, fmt.Errorf("stat opened guest control manifest: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return Manifest{}, fmt.Errorf("guest control manifest identity changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, MaxMessageBytes+1))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode guest control manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, fmt.Errorf("decode guest control manifest: %w", err)
	}
	if err := manifest.Validate(workspace, expectedProfile, expectedProfileDigest, allowedPolicies); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

type Handshake struct {
	ProtocolVersion int      `json:"protocol_version"`
	SessionID       string   `json:"session_id"`
	Generation      uint64   `json:"generation"`
	IncarnationID   string   `json:"incarnation_id"`
	LaunchNonce     string   `json:"launch_nonce"`
	GuestBootID     string   `json:"guest_boot_id"`
	Profile         string   `json:"profile"`
	ProfileDigest   string   `json:"profile_digest"`
	AgentSHVersion  string   `json:"agentsh_version"`
	EventToken      string   `json:"event_token"`
	Policy          string   `json:"policy"`
	VSockCID        uint32   `json:"vsock_cid"`
	VSockPort       uint32   `json:"vsock_port"`
	SupervisorPort  uint32   `json:"supervisor_port"`
	NetworkReady    bool     `json:"network_ready"`
	Capabilities    []string `json:"capabilities"`
	VolumeID        string   `json:"volume_id,omitempty"`
}

func (h Handshake) Validate(manifest Manifest) error {
	if h.ProtocolVersion != manifest.ProtocolVersion || h.SessionID != manifest.SessionID || h.Generation != manifest.ExpectedGeneration ||
		h.LaunchNonce != manifest.LaunchNonce || h.Profile != manifest.Profile || h.ProfileDigest != manifest.ProfileDigest ||
		h.Policy != manifest.Policy || h.VSockCID != manifest.VSockCID || h.VSockPort != manifest.VSockPort || h.SupervisorPort != manifest.SupervisorPort ||
		h.VolumeID != manifest.VolumeID {
		return fmt.Errorf("guest control handshake identity mismatch")
	}
	if strings.TrimSpace(h.IncarnationID) == "" || strings.TrimSpace(h.GuestBootID) == "" || strings.TrimSpace(h.AgentSHVersion) == "" || !validHexSecret(h.EventToken) {
		return fmt.Errorf("guest control handshake is incomplete")
	}
	if !slices.Contains(h.Capabilities, "exec_probe") || !slices.Contains(h.Capabilities, "shutdown") || !slices.Contains(h.Capabilities, "supervisor_proxy") ||
		manifest.ProtocolVersion == ProtocolVersionV3 && (!slices.Contains(h.Capabilities, "artifact_import") || !slices.Contains(h.Capabilities, "artifact_export")) {
		return fmt.Errorf("guest control handshake capabilities are incomplete")
	}
	return nil
}

type Request struct {
	ProtocolVersion int               `json:"protocol_version"`
	Type            string            `json:"type"`
	LaunchNonce     string            `json:"launch_nonce"`
	ControlToken    string            `json:"control_token"`
	RequestID       string            `json:"request_id,omitempty"`
	Artifact        *ArtifactTransfer `json:"artifact,omitempty"`
}

type ExecProbeResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

type Response struct {
	ProtocolVersion int               `json:"protocol_version"`
	Type            string            `json:"type"`
	RequestID       string            `json:"request_id,omitempty"`
	OK              bool              `json:"ok"`
	Error           string            `json:"error,omitempty"`
	Handshake       *Handshake        `json:"handshake,omitempty"`
	ExecProbe       *ExecProbeResult  `json:"exec_probe,omitempty"`
	Artifact        *ArtifactTransfer `json:"artifact,omitempty"`
}

type Handler interface {
	Handshake() Handshake
	ClaimRequest(string) bool
	ExecProbe(context.Context) (ExecProbeResult, error)
	Shutdown(context.Context) error
}

type Server struct {
	fd        int
	localCID  uint32
	port      uint32
	closeOnce sync.Once
	closeErr  error
}

func (s *Server) LocalCID() uint32 { return s.localCID }
func (s *Server) Port() uint32     { return s.port }

func (s *Server) Close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	s.closeOnce.Do(func() { s.closeErr = closeVSock(s.fd) })
	return s.closeErr
}

func (s *Server) Serve(ctx context.Context, manifest Manifest, handler Handler) error {
	if s == nil || s.fd < 0 || handler == nil {
		return fmt.Errorf("guest control server is not initialized")
	}
	if s.localCID != 0 && s.localCID != ^uint32(0) && s.localCID != manifest.VSockCID {
		return fmt.Errorf("guest control local VSOCK CID %d does not match manifest CID %d", s.localCID, manifest.VSockCID)
	}
	handshake := handler.Handshake()
	if err := handshake.Validate(manifest); err != nil {
		return err
	}

	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	for {
		conn, err := acceptVSock(s.fd)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept guest control VSOCK connection: %w", err)
		}
		shutdown, handleErr := handleConnection(ctx, conn, manifest, handler)
		_ = conn.Close()
		if handleErr != nil {
			return handleErr
		}
		if shutdown {
			return nil
		}
	}
}

type deadlineReadWriter interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
}

func handleConnection(ctx context.Context, conn deadlineReadWriter, manifest Manifest, handler Handler) (bool, error) {
	protocol := manifest.ProtocolVersion
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReaderSize(conn, MaxMessageBytes+1)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > MaxMessageBytes {
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "error", OK: false, Error: "invalid request framing"})
	}
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil {
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "error", OK: false, Error: "invalid request"})
	}
	if request.ProtocolVersion != protocol || request.LaunchNonce != manifest.LaunchNonce || !secretEqual(request.ControlToken, manifest.ControlToken) {
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "error", OK: false, Error: "authentication failed"})
	}
	if !validName(request.RequestID) || len(request.RequestID) > 128 {
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, OK: false, Error: "invalid request identity"})
	}
	if !handler.ClaimRequest(request.RequestID) {
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: "duplicate request identity"})
	}
	artifactOperation := request.Type == "artifact_import" || request.Type == "artifact_export"
	if !artifactOperation && request.Artifact != nil {
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: "unexpected artifact transfer identity"})
	}
	if artifactOperation {
		deadline := time.Now().Add(artifactTransferTimeout)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		_ = conn.SetDeadline(deadline)
	}

	switch request.Type {
	case "hello":
		handshake := handler.Handshake()
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "hello", RequestID: request.RequestID, OK: true, Handshake: &handshake})
	case "exec_probe":
		result, err := handler.ExecProbe(ctx)
		if err != nil {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "exec_probe", RequestID: request.RequestID, OK: false, Error: boundedError(err)})
		}
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "exec_probe", RequestID: request.RequestID, OK: true, ExecProbe: &result})
	case "shutdown":
		if err := handler.Shutdown(ctx); err != nil {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "shutdown", RequestID: request.RequestID, OK: false, Error: boundedError(err)})
		}
		return true, writeResponse(conn, Response{ProtocolVersion: protocol, Type: "shutdown", RequestID: request.RequestID, OK: true})
	case "artifact_import":
		artifacts, ok := handler.(ArtifactImportHandler)
		if protocol != ProtocolVersionV3 || !ok || request.Artifact == nil || request.Artifact.Kind != ArtifactKindGitInputBundle || request.Artifact.Validate() != nil {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: "artifact import is unavailable or invalid"})
		}
		limited := io.LimitReader(reader, request.Artifact.Size)
		if err := artifacts.ImportArtifact(ctx, *request.Artifact, limited); err != nil {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: boundedError(err)})
		}
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: true, Artifact: request.Artifact})
	case "artifact_export":
		artifacts, ok := handler.(ArtifactExportHandler)
		if protocol != ProtocolVersionV3 || !ok || request.Artifact == nil || request.Artifact.Kind != ArtifactKindGitResultBundle {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: "artifact export is unavailable or invalid"})
		}
		transfer, source, err := artifacts.ExportArtifact(ctx, request.Artifact.Kind)
		if err != nil {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: boundedError(err)})
		}
		defer source.Close()
		if err := transfer.Validate(); err != nil || transfer.Kind != request.Artifact.Kind {
			return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: "artifact export identity is invalid"})
		}
		if err := writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: true, Artifact: &transfer}); err != nil {
			return false, err
		}
		written, err := io.CopyN(conn, source, transfer.Size)
		if err != nil || written != transfer.Size {
			return false, fmt.Errorf("stream guest artifact export: %w", err)
		}
		return false, nil
	default:
		return false, writeResponse(conn, Response{ProtocolVersion: protocol, Type: request.Type, RequestID: request.RequestID, OK: false, Error: "unsupported request type"})
	}
}

func writeResponse(writer io.Writer, response Response) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}

func ReadHandshake(path string, manifest Manifest) (Handshake, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Handshake{}, fmt.Errorf("guest control handshake path must be clean and absolute")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() > MaxMessageBytes {
		return Handshake{}, fmt.Errorf("guest control handshake has unsafe type, permissions, or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return Handshake{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return Handshake{}, fmt.Errorf("guest control handshake identity changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, MaxMessageBytes+1))
	decoder.DisallowUnknownFields()
	var handshake Handshake
	if err := decoder.Decode(&handshake); err != nil || requireJSONEOF(decoder) != nil {
		return Handshake{}, fmt.Errorf("decode guest control handshake")
	}
	public := handshake
	if public.EventToken == "" {
		public.EventToken = strings.Repeat("0", 64)
	}
	if err := public.Validate(manifest); err != nil {
		return Handshake{}, err
	}
	return handshake, nil
}

func WriteHandshake(path string, handshake Handshake) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("guest control handshake path must be clean and absolute")
	}
	publicHandshake := handshake
	publicHandshake.EventToken = ""
	data, err := json.MarshalIndent(publicHandshake, "", "  ")
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("guest control handshake directory is invalid")
	}
	tmp, err := os.CreateTemp(parent, ".handshake-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
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
	return os.Rename(tmpPath, path)
}

func validateSessionID(value string) error {
	if !strings.HasPrefix(value, "session-") {
		return fmt.Errorf("guest control session identity is invalid")
	}
	parsed, err := uuid.Parse(strings.TrimPrefix(value, "session-"))
	if err != nil || parsed == uuid.Nil || value != "session-"+parsed.String() {
		return fmt.Errorf("guest control session identity is invalid")
	}
	return nil
}

func validHexSecret(value string) bool {
	return len(value) == 64 && validHex(value)
}

func canonicalVolumeID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.Version() == 4 && parsed.Variant() == uuid.RFC4122 && parsed.String() == value
}

func validHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validName(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n/\\") {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '.', char == '_', char == '-':
		default:
			return false
		}
	}
	return true
}

func secretEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("trailing JSON value")
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ReplaceAll(err.Error(), "\x00", "")
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}
