package guestcontrol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	MaxArtifactTransferBytes int64 = 1 << 30
	artifactTransferTimeout        = 10 * time.Minute
)

const (
	ArtifactKindGitInputBundle  = "git-input-bundle"
	ArtifactKindGitResultBundle = "git-result-bundle"
)

type ArtifactTransfer struct {
	Kind           string `json:"kind"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	BaselineCommit string `json:"baseline_commit,omitempty"`
	ResultCommit   string `json:"result_commit,omitempty"`
}

func (a ArtifactTransfer) Validate() error {
	if a.Kind != ArtifactKindGitInputBundle && a.Kind != ArtifactKindGitResultBundle {
		return fmt.Errorf("guest artifact kind is unsupported")
	}
	if a.Size < 0 || a.Size > MaxArtifactTransferBytes || !validSHA256Digest(a.SHA256) {
		return fmt.Errorf("guest artifact transfer identity is invalid")
	}
	switch a.Kind {
	case ArtifactKindGitInputBundle:
		if a.BaselineCommit != "" || a.ResultCommit != "" {
			return fmt.Errorf("Git input byte transfer cannot claim result identity")
		}
	case ArtifactKindGitResultBundle:
		if !validGitOID(a.BaselineCommit) || !validGitOID(a.ResultCommit) || a.BaselineCommit == a.ResultCommit {
			return fmt.Errorf("Git result transfer commit identity is invalid")
		}
	}
	return nil
}

// ArtifactHandler is an optional protocol-v3-and-later extension. Implementations must
// treat ImportArtifact as an exact, all-or-nothing byte transfer and return an
// already-complete immutable stream from ExportArtifact.
type ArtifactImportHandler interface {
	ImportArtifact(context.Context, ArtifactTransfer, io.Reader) error
}

type ArtifactExportHandler interface {
	ExportArtifact(context.Context, string) (ArtifactTransfer, io.ReadCloser, error)
}

func (c *Client) ImportArtifact(ctx context.Context, transfer ArtifactTransfer, source io.Reader) error {
	if c == nil || c.dial == nil || (c.manifest.ProtocolVersion != ProtocolVersionV3 && c.manifest.ProtocolVersion != ProtocolVersionV4) {
		return fmt.Errorf("guest artifact import requires protocol version 3")
	}
	if err := transfer.Validate(); err != nil {
		return err
	}
	if transfer.Kind != ArtifactKindGitInputBundle || source == nil {
		return fmt.Errorf("guest artifact import requires an input bundle")
	}
	conn, request, err := c.openArtifactConnection(ctx, "artifact_import", &transfer)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return contextOrError(ctx, fmt.Errorf("write guest artifact import request: %w", err))
	}
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(conn, hasher), source, transfer.Size)
	if err != nil || written != transfer.Size {
		return contextOrError(ctx, fmt.Errorf("write guest artifact import: %w", err))
	}
	if got := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); got != transfer.SHA256 {
		return fmt.Errorf("guest artifact import source digest mismatch")
	}
	response, err := readArtifactResponse(conn, c.manifest.ProtocolVersion, request.Type, request.RequestID)
	if err != nil {
		return contextOrError(ctx, err)
	}
	if response.Artifact == nil || *response.Artifact != transfer {
		return fmt.Errorf("guest artifact import response identity mismatch")
	}
	return nil
}

func (c *Client) ExportArtifact(ctx context.Context, kind string, destination io.Writer) (ArtifactTransfer, error) {
	if c == nil || c.dial == nil || (c.manifest.ProtocolVersion != ProtocolVersionV3 && c.manifest.ProtocolVersion != ProtocolVersionV4) {
		return ArtifactTransfer{}, fmt.Errorf("guest artifact export requires protocol version 3")
	}
	if kind != ArtifactKindGitResultBundle || destination == nil {
		return ArtifactTransfer{}, fmt.Errorf("guest artifact export requires a result bundle destination")
	}
	conn, request, err := c.openArtifactConnection(ctx, "artifact_export", &ArtifactTransfer{Kind: kind})
	if err != nil {
		return ArtifactTransfer{}, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return ArtifactTransfer{}, contextOrError(ctx, fmt.Errorf("write guest artifact export request: %w", err))
	}
	reader := bufio.NewReaderSize(conn, MaxMessageBytes+1)
	response, err := readArtifactResponseFrom(reader, c.manifest.ProtocolVersion, request.Type, request.RequestID)
	if err != nil {
		return ArtifactTransfer{}, contextOrError(ctx, err)
	}
	if response.Artifact == nil || response.Artifact.Kind != kind {
		return ArtifactTransfer{}, fmt.Errorf("guest artifact export response omitted its identity")
	}
	transfer := *response.Artifact
	if err := transfer.Validate(); err != nil {
		return ArtifactTransfer{}, err
	}
	hasher := sha256.New()
	written, err := io.CopyN(io.MultiWriter(destination, hasher), reader, transfer.Size)
	if err != nil || written != transfer.Size {
		return ArtifactTransfer{}, contextOrError(ctx, fmt.Errorf("read guest artifact export: %w", err))
	}
	if got := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); got != transfer.SHA256 {
		return ArtifactTransfer{}, fmt.Errorf("guest artifact export digest mismatch")
	}
	return transfer, nil
}

func (c *Client) openArtifactConnection(ctx context.Context, operation string, transfer *ArtifactTransfer) (controlConn, Request, error) {
	if err := ctx.Err(); err != nil {
		return nil, Request{}, err
	}
	request := c.newRequest(operation)
	request.Artifact = transfer
	conn, err := c.dial(ctx, c.manifest.VSockCID, c.manifest.VSockPort)
	if err != nil {
		return nil, Request{}, fmt.Errorf("dial guest control endpoint: %w", err)
	}
	deadline := time.Now().Add(artifactTransferTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, Request{}, err
	}
	return conn, request, nil
}

func readArtifactResponse(reader io.Reader, protocol int, operation, requestID string) (Response, error) {
	return readArtifactResponseFrom(bufio.NewReaderSize(reader, MaxMessageBytes+1), protocol, operation, requestID)
}

func readArtifactResponseFrom(reader *bufio.Reader, protocol int, operation, requestID string) (Response, error) {
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > MaxMessageBytes {
		return Response{}, fmt.Errorf("read guest artifact response")
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil || requireJSONEOF(decoder) != nil {
		return Response{}, fmt.Errorf("decode guest artifact response")
	}
	if response.ProtocolVersion != protocol || response.Type != operation || response.RequestID != requestID {
		return Response{}, fmt.Errorf("guest artifact response identity mismatch")
	}
	if !response.OK {
		return Response{}, fmt.Errorf("guest control %s failed: %s", operation, boundedError(errors.New(response.Error)))
	}
	if response.Error != "" {
		return Response{}, fmt.Errorf("guest artifact successful response included an error")
	}
	return response, nil
}

func validGitOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == len(value) && strings.ToLower(value) == value
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
