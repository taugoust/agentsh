package guestcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"
)

type artifactTestHandler struct {
	*fakeHandler
	imported []byte
	exported []byte
}

func (h *artifactTestHandler) ImportArtifact(_ context.Context, transfer ArtifactTransfer, source io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(source, transfer.Size+1))
	if err != nil {
		return err
	}
	if int64(len(data)) != transfer.Size || artifactTestTransfer(transfer.Kind, data) != transfer {
		return ErrArtifactTestIdentity
	}
	h.imported = data
	return nil
}

func (h *artifactTestHandler) ExportArtifact(_ context.Context, kind string) (ArtifactTransfer, io.ReadCloser, error) {
	transfer := artifactTestTransfer(kind, h.exported)
	return transfer, io.NopCloser(bytes.NewReader(h.exported)), nil
}

var ErrArtifactTestIdentity = &artifactTestError{}

type artifactTestError struct{}

func (*artifactTestError) Error() string { return "artifact identity mismatch" }

func artifactTestTransfer(kind string, data []byte) ArtifactTransfer {
	sum := sha256.Sum256(data)
	transfer := ArtifactTransfer{Kind: kind, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if kind == ArtifactKindGitResultBundle {
		transfer.BaselineCommit = strings.Repeat("1", 40)
		transfer.ResultCommit = strings.Repeat("2", 40)
	}
	return transfer
}

func TestClientTransfersAuthenticatedProtocolV3Artifacts(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handler := &artifactTestHandler{
		fakeHandler: &fakeHandler{handshake: testHandshake(manifest)},
		exported:    []byte("result bundle bytes"),
	}
	client, err := newClient(manifest, pipeDialer(t, manifest, handler), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("input bundle bytes")
	inputTransfer := artifactTestTransfer(ArtifactKindGitInputBundle, input)
	if err := client.ImportArtifact(context.Background(), inputTransfer, bytes.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handler.imported, input) {
		t.Fatalf("imported bytes = %q", handler.imported)
	}
	var result bytes.Buffer
	resultTransfer, err := client.ExportArtifact(context.Background(), ArtifactKindGitResultBundle, &result)
	if err != nil {
		t.Fatal(err)
	}
	if resultTransfer != artifactTestTransfer(ArtifactKindGitResultBundle, handler.exported) || !bytes.Equal(result.Bytes(), handler.exported) {
		t.Fatalf("export = %+v %q", resultTransfer, result.Bytes())
	}
}

func TestArtifactTransfersRejectProtocolV2AndDigestMismatch(t *testing.T) {
	manifest := testManifest(t.TempDir())
	manifest.ProtocolVersion = ProtocolVersionV2
	manifest.VolumeID = ""
	handler := &artifactTestHandler{fakeHandler: &fakeHandler{handshake: testHandshake(manifest)}}
	client, err := newClient(manifest, pipeDialer(t, manifest, handler), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transfer := artifactTestTransfer(ArtifactKindGitInputBundle, []byte("expected"))
	if err := client.ImportArtifact(context.Background(), transfer, bytes.NewReader([]byte("expected"))); err == nil {
		t.Fatal("protocol v2 imported an artifact")
	}

	manifest = testManifest(t.TempDir())
	handler = &artifactTestHandler{fakeHandler: &fakeHandler{handshake: testHandshake(manifest)}}
	client, err = newClient(manifest, pipeDialer(t, manifest, handler), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ImportArtifact(context.Background(), transfer, bytes.NewReader([]byte("wrong!!!"))); err == nil {
		t.Fatal("artifact import accepted substituted content")
	}
}
