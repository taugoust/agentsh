//go:build linux

package externalrunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
	"github.com/agentsh/agentsh/internal/runtimeprovider/gitdraft"
	"github.com/agentsh/agentsh/internal/workspace/runtimebin"
)

type gitSealControl interface {
	ExportArtifact(context.Context, string, io.Writer) (guestcontrol.ArtifactTransfer, error)
}

var newGitSealControl = func(manifest guestcontrol.Manifest) (gitSealControl, error) {
	return guestcontrol.NewVSockClient(manifest)
}

var verifyGitSealResult = func(ctx context.Context, input, result *os.File, baseline, resultCommit string) error {
	git, err := runtimebin.Resolve("git")
	if err != nil {
		return err
	}
	return gitdraft.VerifyResultBundles(ctx, git, input, result, baseline, resultCommit)
}

func ExportGitDraftResult(ctx context.Context, sessionID, stateDir, output string) (GitResultRecord, error) {
	var result GitResultRecord
	err := runtimeprovider.WithOperationLock(ctx, stateDir, func() error {
		manifest, err := runtimeprovider.ReadManifest(stateDir)
		if err != nil {
			return err
		}
		if manifest.SessionID != sessionID || manifest.Provider != ProviderName || (manifest.State != runtimeprovider.StateReady && manifest.State != runtimeprovider.StateStopped) {
			return fmt.Errorf("external Git Draft is not reviewable")
		}
		request, err := ReadHostMonitorRequest(stateDir)
		if err != nil {
			return err
		}
		result, err = ReadGitResultRecord(stateDir, request)
		if err != nil {
			return err
		}
		store, err := artifact.NewStore(stateDir, sessionID, guestcontrol.MaxArtifactTransferBytes)
		if err != nil {
			return err
		}
		file, descriptor, err := store.Open(ctx, result.ResultArtifact.ArtifactID, artifact.KindGitResultBundle)
		if err != nil {
			return err
		}
		defer file.Close()
		if descriptor != result.ResultArtifact {
			return fmt.Errorf("Git result artifact identity changed before export")
		}
		output = filepath.Clean(strings.TrimSpace(output))
		if !filepath.IsAbs(output) || output == string(filepath.Separator) {
			return fmt.Errorf("Git result export path must be clean and absolute")
		}
		target, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		written, copyErr := io.CopyN(target, file, descriptor.Size)
		syncErr := target.Sync()
		closeErr := target.Close()
		if err := errors.Join(copyErr, syncErr, closeErr); err != nil || written != descriptor.Size {
			_ = os.Remove(output)
			return fmt.Errorf("export exact Git result artifact: %w", err)
		}
		return nil
	})
	return result, err
}

func SealGitDraft(ctx context.Context, sessionID, stateDir string) (GitResultRecord, error) {
	var result GitResultRecord
	err := runtimeprovider.WithOperationLock(ctx, stateDir, func() error {
		manifest, err := runtimeprovider.ReadManifest(stateDir)
		if err != nil {
			return err
		}
		if manifest.SessionID != sessionID || manifest.Provider != ProviderName || manifest.State != runtimeprovider.StateReady || manifest.CleanupPending || manifest.CleanupComplete {
			return fmt.Errorf("external Git Draft runtime is not ready for sealing")
		}
		request, err := ReadHostMonitorRequest(stateDir)
		if err != nil {
			return err
		}
		if request.SchemaVersion != HostMonitorSchemaVersionV2 || request.InputArtifact == nil {
			return fmt.Errorf("external runtime is not a Git-volume Draft")
		}
		store, err := artifact.NewStore(stateDir, sessionID, guestcontrol.MaxArtifactTransferBytes)
		if err != nil {
			return err
		}
		if existing, readErr := ReadGitResultRecord(stateDir, request); readErr == nil {
			file, descriptor, openErr := store.Open(ctx, existing.ResultArtifact.ArtifactID, artifact.KindGitResultBundle)
			if openErr != nil {
				return openErr
			}
			_ = file.Close()
			if descriptor != existing.ResultArtifact {
				return fmt.Errorf("retained Git result artifact identity changed")
			}
			result = existing
			return nil
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		status, err := ReadHostMonitorStatus(stateDir)
		if err != nil {
			return err
		}
		if status.State != HostMonitorControlReady || status.Guest == nil || status.Endpoint == nil || status.VolumeID != request.VolumeID {
			return fmt.Errorf("external Git Draft guest is not authenticated and ready")
		}
		profile, profileFileDigest, err := ReadProfileSnapshot(request.ProfileFile)
		if err != nil {
			return err
		}
		layout, err := HostMonitorPaths(stateDir)
		if err != nil {
			return err
		}
		guestManifest, guestManifestDigest, err := ReadHostGuestManifestSnapshot(layout.GuestManifest, profile.Guest.Workspace, profile.Name, profile.Guest.ProfileDigest, []string{profile.Guest.Policy})
		if err != nil {
			return err
		}
		if err := validateHostMonitorBindings(request, profile, profileFileDigest, guestManifest, guestManifestDigest); err != nil {
			return fmt.Errorf("validate authoritative Git Draft launch bindings: %w", err)
		}
		control, err := newGitSealControl(guestManifest)
		if err != nil {
			return err
		}
		reader, writer := io.Pipe()
		type exportResult struct {
			transfer guestcontrol.ArtifactTransfer
			err      error
		}
		exported := make(chan exportResult, 1)
		go func() {
			transfer, exportErr := control.ExportArtifact(ctx, guestcontrol.ArtifactKindGitResultBundle, writer)
			_ = writer.CloseWithError(exportErr)
			exported <- exportResult{transfer: transfer, err: exportErr}
		}()
		descriptor, putErr := store.Put(ctx, artifact.KindGitResultBundle, reader)
		_ = reader.CloseWithError(putErr)
		export := <-exported
		if err := errors.Join(putErr, export.err); err != nil {
			return fmt.Errorf("persist sealed Git result artifact: %w", err)
		}
		if descriptor.SHA256 != export.transfer.SHA256 || descriptor.Size != export.transfer.Size || export.transfer.Validate() != nil {
			_ = store.Delete(descriptor.ArtifactID, artifact.KindGitResultBundle)
			return fmt.Errorf("sealed Git result host and guest identities differ")
		}
		inputFile, inputDescriptor, err := store.Open(ctx, request.InputArtifact.ArtifactID, artifact.KindGitInputBundle)
		if err != nil {
			return err
		}
		defer inputFile.Close()
		if inputDescriptor != *request.InputArtifact {
			return fmt.Errorf("Git input artifact changed before result verification")
		}
		resultFile, resultDescriptor, err := store.Open(ctx, descriptor.ArtifactID, artifact.KindGitResultBundle)
		if err != nil {
			return err
		}
		defer resultFile.Close()
		if resultDescriptor != descriptor {
			return fmt.Errorf("Git result artifact changed before verification")
		}
		if err := verifyGitSealResult(ctx, inputFile, resultFile, export.transfer.BaselineCommit, export.transfer.ResultCommit); err != nil {
			_ = store.Delete(descriptor.ArtifactID, artifact.KindGitResultBundle)
			return fmt.Errorf("verify sealed Git result: %w", err)
		}
		result = GitResultRecord{
			SchemaVersion: GitResultSchemaVersion, SessionID: sessionID, VolumeID: request.VolumeID,
			InputArtifactID: request.InputArtifact.ArtifactID, InputSHA256: request.InputArtifact.SHA256,
			ResultArtifact: descriptor, BaselineCommit: export.transfer.BaselineCommit, ResultCommit: export.transfer.ResultCommit, CreatedAt: time.Now().UTC(),
		}
		if err := WriteGitResultRecord(stateDir, request, result); err != nil {
			return err
		}
		return nil
	})
	return result, err
}
