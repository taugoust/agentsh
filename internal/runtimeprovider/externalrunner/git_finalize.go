//go:build linux

package externalrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
)

var deleteGitDraftVolume = DeleteWorkspaceVolume

func FinalizeGitDraftStorage(ctx context.Context, sessionID, stateDir, intent string) (GitTerminalRecord, error) {
	intent = strings.TrimSpace(intent)
	if intent != "applied" && intent != "discarded" {
		return GitTerminalRecord{}, fmt.Errorf("Git Draft terminal intent must be applied or discarded")
	}
	var terminal GitTerminalRecord
	err := runtimeprovider.WithOperationLock(ctx, stateDir, func() error {
		manifest, err := runtimeprovider.ReadManifest(stateDir)
		if err != nil {
			return err
		}
		if manifest.SessionID != sessionID || manifest.Provider != ProviderName || manifest.State != runtimeprovider.StateStopped || !manifest.CleanupComplete || manifest.CleanupPending {
			return fmt.Errorf("Git Draft storage cleanup requires exact stopped runtime evidence")
		}
		request, err := ReadHostMonitorRequest(stateDir)
		if err != nil {
			return err
		}
		if (request.SchemaVersion != HostMonitorSchemaVersionV2 && request.SchemaVersion != HostMonitorSchemaVersionV3) || request.InputArtifact == nil {
			return fmt.Errorf("runtime is not a Git-volume Draft")
		}
		status, err := ReadHostMonitorStatus(stateDir)
		if err != nil {
			return err
		}
		if !hostMonitorStatusTerminal(status) {
			return fmt.Errorf("Git Draft monitor lacks exact terminal teardown evidence")
		}
		result, resultErr := ReadGitResultRecord(stateDir, request)
		if intent == "applied" && resultErr != nil {
			return fmt.Errorf("applied Git Draft has no verified result: %w", resultErr)
		}
		if resultErr != nil && !errors.Is(resultErr, os.ErrNotExist) {
			return resultErr
		}
		terminalPath := filepath.Join(HostMonitorLayoutMust(stateDir).HostDir, GitTerminalRecordName)
		if readErr := readStrictPrivateJSON(terminalPath, &terminal); readErr == nil {
			if terminal.SchemaVersion != 1 || terminal.SessionID != sessionID || terminal.VolumeID != request.VolumeID || terminal.Intent != intent {
				return fmt.Errorf("Git Draft terminal intent conflicts with retained state")
			}
			if terminal.Complete {
				return nil
			}
		} else if errors.Is(readErr, os.ErrNotExist) {
			now := time.Now().UTC()
			terminal = GitTerminalRecord{SchemaVersion: 1, SessionID: sessionID, VolumeID: request.VolumeID, Intent: intent, CreatedAt: now, UpdatedAt: now}
			if err := writeGitTerminalRecord(terminalPath, terminal, true); err != nil {
				return err
			}
		} else {
			return readErr
		}
		profile, profileDigest, err := ReadProfileSnapshot(request.ProfileFile)
		if err != nil {
			return err
		}
		if !terminal.VolumeDeleted {
			volumeRequest := WorkspaceVolumeRequest{StateDir: stateDir, SessionID: sessionID, Profile: profile, ProfileFileSHA256: profileDigest}
			if err := deleteGitDraftVolume(ctx, volumeRequest, request.VolumeID); err != nil {
				return err
			}
			terminal.VolumeDeleted = true
			terminal.UpdatedAt = time.Now().UTC()
			if err := writeGitTerminalRecord(terminalPath, terminal, false); err != nil {
				return err
			}
		}
		if !terminal.ArtifactsDeleted {
			store, err := artifact.NewStore(stateDir, sessionID, guestcontrol.MaxArtifactTransferBytes)
			if err != nil {
				return err
			}
			if resultErr == nil {
				if err := store.Delete(result.ResultArtifact.ArtifactID, artifact.KindGitResultBundle); err != nil {
					return err
				}
			}
			if err := store.Delete(request.InputArtifact.ArtifactID, artifact.KindGitInputBundle); err != nil {
				return err
			}
			terminal.ArtifactsDeleted = true
			terminal.UpdatedAt = time.Now().UTC()
			if err := writeGitTerminalRecord(terminalPath, terminal, false); err != nil {
				return err
			}
		}
		terminal.Complete = true
		terminal.UpdatedAt = time.Now().UTC()
		return writeGitTerminalRecord(terminalPath, terminal, false)
	})
	return terminal, err
}

func HostMonitorLayoutMust(stateDir string) HostMonitorLayout {
	layout, _ := HostMonitorPaths(stateDir)
	return layout
}

func writeGitTerminalRecord(path string, record GitTerminalRecord, exclusive bool) error {
	if record.SchemaVersion != 1 || record.SessionID == "" || !canonicalWorkspaceVolumeUUID(record.VolumeID) || (record.Intent != "applied" && record.Intent != "discarded") ||
		record.CreatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) || record.Complete && (!record.VolumeDeleted || !record.ArtifactsDeleted) {
		return fmt.Errorf("Git Draft terminal record is invalid")
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if exclusive {
		return writeExclusivePrivateFile(path, append(data, '\n'))
	}
	parent := filepath.Dir(path)
	tmp, err := os.CreateTemp(parent, ".git-terminal-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	_, writeErr := tmp.Write(append(data, '\n'))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDirectory(parent)
}
