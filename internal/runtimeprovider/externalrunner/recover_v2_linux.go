//go:build linux

package externalrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
)

const v2RecoveryRecordName = "generation-recovery.json"

type v2RecoveryRecord struct {
	SchemaVersion  int                   `json:"schema_version"`
	SessionID      string                `json:"session_id"`
	FromGeneration uint64                `json:"from_generation"`
	Request        HostMonitorRequest    `json:"request"`
	GuestManifest  guestcontrol.Manifest `json:"guest_manifest"`
	CreatedAt      time.Time             `json:"created_at"`
}

func (p *Provider) recoverV2(ctx context.Context, manifestSessionID, stateDir, profileName string) (*providerInstance, error) {
	profile, profileFileDigest, err := p.profile(profileName)
	if err != nil {
		return nil, err
	}
	if profile.Schema != ProfileSchemaV2 && profile.Schema != ProfileSchemaV3 {
		return nil, fmt.Errorf("external generation recovery requires a v2 or v3 profile")
	}
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return nil, err
	}
	recoveryPath := filepath.Join(layout.RuntimeDir, v2RecoveryRecordName)
	var recovery v2RecoveryRecord
	if err := readStrictPrivateJSON(recoveryPath, &recovery); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		oldRequest, err := ReadHostMonitorRequest(stateDir)
		if err != nil {
			return nil, err
		}
		oldStatus, err := ReadHostMonitorStatus(stateDir)
		if err != nil {
			return nil, err
		}
		if oldRequest.SessionID != manifestSessionID || !hostMonitorStatusTerminal(oldStatus) || detached.ProcessIdentityMatches(oldStatus.Monitor.PID, oldStatus.Monitor.StartIdentity, oldStatus.Monitor.BootID) {
			return nil, fmt.Errorf("external v2 runtime lacks dead terminal generation evidence for recovery")
		}
		launchNonce, err := newProviderSecret()
		if err != nil {
			return nil, err
		}
		controlToken, err := newProviderSecret()
		if err != nil {
			return nil, err
		}
		supervisorToken, err := newProviderSecret()
		if err != nil {
			return nil, err
		}
		monitorID, err := newProviderSecret()
		if err != nil {
			return nil, err
		}
		egressToken := ""
		if profile.Schema == ProfileSchemaV3 {
			egressToken, err = newProviderSecret()
			if err != nil {
				return nil, err
			}
		}
		nextGeneration := oldRequest.ExpectedGuestGeneration + 1
		nextLease := oldRequest.CIDLease
		if verifyErr := VerifyCIDLease(ctx, oldRequest.CIDLeaseRoot, oldRequest.CIDLease, profile.VSock.CIDMin, profile.VSock.CIDMax); verifyErr != nil {
			nextLease, err = AllocateCID(ctx, oldRequest.CIDLeaseRoot, oldRequest.SessionID, profile.VSock.CIDMin, profile.VSock.CIDMax)
			if err != nil {
				return nil, fmt.Errorf("allocate resumed external runner CID: %w", err)
			}
		}
		guestManifest, err := newProviderGuestManifest(oldRequest.SessionID, profile, nextLease.CID, launchNonce, controlToken, supervisorToken, egressToken, oldRequest.VolumeID)
		if err != nil {
			return nil, err
		}
		guestManifest.ExpectedGeneration = nextGeneration
		guestData, err := json.MarshalIndent(guestManifest, "", "  ")
		if err != nil {
			return nil, err
		}
		guestData = append(guestData, '\n')
		guestSum := sha256.Sum256(guestData)
		nextRequest := oldRequest
		nextRequest.MonitorID = monitorID
		nextRequest.CIDLease = nextLease
		if profile.Schema == ProfileSchemaV3 {
			nextRequest.EgressPort, err = deriveHostEgressPort(profile, nextLease.CID)
			if err != nil {
				return nil, err
			}
		}
		nextRequest.ExpectedGuestGeneration = nextGeneration
		nextRequest.LaunchNonce = launchNonce
		nextRequest.GuestManifestSHA256 = "sha256:" + hex.EncodeToString(guestSum[:])
		nextRequest.CreatedAt = time.Now().UTC()
		recovery = v2RecoveryRecord{SchemaVersion: 1, SessionID: oldRequest.SessionID, FromGeneration: oldRequest.ExpectedGuestGeneration, Request: nextRequest, GuestManifest: guestManifest, CreatedAt: time.Now().UTC()}
		data, err := json.MarshalIndent(recovery, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := writeExclusivePrivateFile(recoveryPath, append(data, '\n')); err != nil {
			return nil, err
		}
	}
	if recovery.SchemaVersion != 1 || recovery.SessionID != manifestSessionID || recovery.Request.SessionID != manifestSessionID || recovery.Request.ExpectedGuestGeneration != recovery.FromGeneration+1 ||
		recovery.Request.ProfileName != profile.Name || recovery.Request.ProfileFileSHA256 != profileFileDigest || recovery.GuestManifest.ExpectedGeneration != recovery.Request.ExpectedGuestGeneration {
		return nil, fmt.Errorf("external generation recovery record is invalid")
	}
	archive := filepath.Join(layout.RuntimeDir, "generations", fmt.Sprintf("generation-%020d", recovery.FromGeneration))
	if err := os.MkdirAll(archive, 0o700); err != nil {
		return nil, err
	}
	for _, name := range []string{"host", "control", "logs"} {
		source := filepath.Join(layout.RuntimeDir, name)
		destination := filepath.Join(archive, name)
		sourceInfo, sourceErr := os.Lstat(source)
		_, destinationErr := os.Lstat(destination)
		switch {
		case sourceErr == nil && errors.Is(destinationErr, os.ErrNotExist):
			if !sourceInfo.IsDir() {
				return nil, fmt.Errorf("external recovery source %s is not a directory", name)
			}
			if err := os.Rename(source, destination); err != nil {
				return nil, err
			}
		case errors.Is(sourceErr, os.ErrNotExist) && destinationErr == nil:
		case sourceErr == nil && destinationErr == nil:
			// A recreated current directory and archived prior generation is the
			// idempotent post-archive shape.
		case sourceErr != nil:
			return nil, sourceErr
		default:
			return nil, destinationErr
		}
	}
	for _, path := range []string{layout.HostDir, layout.ControlDir, layout.LogsDir} {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	for _, name := range []string{GitResultRecordName, GitTerminalRecordName} {
		archived := filepath.Join(archive, "host", name)
		current := filepath.Join(layout.HostDir, name)
		if _, currentErr := os.Lstat(current); errors.Is(currentErr, os.ErrNotExist) {
			if _, archivedErr := os.Lstat(archived); archivedErr == nil {
				if err := os.Rename(archived, current); err != nil {
					return nil, err
				}
			} else if !errors.Is(archivedErr, os.ErrNotExist) {
				return nil, archivedErr
			}
		} else if currentErr != nil {
			return nil, currentErr
		}
	}
	guestData, err := json.MarshalIndent(recovery.GuestManifest, "", "  ")
	if err != nil {
		return nil, err
	}
	guestData = append(guestData, '\n')
	for _, manifestPath := range []string{layout.GuestManifest, layout.GuestManifestDelivery} {
		if _, err := os.Lstat(manifestPath); errors.Is(err, os.ErrNotExist) {
			if err := writeExclusivePrivateFile(manifestPath, guestData); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(layout.RequestPath); errors.Is(err, os.ErrNotExist) {
		if err := WriteHostMonitorRequest(stateDir, recovery.Request); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if status, err := ReadHostMonitorStatus(stateDir); err == nil && status.State == HostMonitorControlReady {
		instance, err := p.instanceFromStatus(stateDir, profile, profileFileDigest, status)
		if err == nil {
			_ = os.Remove(recoveryPath)
			_ = syncDirectory(layout.RuntimeDir)
			return instance, nil
		}
	}
	probeCtx, cancelProbe := context.WithTimeout(ctx, 100*time.Millisecond)
	probeLock, lockErr := acquireHostMonitorLock(probeCtx, layout.LockPath)
	cancelProbe()
	if lockErr == nil {
		_ = probeLock.Close()
		monitor, err := launchDetachedHostMonitor(p.options.MonitorExecutable, stateDir)
		if err != nil {
			return nil, err
		}
		status, err := waitForHostMonitorReady(ctx, stateDir, monitor, profile.ReadinessTimeout())
		if err != nil {
			return nil, err
		}
		instance, err := p.instanceFromStatus(stateDir, profile, profileFileDigest, status)
		if err != nil {
			return nil, err
		}
		_ = os.Remove(recoveryPath)
		_ = syncDirectory(layout.RuntimeDir)
		return instance, nil
	}
	deadline := time.NewTimer(profile.ReadinessTimeout())
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("wait for already-launched recovered monitor generation %s", strconv.FormatUint(recovery.Request.ExpectedGuestGeneration, 10))
		case <-ticker.C:
			status, readErr := ReadHostMonitorStatus(stateDir)
			if readErr == nil && status.State == HostMonitorControlReady {
				instance, openErr := p.instanceFromStatus(stateDir, profile, profileFileDigest, status)
				if openErr == nil {
					_ = os.Remove(recoveryPath)
					_ = syncDirectory(layout.RuntimeDir)
					return instance, nil
				}
			}
		}
	}
}
