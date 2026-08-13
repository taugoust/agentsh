package runtimeprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultCleanupTimeout = 30 * time.Second

type Controller struct {
	CleanupTimeout time.Duration
}

// WithLifecycleLock serializes a provider-owned metadata transition with
// controller Start/Recover/Stop operations for one exact state directory.
func WithLifecycleLock(stateDir string, update func() error) error {
	if update == nil {
		return fmt.Errorf("runtime lifecycle update is nil")
	}
	lock, err := acquireLifecycleLock(stateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	return update()
}

func (c Controller) cleanupTimeout() time.Duration {
	if c.CleanupTimeout <= 0 {
		return defaultCleanupTimeout
	}
	return c.CleanupTimeout
}

func (c Controller) Start(ctx context.Context, provider Provider, request Request) (Instance, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if err := validateProviderSelection(provider, request.Provider); err != nil {
		return nil, err
	}
	manifest := NewManifest(request, time.Now().UTC())
	if err := WithLifecycleLock(request.StateDir, func() error {
		if _, err := ReadManifest(request.StateDir); err == nil {
			return fmt.Errorf("runtime-provider manifest already exists for session %s", request.SessionID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return WriteManifest(request.StateDir, manifest)
	}); err != nil {
		return nil, err
	}
	capabilities, err := provider.Preflight(ctx, request)
	if err != nil {
		return nil, c.failWithoutInstance(request.StateDir, manifest, fmt.Errorf("runtime provider preflight: %w", err))
	}
	if err := validateCapabilities(capabilities, request.Provider); err != nil {
		return nil, c.failWithoutInstance(request.StateDir, manifest, err)
	}
	instance, err := provider.Start(ctx, request)
	if err != nil {
		if instance == nil {
			return nil, c.failWithoutInstance(request.StateDir, manifest, fmt.Errorf("start runtime provider: %w", err))
		}
		return nil, c.failStarted(request.StateDir, manifest, instance, StopReasonStartupFailed, fmt.Errorf("start runtime provider: %w", err))
	}
	if instance == nil {
		return nil, c.failWithoutInstance(request.StateDir, manifest, fmt.Errorf("runtime provider returned no instance"))
	}
	identity := instance.Identity()
	endpoint := instance.Endpoint()
	if err := validateIdentityForRequest(identity, request); err != nil {
		return nil, c.failStarted(request.StateDir, manifest, instance, StopReasonStartupFailed, err)
	}
	if err := endpoint.Validate(); err != nil {
		return nil, c.failStarted(request.StateDir, manifest, instance, StopReasonStartupFailed, err)
	}
	status, err := instance.Probe(ctx)
	if err != nil {
		return nil, c.failStarted(request.StateDir, manifest, instance, StopReasonStartupFailed, fmt.Errorf("probe runtime provider: %w", err))
	}
	if err := validateReadyStatus(status, identity, endpoint); err != nil {
		return nil, c.failStarted(request.StateDir, manifest, instance, StopReasonStartupFailed, err)
	}
	manifest.State = StateReady
	manifest.Identity = identity
	manifest.Endpoint = endpoint
	manifest.LastError = ""
	manifest.CleanupComplete = false
	if err := WithLifecycleLock(request.StateDir, func() error {
		current, readErr := ReadManifest(request.StateDir)
		if readErr != nil {
			return readErr
		}
		if current.State == StateStopping || current.State == StateStopped {
			return fmt.Errorf("runtime session %s committed stop during startup", current.SessionID)
		}
		if current.Provider != manifest.Provider || current.Profile != manifest.Profile || current.SessionID != manifest.SessionID || current.StateDir != manifest.StateDir {
			return fmt.Errorf("runtime-provider manifest changed during startup")
		}
		return WriteManifest(request.StateDir, manifest)
	}); err != nil {
		return nil, c.failStarted(request.StateDir, manifest, instance, StopReasonStartupFailed, fmt.Errorf("persist ready runtime provider: %w", err))
	}
	return instance, nil
}

func (c Controller) Recover(ctx context.Context, provider Provider, stateDir string, manifest Manifest) (Instance, error) {
	if err := validateManifestStateDir(stateDir, manifest); err != nil {
		return nil, err
	}
	if err := validateProviderSelection(provider, manifest.Provider); err != nil {
		return nil, err
	}
	var current Manifest
	if err := WithLifecycleLock(stateDir, func() error {
		var readErr error
		current, readErr = ReadManifest(stateDir)
		if readErr != nil {
			return readErr
		}
		if !sameManifestRevision(current, manifest) {
			return fmt.Errorf("runtime-provider manifest changed before recovery")
		}
		if current.State == StateStopping || current.State == StateStopped {
			return fmt.Errorf("runtime session %s is %s and cannot be recovered", current.SessionID, current.State)
		}
		if current.CleanupPending {
			return fmt.Errorf("runtime session %s has incomplete cleanup and cannot be recovered", current.SessionID)
		}
		if current.State == StateFailed && !current.CleanupComplete && !manifestHasExactRuntime(current) {
			return fmt.Errorf("runtime session %s has unbound incomplete cleanup and cannot be recovered", current.SessionID)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	manifest = current
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if manifest.Identity.Generation > 0 {
		existing, openErr := provider.Open(ctx, manifest)
		if openErr == nil && existing != nil {
			status, probeErr := existing.Probe(ctx)
			if probeErr == nil && validateReadyStatus(status, manifest.Identity, manifest.Endpoint) == nil {
				return existing, nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prior := manifest.Identity
	manifest.State = StateRecovering
	manifest.LastError = ""
	manifest.CleanupComplete = false
	if err := WithLifecycleLock(stateDir, func() error {
		latest, readErr := ReadManifest(stateDir)
		if readErr != nil {
			return readErr
		}
		if !sameManifestRevision(latest, current) {
			return fmt.Errorf("runtime-provider manifest changed while preparing recovery")
		}
		return WriteManifest(stateDir, manifest)
	}); err != nil {
		return nil, err
	}
	prepared := manifest
	instance, err := provider.Recover(ctx, manifest)
	if err != nil {
		if instance == nil {
			return nil, c.failWithoutInstance(stateDir, manifest, fmt.Errorf("recover runtime provider: %w", err))
		}
		return nil, c.failStarted(stateDir, manifest, instance, StopReasonRecoveryFailed, fmt.Errorf("recover runtime provider: %w", err))
	}
	if instance == nil {
		return nil, c.failWithoutInstance(stateDir, manifest, fmt.Errorf("runtime provider recovery returned no instance"))
	}
	identity := instance.Identity()
	endpoint := instance.Endpoint()
	if err := validateRecoveredIdentity(identity, prior, manifest); err != nil {
		return nil, c.failStarted(stateDir, manifest, instance, StopReasonRecoveryFailed, err)
	}
	if err := endpoint.Validate(); err != nil {
		return nil, c.failStarted(stateDir, manifest, instance, StopReasonRecoveryFailed, err)
	}
	status, err := instance.Probe(ctx)
	if err != nil {
		return nil, c.failStarted(stateDir, manifest, instance, StopReasonRecoveryFailed, fmt.Errorf("probe recovered runtime provider: %w", err))
	}
	if err := validateReadyStatus(status, identity, endpoint); err != nil {
		return nil, c.failStarted(stateDir, manifest, instance, StopReasonRecoveryFailed, err)
	}
	manifest.State = StateReady
	manifest.Identity = identity
	manifest.Endpoint = endpoint
	manifest.LastError = ""
	manifest.CleanupComplete = false
	if err := WithLifecycleLock(stateDir, func() error {
		current, readErr := ReadManifest(stateDir)
		if readErr != nil {
			return readErr
		}
		if current.State == StateStopping || current.State == StateStopped {
			return fmt.Errorf("runtime session %s committed stop during recovery", current.SessionID)
		}
		if current.Provider != prepared.Provider || current.Profile != prepared.Profile ||
			current.SessionID != prepared.SessionID || current.StateDir != prepared.StateDir ||
			(current.State != StateRecovering && current.State != StateReady && current.State != StateDegraded) ||
			!current.CreatedAt.Equal(prepared.CreatedAt) || current.Identity.Generation > identity.Generation ||
			(current.Identity.Generation == identity.Generation && current.Identity.IncarnationID != "" && current.Identity != identity) {
			return fmt.Errorf("runtime-provider manifest changed during recovery")
		}
		return WriteManifest(stateDir, manifest)
	}); err != nil {
		return nil, c.failStarted(stateDir, manifest, instance, StopReasonRecoveryFailed, fmt.Errorf("persist recovered runtime provider: %w", err))
	}
	return instance, nil
}

// Stop commits to exact cleanup only after Open has returned an identity-bound
// handle. Stop and Destroy then use a fresh bounded context, so cancellation of
// the caller cannot strand an already-committed runtime teardown.
func (c Controller) Stop(ctx context.Context, provider Provider, stateDir string, manifest Manifest, reason StopReason) error {
	if err := validateManifestStateDir(stateDir, manifest); err != nil {
		return err
	}
	if err := validateProviderSelection(provider, manifest.Provider); err != nil {
		return err
	}
	var instance Instance
	if err := WithLifecycleLock(stateDir, func() error {
		current, readErr := ReadManifest(stateDir)
		if readErr != nil {
			return readErr
		}
		if !sameManifestRevision(current, manifest) {
			return fmt.Errorf("runtime-provider manifest changed before stop")
		}
		manifest = current
		if manifest.State == StateStopped && manifest.CleanupComplete {
			return nil
		}
		var openErr error
		instance, openErr = provider.Open(ctx, manifest)
		if openErr != nil {
			return fmt.Errorf("open exact runtime provider instance: %w", openErr)
		}
		if instance == nil {
			return fmt.Errorf("runtime provider returned no exact instance")
		}
		identity := instance.Identity()
		endpoint := instance.Endpoint()
		if identityErr := validateIdentityForManifest(identity, manifest); identityErr != nil {
			return identityErr
		}
		if endpointErr := endpoint.Validate(); endpointErr != nil {
			return endpointErr
		}
		manifest.Identity = identity
		manifest.Endpoint = endpoint
		manifest.State = StateStopping
		manifest.LastError = ""
		manifest.CleanupComplete = false
		manifest.CleanupPending = true
		return WriteManifest(stateDir, manifest)
	}); err != nil {
		return err
	}
	if instance == nil { // already stopped and cleanup-complete
		return nil
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout())
	defer cancel()
	stopErr := instance.Stop(cleanupCtx, reason)
	destroyErr := instance.Destroy(cleanupCtx)
	cleanupErr := errors.Join(stopErr, destroyErr)
	if cleanupErr != nil {
		// Preserve the committed stop intent. Recovery must never resurrect a
		// runtime merely because one cleanup step needs to be retried.
		manifest.State = StateStopping
		manifest.LastError = boundedError(cleanupErr)
		manifest.CleanupComplete = false
		manifest.CleanupPending = true
		writeErr := WithLifecycleLock(stateDir, func() error {
			return writeManifestIfStopStillCurrent(stateDir, manifest)
		})
		return errors.Join(fmt.Errorf("exact runtime cleanup: %w", cleanupErr), writeErr)
	}
	manifest.State = StateStopped
	manifest.LastError = ""
	manifest.CleanupComplete = true
	manifest.CleanupPending = false
	return WithLifecycleLock(stateDir, func() error {
		return writeManifestIfStopStillCurrent(stateDir, manifest)
	})
}

func writeManifestIfStopStillCurrent(stateDir string, replacement Manifest) error {
	current, err := ReadManifest(stateDir)
	if err != nil {
		return err
	}
	if current.Provider != replacement.Provider || current.Profile != replacement.Profile ||
		current.SessionID != replacement.SessionID || current.StateDir != replacement.StateDir ||
		current.Identity != replacement.Identity || current.Endpoint != replacement.Endpoint ||
		current.State != StateStopping {
		return fmt.Errorf("runtime-provider incarnation changed during exact cleanup")
	}
	return WriteManifest(stateDir, replacement)
}

func (c Controller) failWithoutInstance(stateDir string, manifest Manifest, cause error) error {
	manifest.State = StateFailed
	manifest.LastError = boundedError(cause)
	manifest.CleanupComplete = true
	manifest.CleanupPending = false
	writeErr := WithLifecycleLock(stateDir, func() error {
		current, err := ReadManifest(stateDir)
		if err != nil {
			return err
		}
		if current.State == StateStopping || current.State == StateStopped || current.CleanupPending {
			return nil
		}
		if !sameManifestLineage(current, manifest) {
			return fmt.Errorf("runtime-provider manifest changed before failure persistence")
		}
		return WriteManifest(stateDir, manifest)
	})
	return errors.Join(cause, writeErr)
}

func (c Controller) failStarted(stateDir string, manifest Manifest, instance Instance, reason StopReason, cause error) error {
	original := manifest
	identity := instance.Identity()
	endpoint := instance.Endpoint()
	bindingErr := identity.ValidateComplete()
	if bindingErr == nil && (identity.Provider != manifest.Provider || identity.Profile != manifest.Profile || identity.SessionID != manifest.SessionID) {
		bindingErr = fmt.Errorf("runtime provider returned a different exact identity")
	}
	if bindingErr == nil {
		bindingErr = endpoint.Validate()
	}

	intent := manifest
	intent.LastError = boundedError(errors.Join(cause, bindingErr))
	intent.CleanupComplete = false
	intent.CleanupPending = true
	if bindingErr == nil {
		// Exact cleanup intent is absorbing and retryable through Controller.Stop.
		intent.State = StateStopping
		intent.Identity = identity
		intent.Endpoint = endpoint
	} else {
		// Never bind cleanup debt to an incomplete or substituted identity.
		intent.State = StateFailed
		intent.Identity = Identity{}
		intent.Endpoint = Endpoint{}
	}

	var committed Manifest
	commitErr := WithLifecycleLock(stateDir, func() error {
		current, err := ReadManifest(stateDir)
		if err != nil {
			return err
		}
		if current.State == StateStopping || current.State == StateStopped {
			return fmt.Errorf("runtime session %s committed stop while handling provider failure", current.SessionID)
		}
		if !sameManifestLineage(current, original) {
			return fmt.Errorf("runtime-provider manifest changed before failed-instance cleanup")
		}
		if bindingErr == nil {
			if current.Identity.Generation > identity.Generation ||
				(current.Identity.Generation == identity.Generation && current.Identity.IncarnationID != "" && current.Identity != identity) ||
				(current.Identity.Generation == identity.Generation && current.Endpoint != (Endpoint{}) && current.Endpoint != endpoint) {
				return fmt.Errorf("runtime-provider incarnation changed before failed-instance cleanup")
			}
		} else if current.Identity != original.Identity || current.Endpoint != original.Endpoint {
			return fmt.Errorf("runtime-provider incarnation changed before unbound cleanup")
		}
		if err := WriteManifest(stateDir, intent); err != nil {
			return err
		}
		committed, err = ReadManifest(stateDir)
		return err
	})

	if commitErr != nil {
		return errors.Join(cause, bindingErr, commitErr)
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), c.cleanupTimeout())
	stopErr := instance.Stop(cleanupCtx, reason)
	destroyErr := instance.Destroy(cleanupCtx)
	cancel()
	cleanupErr := errors.Join(stopErr, destroyErr)

	replacement := committed
	replacement.LastError = boundedError(errors.Join(cause, bindingErr, cleanupErr))
	switch {
	case cleanupErr == nil:
		replacement.State = StateFailed
		replacement.CleanupComplete = true
		replacement.CleanupPending = false
		if bindingErr != nil {
			replacement.Identity = original.Identity
			replacement.Endpoint = original.Endpoint
		}
	case bindingErr == nil:
		replacement.State = StateStopping
		replacement.CleanupComplete = false
		replacement.CleanupPending = true
	default:
		replacement.State = StateFailed
		replacement.CleanupComplete = false
		replacement.CleanupPending = true
	}
	writeErr := WithLifecycleLock(stateDir, func() error {
		return writeManifestIfRevisionCurrent(stateDir, committed, replacement)
	})
	return errors.Join(cause, bindingErr, cleanupErr, writeErr)
}

func manifestHasExactRuntime(manifest Manifest) bool {
	return validateIdentityForManifest(manifest.Identity, manifest) == nil && manifest.Endpoint.Validate() == nil
}

func sameManifestLineage(current, supplied Manifest) bool {
	return current.SchemaVersion == supplied.SchemaVersion && current.ContractVersion == supplied.ContractVersion &&
		current.Provider == supplied.Provider && current.Profile == supplied.Profile &&
		current.SessionID == supplied.SessionID && current.StateDir == supplied.StateDir &&
		current.CreatedAt.Equal(supplied.CreatedAt)
}

func writeManifestIfRevisionCurrent(stateDir string, expected, replacement Manifest) error {
	current, err := ReadManifest(stateDir)
	if err != nil {
		return err
	}
	if !sameManifestRevision(current, expected) {
		return fmt.Errorf("runtime-provider manifest changed during failed-instance cleanup")
	}
	return WriteManifest(stateDir, replacement)
}

func sameManifestRevision(current, supplied Manifest) bool {
	return current.SchemaVersion == supplied.SchemaVersion &&
		current.ContractVersion == supplied.ContractVersion &&
		current.Provider == supplied.Provider && current.Profile == supplied.Profile &&
		current.SessionID == supplied.SessionID && current.StateDir == supplied.StateDir &&
		current.State == supplied.State && current.CreatedAt.Equal(supplied.CreatedAt) &&
		current.UpdatedAt.Equal(supplied.UpdatedAt) && current.Identity == supplied.Identity &&
		current.Endpoint == supplied.Endpoint && current.LastError == supplied.LastError &&
		current.CleanupComplete == supplied.CleanupComplete && current.CleanupPending == supplied.CleanupPending
}

func validateProviderSelection(provider Provider, expected string) error {
	if provider == nil {
		return fmt.Errorf("runtime provider is nil")
	}
	if strings.TrimSpace(provider.Name()) != expected {
		return fmt.Errorf("runtime provider identity mismatch: got %q, want %q", provider.Name(), expected)
	}
	return nil
}

func validateCapabilities(capabilities Capabilities, provider string) error {
	if capabilities.ContractVersion != ContractVersion || capabilities.Provider != provider {
		return fmt.Errorf("runtime provider capability identity mismatch")
	}
	return nil
}

func validateIdentityForRequest(identity Identity, request Request) error {
	if err := identity.ValidateComplete(); err != nil {
		return err
	}
	if identity.Provider != request.Provider || identity.Profile != request.Profile || identity.SessionID != request.SessionID {
		return fmt.Errorf("runtime provider returned a different exact identity")
	}
	return nil
}

func validateIdentityForManifest(identity Identity, manifest Manifest) error {
	if err := identity.ValidateComplete(); err != nil {
		return err
	}
	if identity.Provider != manifest.Provider || identity.Profile != manifest.Profile || identity.SessionID != manifest.SessionID {
		return fmt.Errorf("runtime provider manifest identity mismatch")
	}
	if manifest.Identity.Generation != 0 && identity != manifest.Identity {
		return fmt.Errorf("runtime provider exact incarnation mismatch")
	}
	return nil
}

func validateRecoveredIdentity(identity, prior Identity, manifest Manifest) error {
	if err := identity.ValidateComplete(); err != nil {
		return err
	}
	if identity.Provider != manifest.Provider || identity.Profile != manifest.Profile || identity.SessionID != manifest.SessionID {
		return fmt.Errorf("recovered runtime provider returned a different exact identity")
	}
	if prior.Generation == 0 {
		return nil
	}
	if identity.Generation < prior.Generation {
		return fmt.Errorf("recovered runtime provider generation regressed")
	}
	if identity.Generation == prior.Generation && identity != prior {
		return fmt.Errorf("recovered runtime provider changed an existing generation identity")
	}
	if identity.Generation > prior.Generation && identity.IncarnationID == prior.IncarnationID {
		return fmt.Errorf("recovered runtime provider reused an incarnation identity")
	}
	return nil
}

func validateReadyStatus(status Status, identity Identity, endpoint Endpoint) error {
	if status.Identity != identity || status.Endpoint != endpoint {
		return fmt.Errorf("runtime provider readiness identity mismatch")
	}
	if !status.Ready || (status.State != StateReady && status.State != StateDegraded) {
		return fmt.Errorf("runtime provider is not ready: state=%s: %s", status.State, status.LastError)
	}
	return nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	const maximum = 4096
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
