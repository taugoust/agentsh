//go:build linux

package externalrunner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/workspace/runtimebin"
	"golang.org/x/sys/unix"
)

const (
	workspaceVolumeDirectoryName         = "workspace"
	workspaceVolumeLockName              = ".workspace.lock"
	workspaceVolumeCreatePrefix          = ".workspace-create-"
	workspaceVolumePreparePrefix         = ".workspace-prepare-"
	workspaceVolumeDeletePrefix          = ".workspace-delete-"
	qcow2IdentityHeaderBytes             = 32
	qcow2ValidationHeaderBytes           = 104
	qcow2DataFileIncompatibleFeature     = uint64(1 << 2)
	maxQEMUImgJSONBytes                  = 8 << 20
	maxQEMUImgErrorBytes                 = 4096
	workspaceVolumeQEMUImgCommandTimeout = 2 * time.Minute
)

type workspaceVolumeLayout struct {
	stateDir     string
	runtimeDir   string
	volumesDir   string
	workspaceDir string
	manifestPath string
	imagePath    string
	lockPath     string
}

type workspaceVolumeDependencies struct {
	resolveQEMUImg func(string) (string, error)
	runQEMUImg     func(context.Context, string, string, *os.File, ...string) ([]byte, error)
	now            func() time.Time
}

var defaultWorkspaceVolumeDependencies = workspaceVolumeDependencies{
	resolveQEMUImg: runtimebin.Resolve,
	runQEMUImg:     runWorkspaceVolumeQEMUImg,
	now:            func() time.Time { return time.Now().UTC() },
}

func createWorkspaceVolume(ctx context.Context, request WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
	return createWorkspaceVolumeWithDependencies(ctx, request, volumeID, defaultWorkspaceVolumeDependencies)
}

func createWorkspaceVolumeWithDependencies(ctx context.Context, request WorkspaceVolumeRequest, volumeID string, deps workspaceVolumeDependencies) (*WorkspaceVolume, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	if !canonicalWorkspaceVolumeUUID(volumeID) {
		return nil, fmt.Errorf("%w: requested volume identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if err := validateWorkspaceVolumeDependencies(deps); err != nil {
		return nil, err
	}
	qemuImg, err := resolveWorkspaceVolumeQEMUImg(deps)
	if err != nil {
		return nil, err
	}

	layout := workspaceVolumePaths(request.StateDir)
	if err := prepareWorkspaceVolumeLayout(layout, true); err != nil {
		return nil, err
	}
	lock, err := acquireWorkspaceVolumeLock(ctx, layout, unix.LOCK_EX)
	if err != nil {
		return nil, err
	}
	keepLock := false
	defer func() {
		if !keepLock {
			_ = lock.Close()
		}
	}()

	_, workspaceErr := os.Lstat(layout.workspaceDir)
	workspaceExists := workspaceErr == nil
	if workspaceErr != nil && !errors.Is(workspaceErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect external runner workspace volume: %w", workspaceErr)
	}
	if err := reconcileWorkspaceVolumePrepareTransactions(layout, request, volumeID, workspaceExists); err != nil {
		return nil, err
	}
	if err := refuseConflictingWorkspaceVolumeTransactions(layout, volumeID, workspaceExists); err != nil {
		return nil, err
	}
	if workspaceExists {
		manifest, image, err := openPublishedWorkspaceVolume(ctx, qemuImg, deps, layout.workspaceDir, request, volumeID)
		if err != nil {
			return nil, fmt.Errorf("%w: existing publication is not the exact requested create transaction: %w", ErrWorkspaceVolumeExists, err)
		}
		keepLock = true
		return &WorkspaceVolume{Manifest: manifest, Image: image, lock: lock}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	transactionDir, intent, err := ensureWorkspaceVolumeCreateTransaction(layout, request, volumeID, deps)
	if err != nil {
		return nil, err
	}
	manifest, image, err := materializeWorkspaceVolumeCreateTransaction(ctx, qemuImg, deps, transactionDir, request, intent)
	if err != nil {
		return nil, err
	}
	keepImage := false
	defer func() {
		if !keepImage {
			_ = image.Close()
		}
	}()
	if err := revalidateWorkspaceVolumeImage(ctx, qemuImg, deps, filepath.Join(transactionDir, WorkspaceVolumeImageName), image, manifest, true); err != nil {
		return nil, err
	}
	intentPath := filepath.Join(transactionDir, workspaceVolumeCreateIntentName)
	if err := os.Remove(intentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("commit workspace volume create intent: %w", err)
	}
	if err := syncWorkspaceVolumeDirectory(transactionDir); err != nil {
		return nil, fmt.Errorf("sync committed workspace volume transaction: %w", err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, transactionDir, unix.AT_FDCWD, layout.workspaceDir, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
			return nil, ErrWorkspaceVolumeExists
		}
		return nil, fmt.Errorf("atomically publish workspace volume: %w", err)
	}
	if err := lock.syncParent(); err != nil {
		return nil, fmt.Errorf("sync published workspace volume: %w", err)
	}
	keepImage = true
	keepLock = true
	return &WorkspaceVolume{Manifest: manifest, Image: image, lock: lock}, nil
}

func openWorkspaceVolume(ctx context.Context, request WorkspaceVolumeRequest, volumeID string) (*WorkspaceVolume, error) {
	return openWorkspaceVolumeWithDependencies(ctx, request, volumeID, defaultWorkspaceVolumeDependencies)
}

func openWorkspaceVolumeWithDependencies(ctx context.Context, request WorkspaceVolumeRequest, volumeID string, deps workspaceVolumeDependencies) (*WorkspaceVolume, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	if !canonicalWorkspaceVolumeUUID(volumeID) {
		return nil, fmt.Errorf("%w: requested volume identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if err := validateWorkspaceVolumeDependencies(deps); err != nil {
		return nil, err
	}
	qemuImg, err := resolveWorkspaceVolumeQEMUImg(deps)
	if err != nil {
		return nil, err
	}
	layout := workspaceVolumePaths(request.StateDir)
	if err := prepareWorkspaceVolumeLayout(layout, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrWorkspaceVolumeNotFound
		}
		return nil, err
	}
	lock, err := acquireWorkspaceVolumeLock(ctx, layout, unix.LOCK_EX)
	if err != nil {
		return nil, err
	}
	manifest, image, err := openPublishedWorkspaceVolume(ctx, qemuImg, deps, layout.workspaceDir, request, volumeID)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return &WorkspaceVolume{Manifest: manifest, Image: image, lock: lock}, nil
}

func deleteWorkspaceVolume(ctx context.Context, request WorkspaceVolumeRequest, volumeID string) error {
	return deleteWorkspaceVolumeWithDependencies(ctx, request, volumeID, defaultWorkspaceVolumeDependencies)
}

func deleteWorkspaceVolumeWithDependencies(ctx context.Context, request WorkspaceVolumeRequest, volumeID string, deps workspaceVolumeDependencies) error {
	if err := request.validate(); err != nil {
		return err
	}
	if !canonicalWorkspaceVolumeUUID(volumeID) {
		return fmt.Errorf("%w: requested volume identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if err := validateWorkspaceVolumeDependencies(deps); err != nil {
		return err
	}
	layout := workspaceVolumePaths(request.StateDir)
	if err := prepareWorkspaceVolumeLayout(layout, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lock, err := acquireWorkspaceVolumeLock(ctx, layout, unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer lock.Close()

	tombstone := workspaceVolumeTombstonePath(layout, volumeID)
	_, workspaceErr := os.Lstat(layout.workspaceDir)
	_, tombstoneErr := os.Lstat(tombstone)
	if workspaceErr != nil && !errors.Is(workspaceErr, os.ErrNotExist) {
		return fmt.Errorf("inspect workspace volume before deletion: %w", workspaceErr)
	}
	if tombstoneErr != nil && !errors.Is(tombstoneErr, os.ErrNotExist) {
		return fmt.Errorf("inspect workspace volume deletion transaction: %w", tombstoneErr)
	}
	workspaceExists := workspaceErr == nil
	tombstoneExists := tombstoneErr == nil
	if workspaceExists && tombstoneExists {
		return fmt.Errorf("%w: live volume and deletion transaction coexist", ErrWorkspaceVolumeCorrupt)
	}
	if !workspaceExists && !tombstoneExists {
		// Also makes a retry after an ambiguous final directory sync durable;
		// an already-removed volume does not depend on qemu-img availability.
		return lock.syncParent()
	}
	qemuImg, err := resolveWorkspaceVolumeQEMUImg(deps)
	if err != nil {
		return err
	}
	if workspaceExists {
		manifest, image, openErr := openPublishedWorkspaceVolume(ctx, qemuImg, deps, layout.workspaceDir, request, volumeID)
		if openErr != nil {
			return openErr
		}
		if closeErr := image.Close(); closeErr != nil {
			return closeErr
		}
		if manifest.VolumeID != volumeID {
			return fmt.Errorf("%w: volume identity changed before delete", ErrWorkspaceVolumeInvalid)
		}
		if err := unix.Renameat2(unix.AT_FDCWD, layout.workspaceDir, unix.AT_FDCWD, tombstone, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("begin explicit workspace volume deletion: %w", err)
		}
		if err := lock.syncParent(); err != nil {
			return fmt.Errorf("sync workspace volume deletion intent: %w", err)
		}
	}
	return finishWorkspaceVolumeDelete(ctx, qemuImg, deps, tombstone, layout, request, volumeID, lock)
}

func openPublishedWorkspaceVolume(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, root string, request WorkspaceVolumeRequest, volumeID string) (WorkspaceVolumeManifest, *os.File, error) {
	rootIdentity, err := validatePrivateWorkspaceVolumeDirectory(root)
	if errors.Is(err, os.ErrNotExist) {
		return WorkspaceVolumeManifest{}, nil, ErrWorkspaceVolumeNotFound
	}
	if err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	rootHandle, err := os.Open(root)
	if err != nil {
		return WorkspaceVolumeManifest{}, nil, fmt.Errorf("open workspace volume directory: %w", err)
	}
	defer rootHandle.Close()
	openedRoot, err := rootHandle.Stat()
	if err != nil || !os.SameFile(rootIdentity, openedRoot) {
		return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: workspace volume directory identity changed while opening", ErrWorkspaceVolumeCorrupt)
	}
	entries, err := rootHandle.ReadDir(-1)
	if err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	if err := validateWorkspaceVolumeEntries(entries, false); err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}

	manifest, err := readWorkspaceVolumeManifest(filepath.Join(root, WorkspaceVolumeManifestName))
	if err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	if err := manifest.matches(request, volumeID); err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	imagePath := filepath.Join(root, WorkspaceVolumeImageName)
	image, _, err := openExactWorkspaceVolumeImage(ctx, qemuImg, deps, imagePath, manifest.WorkspaceVolume, &manifest.Image, false)
	if err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	currentRoot, err := os.Lstat(root)
	if err != nil || !os.SameFile(rootIdentity, currentRoot) {
		_ = image.Close()
		return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: workspace volume directory changed during reopen", ErrWorkspaceVolumeCorrupt)
	}
	return manifest, image, nil
}

func finishWorkspaceVolumeDelete(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, tombstone string, layout workspaceVolumeLayout, request WorkspaceVolumeRequest, volumeID string, lock *workspaceVolumeLock) error {
	if _, err := validatePrivateWorkspaceVolumeDirectory(tombstone); err != nil {
		return err
	}
	entries, err := os.ReadDir(tombstone)
	if err != nil {
		return err
	}
	if err := validateWorkspaceVolumeEntries(entries, true); err != nil {
		return err
	}
	hasManifest := workspaceVolumeEntryExists(entries, WorkspaceVolumeManifestName)
	hasImage := workspaceVolumeEntryExists(entries, WorkspaceVolumeImageName)
	if hasImage && !hasManifest {
		return fmt.Errorf("%w: deletion transaction has an unbound image", ErrWorkspaceVolumeCorrupt)
	}
	var manifest WorkspaceVolumeManifest
	if hasManifest {
		manifest, err = readWorkspaceVolumeManifest(filepath.Join(tombstone, WorkspaceVolumeManifestName))
		if err != nil {
			return err
		}
		if err := manifest.matches(request, volumeID); err != nil {
			return err
		}
	}
	if hasImage {
		imagePath := filepath.Join(tombstone, WorkspaceVolumeImageName)
		image, _, err := openExactWorkspaceVolumeImage(ctx, qemuImg, deps, imagePath, manifest.WorkspaceVolume, &manifest.Image, false)
		if err != nil {
			return err
		}
		if err := image.Close(); err != nil {
			return err
		}
		if err := os.Remove(imagePath); err != nil {
			return fmt.Errorf("delete workspace volume image: %w", err)
		}
		if err := syncWorkspaceVolumeDirectory(tombstone); err != nil {
			return err
		}
	}
	if hasManifest {
		if err := os.Remove(filepath.Join(tombstone, WorkspaceVolumeManifestName)); err != nil {
			return fmt.Errorf("delete workspace volume manifest: %w", err)
		}
		if err := syncWorkspaceVolumeDirectory(tombstone); err != nil {
			return err
		}
	}
	if err := os.Remove(tombstone); err != nil {
		return fmt.Errorf("finish workspace volume deletion: %w", err)
	}
	return lock.syncParent()
}

func workspaceVolumePaths(stateDir string) workspaceVolumeLayout {
	runtimeDir := filepath.Join(stateDir, "runtime")
	volumesDir := filepath.Join(runtimeDir, "volumes")
	workspaceDir := filepath.Join(volumesDir, workspaceVolumeDirectoryName)
	return workspaceVolumeLayout{
		stateDir:     stateDir,
		runtimeDir:   runtimeDir,
		volumesDir:   volumesDir,
		workspaceDir: workspaceDir,
		manifestPath: filepath.Join(workspaceDir, WorkspaceVolumeManifestName),
		imagePath:    filepath.Join(workspaceDir, WorkspaceVolumeImageName),
		lockPath:     filepath.Join(volumesDir, workspaceVolumeLockName),
	}
}

func workspaceVolumeCreateTransactionPath(layout workspaceVolumeLayout, volumeID string) string {
	return filepath.Join(layout.volumesDir, workspaceVolumeCreatePrefix+volumeID)
}

func workspaceVolumeTombstonePath(layout workspaceVolumeLayout, volumeID string) string {
	return filepath.Join(layout.volumesDir, workspaceVolumeDeletePrefix+volumeID)
}

func reconcileWorkspaceVolumePrepareTransactions(layout workspaceVolumeLayout, request WorkspaceVolumeRequest, volumeID string, workspaceExists bool) error {
	entries, err := os.ReadDir(layout.volumesDir)
	if err != nil {
		return err
	}
	exactPrefix := workspaceVolumePreparePrefix + volumeID + "-"
	transactionDir := workspaceVolumeCreateTransactionPath(layout, volumeID)
	_, transactionErr := os.Lstat(transactionDir)
	transactionExists := transactionErr == nil
	if transactionErr != nil && !errors.Is(transactionErr, os.ErrNotExist) {
		return fmt.Errorf("inspect canonical workspace volume create transaction: %w", transactionErr)
	}
	parentChanged := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, workspaceVolumePreparePrefix) {
			continue
		}
		if !strings.HasPrefix(name, exactPrefix) {
			return fmt.Errorf("%w: a different workspace volume preparation requires explicit recovery", ErrWorkspaceVolumeExists)
		}
		prepareDir := filepath.Join(layout.volumesDir, name)
		if _, err := validatePrivateWorkspaceVolumeDirectory(prepareDir); err != nil {
			return err
		}
		prepareEntries, err := os.ReadDir(prepareDir)
		if err != nil {
			return err
		}
		if len(prepareEntries) == 0 {
			// No volume image is created before the canonical intent directory is
			// published, so an empty pre-publication directory has no identity or
			// mutable data to preserve after a crash.
			if err := os.Remove(prepareDir); err != nil {
				return err
			}
			parentChanged = true
			continue
		}
		if len(prepareEntries) != 1 || prepareEntries[0].Name() != workspaceVolumeCreateIntentName {
			return fmt.Errorf("%w: workspace volume preparation has unexpected content", ErrWorkspaceVolumeCorrupt)
		}
		intent, err := readWorkspaceVolumeCreateIntent(filepath.Join(prepareDir, workspaceVolumeCreateIntentName))
		if err != nil {
			// A partial intent was never made canonical and cannot have an image;
			// discard only this caller-ID-scoped pre-publication directory.
			if removeErr := removeWorkspaceVolumePrepareDirectory(prepareDir); removeErr != nil {
				return errors.Join(err, removeErr)
			}
			parentChanged = true
			continue
		}
		if err := intent.matches(request, volumeID); err != nil {
			return fmt.Errorf("%w: prepared create transaction is not exact: %w", ErrWorkspaceVolumeExists, err)
		}
		if workspaceExists || transactionExists {
			if err := removeWorkspaceVolumePrepareDirectory(prepareDir); err != nil {
				return err
			}
			parentChanged = true
			continue
		}
		if err := unix.Renameat2(unix.AT_FDCWD, prepareDir, unix.AT_FDCWD, transactionDir, unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("recover exact workspace volume preparation: %w", err)
		}
		transactionExists = true
		parentChanged = true
	}
	if parentChanged {
		return syncWorkspaceVolumeDirectory(layout.volumesDir)
	}
	return nil
}

func removeWorkspaceVolumePrepareDirectory(path string) error {
	if err := os.Remove(filepath.Join(path, workspaceVolumeCreateIntentName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(path)
}

func refuseConflictingWorkspaceVolumeTransactions(layout workspaceVolumeLayout, volumeID string, workspaceExists bool) error {
	entries, err := os.ReadDir(layout.volumesDir)
	if err != nil {
		return err
	}
	exactCreateName := workspaceVolumeCreatePrefix + volumeID
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, workspaceVolumeDeletePrefix):
			return fmt.Errorf("%w: a workspace volume deletion transaction requires explicit recovery", ErrWorkspaceVolumeExists)
		case strings.HasPrefix(name, workspaceVolumeCreatePrefix):
			if name != exactCreateName {
				return fmt.Errorf("%w: a different workspace volume create transaction requires explicit recovery", ErrWorkspaceVolumeExists)
			}
			if workspaceExists {
				return fmt.Errorf("%w: a published volume and its create transaction coexist", ErrWorkspaceVolumeCorrupt)
			}
		}
	}
	return nil
}

type workspaceVolumeCreateIntent struct {
	SchemaVersion     int                 `json:"schema_version"`
	SessionID         string              `json:"session_id"`
	Provider          string              `json:"provider"`
	Profile           string              `json:"profile"`
	ProfileSchema     string              `json:"profile_schema"`
	ProfileDigest     string              `json:"profile_digest"`
	ProfileFileSHA256 string              `json:"profile_file_sha256"`
	VolumeID          string              `json:"volume_id"`
	WorkspaceVolume   WorkspaceVolumeSpec `json:"workspace_volume"`
	CreatedAt         time.Time           `json:"created_at"`
}

func newWorkspaceVolumeCreateIntent(request WorkspaceVolumeRequest, volumeID string, createdAt time.Time) workspaceVolumeCreateIntent {
	return workspaceVolumeCreateIntent{
		SchemaVersion:     WorkspaceVolumeManifestSchemaVersion,
		SessionID:         request.SessionID,
		Provider:          request.Profile.Provider,
		Profile:           request.Profile.Name,
		ProfileSchema:     request.Profile.Schema,
		ProfileDigest:     request.Profile.ProfileDigest,
		ProfileFileSHA256: request.ProfileFileSHA256,
		VolumeID:          volumeID,
		WorkspaceVolume:   *request.Profile.WorkspaceVolume,
		CreatedAt:         createdAt.UTC(),
	}
}

func workspaceVolumeCreateIntentFromManifest(manifest WorkspaceVolumeManifest) workspaceVolumeCreateIntent {
	return workspaceVolumeCreateIntent{
		SchemaVersion:     manifest.SchemaVersion,
		SessionID:         manifest.SessionID,
		Provider:          manifest.Provider,
		Profile:           manifest.Profile,
		ProfileSchema:     manifest.ProfileSchema,
		ProfileDigest:     manifest.ProfileDigest,
		ProfileFileSHA256: manifest.ProfileFileSHA256,
		VolumeID:          manifest.VolumeID,
		WorkspaceVolume:   manifest.WorkspaceVolume,
		CreatedAt:         manifest.CreatedAt,
	}
}

func (i workspaceVolumeCreateIntent) matches(request WorkspaceVolumeRequest, volumeID string) error {
	if i.SchemaVersion != WorkspaceVolumeManifestSchemaVersion || i.SessionID != request.SessionID || i.Provider != request.Profile.Provider ||
		i.Profile != request.Profile.Name || (i.ProfileSchema != ProfileSchemaV2 && i.ProfileSchema != ProfileSchemaV3) || i.ProfileSchema != request.Profile.Schema ||
		i.ProfileDigest != request.Profile.ProfileDigest || i.ProfileFileSHA256 != request.ProfileFileSHA256 ||
		i.VolumeID != volumeID || request.Profile.WorkspaceVolume == nil || i.WorkspaceVolume != *request.Profile.WorkspaceVolume {
		return fmt.Errorf("%w: create intent does not match the exact session, profile, and volume", ErrWorkspaceVolumeInvalid)
	}
	if !canonicalWorkspaceVolumeUUID(i.VolumeID) {
		return fmt.Errorf("%w: create intent volume identity is invalid", ErrWorkspaceVolumeInvalid)
	}
	if err := i.WorkspaceVolume.Validate(); err != nil {
		return fmt.Errorf("%w: create intent workspace contract is invalid: %v", ErrWorkspaceVolumeInvalid, err)
	}
	if i.CreatedAt.IsZero() || i.CreatedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return fmt.Errorf("%w: create intent time is invalid", ErrWorkspaceVolumeInvalid)
	}
	return nil
}

func (i workspaceVolumeCreateIntent) manifest(identity WorkspaceVolumeImageIdentity) WorkspaceVolumeManifest {
	return WorkspaceVolumeManifest{
		SchemaVersion:     i.SchemaVersion,
		Complete:          true,
		SessionID:         i.SessionID,
		Provider:          i.Provider,
		Profile:           i.Profile,
		ProfileSchema:     i.ProfileSchema,
		ProfileDigest:     i.ProfileDigest,
		ProfileFileSHA256: i.ProfileFileSHA256,
		VolumeID:          i.VolumeID,
		WorkspaceVolume:   i.WorkspaceVolume,
		Image:             identity,
		CreatedAt:         i.CreatedAt,
	}
}

func ensureWorkspaceVolumeCreateTransaction(layout workspaceVolumeLayout, request WorkspaceVolumeRequest, volumeID string, deps workspaceVolumeDependencies) (string, workspaceVolumeCreateIntent, error) {
	transactionDir := workspaceVolumeCreateTransactionPath(layout, volumeID)
	if _, err := os.Lstat(transactionDir); err == nil {
		intent, loadErr := loadWorkspaceVolumeCreateTransaction(transactionDir, request, volumeID)
		return transactionDir, intent, loadErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", workspaceVolumeCreateIntent{}, fmt.Errorf("inspect workspace volume create transaction: %w", err)
	}

	intent := newWorkspaceVolumeCreateIntent(request, volumeID, deps.now())
	if err := intent.matches(request, volumeID); err != nil {
		return "", workspaceVolumeCreateIntent{}, err
	}
	prepareDir, err := os.MkdirTemp(layout.volumesDir, workspaceVolumePreparePrefix+volumeID+"-")
	if err != nil {
		return "", workspaceVolumeCreateIntent{}, fmt.Errorf("prepare workspace volume create transaction: %w", err)
	}
	prepared := false
	defer func() {
		if !prepared {
			cleanupUnpublishedWorkspaceVolume(prepareDir)
		}
	}()
	if _, err := validatePrivateWorkspaceVolumeDirectory(prepareDir); err != nil {
		return "", workspaceVolumeCreateIntent{}, err
	}
	if err := writeWorkspaceVolumeCreateIntent(filepath.Join(prepareDir, workspaceVolumeCreateIntentName), intent); err != nil {
		return "", workspaceVolumeCreateIntent{}, err
	}
	if err := syncWorkspaceVolumeDirectory(prepareDir); err != nil {
		return "", workspaceVolumeCreateIntent{}, fmt.Errorf("sync workspace volume create intent: %w", err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, prepareDir, unix.AT_FDCWD, transactionDir, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.ENOTEMPTY) {
			return "", workspaceVolumeCreateIntent{}, fmt.Errorf("publish workspace volume create intent: %w", err)
		}
		loaded, loadErr := loadWorkspaceVolumeCreateTransaction(transactionDir, request, volumeID)
		return transactionDir, loaded, loadErr
	}
	prepared = true
	if err := syncWorkspaceVolumeDirectory(layout.volumesDir); err != nil {
		return "", workspaceVolumeCreateIntent{}, fmt.Errorf("sync workspace volume create transaction: %w", err)
	}
	return transactionDir, intent, nil
}

func loadWorkspaceVolumeCreateTransaction(transactionDir string, request WorkspaceVolumeRequest, volumeID string) (workspaceVolumeCreateIntent, error) {
	if _, err := validatePrivateWorkspaceVolumeDirectory(transactionDir); err != nil {
		return workspaceVolumeCreateIntent{}, err
	}
	entries, err := os.ReadDir(transactionDir)
	if err != nil {
		return workspaceVolumeCreateIntent{}, err
	}
	if err := validateWorkspaceVolumeCreateEntries(entries); err != nil {
		return workspaceVolumeCreateIntent{}, err
	}
	if workspaceVolumeEntryExists(entries, workspaceVolumeCreateIntentName) {
		intent, err := readWorkspaceVolumeCreateIntent(filepath.Join(transactionDir, workspaceVolumeCreateIntentName))
		if err != nil {
			return workspaceVolumeCreateIntent{}, err
		}
		if err := intent.matches(request, volumeID); err != nil {
			return workspaceVolumeCreateIntent{}, fmt.Errorf("%w: pending create transaction is not exact: %w", ErrWorkspaceVolumeExists, err)
		}
		return intent, nil
	}
	if !workspaceVolumeEntryExists(entries, WorkspaceVolumeManifestName) {
		return workspaceVolumeCreateIntent{}, fmt.Errorf("%w: create transaction has no exact intent or committed manifest", ErrWorkspaceVolumeCorrupt)
	}
	manifest, err := readWorkspaceVolumeManifest(filepath.Join(transactionDir, WorkspaceVolumeManifestName))
	if err != nil {
		return workspaceVolumeCreateIntent{}, err
	}
	if err := manifest.matches(request, volumeID); err != nil {
		return workspaceVolumeCreateIntent{}, fmt.Errorf("%w: committed create transaction is not exact: %w", ErrWorkspaceVolumeExists, err)
	}
	return workspaceVolumeCreateIntentFromManifest(manifest), nil
}

func materializeWorkspaceVolumeCreateTransaction(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, transactionDir string, request WorkspaceVolumeRequest, intent workspaceVolumeCreateIntent) (WorkspaceVolumeManifest, *os.File, error) {
	entries, err := os.ReadDir(transactionDir)
	if err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	if err := validateWorkspaceVolumeCreateEntries(entries); err != nil {
		return WorkspaceVolumeManifest{}, nil, err
	}
	manifestPath := filepath.Join(transactionDir, WorkspaceVolumeManifestName)
	imagePath := filepath.Join(transactionDir, WorkspaceVolumeImageName)
	hasIntent := workspaceVolumeEntryExists(entries, workspaceVolumeCreateIntentName)
	hasManifest := workspaceVolumeEntryExists(entries, WorkspaceVolumeManifestName)
	hasImage := workspaceVolumeEntryExists(entries, WorkspaceVolumeImageName)

	if hasManifest {
		manifest, manifestErr := readWorkspaceVolumeManifest(manifestPath)
		if manifestErr != nil && hasIntent {
			if removeErr := os.Remove(manifestPath); removeErr != nil {
				return WorkspaceVolumeManifest{}, nil, errors.Join(manifestErr, removeErr)
			}
			if syncErr := syncWorkspaceVolumeDirectory(transactionDir); syncErr != nil {
				return WorkspaceVolumeManifest{}, nil, syncErr
			}
			hasManifest = false
		} else if manifestErr != nil {
			return WorkspaceVolumeManifest{}, nil, manifestErr
		} else {
			if err := manifest.matches(request, intent.VolumeID); err != nil || workspaceVolumeCreateIntentFromManifest(manifest) != intent {
				return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: committed manifest differs from its exact create intent", ErrWorkspaceVolumeCorrupt)
			}
			if !hasImage {
				return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: committed create transaction has no image", ErrWorkspaceVolumeCorrupt)
			}
			image, _, err := openExactWorkspaceVolumeImage(ctx, qemuImg, deps, imagePath, manifest.WorkspaceVolume, &manifest.Image, true)
			return manifest, image, err
		}
	}

	if !hasManifest {
		if !hasIntent {
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: incomplete create transaction lacks an exact intent", ErrWorkspaceVolumeCorrupt)
		}
		if hasImage {
			if err := os.Remove(imagePath); err != nil {
				return WorkspaceVolumeManifest{}, nil, fmt.Errorf("reset interrupted exact workspace volume image: %w", err)
			}
			if err := syncWorkspaceVolumeDirectory(transactionDir); err != nil {
				return WorkspaceVolumeManifest{}, nil, err
			}
		}
		size := strconv.FormatInt(intent.WorkspaceVolume.VirtualSizeBytes, 10)
		if _, err := invokeWorkspaceVolumeQEMUImg(ctx, deps, qemuImg, transactionDir, nil, "create", "-q", "-f", WorkspaceVolumeFormat, "-o", "compat=1.1", imagePath, size); err != nil {
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("create external runner workspace volume image: %w", err)
		}
		createdInfo, err := os.Lstat(imagePath)
		if err != nil {
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("inspect created workspace volume image: %w", err)
		}
		if !createdInfo.Mode().IsRegular() || createdInfo.Mode()&os.ModeSymlink != 0 {
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: qemu-img did not create a direct regular image", ErrWorkspaceVolumeCorrupt)
		}
		if err := os.Chmod(imagePath, 0o600); err != nil {
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("protect workspace volume image: %w", err)
		}
		image, imageIdentity, err := openExactWorkspaceVolumeImage(ctx, qemuImg, deps, imagePath, intent.WorkspaceVolume, nil, true)
		if err != nil {
			return WorkspaceVolumeManifest{}, nil, err
		}
		if err := image.Sync(); err != nil {
			_ = image.Close()
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("sync workspace volume image: %w", err)
		}
		manifest := intent.manifest(imageIdentity)
		if err := manifest.matches(request, intent.VolumeID); err != nil {
			_ = image.Close()
			return WorkspaceVolumeManifest{}, nil, err
		}
		if err := writeWorkspaceVolumeManifest(manifestPath, manifest); err != nil {
			_ = image.Close()
			return WorkspaceVolumeManifest{}, nil, err
		}
		if err := syncWorkspaceVolumeDirectory(transactionDir); err != nil {
			_ = image.Close()
			return WorkspaceVolumeManifest{}, nil, fmt.Errorf("sync workspace volume transaction: %w", err)
		}
		return manifest, image, nil
	}
	return WorkspaceVolumeManifest{}, nil, fmt.Errorf("%w: unreachable workspace volume transaction state", ErrWorkspaceVolumeCorrupt)
}

func prepareWorkspaceVolumeLayout(layout workspaceVolumeLayout, create bool) error {
	if _, err := validatePrivateWorkspaceVolumeDirectory(layout.stateDir); err != nil {
		return fmt.Errorf("validate workspace volume state directory: %w", err)
	}
	for _, path := range []string{layout.runtimeDir, layout.volumesDir} {
		if create {
			if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create workspace volume layout: %w", err)
			}
		}
		if _, err := validatePrivateWorkspaceVolumeDirectory(path); err != nil {
			return fmt.Errorf("validate workspace volume layout: %w", err)
		}
	}
	if create {
		if err := syncWorkspaceVolumeDirectory(layout.stateDir); err != nil {
			return err
		}
		if err := syncWorkspaceVolumeDirectory(layout.runtimeDir); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateWorkspaceVolumeDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !ok || !trustedWorkspaceVolumeOwner(stat.Uid) {
		return nil, fmt.Errorf("%w: workspace volume directory is not a private direct directory", ErrWorkspaceVolumeInvalid)
	}
	return info, nil
}

type workspaceVolumeLock struct {
	file       *os.File
	parent     *os.File
	fd         int
	parentInfo os.FileInfo
}

func acquireWorkspaceVolumeLock(ctx context.Context, layout workspaceVolumeLayout, operation int) (*workspaceVolumeLock, error) {
	parentInfo, err := validatePrivateWorkspaceVolumeDirectory(layout.volumesDir)
	if err != nil {
		return nil, err
	}
	parent, err := os.Open(layout.volumesDir)
	if err != nil {
		return nil, fmt.Errorf("open workspace volume root: %w", err)
	}
	openedParent, err := parent.Stat()
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		_ = parent.Close()
		return nil, fmt.Errorf("%w: workspace volume root identity changed while opening", ErrWorkspaceVolumeInvalid)
	}
	fd, err := unix.Open(layout.lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("open workspace volume lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), workspaceVolumeLockName)
	lockInfo, err := file.Stat()
	if err != nil || !safePrivateWorkspaceVolumeFile(lockInfo) {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("%w: workspace volume lock is unsafe", ErrWorkspaceVolumeInvalid)
	}
	lock := &workspaceVolumeLock{file: file, parent: parent, fd: fd, parentInfo: parentInfo}
	for {
		if err := ctx.Err(); err != nil {
			_ = lock.Close()
			return nil, err
		}
		if err := unix.Flock(fd, operation|unix.LOCK_NB); err == nil {
			break
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = lock.Close()
			return nil, fmt.Errorf("lock workspace volume state: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	currentLock, err := os.Lstat(layout.lockPath)
	currentParent, parentErr := os.Lstat(layout.volumesDir)
	if err != nil || parentErr != nil || !os.SameFile(lockInfo, currentLock) || !os.SameFile(parentInfo, currentParent) {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: workspace volume lock or root identity changed", ErrWorkspaceVolumeInvalid)
	}
	return lock, nil
}

func (l *workspaceVolumeLock) syncParent() error {
	current, err := l.parent.Stat()
	if err != nil || !os.SameFile(l.parentInfo, current) {
		return fmt.Errorf("%w: workspace volume root identity changed", ErrWorkspaceVolumeInvalid)
	}
	if err := l.parent.Sync(); err != nil {
		return err
	}
	return nil
}

func (l *workspaceVolumeLock) Close() error {
	if l == nil {
		return nil
	}
	return errors.Join(unix.Flock(l.fd, unix.LOCK_UN), l.file.Close(), l.parent.Close())
}

func writeWorkspaceVolumeCreateIntent(path string, intent workspaceVolumeCreateIntent) error {
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return fmt.Errorf("encode workspace volume create intent: %w", err)
	}
	data = append(data, '\n')
	if len(data) > workspaceVolumeManifestMaxBytes {
		return fmt.Errorf("%w: workspace volume create intent exceeds its size limit", ErrWorkspaceVolumeInvalid)
	}
	if err := writeWorkspaceVolumePrivateFile(path, workspaceVolumeCreateIntentName, data); err != nil {
		return fmt.Errorf("persist workspace volume create intent: %w", err)
	}
	return nil
}

func readWorkspaceVolumeCreateIntent(path string) (workspaceVolumeCreateIntent, error) {
	file, err := openWorkspaceVolumePrivateJSONFile(path, workspaceVolumeCreateIntentName)
	if err != nil {
		return workspaceVolumeCreateIntent{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, workspaceVolumeManifestMaxBytes+1))
	decoder.DisallowUnknownFields()
	var intent workspaceVolumeCreateIntent
	if err := decoder.Decode(&intent); err != nil {
		return workspaceVolumeCreateIntent{}, fmt.Errorf("%w: decode workspace volume create intent: %v", ErrWorkspaceVolumeInvalid, err)
	}
	if err := requireEOF(decoder); err != nil {
		return workspaceVolumeCreateIntent{}, fmt.Errorf("%w: workspace volume create intent has trailing content", ErrWorkspaceVolumeInvalid)
	}
	return intent, nil
}

func writeWorkspaceVolumeManifest(path string, manifest WorkspaceVolumeManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode workspace volume manifest: %w", err)
	}
	data = append(data, '\n')
	if len(data) > workspaceVolumeManifestMaxBytes {
		return fmt.Errorf("%w: workspace volume manifest exceeds its size limit", ErrWorkspaceVolumeInvalid)
	}
	if err := writeWorkspaceVolumePrivateFile(path, WorkspaceVolumeManifestName, data); err != nil {
		return fmt.Errorf("persist workspace volume manifest: %w", err)
	}
	return nil
}

func writeWorkspaceVolumePrivateFile(path, name string, data []byte) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	info, statErr := file.Stat()
	if statErr != nil || !safePrivateWorkspaceVolumeFile(info) {
		_ = file.Close()
		return fmt.Errorf("%w: created workspace volume metadata is unsafe", ErrWorkspaceVolumeInvalid)
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func readWorkspaceVolumeManifest(path string) (WorkspaceVolumeManifest, error) {
	file, err := openWorkspaceVolumePrivateJSONFile(path, WorkspaceVolumeManifestName)
	if err != nil {
		return WorkspaceVolumeManifest{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, workspaceVolumeManifestMaxBytes+1))
	decoder.DisallowUnknownFields()
	var manifest WorkspaceVolumeManifest
	if err := decoder.Decode(&manifest); err != nil {
		return WorkspaceVolumeManifest{}, fmt.Errorf("%w: decode workspace volume manifest: %v", ErrWorkspaceVolumeInvalid, err)
	}
	if err := requireEOF(decoder); err != nil {
		return WorkspaceVolumeManifest{}, fmt.Errorf("%w: workspace volume manifest has trailing content", ErrWorkspaceVolumeInvalid)
	}
	if err := manifest.Validate(); err != nil {
		return WorkspaceVolumeManifest{}, err
	}
	return manifest, nil
}

func openWorkspaceVolumePrivateJSONFile(path, name string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect workspace volume metadata: %w", err)
	}
	if !safePrivateWorkspaceVolumeFile(before) || before.Size() > workspaceVolumeManifestMaxBytes {
		return nil, fmt.Errorf("%w: workspace volume metadata is not a bounded private regular file", ErrWorkspaceVolumeInvalid)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open workspace volume metadata: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !safePrivateWorkspaceVolumeFile(opened) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: workspace volume metadata identity changed while opening", ErrWorkspaceVolumeInvalid)
	}
	return file, nil
}

func openExactWorkspaceVolumeImage(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, path string, spec WorkspaceVolumeSpec, expected *WorkspaceVolumeImageIdentity, initiallyBlank bool) (*os.File, WorkspaceVolumeImageIdentity, error) {
	readOnly, identity, err := inspectWorkspaceVolumeImageReadOnly(ctx, qemuImg, deps, path, spec, initiallyBlank)
	if err != nil {
		return nil, WorkspaceVolumeImageIdentity{}, err
	}
	if expected != nil && identity != *expected {
		_ = readOnly.Close()
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume image identity mismatch", ErrWorkspaceVolumeCorrupt)
	}

	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = readOnly.Close()
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("open mutable workspace volume image: %w", err)
	}
	mutable := os.NewFile(uintptr(fd), WorkspaceVolumeImageName)
	readInfo, readErr := readOnly.Stat()
	mutableInfo, mutableErr := mutable.Stat()
	current, currentErr := os.Lstat(path)
	if readErr != nil || mutableErr != nil || currentErr != nil || !safePrivateWorkspaceVolumeFile(mutableInfo) ||
		!os.SameFile(readInfo, mutableInfo) || !os.SameFile(mutableInfo, current) {
		_ = mutable.Close()
		_ = readOnly.Close()
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume image changed before mutable open", ErrWorkspaceVolumeCorrupt)
	}
	digest, err := inspectQcow2WorkspaceVolumeHeader(mutable, spec.VirtualSizeBytes)
	if err != nil || digest != identity.HeaderSHA256 {
		_ = mutable.Close()
		_ = readOnly.Close()
		if err != nil {
			return nil, WorkspaceVolumeImageIdentity{}, err
		}
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume header changed before mutable open", ErrWorkspaceVolumeCorrupt)
	}
	if err := readOnly.Close(); err != nil {
		_ = mutable.Close()
		return nil, WorkspaceVolumeImageIdentity{}, err
	}
	return mutable, identity, nil
}

func inspectWorkspaceVolumeImageReadOnly(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, path string, spec WorkspaceVolumeSpec, initiallyBlank bool) (*os.File, WorkspaceVolumeImageIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("inspect workspace volume image: %w", err)
	}
	if !safePrivateWorkspaceVolumeFile(before) {
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume image is not a private regular file", ErrWorkspaceVolumeCorrupt)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("open workspace volume image for validation: %w", err)
	}
	file := os.NewFile(uintptr(fd), WorkspaceVolumeImageName)
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !safePrivateWorkspaceVolumeFile(opened) {
		_ = file.Close()
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume image identity changed while opening", ErrWorkspaceVolumeCorrupt)
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume image lacks a Linux file identity", ErrWorkspaceVolumeCorrupt)
	}
	// Reject header-declared backing and data files before invoking qemu-img so
	// validation itself cannot follow an image-controlled external path.
	headerDigest, err := inspectQcow2WorkspaceVolumeHeader(file, spec.VirtualSizeBytes)
	if err != nil {
		_ = file.Close()
		return nil, WorkspaceVolumeImageIdentity{}, err
	}
	if err := validateWorkspaceVolumeQEMUImage(ctx, qemuImg, deps, filepath.Dir(path), file, spec.VirtualSizeBytes, initiallyBlank); err != nil {
		_ = file.Close()
		return nil, WorkspaceVolumeImageIdentity{}, err
	}
	after, afterErr := file.Stat()
	current, currentErr := os.Lstat(path)
	afterDigest, digestErr := inspectQcow2WorkspaceVolumeHeader(file, spec.VirtualSizeBytes)
	if afterErr != nil || currentErr != nil || digestErr != nil || !safePrivateWorkspaceVolumeFile(after) ||
		!os.SameFile(before, after) || !os.SameFile(after, current) || afterDigest != headerDigest {
		_ = file.Close()
		return nil, WorkspaceVolumeImageIdentity{}, fmt.Errorf("%w: workspace volume image changed during structural validation", ErrWorkspaceVolumeCorrupt)
	}
	identity := WorkspaceVolumeImageIdentity{
		FileName:     WorkspaceVolumeImageName,
		Device:       uint64(stat.Dev),
		Inode:        stat.Ino,
		HeaderSHA256: headerDigest,
	}
	return file, identity, nil
}

func revalidateWorkspaceVolumeImage(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, path string, opened *os.File, manifest WorkspaceVolumeManifest, initiallyBlank bool) error {
	readOnly, identity, err := inspectWorkspaceVolumeImageReadOnly(ctx, qemuImg, deps, path, manifest.WorkspaceVolume, initiallyBlank)
	if err != nil {
		return err
	}
	defer readOnly.Close()
	openedInfo, openedErr := opened.Stat()
	readInfo, readErr := readOnly.Stat()
	if openedErr != nil || readErr != nil || !os.SameFile(openedInfo, readInfo) || identity != manifest.Image {
		return fmt.Errorf("%w: workspace volume image changed before publication", ErrWorkspaceVolumeCorrupt)
	}
	return nil
}

func inspectQcow2WorkspaceVolumeHeader(file *os.File, virtualSize int64) (string, error) {
	header := make([]byte, qcow2ValidationHeaderBytes)
	if _, err := file.ReadAt(header, 0); err != nil {
		return "", fmt.Errorf("%w: read complete qcow2 workspace volume header: %v", ErrWorkspaceVolumeCorrupt, err)
	}
	if binary.BigEndian.Uint32(header[0:4]) != 0x514649fb {
		return "", fmt.Errorf("%w: workspace volume image is not qcow2", ErrWorkspaceVolumeCorrupt)
	}
	if version := binary.BigEndian.Uint32(header[4:8]); version < 3 {
		return "", fmt.Errorf("%w: workspace volume qcow2 compatibility is older than 1.1", ErrWorkspaceVolumeCorrupt)
	}
	if binary.BigEndian.Uint64(header[8:16]) != 0 || binary.BigEndian.Uint32(header[16:20]) != 0 {
		return "", fmt.Errorf("%w: workspace volume qcow2 declares a backing file", ErrWorkspaceVolumeCorrupt)
	}
	clusterBits := binary.BigEndian.Uint32(header[20:24])
	if clusterBits < 9 || clusterBits > 21 {
		return "", fmt.Errorf("%w: workspace volume qcow2 cluster size is invalid", ErrWorkspaceVolumeCorrupt)
	}
	if binary.BigEndian.Uint64(header[24:32]) != uint64(virtualSize) {
		return "", fmt.Errorf("%w: workspace volume virtual size differs from its profile", ErrWorkspaceVolumeCorrupt)
	}
	if binary.BigEndian.Uint64(header[72:80])&qcow2DataFileIncompatibleFeature != 0 {
		return "", fmt.Errorf("%w: workspace volume qcow2 declares an external data file", ErrWorkspaceVolumeCorrupt)
	}
	headerLength := binary.BigEndian.Uint32(header[100:104])
	info, statErr := file.Stat()
	if headerLength < qcow2ValidationHeaderBytes || uint64(headerLength) > uint64(1)<<clusterBits || statErr != nil || info.Size() < int64(headerLength) {
		return "", fmt.Errorf("%w: workspace volume qcow2 header is truncated or invalid", ErrWorkspaceVolumeCorrupt)
	}
	sum := sha256.Sum256(header[:qcow2IdentityHeaderBytes])
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type workspaceVolumeQEMUInfo struct {
	VirtualSize           *int64            `json:"virtual-size"`
	Format                string            `json:"format"`
	Encrypted             *bool             `json:"encrypted"`
	Snapshots             []json.RawMessage `json:"snapshots"`
	BackingFilename       json.RawMessage   `json:"backing-filename"`
	FullBackingFilename   json.RawMessage   `json:"full-backing-filename"`
	BackingFilenameFormat json.RawMessage   `json:"backing-filename-format"`
	FormatSpecific        *struct {
		Type string `json:"type"`
		Data *struct {
			Compat   string          `json:"compat"`
			DataFile json.RawMessage `json:"data-file"`
			Corrupt  *bool           `json:"corrupt"`
		} `json:"data"`
	} `json:"format-specific"`
}

type workspaceVolumeQEMUCheck struct {
	Format             string `json:"format"`
	CheckErrors        *int64 `json:"check-errors"`
	Corruptions        *int64 `json:"corruptions"`
	Leaks              *int64 `json:"leaks"`
	CorruptionsFixed   *int64 `json:"corruptions-fixed"`
	LeaksFixed         *int64 `json:"leaks-fixed"`
	AllocatedClusters  *int64 `json:"allocated-clusters"`
	CompressedClusters *int64 `json:"compressed-clusters"`
}

type workspaceVolumeQEMUMapEntry struct {
	Start   *int64 `json:"start"`
	Length  *int64 `json:"length"`
	Depth   *int64 `json:"depth"`
	Present *bool  `json:"present"`
	Zero    *bool  `json:"zero"`
	Data    *bool  `json:"data"`
}

func validateWorkspaceVolumeQEMUImage(ctx context.Context, qemuImg string, deps workspaceVolumeDependencies, workingDirectory string, image *os.File, virtualSize int64, initiallyBlank bool) error {
	descriptorPath := filepath.Join(string(filepath.Separator), "proc", "self", "fd", "3")
	infoJSON, err := invokeWorkspaceVolumeQEMUImg(ctx, deps, qemuImg, workingDirectory, image, "info", "--output=json", "-f", WorkspaceVolumeFormat, descriptorPath)
	if err != nil {
		return workspaceVolumeQEMUValidationError(ctx, "info", err)
	}
	if err := validateWorkspaceVolumeQEMUInfoJSON(infoJSON, virtualSize); err != nil {
		return err
	}
	checkJSON, err := invokeWorkspaceVolumeQEMUImg(ctx, deps, qemuImg, workingDirectory, image, "check", "--output=json", "-f", WorkspaceVolumeFormat, descriptorPath)
	if err != nil {
		return workspaceVolumeQEMUValidationError(ctx, "check", err)
	}
	if err := validateWorkspaceVolumeQEMUCheckJSON(checkJSON, initiallyBlank); err != nil {
		return err
	}
	mapJSON, err := invokeWorkspaceVolumeQEMUImg(ctx, deps, qemuImg, workingDirectory, image, "map", "--output=json", "-f", WorkspaceVolumeFormat, descriptorPath)
	if err != nil {
		return workspaceVolumeQEMUValidationError(ctx, "map", err)
	}
	return validateWorkspaceVolumeQEMUMapJSON(mapJSON, virtualSize, initiallyBlank)
}

func validateWorkspaceVolumeQEMUInfoJSON(data []byte, virtualSize int64) error {
	var info workspaceVolumeQEMUInfo
	if err := decodeWorkspaceVolumeQEMUJSON(data, &info); err != nil {
		return fmt.Errorf("%w: invalid qemu-img info JSON: %v", ErrWorkspaceVolumeCorrupt, err)
	}
	if info.VirtualSize == nil || *info.VirtualSize != virtualSize || info.Format != WorkspaceVolumeFormat || info.FormatSpecific == nil ||
		info.FormatSpecific.Type != WorkspaceVolumeFormat || info.FormatSpecific.Data == nil || !qcow2CompatAtLeast11(info.FormatSpecific.Data.Compat) {
		return fmt.Errorf("%w: qemu-img info does not describe the exact qcow2 1.1+ workspace volume", ErrWorkspaceVolumeCorrupt)
	}
	if len(info.BackingFilename) != 0 || len(info.FullBackingFilename) != 0 || len(info.BackingFilenameFormat) != 0 || len(info.FormatSpecific.Data.DataFile) != 0 {
		return fmt.Errorf("%w: qemu-img info reports a backing or external data file", ErrWorkspaceVolumeCorrupt)
	}
	if len(info.Snapshots) != 0 || info.Encrypted != nil && *info.Encrypted {
		return fmt.Errorf("%w: qemu-img info reports snapshots or encryption outside the workspace volume contract", ErrWorkspaceVolumeCorrupt)
	}
	if info.FormatSpecific.Data.Corrupt != nil && *info.FormatSpecific.Data.Corrupt {
		return fmt.Errorf("%w: qemu-img info reports a corrupt qcow2 image", ErrWorkspaceVolumeCorrupt)
	}
	return nil
}

func validateWorkspaceVolumeQEMUCheckJSON(data []byte, initiallyBlank bool) error {
	var check workspaceVolumeQEMUCheck
	if err := decodeWorkspaceVolumeQEMUJSON(data, &check); err != nil {
		return fmt.Errorf("%w: invalid qemu-img check JSON: %v", ErrWorkspaceVolumeCorrupt, err)
	}
	if check.Format != WorkspaceVolumeFormat || check.CheckErrors == nil || *check.CheckErrors != 0 ||
		nonzeroOptionalInt64(check.Corruptions) || nonzeroOptionalInt64(check.Leaks) ||
		nonzeroOptionalInt64(check.CorruptionsFixed) || nonzeroOptionalInt64(check.LeaksFixed) {
		return fmt.Errorf("%w: qemu-img check reports structural errors", ErrWorkspaceVolumeCorrupt)
	}
	if initiallyBlank && (nonzeroOptionalInt64(check.AllocatedClusters) || nonzeroOptionalInt64(check.CompressedClusters)) {
		return fmt.Errorf("%w: qemu-img check reports allocated data in a newly-created workspace volume", ErrWorkspaceVolumeCorrupt)
	}
	return nil
}

func validateWorkspaceVolumeQEMUMapJSON(data []byte, virtualSize int64, initiallyBlank bool) error {
	var entries []workspaceVolumeQEMUMapEntry
	if err := decodeWorkspaceVolumeQEMUJSON(data, &entries); err != nil {
		return fmt.Errorf("%w: invalid qemu-img map JSON: %v", ErrWorkspaceVolumeCorrupt, err)
	}
	next := int64(0)
	for _, entry := range entries {
		if entry.Start == nil || entry.Length == nil || entry.Depth == nil || entry.Present == nil || entry.Zero == nil || entry.Data == nil ||
			*entry.Start != next || *entry.Length <= 0 || *entry.Length > virtualSize-next || *entry.Depth != 0 || (*entry.Data && !*entry.Present) {
			return fmt.Errorf("%w: qemu-img map is incomplete or structurally invalid", ErrWorkspaceVolumeCorrupt)
		}
		if initiallyBlank && (*entry.Present || !*entry.Zero || *entry.Data) {
			return fmt.Errorf("%w: newly-created workspace volume is not blank", ErrWorkspaceVolumeCorrupt)
		}
		next += *entry.Length
	}
	if next != virtualSize {
		return fmt.Errorf("%w: qemu-img map does not cover the exact virtual size", ErrWorkspaceVolumeCorrupt)
	}
	return nil
}

func decodeWorkspaceVolumeQEMUJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxQEMUImgJSONBytes {
		return fmt.Errorf("qemu-img JSON output is empty or exceeds %d bytes", maxQEMUImgJSONBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func qcow2CompatAtLeast11(value string) bool {
	majorText, minorText, ok := strings.Cut(value, ".")
	if !ok || majorText == "" || minorText == "" || strings.Contains(minorText, ".") {
		return false
	}
	for _, value := range []string{majorText, minorText} {
		for _, char := range value {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	major, majorErr := strconv.ParseUint(majorText, 10, 32)
	minor, minorErr := strconv.ParseUint(minorText, 10, 32)
	return majorErr == nil && minorErr == nil && (major > 1 || major == 1 && minor >= 1)
}

func nonzeroOptionalInt64(value *int64) bool {
	return value != nil && *value != 0
}

func workspaceVolumeQEMUValidationError(ctx context.Context, operation string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: qemu-img %s validation failed: %v", ErrWorkspaceVolumeCorrupt, operation, err)
}

func safePrivateWorkspaceVolumeFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && trustedWorkspaceVolumeOwner(stat.Uid)
}

func trustedWorkspaceVolumeOwner(uid uint32) bool {
	return uid == 0 || uid == uint32(os.Geteuid())
}

func validateWorkspaceVolumeEntries(entries []os.DirEntry, allowPartial bool) error {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name != WorkspaceVolumeManifestName && name != WorkspaceVolumeImageName {
			return fmt.Errorf("%w: unexpected workspace volume path %q", ErrWorkspaceVolumeCorrupt, name)
		}
		if seen[name] {
			return fmt.Errorf("%w: duplicate workspace volume path %q", ErrWorkspaceVolumeCorrupt, name)
		}
		seen[name] = true
	}
	if !allowPartial && (!seen[WorkspaceVolumeManifestName] || !seen[WorkspaceVolumeImageName] || len(seen) != 2) {
		return fmt.Errorf("%w: workspace volume publication is incomplete", ErrWorkspaceVolumeCorrupt)
	}
	return nil
}

func validateWorkspaceVolumeCreateEntries(entries []os.DirEntry) error {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name != workspaceVolumeCreateIntentName && name != WorkspaceVolumeManifestName && name != WorkspaceVolumeImageName {
			return fmt.Errorf("%w: unexpected workspace volume create path %q", ErrWorkspaceVolumeCorrupt, name)
		}
		if seen[name] {
			return fmt.Errorf("%w: duplicate workspace volume create path %q", ErrWorkspaceVolumeCorrupt, name)
		}
		seen[name] = true
	}
	if !seen[workspaceVolumeCreateIntentName] && !seen[WorkspaceVolumeManifestName] {
		return fmt.Errorf("%w: workspace volume create transaction lacks an exact identity record", ErrWorkspaceVolumeCorrupt)
	}
	return nil
}

func workspaceVolumeEntryExists(entries []os.DirEntry, name string) bool {
	for _, entry := range entries {
		if entry.Name() == name {
			return true
		}
	}
	return false
}

func syncWorkspaceVolumeDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func cleanupUnpublishedWorkspaceVolume(root string) {
	_ = os.Remove(filepath.Join(root, WorkspaceVolumeImageName))
	_ = os.Remove(filepath.Join(root, WorkspaceVolumeManifestName))
	_ = os.Remove(filepath.Join(root, workspaceVolumeCreateIntentName))
	_ = os.Remove(root)
}

func validateWorkspaceVolumeDependencies(deps workspaceVolumeDependencies) error {
	if deps.resolveQEMUImg == nil || deps.runQEMUImg == nil || deps.now == nil {
		return fmt.Errorf("%w: workspace volume dependencies are incomplete", ErrWorkspaceVolumeInvalid)
	}
	return nil
}

func resolveWorkspaceVolumeQEMUImg(deps workspaceVolumeDependencies) (string, error) {
	qemuImg, err := deps.resolveQEMUImg("qemu-img")
	if err != nil {
		return "", fmt.Errorf("resolve packaged qemu-img: %w", err)
	}
	if !filepath.IsAbs(qemuImg) || filepath.Clean(qemuImg) != qemuImg {
		return "", fmt.Errorf("%w: resolved qemu-img path is not clean and absolute", ErrWorkspaceVolumeInvalid)
	}
	return qemuImg, nil
}

func invokeWorkspaceVolumeQEMUImg(ctx context.Context, deps workspaceVolumeDependencies, executable, workingDirectory string, image *os.File, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, workspaceVolumeQEMUImgCommandTimeout)
	defer cancel()
	output, err := deps.runQEMUImg(commandCtx, executable, workingDirectory, image, args...)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if commandErr := commandCtx.Err(); commandErr != nil {
		return nil, fmt.Errorf("bounded qemu-img command: %w", commandErr)
	}
	return output, err
}

type boundedQEMUImgOutput struct {
	limit     int
	data      []byte
	truncated bool
}

func (b *boundedQEMUImgOutput) Write(data []byte) (int, error) {
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		b.data = append(b.data, data[:remaining]...)
	}
	if remaining < len(data) {
		b.truncated = true
	}
	return len(data), nil
}

func (b *boundedQEMUImgOutput) String() string {
	message := strings.TrimSpace(string(b.data))
	message = strings.Map(func(char rune) rune {
		if char == '\n' || char == '\t' || char >= 0x20 {
			return char
		}
		return -1
	}, message)
	if b.truncated {
		message += " [truncated]"
	}
	return message
}

func runWorkspaceVolumeQEMUImg(ctx context.Context, executable, workingDirectory string, image *os.File, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = workingDirectory
	command.Env = []string{
		"HOME=" + workingDirectory,
		"LC_ALL=C",
		"PATH=" + filepath.Dir(executable),
	}
	command.WaitDelay = 2 * time.Second
	if image != nil {
		command.ExtraFiles = []*os.File{image}
	}
	stdout := boundedQEMUImgOutput{limit: maxQEMUImgJSONBytes}
	stderr := boundedQEMUImgOutput{limit: maxQEMUImgErrorBytes}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if detail := stderr.String(); detail != "" {
			return nil, fmt.Errorf("qemu-img failed: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("qemu-img failed: %w", err)
	}
	if stdout.truncated {
		return nil, fmt.Errorf("qemu-img JSON output exceeds %d bytes", maxQEMUImgJSONBytes)
	}
	return append([]byte(nil), stdout.data...), nil
}
