package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

var (
	ErrCheckpointNotFound   = errors.New("checkpoint not found")
	ErrRollbackNotSupported = errors.New("rollback not supported for this checkpoint")
)

// Checkpoint represents a snapshot of session state that can be used for recovery.
type Checkpoint struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"`

	// Snapshot of session state
	Stats types.SessionStats `json:"stats"`

	// File system state (for recovery)
	WorkspaceHash string   `json:"workspace_hash"`
	ModifiedFiles []string `json:"modified_files"`

	// Can be used for rollback
	CanRollback bool `json:"can_rollback"`
}

// CheckpointStorage provides persistence for checkpoints.
type CheckpointStorage interface {
	Save(cp *Checkpoint) error
	Load(sessionID, checkpointID string) (*Checkpoint, error)
	List(sessionID string) ([]*Checkpoint, error)
	Delete(sessionID, checkpointID string) error
}

// FileCheckpointStorageInterface extends CheckpointStorage with file backup capabilities.
type FileCheckpointStorageInterface interface {
	CheckpointStorage

	// CreateSnapshot backs up specified files to checkpoint storage.
	CreateSnapshot(sessionID, checkpointID string, files []string, workspacePath string) error

	// Rollback restores files from checkpoint to workspace.
	Rollback(sessionID, checkpointID string, workspacePath string) ([]string, error)

	// Diff returns files that changed between checkpoint and current workspace.
	Diff(sessionID, checkpointID string, workspacePath string) ([]FileDiff, error)

	// Purge removes checkpoints older than maxAge or exceeding count limit.
	Purge(sessionID string, maxAge time.Duration, maxCount int) (int, error)

	// LoadMetadata retrieves full checkpoint metadata including file list.
	LoadMetadata(sessionID, checkpointID string) (*CheckpointMetadata, error)
}

// CheckpointManager handles checkpoint creation and recovery for sessions.
type CheckpointManager struct {
	mu      sync.RWMutex
	storage CheckpointStorage
}

// NewCheckpointManager creates a new checkpoint manager.
func NewCheckpointManager(storage CheckpointStorage) *CheckpointManager {
	return &CheckpointManager{
		storage: storage,
	}
}

// ListCheckpoints returns all checkpoints for a session.
func (m *CheckpointManager) ListCheckpoints(sessionID string) ([]*Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.storage == nil {
		return nil, nil
	}

	return m.storage.List(sessionID)
}

// CreateCheckpointWithSnapshot creates a checkpoint with file backup for rollback.
// If files is nil, backs up the entire workspace.
func (m *CheckpointManager) CreateCheckpointWithSnapshot(s *Session, reason string, files []string) (*Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.storage == nil {
		return nil, errors.New("no storage configured")
	}

	s.mu.Lock()
	stats := s.stats
	workspace := s.Workspace
	sessionID := s.ID
	s.mu.Unlock()

	cp := &Checkpoint{
		ID:        uuid.New().String(),
		SessionID: sessionID,
		CreatedAt: time.Now().UTC(),
		Reason:    reason,
		Stats:     stats,
	}

	// Hash current workspace state
	hash, modifiedFiles, err := hashWorkspace(workspace)
	if err == nil {
		cp.WorkspaceHash = hash
		cp.ModifiedFiles = modifiedFiles
	}

	// Save checkpoint metadata first
	if err := m.storage.Save(cp); err != nil {
		return nil, err
	}

	// If storage supports file snapshots, create one
	if fs, ok := m.storage.(FileCheckpointStorageInterface); ok {
		if err := fs.CreateSnapshot(sessionID, cp.ID, files, workspace); err != nil {
			// Clean up on failure
			_ = m.storage.Delete(sessionID, cp.ID)
			return nil, err
		}
		cp.CanRollback = true
	}

	return cp, nil
}

// Rollback restores files from a checkpoint to the workspace.
// Returns list of restored file paths.
func (m *CheckpointManager) Rollback(sessionID, checkpointID, workspacePath string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.storage == nil {
		return nil, ErrCheckpointNotFound
	}

	fs, ok := m.storage.(FileCheckpointStorageInterface)
	if !ok {
		return nil, ErrRollbackNotSupported
	}

	return fs.Rollback(sessionID, checkpointID, workspacePath)
}

// Diff returns files that changed between checkpoint and current workspace.
func (m *CheckpointManager) Diff(sessionID, checkpointID, workspacePath string) ([]FileDiff, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.storage == nil {
		return nil, ErrCheckpointNotFound
	}

	fs, ok := m.storage.(FileCheckpointStorageInterface)
	if !ok {
		return nil, errors.New("storage does not support diff")
	}

	return fs.Diff(sessionID, checkpointID, workspacePath)
}

// PurgeCheckpoints removes old checkpoints based on age and count limits.
func (m *CheckpointManager) PurgeCheckpoints(sessionID string, maxAge time.Duration, maxCount int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.storage == nil {
		return 0, nil
	}

	fs, ok := m.storage.(FileCheckpointStorageInterface)
	if !ok {
		return 0, errors.New("storage does not support purge")
	}

	return fs.Purge(sessionID, maxAge, maxCount)
}

// GetCheckpointMetadata retrieves full checkpoint metadata including file list.
func (m *CheckpointManager) GetCheckpointMetadata(sessionID, checkpointID string) (*CheckpointMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.storage == nil {
		return nil, ErrCheckpointNotFound
	}

	fs, ok := m.storage.(FileCheckpointStorageInterface)
	if !ok {
		// Fall back to basic checkpoint
		cp, err := m.storage.Load(sessionID, checkpointID)
		if err != nil {
			return nil, err
		}
		return &CheckpointMetadata{Checkpoint: *cp}, nil
	}

	return fs.LoadMetadata(sessionID, checkpointID)
}

// hashWorkspace calculates a hash of the workspace and returns modified files.
func hashWorkspace(workspacePath string) (string, []string, error) {
	h := sha256.New()
	var modifiedFiles []string

	err := filepath.WalkDir(workspacePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories
		if d.IsDir() && len(d.Name()) > 0 && d.Name()[0] == '.' {
			return filepath.SkipDir
		}

		// Skip directories for hashing
		if d.IsDir() {
			return nil
		}

		// Get relative path
		rel, err := filepath.Rel(workspacePath, path)
		if err != nil {
			return err
		}

		// Hash file content
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		// Write path to hash
		h.Write([]byte(rel))

		// Write content to hash
		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		modifiedFiles = append(modifiedFiles, rel)
		return nil
	})

	if err != nil {
		return "", nil, err
	}

	return hex.EncodeToString(h.Sum(nil)), modifiedFiles, nil
}
