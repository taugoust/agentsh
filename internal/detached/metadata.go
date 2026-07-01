package detached

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ProtocolVersion = 1

var ErrMetadataInvalid = errors.New("invalid detached supervisor metadata")

type WorkspaceRoot struct {
	Name string `json:"name"`
	Real string `json:"real"`
	Work string `json:"work"`
}

type Metadata struct {
	SessionID       string          `json:"session_id"`
	ID              string          `json:"id,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	State           string          `json:"state"`
	Policy          string          `json:"policy"`
	RealWorkspace   string          `json:"real_workspace"`
	WorkspaceMode   string          `json:"workspace_mode"`
	Worktree        string          `json:"worktree"`
	WorkspaceRoots  []WorkspaceRoot `json:"workspace_roots,omitempty"`
	RuntimeHome     string          `json:"runtime_home,omitempty"`
	RuntimeTmp      string          `json:"runtime_tmp,omitempty"`
	SupervisorSock  string          `json:"supervisor_sock"`
	EventToken      string          `json:"event_token,omitempty"`
	OwnerPID        int             `json:"owner_pid"`
	ProtocolVersion int             `json:"protocol_version"`
}

type DiscoveryOptions struct {
	RequireSocket bool
	CheckPID      bool
	PIDAlive      func(int) bool
}

func MetadataPath(stateDir string) string {
	return filepath.Join(stateDir, "metadata.json")
}

func WriteMetadata(stateDir string, meta Metadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	path := MetadataPath(stateDir)
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

func ReadMetadataFromRoot(root string, sessionID string) (Metadata, string, error) {
	stateDir := filepath.Join(root, sessionID)
	path := MetadataPath(stateDir)
	b, err := os.ReadFile(path)
	if err != nil {
		return Metadata{}, stateDir, fmt.Errorf("read detached supervisor metadata for %s at %s: %w", sessionID, path, err)
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Metadata{}, stateDir, fmt.Errorf("%w for %s at %s: %v", ErrMetadataInvalid, sessionID, path, err)
	}
	if meta.SessionID == "" {
		return Metadata{}, stateDir, fmt.Errorf("%w for %s at %s: missing session_id", ErrMetadataInvalid, sessionID, path)
	}
	return meta, stateDir, nil
}

func ListMetadataFromRoot(root string, opts DiscoveryOptions) ([]Metadata, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("discover detached supervisors under %s: %w", root, err)
	}
	var out []Metadata
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		meta, _, err := ReadMetadataFromRoot(root, ent.Name())
		if err != nil {
			continue
		}
		if opts.RequireSocket && strings.TrimSpace(meta.SupervisorSock) == "" {
			continue
		}
		if opts.RequireSocket {
			if _, err := os.Stat(meta.SupervisorSock); err != nil {
				continue
			}
		}
		if opts.CheckPID && meta.OwnerPID > 0 && opts.PIDAlive != nil && !opts.PIDAlive(meta.OwnerPID) {
			continue
		}
		out = append(out, meta)
	}
	return out, nil
}

func ValidateUsable(meta Metadata, pidAlive func(int) bool) error {
	if strings.TrimSpace(meta.SupervisorSock) == "" {
		return fmt.Errorf("stale metadata for detached session %s: metadata.json has no supervisor_sock", meta.SessionID)
	}
	if _, err := os.Stat(meta.SupervisorSock); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stale metadata for detached session %s: supervisor.sock is missing at %s; stop/remove the stale session or start a new detached session", meta.SessionID, meta.SupervisorSock)
		}
		return fmt.Errorf("stale metadata for detached session %s: cannot stat supervisor.sock at %s: %w", meta.SessionID, meta.SupervisorSock, err)
	}
	if meta.OwnerPID > 0 && pidAlive != nil && !pidAlive(meta.OwnerPID) {
		return fmt.Errorf("dead supervisor for detached session %s: owner_pid %d is not running; stop/remove the stale session or start a new detached session", meta.SessionID, meta.OwnerPID)
	}
	return nil
}
