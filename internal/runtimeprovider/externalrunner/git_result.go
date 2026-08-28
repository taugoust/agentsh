package externalrunner

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
)

const (
	GitResultSchemaVersion = 1
	GitResultRecordName    = "git-result.json"
	GitTerminalRecordName  = "git-terminal.json"
)

type GitTerminalRecord struct {
	SchemaVersion    int       `json:"schema_version"`
	SessionID        string    `json:"session_id"`
	VolumeID         string    `json:"volume_id"`
	Intent           string    `json:"intent"`
	VolumeDeleted    bool      `json:"volume_deleted,omitempty"`
	ArtifactsDeleted bool      `json:"artifacts_deleted,omitempty"`
	Complete         bool      `json:"complete,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type GitResultRecord struct {
	SchemaVersion   int                 `json:"schema_version"`
	SessionID       string              `json:"session_id"`
	VolumeID        string              `json:"volume_id"`
	InputArtifactID string              `json:"input_artifact_id"`
	InputSHA256     string              `json:"input_sha256"`
	ResultArtifact  artifact.Descriptor `json:"result_artifact"`
	BaselineCommit  string              `json:"baseline_commit"`
	ResultCommit    string              `json:"result_commit"`
	CreatedAt       time.Time           `json:"created_at"`
}

func (r GitResultRecord) Validate(request HostMonitorRequest) error {
	if r.SchemaVersion != GitResultSchemaVersion || r.SessionID != request.SessionID || r.VolumeID != request.VolumeID || request.InputArtifact == nil ||
		r.InputArtifactID != request.InputArtifact.ArtifactID || r.InputSHA256 != request.InputArtifact.SHA256 || r.ResultArtifact.Validate() != nil ||
		r.ResultArtifact.SessionID != request.SessionID || r.ResultArtifact.Kind != artifact.KindGitResultBundle || !validGitResultOID(r.BaselineCommit) ||
		!validGitResultOID(r.ResultCommit) || r.BaselineCommit == r.ResultCommit || r.CreatedAt.IsZero() {
		return fmt.Errorf("external runner Git result record is invalid or not bound to its immutable request")
	}
	return nil
}

func WriteGitResultRecord(stateDir string, request HostMonitorRequest, record GitResultRecord) error {
	if err := record.Validate(request); err != nil {
		return err
	}
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusivePrivateFile(filepath.Join(layout.HostDir, GitResultRecordName), append(data, '\n'))
}

func ReadGitResultRecord(stateDir string, request HostMonitorRequest) (GitResultRecord, error) {
	layout, err := HostMonitorPaths(stateDir)
	if err != nil {
		return GitResultRecord{}, err
	}
	var record GitResultRecord
	if err := readStrictPrivateJSON(filepath.Join(layout.HostDir, GitResultRecordName), &record); err != nil {
		return GitResultRecord{}, err
	}
	if err := record.Validate(request); err != nil {
		return GitResultRecord{}, err
	}
	return record, nil
}

func validGitResultOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
