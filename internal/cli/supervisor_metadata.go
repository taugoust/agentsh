package cli

import (
	"path/filepath"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
)

const supervisorProtocolVersion = detached.ProtocolVersion

type supervisorMetadata = detached.Metadata

type supervisorDiscoveryOptions = detached.DiscoveryOptions

func supervisorMetadataPath(stateDir string) string {
	return detached.MetadataPath(stateDir)
}

func writeSupervisorMetadata(stateDir string, meta supervisorMetadata) error {
	return detached.WriteMetadata(stateDir, meta)
}

func readSupervisorMetadata(sessionID string) (supervisorMetadata, string, error) {
	return readSupervisorMetadataFromRoot(detachedSessionsRoot(), sessionID)
}

func readSupervisorMetadataFromRoot(root string, sessionID string) (supervisorMetadata, string, error) {
	return detached.ReadMetadataFromRoot(root, sessionID)
}

func listSupervisorMetadata() ([]supervisorMetadata, error) {
	return listSupervisorMetadataFromRoot(detachedSessionsRoot(), supervisorDiscoveryOptions{
		RequireSocket: true,
		CheckPID:      true,
		PIDAlive:      supervisorPIDAlive,
	})
}

func listSupervisorMetadataFromRoot(root string, opts supervisorDiscoveryOptions) ([]supervisorMetadata, error) {
	if opts.CheckPID && opts.PIDAlive == nil {
		opts.PIDAlive = supervisorPIDAlive
	}
	return detached.ListMetadataFromRoot(root, opts)
}

func validateSupervisorMetadataUsable(meta supervisorMetadata) error {
	return detached.ValidateUsable(meta, supervisorPIDAlive)
}

func detachedSessionsRoot() string {
	return filepath.Join(config.GetUserStateDir(), "sessions")
}
