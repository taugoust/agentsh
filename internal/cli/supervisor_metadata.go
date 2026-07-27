package cli

import (
	"context"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/client"
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
	metas, err := listSupervisorMetadataFromRoot(detachedSessionsRoot(), supervisorDiscoveryOptions{
		RequireSocket: true,
		CheckPID:      true,
		PIDAlive:      supervisorPIDAlive,
	})
	if err != nil {
		return nil, err
	}
	// Discovery callers need routing metadata, never the detached bridge
	// credential. Keep it confined to the mode-0600 on-disk record. Protocol-v2
	// records are returned only after their protected metadata matches the live
	// socket incarnation handshake.
	out := make([]supervisorMetadata, 0, len(metas))
	for _, meta := range metas {
		if err := validateSupervisorMetadataUsable(meta); err != nil {
			continue
		}
		if meta.ProtocolVersion >= 2 {
			c := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", 2*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := validateDetachedRuntimeHandshake(ctx, c, meta)
			cancel()
			if err != nil {
				continue
			}
		}
		meta.EventToken = ""
		meta.NetworkEnforcement = detached.StaleNetworkEnforcementSnapshot(meta.NetworkEnforcement)
		out = append(out, meta)
	}
	return out, nil
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
