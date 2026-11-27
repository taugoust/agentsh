package session

import (
	"github.com/agentsh/agentsh/internal/policy"
)

// ResolvedMount represents an active mount with its loaded policy.
type ResolvedMount struct {
	Path         string         // Absolute path that was mounted
	Policy       string         // Policy name
	MountPoint   string         // Where FUSE mounted it
	PolicyEngine *policy.Engine // Loaded policy engine for this mount
	Unmount      func() error   // Function to unmount
}
