package pnacl

import (
	"github.com/agentsh/agentsh/internal/events"
)

// Event types for PNACL
const (
	EventNetworkACL         events.EventType = "network_acl"
	EventNetworkACLApproval events.EventType = "network_acl_approval"
	EventNetworkACLAudit    events.EventType = "network_acl_audit"
)

func init() {
	// Register PNACL event types
	events.EventCategory[EventNetworkACL] = "network"
	events.EventCategory[EventNetworkACLApproval] = "network"
	events.EventCategory[EventNetworkACLAudit] = "network"
}
