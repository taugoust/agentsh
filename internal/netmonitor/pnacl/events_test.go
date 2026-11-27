package pnacl

import (
	"testing"

	"github.com/agentsh/agentsh/internal/events"
)

func TestEventCategory(t *testing.T) {
	// Verify PNACL event types are registered in the category map
	if events.EventCategory[EventNetworkACL] != "network" {
		t.Errorf("EventNetworkACL category = %s, want network", events.EventCategory[EventNetworkACL])
	}
	if events.EventCategory[EventNetworkACLApproval] != "network" {
		t.Errorf("EventNetworkACLApproval category = %s, want network", events.EventCategory[EventNetworkACLApproval])
	}
	if events.EventCategory[EventNetworkACLAudit] != "network" {
		t.Errorf("EventNetworkACLAudit category = %s, want network", events.EventCategory[EventNetworkACLAudit])
	}
}
