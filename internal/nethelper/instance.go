package nethelper

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
)

// EphemeralInstanceControllerOptions binds one fixed helper lease to its
// expected Unix peer and instance credential.
type EphemeralInstanceControllerOptions struct {
	LeaseID                  string
	HelperInstanceCredential string
	ExpectedUID              uint32
	ExpectedGID              uint32
	EnforceGID               bool
	Registrations            interface{ ActiveRegistrationCount() int }
}

// EphemeralInstanceController authorizes release of one transient helper. It
// deliberately exposes no generic stop, cleanup, unit, path, or process API.
type EphemeralInstanceController struct {
	opts EphemeralInstanceControllerOptions

	mu       sync.Mutex
	released bool
}

func NewEphemeralInstanceController(opts EphemeralInstanceControllerOptions) *EphemeralInstanceController {
	return &EphemeralInstanceController{opts: opts}
}

// ReleaseInstance authenticates the same-UID trusted wrapper and refuses to
// stop while any command registration remains. Server invokes its Stop callback
// only after the successful response write has been attempted.
func (c *EphemeralInstanceController) ReleaseInstance(_ context.Context, peer PeerInfo, req ReleaseInstanceRequest) (ReleaseInstanceResponse, error) {
	resp := ReleaseInstanceResponse{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       req.RequestID,
		LeaseID:         req.LeaseID,
	}
	if c == nil {
		return resp, fmt.Errorf("ephemeral instance controller is nil")
	}
	if err := req.Validate(); err != nil {
		return resp, err
	}
	if !peer.Supported || peer.PID <= 0 {
		return resp, fmt.Errorf("peer credentials are required for instance release")
	}
	if peer.UID != c.opts.ExpectedUID {
		return resp, fmt.Errorf("peer uid is not authorized to release this helper instance")
	}
	if c.opts.EnforceGID && peer.GID != c.opts.ExpectedGID {
		return resp, fmt.Errorf("peer gid is not authorized to release this helper instance")
	}
	lease := strings.TrimSpace(c.opts.LeaseID)
	if lease == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.LeaseID)), []byte(lease)) != 1 {
		return resp, fmt.Errorf("lease_id is not authorized")
	}
	expectedCredential := strings.TrimSpace(c.opts.HelperInstanceCredential)
	if expectedCredential == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.HelperInstanceCredential)), []byte(expectedCredential)) != 1 {
		return resp, fmt.Errorf("helper instance credential is not authorized")
	}
	if c.opts.Registrations != nil {
		if count := c.opts.Registrations.ActiveRegistrationCount(); count != 0 {
			return resp, fmt.Errorf("cannot release helper instance while %d command registrations remain", count)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return resp, fmt.Errorf("helper instance release is already in progress")
	}
	c.released = true
	resp.OK = true
	return resp, nil
}

func (c *EphemeralInstanceController) Released() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.released
}
