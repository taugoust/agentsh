package nethelper

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"
)

// InstanceTimer is the resettable timer seam used by ephemeral lifecycle tests.
type InstanceTimer interface {
	C() <-chan time.Time
	Reset(time.Duration) bool
	Stop() bool
}

type realInstanceTimer struct{ timer *time.Timer }

func (t *realInstanceTimer) C() <-chan time.Time        { return t.timer.C }
func (t *realInstanceTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }
func (t *realInstanceTimer) Stop() bool                 { return t.timer.Stop() }

// EphemeralInstanceControllerOptions binds one fixed helper lease to its
// expected Unix peer, credential, and finite soft/hard deadlines.
type EphemeralInstanceControllerOptions struct {
	LeaseID                  string
	UnitName                 string
	HelperInstanceCredential string
	ExpectedUID              uint32
	ExpectedGID              uint32
	EnforceGID               bool
	Registrations            interface{ ActiveRegistrationCount() int }
	Operations               *OperationGate
	CreatedAt                time.Time
	HardExpiresAt            time.Time
	SoftLease                time.Duration
	ReleaseDrainTimeout      time.Duration
	Now                      func() time.Time
	NewTimer                 func(time.Duration) InstanceTimer
	Stop                     func()
}

// EphemeralInstanceController owns authenticated status, renewal, expiry, and
// release for one transient helper. It deliberately exposes no generic process,
// path, pin, or unit mutation API.
type EphemeralInstanceController struct {
	opts EphemeralInstanceControllerOptions

	mu                sync.Mutex
	softExpiresAt     time.Time
	renewalGeneration uint64
	released          bool
	terminalReason    string
	wake              chan struct{}
}

func NewEphemeralInstanceController(opts EphemeralInstanceControllerOptions) *EphemeralInstanceController {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewTimer == nil {
		opts.NewTimer = func(d time.Duration) InstanceTimer { return &realInstanceTimer{timer: time.NewTimer(d)} }
	}
	now := opts.Now().UTC()
	if opts.CreatedAt.IsZero() {
		opts.CreatedAt = now
	} else {
		opts.CreatedAt = opts.CreatedAt.UTC()
	}
	if opts.HardExpiresAt.IsZero() {
		opts.HardExpiresAt = opts.CreatedAt.Add(DefaultBootstrapRuntime)
	} else {
		opts.HardExpiresAt = opts.HardExpiresAt.UTC()
	}
	// A zero soft lease is the compatibility mode: runtime-only/legacy
	// bootstraps live until hard expiry. Soft expiry is enabled only when the
	// launching wrapper explicitly commits to renewal.
	soft := opts.HardExpiresAt
	if opts.SoftLease > 0 {
		soft = opts.CreatedAt.Add(opts.SoftLease)
		if soft.After(opts.HardExpiresAt) {
			soft = opts.HardExpiresAt
		}
	}
	c := &EphemeralInstanceController{opts: opts, softExpiresAt: soft, wake: make(chan struct{}, 1)}
	if opts.Stop != nil {
		go c.expiryLoop()
	}
	return c
}

func (c *EphemeralInstanceController) now() time.Time { return c.opts.Now().UTC() }

func (c *EphemeralInstanceController) authenticate(peer PeerInfo, leaseID, credential, operation string) error {
	if !peer.Supported || peer.PID <= 0 {
		return fmt.Errorf("peer credentials are required for instance %s", operation)
	}
	if peer.UID != c.opts.ExpectedUID {
		return fmt.Errorf("peer uid is not authorized for this helper instance")
	}
	if c.opts.EnforceGID && peer.GID != c.opts.ExpectedGID {
		return fmt.Errorf("peer gid is not authorized for this helper instance")
	}
	lease := strings.TrimSpace(c.opts.LeaseID)
	if lease == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(leaseID)), []byte(lease)) != 1 {
		return fmt.Errorf("lease_id is not authorized")
	}
	expected := strings.TrimSpace(c.opts.HelperInstanceCredential)
	if expected == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(credential)), []byte(expected)) != 1 {
		return fmt.Errorf("helper instance credential is not authorized")
	}
	return nil
}

func (c *EphemeralInstanceController) activeRegistrations() int {
	if c.opts.Registrations == nil {
		return 0
	}
	return c.opts.Registrations.ActiveRegistrationCount()
}

func (c *EphemeralInstanceController) statusLocked(requestID string, now time.Time) InstanceStatusResponse {
	status := "active"
	reason := ""
	if c.released {
		status, reason = "stopping", "released"
	} else if !now.Before(c.opts.HardExpiresAt) {
		status, reason = "expired", "hard-expiry"
	} else if !now.Before(c.softExpiresAt) {
		status, reason = "expired", "soft-lease-expired"
	} else if c.terminalReason != "" {
		status, reason = "stopping", c.terminalReason
	}
	return InstanceStatusResponse{
		ProtocolVersion:         CurrentProtocolVersion,
		RequestID:               requestID,
		Capabilities:            append([]string(nil), LifecycleCapabilities...),
		HelperKind:              "ephemeral",
		LeaseID:                 c.opts.LeaseID,
		UnitName:                c.opts.UnitName,
		CreatedAt:               c.opts.CreatedAt,
		SoftExpiresAt:           c.softExpiresAt,
		HardExpiresAt:           c.opts.HardExpiresAt,
		ActiveRegistrationCount: c.activeRegistrations(),
		Status:                  status,
		Reason:                  reason,
		RenewalGeneration:       c.renewalGeneration,
		OK:                      status == "active",
	}
}

func (c *EphemeralInstanceController) InstanceStatus(_ context.Context, peer PeerInfo, req InstanceStatusRequest) (InstanceStatusResponse, error) {
	resp := InstanceStatusResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, LeaseID: req.LeaseID, HelperKind: "ephemeral"}
	if c == nil {
		return resp, fmt.Errorf("ephemeral instance controller is nil")
	}
	if err := req.Validate(); err != nil {
		return resp, err
	}
	if err := c.authenticate(peer, req.LeaseID, req.HelperInstanceCredential, "status"); err != nil {
		return resp, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	resp = c.statusLocked(req.RequestID, c.now())
	if !resp.OK {
		return resp, fmt.Errorf("helper instance is %s: %s", resp.Status, resp.Reason)
	}
	return resp, nil
}

func (c *EphemeralInstanceController) RenewInstance(_ context.Context, peer PeerInfo, req RenewInstanceRequest) (RenewInstanceResponse, error) {
	resp := RenewInstanceResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, LeaseID: req.LeaseID, HelperKind: "ephemeral"}
	if c == nil {
		return resp, fmt.Errorf("ephemeral instance controller is nil")
	}
	if err := req.Validate(); err != nil {
		return resp, err
	}
	if err := c.authenticate(peer, req.LeaseID, req.HelperInstanceCredential, "renewal"); err != nil {
		return resp, err
	}
	c.mu.Lock()
	now := c.now()
	current := c.statusLocked(req.RequestID, now)
	if !current.OK {
		c.mu.Unlock()
		return current, fmt.Errorf("helper instance cannot be renewed after %s", current.Reason)
	}
	soft := now.Add(c.opts.SoftLease)
	if soft.After(c.opts.HardExpiresAt) {
		soft = c.opts.HardExpiresAt
	}
	// A renewal may keep the same capped deadline, but it never moves backward
	// and still increments the authenticated renewal generation.
	if soft.After(c.softExpiresAt) {
		c.softExpiresAt = soft
	}
	c.renewalGeneration++
	resp = c.statusLocked(req.RequestID, now)
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return resp, nil
}

// ReleaseInstance authenticates the wrapper and refuses to stop while any
// command registration remains. Server invokes Stop only after writing the
// successful response.
func (c *EphemeralInstanceController) ReleaseInstance(ctx context.Context, peer PeerInfo, req ReleaseInstanceRequest) (ReleaseInstanceResponse, error) {
	resp := ReleaseInstanceResponse{ProtocolVersion: CurrentProtocolVersion, RequestID: req.RequestID, LeaseID: req.LeaseID}
	if c == nil {
		return resp, fmt.Errorf("ephemeral instance controller is nil")
	}
	if err := req.Validate(); err != nil {
		return resp, err
	}
	if err := c.authenticate(peer, req.LeaseID, req.HelperInstanceCredential, "release"); err != nil {
		return resp, err
	}
	drainTimeout := c.opts.ReleaseDrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = 5 * time.Second
	}
	drainCtx, cancelDrain := context.WithTimeout(ctx, drainTimeout)
	defer cancelDrain()
	rollback, err := c.opts.Operations.StopAndWait(drainCtx)
	if err != nil {
		return resp, fmt.Errorf("wait for admitted lifecycle operations: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollback()
		}
	}()
	// Cancellation after the drain but before commit must also reopen admission.
	if err := ctx.Err(); err != nil {
		return resp, err
	}
	// Admission is closed and all register/update/cleanup dispatch has finished,
	// so this count is authoritative for the release transition.
	if count := c.activeRegistrations(); count != 0 {
		return resp, fmt.Errorf("cannot release helper instance while %d command registrations remain", count)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released || c.terminalReason != "" {
		return resp, fmt.Errorf("helper instance release is already in progress")
	}
	c.released = true
	c.terminalReason = "released"
	committed = true
	resp.OK = true
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return resp, nil
}

func (c *EphemeralInstanceController) expiryLoop() {
	for {
		c.mu.Lock()
		now := c.now()
		deadline := c.softExpiresAt
		if c.opts.HardExpiresAt.Before(deadline) {
			deadline = c.opts.HardExpiresAt
		}
		if c.released || c.terminalReason != "" {
			c.mu.Unlock()
			return
		}
		if !now.Before(deadline) {
			if !now.Before(c.opts.HardExpiresAt) {
				c.terminalReason = "hard-expiry"
			} else {
				c.terminalReason = "soft-lease-expired"
			}
			stop := c.opts.Stop
			c.mu.Unlock()
			stop()
			return
		}
		wait := deadline.Sub(now)
		c.mu.Unlock()
		timer := c.opts.NewTimer(wait)
		select {
		case <-timer.C():
		case <-c.wake:
			timer.Stop()
		}
	}
}

func (c *EphemeralInstanceController) Released() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.released
}
