// Package detachedtransport defines the versioned, transport-neutral exchange
// used to mirror detached approvals and deliver operator resolutions. Native
// deployments carry it over an authenticated Unix socket; VM providers can
// implement the same contract over an authenticated host/guest channel.
package detachedtransport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

const (
	Version            = 2
	ControlTokenHeader = "X-AgentSH-Detached-Control-Token"
)

type Kind string

const (
	KindApprovalRequested Kind = "approval.requested"
	KindApprovalResolved  Kind = "approval.resolved"
)

type Identity struct {
	SessionID     string `json:"session_id"`
	Generation    uint64 `json:"generation"`
	IncarnationID string `json:"incarnation_id"`
}

func (i Identity) Validate() error {
	if strings.TrimSpace(i.SessionID) == "" || i.Generation == 0 || strings.TrimSpace(i.IncarnationID) == "" ||
		strings.ContainsAny(i.SessionID+i.IncarnationID, "\x00\r\n") {
		return fmt.Errorf("detached transport identity is incomplete")
	}
	return nil
}

type Record struct {
	Version    int                   `json:"version"`
	ID         string                `json:"id"`
	Kind       Kind                  `json:"kind"`
	Sequence   uint64                `json:"sequence"`
	CreatedAt  time.Time             `json:"created_at"`
	ExpiresAt  time.Time             `json:"expires_at,omitempty"`
	Digest     string                `json:"digest"`
	Approval   *approvals.Request    `json:"approval,omitempty"`
	Resolution *approvals.Resolution `json:"resolution,omitempty"`
}

func NewApprovalRequest(sequence uint64, request approvals.Request) (Record, error) {
	record := Record{Version: Version, ID: request.ID, Kind: KindApprovalRequested, Sequence: sequence, CreatedAt: request.CreatedAt, ExpiresAt: request.ExpiresAt, Approval: &request}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := record.seal(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func NewApprovalResolution(sequence uint64, approvalID string, resolution approvals.Resolution) (Record, error) {
	record := Record{Version: Version, ID: approvalID, Kind: KindApprovalResolved, Sequence: sequence, CreatedAt: resolution.At, Resolution: &resolution}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if err := record.seal(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r *Record) seal() error {
	r.Digest = ""
	if err := r.ValidatePayload(); err != nil {
		return err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	r.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

func (r Record) ValidatePayload() error {
	if r.Version != Version || strings.TrimSpace(r.ID) == "" || r.Sequence == 0 || r.CreatedAt.IsZero() || strings.ContainsAny(r.ID, "\x00\r\n") {
		return fmt.Errorf("detached transport record header is invalid")
	}
	switch r.Kind {
	case KindApprovalRequested:
		if r.Approval == nil || r.Resolution != nil || r.Approval.ID != r.ID || strings.TrimSpace(r.Approval.SessionID) == "" {
			return fmt.Errorf("detached approval request record is invalid")
		}
	case KindApprovalResolved:
		if r.Resolution == nil || r.Approval != nil {
			return fmt.Errorf("detached approval resolution record is invalid")
		}
	default:
		return fmt.Errorf("unsupported detached transport record kind %q", r.Kind)
	}
	return nil
}

func (r Record) Validate() error {
	if !strings.HasPrefix(r.Digest, "sha256:") {
		return fmt.Errorf("detached transport record digest is missing")
	}
	got := r.Digest
	copy := r
	copy.Digest = ""
	if err := copy.ValidatePayload(); err != nil {
		return err
	}
	encoded, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	if got != "sha256:"+hex.EncodeToString(sum[:]) {
		return fmt.Errorf("detached transport record digest mismatch")
	}
	return nil
}

type ExchangeRequest struct {
	Version  int      `json:"version"`
	Identity Identity `json:"identity"`
	// The credential is carried inside the typed schema as well as the protected
	// transport header so non-HTTP host/guest adapters can enforce the same
	// authentication contract.
	Credential string `json:"credential"`
	// Cursor acknowledges the highest supervisor-origin record consumed by the
	// parent. Records use an independent parent-origin sequence space.
	Cursor  uint64   `json:"cursor"`
	Limit   int      `json:"limit"`
	Records []Record `json:"records"`
	// AckFloor is the parent's retained cumulative acknowledgment. A restarted
	// supervisor may restore an empty inbox to this exact high-water mark.
	AckFloor uint64 `json:"ack_floor,omitempty"`
}

type ExchangeResponse struct {
	Version  int      `json:"version"`
	Identity Identity `json:"identity"`
	// Ack is the highest parent-origin resolution durably accepted by the
	// supervisor. Cursor is the highest supervisor-origin record returned.
	Ack     uint64   `json:"ack"`
	Cursor  uint64   `json:"cursor"`
	Records []Record `json:"records"`
	// Pending is the authoritative exact-incarnation snapshot. It lets a
	// restarted parent reconstruct unresolved approvals after journal compaction.
	Pending []approvals.Request `json:"pending"`
}

func (r ExchangeRequest) Validate() error {
	if r.Version != Version || strings.TrimSpace(r.Credential) == "" || strings.ContainsAny(r.Credential, "\r\n") || r.Limit < 0 || r.Limit > 256 || len(r.Records) > 256 {
		return fmt.Errorf("detached transport exchange request is invalid")
	}
	if err := r.Identity.Validate(); err != nil {
		return err
	}
	prior := r.AckFloor
	for _, record := range r.Records {
		if err := record.Validate(); err != nil {
			return err
		}
		if record.Kind != KindApprovalResolved || record.Resolution == nil {
			return fmt.Errorf("parent may send only detached approval resolutions")
		}
		if record.Sequence <= prior {
			return fmt.Errorf("detached transport records are not strictly ordered")
		}
		prior = record.Sequence
	}
	return nil
}

func (r ExchangeResponse) Validate(expected Identity, acknowledged, sentMax, requestedCursor uint64, sentRecords bool) error {
	if r.Version != Version || r.Identity != expected || r.Ack < acknowledged || (sentRecords && r.Ack > sentMax) || r.Cursor < requestedCursor || len(r.Records) > 256 || len(r.Pending) > 256 {
		return fmt.Errorf("detached transport exchange response is invalid")
	}
	prior := requestedCursor
	for _, record := range r.Records {
		if err := record.Validate(); err != nil {
			return err
		}
		if record.Approval != nil && record.Approval.SessionID != expected.SessionID {
			return fmt.Errorf("detached transport record session identity mismatch")
		}
		if record.Sequence <= prior {
			return fmt.Errorf("detached transport response records are not strictly ordered")
		}
		prior = record.Sequence
	}
	for _, request := range r.Pending {
		if strings.TrimSpace(request.ID) == "" || request.SessionID != expected.SessionID {
			return fmt.Errorf("detached transport pending snapshot identity mismatch")
		}
	}
	if len(r.Records) == 0 {
		if r.Cursor != requestedCursor {
			return fmt.Errorf("detached transport empty response advanced its cursor")
		}
	} else if r.Cursor != prior {
		return fmt.Errorf("detached transport response cursor does not match its records")
	}
	return nil
}
