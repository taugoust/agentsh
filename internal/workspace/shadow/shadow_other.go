//go:build !linux

package shadow

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	StateActive   = "active"
	StateAccepted = "accepted"
	StateRejected = "rejected"
	StateClosed   = "closed"
)

var (
	ErrInactive    = errors.New("shadow workspace is not active")
	ErrStaleReview = errors.New("shadow workspace review is stale")
)

type Review struct {
	SchemaVersion int       `json:"schema_version"`
	Generation    uint64    `json:"generation"`
	Hash          string    `json:"hash"`
	BaseHash      string    `json:"base_hash"`
	ShadowHash    string    `json:"shadow_hash"`
	DiffHash      string    `json:"diff_hash"`
	CreatedAt     time.Time `json:"created_at"`
	Diff          []byte    `json:"-"`
}

const (
	FinalizationAccept   = "accept"
	FinalizationReject   = "reject"
	FinalizationPrepared = "prepared"
	FinalizationApplying = "applying"
	FinalizationApplied  = "applied"
)

type Finalization struct {
	SchemaVersion    int       `json:"schema_version"`
	ID               string    `json:"finalization_id"`
	Action           string    `json:"action"`
	Phase            string    `json:"phase"`
	ReviewGeneration uint64    `json:"review_generation,omitempty"`
	ReviewHash       string    `json:"review_hash,omitempty"`
	BaseHash         string    `json:"base_hash,omitempty"`
	ShadowHash       string    `json:"shadow_hash,omitempty"`
	DiffHash         string    `json:"diff_hash,omitempty"`
	SnapshotDir      string    `json:"snapshot_dir,omitempty"`
	AcceptExcludes   []string  `json:"accept_excludes,omitempty"`
	AcceptChown      bool      `json:"accept_chown,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	AppliedAt        time.Time `json:"applied_at,omitempty"`
}

type Options struct {
	BaseDir        string
	DiffExcludes   []string
	AcceptExcludes []string
	AcceptChown    bool
}

type RootSpec struct {
	Name string
	Path string
}

type Root struct {
	Name string
	Real string
	Work string
}

type Workspace struct {
	ID        string
	Real      string
	Work      string
	Home      string
	Tmp       string
	Roots     []Root
	OwnerUID  int
	OwnerGID  int
	CreatedAt time.Time
	State     string
}

func Create(ctx context.Context, id string, real string, opts Options) (*Workspace, error) {
	return nil, fmt.Errorf("shadow workspaces are only supported on Linux")
}

func CreateMulti(ctx context.Context, id string, specs []RootSpec, opts Options) (*Workspace, error) {
	return nil, fmt.Errorf("shadow workspaces are only supported on Linux")
}

func OpenMulti(ctx context.Context, id string, specs []RootSpec, opts Options, expected []Root, createdAt time.Time) (*Workspace, error) {
	return nil, fmt.Errorf("shadow workspaces are only supported on Linux")
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) { return nil, fmt.Errorf("unsupported") }
func (w *Workspace) Review(ctx context.Context) (Review, error) {
	return Review{}, fmt.Errorf("unsupported")
}
func (w *Workspace) Accept(ctx context.Context) error { return fmt.Errorf("unsupported") }
func (w *Workspace) ValidateReview(ctx context.Context, generation uint64, hash string) error {
	return fmt.Errorf("unsupported")
}
func (w *Workspace) AcceptReviewed(ctx context.Context, generation uint64, hash string) error {
	return fmt.Errorf("unsupported")
}
func (w *Workspace) PrepareAccept(ctx context.Context, finalizationID string, generation uint64, hash string) (Finalization, error) {
	return Finalization{}, fmt.Errorf("unsupported")
}
func (w *Workspace) PrepareReject(ctx context.Context, finalizationID string) (Finalization, error) {
	return Finalization{}, fmt.Errorf("unsupported")
}
func (w *Workspace) PendingFinalization() (Finalization, bool) { return Finalization{}, false }
func (w *Workspace) ApplyFinalization(ctx context.Context, finalizationID string) error {
	return fmt.Errorf("unsupported")
}
func (w *Workspace) ResumeFinalization(ctx context.Context, finalizationID string) error {
	return fmt.Errorf("unsupported")
}
func (w *Workspace) Reject(ctx context.Context) error { return fmt.Errorf("unsupported") }
func (w *Workspace) CleanupFinalized() error          { return fmt.Errorf("unsupported") }
func (w *Workspace) StateValue() string               { return w.State }
func (w *Workspace) Close(ctx context.Context) error  { return nil }
