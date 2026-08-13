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
func (w *Workspace) Reject(ctx context.Context) error { return fmt.Errorf("unsupported") }
func (w *Workspace) CleanupFinalized() error          { return fmt.Errorf("unsupported") }
func (w *Workspace) StateValue() string               { return w.State }
func (w *Workspace) Close(ctx context.Context) error  { return nil }
