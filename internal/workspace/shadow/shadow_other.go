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

var ErrInactive = errors.New("shadow workspace is not active")

type Options struct {
	BaseDir        string
	DiffExcludes   []string
	AcceptExcludes []string
	AcceptChown    bool
}

type Workspace struct {
	ID        string
	Real      string
	Work      string
	Home      string
	Tmp       string
	OwnerUID  int
	OwnerGID  int
	CreatedAt time.Time
	State     string
}

func Create(ctx context.Context, id string, real string, opts Options) (*Workspace, error) {
	return nil, fmt.Errorf("shadow workspaces are only supported on Linux")
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) { return nil, fmt.Errorf("unsupported") }
func (w *Workspace) Accept(ctx context.Context) error         { return fmt.Errorf("unsupported") }
func (w *Workspace) Reject(ctx context.Context) error         { return fmt.Errorf("unsupported") }
func (w *Workspace) Close(ctx context.Context) error          { return nil }
