//go:build !linux

package overlay

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

var ErrInactive = errors.New("overlay workspace is not active")

type Options struct {
	BaseDir     string
	Excludes    []string
	AcceptChown bool
}

type Workspace struct {
	ID        string
	Real      string
	Upper     string
	Work      string
	Merged    string
	OwnerUID  int
	OwnerGID  int
	Excludes  []string
	CreatedAt time.Time
	State     string
}

func Create(ctx context.Context, id string, real string, opts Options) (*Workspace, error) {
	return nil, fmt.Errorf("overlay workspaces are only supported on Linux")
}

func (w *Workspace) Diff(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("overlay workspaces are only supported on Linux")
}

func (w *Workspace) Accept(ctx context.Context) error {
	return fmt.Errorf("overlay workspaces are only supported on Linux")
}

func (w *Workspace) Reject(ctx context.Context) error {
	return fmt.Errorf("overlay workspaces are only supported on Linux")
}

func (w *Workspace) Close(ctx context.Context) error {
	return fmt.Errorf("overlay workspaces are only supported on Linux")
}
