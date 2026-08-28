//go:build !linux

package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	SchemaVersion            = 1
	MediaTypeGitBundle       = "application/vnd.git.bundle"
	KindGitInputBundle  Kind = "git-input-bundle"
	KindGitResultBundle Kind = "git-result-bundle"
)

var (
	ErrInvalid     = errors.New("invalid runtime artifact")
	ErrNotFound    = errors.New("runtime artifact not found")
	ErrTooLarge    = errors.New("runtime artifact exceeds its size limit")
	ErrCorrupt     = errors.New("runtime artifact integrity check failed")
	ErrUnsupported = errors.New("runtime artifacts are supported only on Linux")
)

type Kind string

type Descriptor struct {
	SchemaVersion int       `json:"schema_version"`
	ArtifactID    string    `json:"artifact_id"`
	SessionID     string    `json:"session_id"`
	Kind          Kind      `json:"kind"`
	MediaType     string    `json:"media_type"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	Complete      bool      `json:"complete"`
	CreatedAt     time.Time `json:"created_at"`
}

func (d Descriptor) Validate() error {
	if d.SchemaVersion != SchemaVersion || !d.Complete || d.ArtifactID == "" || d.SessionID == "" ||
		(d.Kind != KindGitInputBundle && d.Kind != KindGitResultBundle) || d.MediaType != MediaTypeGitBundle || d.Size < 0 || d.CreatedAt.IsZero() {
		return fmt.Errorf("%w: descriptor is incomplete or unsupported", ErrInvalid)
	}
	return nil
}

type Store struct{}

func NewStore(string, string, int64) (*Store, error) { return nil, ErrUnsupported }
func (*Store) Put(context.Context, Kind, io.Reader) (Descriptor, error) {
	return Descriptor{}, ErrUnsupported
}
func (*Store) Open(context.Context, string, Kind) (*os.File, Descriptor, error) {
	return nil, Descriptor{}, ErrUnsupported
}
func (*Store) List() ([]Descriptor, error) { return nil, ErrUnsupported }
func (*Store) Delete(string, Kind) error   { return ErrUnsupported }
