package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// ErrEventBufferFull reports best-effort loss of a non-critical bulk audit
// event. Callers may aggregate this signal instead of logging every dropped
// filesystem operation.
var ErrEventBufferFull = errors.New("event buffer full")

func lockMutexContext(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for !mu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	return nil
}

type EventStore interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error)
	Close() error
}

// RawWriter can write pre-serialized bytes as a single JSONL line.
type RawWriter interface {
	WriteRaw(ctx context.Context, data []byte) error
}

// Syncer can flush buffered writes to durable storage.
type Syncer interface {
	Sync() error
}

type OutputStore interface {
	SaveOutput(ctx context.Context, sessionID, commandID string, stdout, stderr []byte, stdoutTotal, stderrTotal int64, stdoutTrunc, stderrTrunc bool) error
	ReadOutputChunk(ctx context.Context, commandID string, stream string, offset, limit int64) (chunk []byte, total int64, truncated bool, err error)
}
