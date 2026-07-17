package nethelper

import (
	"context"
	"fmt"
	"sync"
)

// OperationGate serializes helper registration lifecycle operations with
// instance shutdown. Once stopping begins no new register/update/cleanup
// operation is admitted; shutdown waits for every admitted operation to finish.
type OperationGate struct {
	mu       sync.Mutex
	stopping bool
	inFlight int
	changed  chan struct{}
}

func NewOperationGate() *OperationGate { return &OperationGate{changed: make(chan struct{})} }

func (g *OperationGate) signalLocked() {
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *OperationGate) Admit() (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopping {
		return nil, fmt.Errorf("helper instance is stopping; lifecycle operation refused")
	}
	g.inFlight++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.inFlight--
			g.signalLocked()
			g.mu.Unlock()
		})
	}, nil
}

// StopAndWait atomically closes admission and waits for admitted operations.
// The returned rollback must be called when shutdown cannot proceed (for
// example, registrations remain), so cleanup can subsequently be admitted.
func (g *OperationGate) StopAndWait(ctx context.Context) (rollback func(), err error) {
	if g == nil {
		return func() {}, nil
	}
	g.mu.Lock()
	if g.stopping {
		g.mu.Unlock()
		return nil, fmt.Errorf("helper instance release is already in progress")
	}
	g.stopping = true
	g.signalLocked()
	for g.inFlight != 0 {
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			g.mu.Lock()
			g.stopping = false
			g.signalLocked()
			g.mu.Unlock()
			return nil, ctx.Err()
		case <-changed:
			g.mu.Lock()
		}
	}
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.stopping = false
			g.signalLocked()
			g.mu.Unlock()
		})
	}, nil
}
