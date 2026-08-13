package detachedtransport

import (
	"fmt"
	"sync"
)

type ResolveResult uint8

const (
	ResolveApplied ResolveResult = iota + 1
	ResolveAlreadyTerminal
	ResolveRejected
)

type ResolveRecord func(Record) ResolveResult

// ResolutionInbox provides exactly-once application and replay-safe
// acknowledgment for one parent-to-supervisor stream per exact incarnation.
type ResolutionInbox struct {
	mu       sync.Mutex
	max      int
	ack      map[Identity]uint64
	receipts map[Identity]map[uint64]Record
}

func NewResolutionInbox(max int) *ResolutionInbox {
	if max <= 0 {
		max = 4096
	}
	return &ResolutionInbox{max: max, ack: make(map[Identity]uint64), receipts: make(map[Identity]map[uint64]Record)}
}

func (i *ResolutionInbox) Apply(identity Identity, records []Record, resolve ResolveRecord) (uint64, error) {
	if i == nil || resolve == nil {
		return 0, fmt.Errorf("detached resolution inbox is unavailable")
	}
	if err := identity.Validate(); err != nil {
		return 0, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	ack := i.ack[identity]
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return ack, err
		}
		if record.Kind != KindApprovalResolved || record.Resolution == nil {
			return ack, fmt.Errorf("detached resolution inbox accepts only approval resolutions")
		}
		if record.Sequence <= ack {
			existing, ok := i.receipts[identity][record.Sequence]
			if !ok || existing.ID != record.ID || existing.Digest != record.Digest {
				return ack, fmt.Errorf("conflicting detached resolution replay at sequence %d", record.Sequence)
			}
			continue
		}
		if record.Sequence != ack+1 {
			return ack, fmt.Errorf("detached resolution sequence gap: got %d after %d", record.Sequence, ack)
		}
		if i.receiptCountLocked() >= i.max {
			// ACK is cumulative and every earlier sequence is already terminal;
			// retain only the most recent receipt needed to authenticate replay.
			delete(i.receipts, identity)
		}
		result := resolve(record)
		if result == ResolveRejected {
			return ack, fmt.Errorf("approval %s resolution was rejected by exact detached incarnation", record.ID)
		}
		cloned, err := cloneRecord(record)
		if err != nil {
			return ack, err
		}
		if i.receipts[identity] == nil {
			i.receipts[identity] = make(map[uint64]Record)
		}
		i.receipts[identity][record.Sequence] = cloned
		ack = record.Sequence
		i.ack[identity] = ack
	}
	return ack, nil
}

// RestoreAck advances an empty incarnation inbox to a parent-retained
// high-water mark after supervisor restart. It is accepted only before this
// process has applied records, preserving conflict checks for live receipts.
func (i *ResolutionInbox) RestoreAck(identity Identity, ack uint64) error {
	if i == nil {
		return fmt.Errorf("detached resolution inbox is unavailable")
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.ack[identity] != 0 || len(i.receipts[identity]) != 0 {
		if i.ack[identity] == ack {
			return nil
		}
		return fmt.Errorf("detached resolution acknowledgment conflicts with live inbox")
	}
	i.ack[identity] = ack
	return nil
}

func (i *ResolutionInbox) Ack(identity Identity) uint64 {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.ack[identity]
}

func (i *ResolutionInbox) receiptCountLocked() int {
	count := 0
	for _, records := range i.receipts {
		count += len(records)
	}
	return count
}
