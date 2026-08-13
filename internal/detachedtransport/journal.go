package detachedtransport

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/approvals"
)

// Journal is a bounded, idempotent replay buffer. Records are retained until
// the peer acknowledges their contiguous sequence prefix.
type Journal struct {
	mu      sync.Mutex
	records map[Identity]map[uint64]Record
	byID    map[Identity]map[string]uint64
	max     int
	last    map[Identity]uint64
}

func NewJournal(max int) *Journal {
	if max <= 0 {
		max = 4096
	}
	return &Journal{
		records: make(map[Identity]map[uint64]Record),
		byID:    make(map[Identity]map[string]uint64),
		max:     max,
		last:    make(map[Identity]uint64),
	}
}

func recordIDKey(record Record) string {
	return string(record.Kind) + "\x00" + record.ID
}

// Put returns true when the record was newly inserted. Exact replay is
// idempotent; reuse of an identity with a different digest fails closed.
func (j *Journal) Put(identity Identity, record Record) (bool, error) {
	if j == nil {
		return false, fmt.Errorf("detached transport journal is nil")
	}
	if err := identity.Validate(); err != nil {
		return false, err
	}
	if err := record.Validate(); err != nil {
		return false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.putLocked(identity, record)
}

func (j *Journal) putLocked(identity Identity, record Record) (bool, error) {
	idKey := recordIDKey(record)
	if sequence, ok := j.byID[identity][idKey]; ok {
		existing := j.records[identity][sequence]
		if existing.Digest != record.Digest {
			return false, fmt.Errorf("conflicting detached transport replay for %s", record.ID)
		}
		return false, nil
	}
	if record.Sequence != j.last[identity]+1 {
		return false, fmt.Errorf("detached transport sequence is not contiguous")
	}
	if j.recordCountLocked() >= j.max {
		return false, fmt.Errorf("detached transport journal is full")
	}
	cloned, err := cloneRecord(record)
	if err != nil {
		return false, err
	}
	if j.records[identity] == nil {
		j.records[identity] = make(map[uint64]Record)
	}
	if j.byID[identity] == nil {
		j.byID[identity] = make(map[string]uint64)
	}
	j.records[identity][record.Sequence] = cloned
	j.byID[identity][idKey] = record.Sequence
	j.last[identity] = record.Sequence
	return true, nil
}

func (j *Journal) appendLocked(identity Identity, idKey string, makeRecord func(uint64) (Record, error)) (Record, error) {
	if sequence, ok := j.byID[identity][idKey]; ok {
		return cloneRecord(j.records[identity][sequence])
	}
	if j.recordCountLocked() >= j.max {
		return Record{}, fmt.Errorf("detached transport journal is full")
	}
	record, err := makeRecord(j.last[identity] + 1)
	if err != nil {
		return Record{}, err
	}
	if _, err := j.putLocked(identity, record); err != nil {
		return Record{}, err
	}
	return cloneRecord(record)
}

func (j *Journal) AppendApproval(identity Identity, request approvals.Request) (Record, error) {
	if j == nil {
		return Record{}, fmt.Errorf("detached transport journal is nil")
	}
	if err := identity.Validate(); err != nil {
		return Record{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.appendLocked(identity, string(KindApprovalRequested)+"\x00"+request.ID, func(sequence uint64) (Record, error) {
		return NewApprovalRequest(sequence, request)
	})
}

func (j *Journal) AppendResolution(identity Identity, approvalID string, resolution approvals.Resolution) (Record, error) {
	if j == nil {
		return Record{}, fmt.Errorf("detached transport journal is nil")
	}
	if err := identity.Validate(); err != nil {
		return Record{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.appendLocked(identity, string(KindApprovalResolved)+"\x00"+approvalID, func(sequence uint64) (Record, error) {
		return NewApprovalResolution(sequence, approvalID, resolution)
	})
}

func (j *Journal) HighWater(identity Identity) uint64 {
	if j == nil {
		return 0
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.last[identity]
}

func (j *Journal) NextSequence(identity Identity) uint64 {
	return j.HighWater(identity) + 1
}

func (j *Journal) Since(identity Identity, cursor uint64, limit int, kind Kind) []Record {
	if j == nil {
		return nil
	}
	if limit <= 0 || limit > 256 {
		limit = 256
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Record, 0, limit)
	for sequence := cursor + 1; sequence <= j.last[identity]; sequence++ {
		record, ok := j.records[identity][sequence]
		if !ok {
			continue
		}
		if kind != "" && record.Kind != kind {
			continue
		}
		cloned, err := cloneRecord(record)
		if err != nil {
			continue
		}
		out = append(out, cloned)
		if len(out) == limit {
			break
		}
	}
	return out
}

// Acknowledge removes the acknowledged contiguous prefix while preserving the
// high-water mark so future records never reuse a sequence.
func (j *Journal) Acknowledge(identity Identity, cursor uint64) error {
	if j == nil {
		return fmt.Errorf("detached transport journal is nil")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if cursor > j.last[identity] {
		return fmt.Errorf("detached transport acknowledgment exceeds journal high-water")
	}
	for sequence, record := range j.records[identity] {
		if sequence > cursor {
			continue
		}
		delete(j.records[identity], sequence)
		delete(j.byID[identity], recordIDKey(record))
	}
	if len(j.records[identity]) == 0 {
		delete(j.records, identity)
		delete(j.byID, identity)
	}
	return nil
}

func (j *Journal) recordCountLocked() int {
	count := 0
	for _, records := range j.records {
		count += len(records)
	}
	return count
}

func cloneRecord(record Record) (Record, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	var clone Record
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return Record{}, err
	}
	return clone, nil
}
