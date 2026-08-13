package detachedtransport

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/approvals"
)

// Journal is a bounded, idempotent replay buffer. A production remote adapter
// can place the same interface over durable storage; the native parent mirror
// uses it to avoid ID-only collisions and conflicting duplicate replacement.
type Journal struct {
	mu      sync.Mutex
	records map[string]Record
	order   []string
	max     int
	last    map[Identity]uint64
}

func NewJournal(max int) *Journal {
	if max <= 0 {
		max = 4096
	}
	return &Journal{records: make(map[string]Record), max: max, last: make(map[Identity]uint64)}
}

func journalKey(identity Identity, record Record) string {
	return fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s", identity.SessionID, identity.Generation, identity.IncarnationID, record.Kind, record.ID)
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
	key := journalKey(identity, record)
	j.mu.Lock()
	defer j.mu.Unlock()
	if existing, ok := j.records[key]; ok {
		if existing.Digest != record.Digest {
			return false, fmt.Errorf("conflicting detached transport replay for %s", record.ID)
		}
		return false, nil
	}
	if record.Sequence <= j.last[identity] {
		return false, fmt.Errorf("detached transport sequence is not monotonic")
	}
	if len(j.records) >= j.max {
		return false, fmt.Errorf("detached transport journal is full")
	}
	cloned, err := cloneRecord(record)
	if err != nil {
		return false, err
	}
	j.records[key] = cloned
	j.order = append(j.order, key)
	j.last[identity] = record.Sequence
	return true, nil
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
	record, err := NewApprovalRequest(j.last[identity]+1, request)
	if err != nil {
		return Record{}, err
	}
	key := journalKey(identity, record)
	if existing, ok := j.records[key]; ok {
		if existing.Digest != record.Digest {
			return Record{}, fmt.Errorf("conflicting detached transport replay for %s", record.ID)
		}
		return cloneRecord(existing)
	}
	if len(j.records) >= j.max {
		return Record{}, fmt.Errorf("detached transport journal is full")
	}
	cloned, err := cloneRecord(record)
	if err != nil {
		return Record{}, err
	}
	j.records[key] = cloned
	j.order = append(j.order, key)
	j.last[identity] = record.Sequence
	return cloneRecord(record)
}

func (j *Journal) NextSequence(identity Identity) uint64 {
	if j == nil {
		return 0
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.last[identity] + 1
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
	for _, key := range j.order {
		record := j.records[key]
		if record.Sequence <= cursor || (kind != "" && record.Kind != kind) || key != journalKey(identity, record) {
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
