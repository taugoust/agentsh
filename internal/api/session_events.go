package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

type sessionEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	SessionID string         `json:"session_id"`
	CreatedAt string         `json:"created_at"`
	Source    string         `json:"source,omitempty"`
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	CWD       string         `json:"cwd,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	Acked     bool           `json:"acked"`
	AckedAt   string         `json:"acked_at,omitempty"`
}

type sessionEventStore struct {
	mu     sync.Mutex
	events map[string]sessionEvent
	order  []string
	max    int
}

func newSessionEventStore() *sessionEventStore {
	return &sessionEventStore{events: make(map[string]sessionEvent), max: 500}
}

func (s *sessionEventStore) Publish(ev sessionEvent) sessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(ev.ID) == "" {
		ev.ID = "event-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	if strings.TrimSpace(ev.CreatedAt) == "" {
		ev.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if strings.TrimSpace(ev.Source) == "" {
		ev.Source = "agent"
	}
	ev.Acked = false
	ev.AckedAt = ""
	if _, exists := s.events[ev.ID]; !exists {
		s.order = append(s.order, ev.ID)
	}
	s.events[ev.ID] = ev
	for len(s.order) > s.max {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.events, old)
	}
	return ev
}

func (s *sessionEventStore) ListPending() []sessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sessionEvent, 0, len(s.events))
	for _, id := range s.order {
		ev, ok := s.events[id]
		if ok && !ev.Acked {
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

func (s *sessionEventStore) Ack(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.events[id]
	if !ok || ev.Acked {
		return false
	}
	ev.Acked = true
	ev.AckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.events[id] = ev
	return true
}

func (a *App) publishSessionEvent(ev sessionEvent) sessionEvent {
	if a.sessionEvents == nil {
		a.sessionEvents = newSessionEventStore()
	}
	return a.sessionEvents.Publish(ev)
}

func (a *App) listSessionEvents(w http.ResponseWriter, r *http.Request) {
	if a.sessionEvents == nil {
		writeJSON(w, http.StatusOK, []sessionEvent{})
		return
	}
	writeJSON(w, http.StatusOK, a.sessionEvents.ListPending())
}

func (a *App) ackSessionEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing event id"})
		return
	}
	if a.sessionEvents == nil || !a.sessionEvents.Ack(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session event not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func decodeSessionEvent(raw json.RawMessage) (sessionEvent, error) {
	var ev sessionEvent
	if len(raw) == 0 {
		return ev, nil
	}
	err := json.Unmarshal(raw, &ev)
	return ev, err
}
