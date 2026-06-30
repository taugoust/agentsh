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
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	SessionID string                 `json:"session_id"`
	CreatedAt string                 `json:"created_at"`
	Source    string                 `json:"source,omitempty"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	CWD       string                 `json:"cwd,omitempty"`
	Fields    map[string]any         `json:"fields,omitempty"`
	Acked     bool                   `json:"acked"`
	AckedAt   string                 `json:"acked_at,omitempty"`
	Answer    *sessionQuestionAnswer `json:"answer,omitempty"`
}

type sessionQuestionAnswer struct {
	QuestionnaireID string           `json:"questionnaire_id"`
	EventID         string           `json:"event_id"`
	SessionID       string           `json:"session_id"`
	AnsweredAt      string           `json:"answered_at"`
	Cancelled       bool             `json:"cancelled"`
	Answers         []map[string]any `json:"answers,omitempty"`
}

type sessionEventStore struct {
	mu                     sync.Mutex
	events                 map[string]sessionEvent
	answersByQuestionnaire map[string]sessionQuestionAnswer
	pendingByQuestionnaire map[string]string
	order                  []string
	max                    int
}

func newSessionEventStore() *sessionEventStore {
	return &sessionEventStore{
		events:                 make(map[string]sessionEvent),
		answersByQuestionnaire: make(map[string]sessionQuestionAnswer),
		pendingByQuestionnaire: make(map[string]string),
		max:                    500,
	}
}

func eventQuestionnaireID(ev sessionEvent) string {
	if ev.Fields == nil {
		return ""
	}
	if value, ok := ev.Fields["questionnaire_id"].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
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
	if qid := eventQuestionnaireID(ev); qid != "" {
		key := ev.SessionID + "\x00" + qid
		switch ev.Type {
		case "agent.question.pending":
			s.pendingByQuestionnaire[key] = ev.ID
		case "agent.question.answered":
			if pendingID := s.pendingByQuestionnaire[key]; pendingID != "" {
				if pending, ok := s.events[pendingID]; ok && !pending.Acked {
					pending.Acked = true
					pending.AckedAt = time.Now().UTC().Format(time.RFC3339Nano)
					s.events[pendingID] = pending
				}
			}
		}
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

func (s *sessionEventStore) Answer(eventID string, answer sessionQuestionAnswer) (sessionQuestionAnswer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.events[eventID]
	if !ok {
		return sessionQuestionAnswer{}, false
	}
	qid := strings.TrimSpace(answer.QuestionnaireID)
	if qid == "" {
		if value, ok := ev.Fields["questionnaire_id"].(string); ok {
			qid = strings.TrimSpace(value)
		}
	}
	if qid == "" {
		return sessionQuestionAnswer{}, false
	}
	answer.QuestionnaireID = qid
	answer.EventID = eventID
	answer.SessionID = ev.SessionID
	answer.AnsweredAt = time.Now().UTC().Format(time.RFC3339Nano)
	ev.Answer = &answer
	ev.Acked = true
	ev.AckedAt = answer.AnsweredAt
	s.events[eventID] = ev
	s.answersByQuestionnaire[ev.SessionID+"\x00"+qid] = answer
	return answer, true
}

func (s *sessionEventStore) GetAnswer(sessionID, questionnaireID string) (sessionQuestionAnswer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	answer, ok := s.answersByQuestionnaire[strings.TrimSpace(sessionID)+"\x00"+strings.TrimSpace(questionnaireID)]
	return answer, ok
}

func (a *App) publishSessionEvent(ev sessionEvent) sessionEvent {
	if a.sessionEvents == nil {
		a.sessionEvents = newSessionEventStore()
	}
	return a.sessionEvents.Publish(ev)
}

func (a *App) publishSessionEventForSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id"})
		return
	}
	if _, ok := a.sessions.Get(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	var ev sessionEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid event"})
		return
	}
	ev.SessionID = id
	if strings.TrimSpace(ev.Type) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing event type"})
		return
	}
	if strings.TrimSpace(ev.Title) == "" {
		ev.Title = ev.Type
	}
	published := a.publishSessionEvent(ev)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "event": published})
}

func (a *App) getSessionQuestionAnswerForSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	qid := strings.TrimSpace(chi.URLParam(r, "qid"))
	if id == "" || qid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing session id or questionnaire id"})
		return
	}
	if _, ok := a.sessions.Get(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	if a.sessionEvents == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	answer, ok := a.sessionEvents.GetAnswer(id, qid)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "answer": answer})
}

func (a *App) listSessionEvents(w http.ResponseWriter, r *http.Request) {
	out := make([]any, 0)
	if a.sessionEvents != nil {
		for _, ev := range a.sessionEvents.ListPending() {
			out = append(out, ev)
		}
	}
	out = append(out, a.listDetachedSessionEvents(r.Context())...)
	writeJSON(w, http.StatusOK, out)
}

func (a *App) ackSessionEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing event id"})
		return
	}
	if a.sessionEvents != nil && a.sessionEvents.Ack(id) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if a.forwardDetachedRaw(r.Context(), escapedAPIPath("session-events", id, "ack"), []byte(`{}`)) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "session event not found"})
}

func (a *App) answerSessionEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing event id"})
		return
	}
	raw, err := readRawJSONBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid answer"})
		return
	}
	if a.sessionEvents != nil {
		var answer sessionQuestionAnswer
		if err := decodeRawJSON(raw, &answer); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid answer"})
			return
		}
		if stored, ok := a.sessionEvents.Answer(id, answer); ok {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "answer": stored})
			return
		}
	}
	if a.forwardDetachedRaw(r.Context(), escapedAPIPath("session-events", id, "answer"), raw) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "question event not found"})
}

func decodeSessionEvent(raw json.RawMessage) (sessionEvent, error) {
	var ev sessionEvent
	if len(raw) == 0 {
		return ev, nil
	}
	err := json.Unmarshal(raw, &ev)
	return ev, err
}
