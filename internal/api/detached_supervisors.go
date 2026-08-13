package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/detachedtransport"
)

type detachedSupervisor struct {
	Meta   detached.Metadata `json:"metadata"`
	Socket string            `json:"socket"`
}

func (a *App) detachedSupervisorTimeout() time.Duration {
	if a == nil || a.cfg == nil {
		return 500 * time.Millisecond
	}
	d, err := time.ParseDuration(strings.TrimSpace(a.cfg.Sessions.DetachedSupervisors.RequestTimeout))
	if err != nil || d <= 0 {
		return 500 * time.Millisecond
	}
	return d
}

func (a *App) detachedSupervisorsEnabled() bool {
	return a != nil && a.cfg != nil && a.cfg.Sessions.DetachedSupervisors.IsEnabled()
}

func (a *App) discoverDetachedSupervisors() []detachedSupervisor {
	if !a.detachedSupervisorsEnabled() {
		return nil
	}
	roots := a.cfg.Sessions.DetachedSupervisors.Roots
	if len(roots) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]detachedSupervisor, 0)
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		metas, err := detached.ListMetadataFromRoot(root, detached.DiscoveryOptions{
			RequireSocket: true,
			CheckPID:      true,
			PIDAlive:      detachedSupervisorPIDAlive,
		})
		if err != nil {
			slog.Debug("detached supervisor discovery failed", "root", root, "error", err)
			continue
		}
		for _, meta := range metas {
			if err := detached.ValidateUsable(meta, detachedSupervisorPIDAlive); err != nil {
				continue
			}
			if meta.ProtocolVersion >= 2 && !a.detachedMetadataMatchesLiveRuntime(meta) {
				continue
			}
			key := strings.TrimSpace(meta.SupervisorSock)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, detachedSupervisor{Meta: meta, Socket: key})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Meta.SessionID < out[j].Meta.SessionID
	})
	return out
}

func (a *App) detachedMetadataMatchesLiveRuntime(meta detached.Metadata) bool {
	ctx, cancel := context.WithTimeout(context.Background(), a.detachedSupervisorTimeout())
	defer cancel()
	var status detached.RuntimeStatus
	c := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", a.detachedSupervisorTimeout())
	if err := c.DoRawJSON(ctx, http.MethodGet, "/api/v1/detached/status", nil, &status); err != nil {
		return false
	}
	return status.ProtocolVersion == meta.ProtocolVersion && status.SessionID == meta.SessionID &&
		status.Generation == meta.Generation && status.IncarnationID == meta.IncarnationID &&
		status.OwnerPID == meta.OwnerPID && status.OwnerStartIdentity == meta.OwnerStartIdentity && status.BootID == meta.BootID
}

func (a *App) detachedSupervisorClient(s detachedSupervisor) *client.Client {
	return client.NewWithTimeout("unix://"+s.Socket, "", a.detachedSupervisorTimeout())
}

func (a *App) queryDetachedJSON(ctx context.Context, s detachedSupervisor, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, a.detachedSupervisorTimeout())
	defer cancel()
	return a.detachedSupervisorClient(s).DoRawJSON(ctx, http.MethodGet, path, nil, out)
}

func (a *App) postDetachedRaw(ctx context.Context, s detachedSupervisor, path string, raw []byte) error {
	ctx, cancel := context.WithTimeout(ctx, a.detachedSupervisorTimeout())
	defer cancel()
	return a.detachedSupervisorClient(s).DoRawJSON(ctx, http.MethodPost, path, raw, nil)
}

func isHTTPNotFound(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound
}

func isHTTPBadRequest(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusBadRequest
}

type detachedRelay struct {
	mu         sync.Mutex
	identity   detachedtransport.Identity
	supervisor detachedSupervisor
	cursor     uint64
	ack        uint64
	next       uint64
	pending    map[string]approvals.Request
	outbox     map[uint64]detachedtransport.Record
	decisions  map[string]detachedtransport.Record
}

func (a *App) detachedRelayFor(sup detachedSupervisor) *detachedRelay {
	identity := detachedtransport.Identity{SessionID: sup.Meta.SessionID, Generation: sup.Meta.Generation, IncarnationID: sup.Meta.IncarnationID}
	a.detachedRouteMu.Lock()
	defer a.detachedRouteMu.Unlock()
	if a.detachedRelays == nil {
		a.detachedRelays = make(map[detachedtransport.Identity]*detachedRelay)
	}
	for known := range a.detachedRelays {
		if known.SessionID == identity.SessionID && known != identity {
			delete(a.detachedRelays, known)
		}
	}
	relay := a.detachedRelays[identity]
	if relay == nil {
		relay = &detachedRelay{identity: identity, supervisor: sup, pending: make(map[string]approvals.Request), outbox: make(map[uint64]detachedtransport.Record), decisions: make(map[string]detachedtransport.Record)}
		a.detachedRelays[identity] = relay
	} else {
		relay.supervisor = sup
	}
	return relay
}

func (a *App) exchangeDetachedRelay(ctx context.Context, relay *detachedRelay) error {
	if relay == nil {
		return fmt.Errorf("detached relay is nil")
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	records := make([]detachedtransport.Record, 0, len(relay.outbox))
	for sequence := relay.ack + 1; sequence <= relay.next; sequence++ {
		if record, ok := relay.outbox[sequence]; ok {
			records = append(records, record)
		}
	}
	request := detachedtransport.ExchangeRequest{Version: detachedtransport.Version, Identity: relay.identity, Credential: relay.supervisor.Meta.EventToken, Cursor: relay.cursor, Limit: 256, Records: records}
	response, err := client.ExchangeDetachedControl(ctx, relay.supervisor.Socket, relay.supervisor.Meta.EventToken, request, a.detachedSupervisorTimeout())
	if err != nil {
		return err
	}
	for sequence := relay.ack + 1; sequence <= response.Ack; sequence++ {
		delete(relay.outbox, sequence)
	}
	relay.ack = response.Ack
	for _, record := range response.Records {
		switch record.Kind {
		case detachedtransport.KindApprovalRequested:
			if record.Approval != nil {
				relay.pending[record.ID] = *record.Approval
			}
		case detachedtransport.KindApprovalResolved:
			delete(relay.pending, record.ID)
		}
	}
	relay.cursor = response.Cursor
	return nil
}

func (a *App) listDetachedApprovals(ctx context.Context) []any {
	supervisors := a.discoverDetachedSupervisors()
	out := make([]any, 0)
	for _, sup := range supervisors {
		relay := a.detachedRelayFor(sup)
		if err := a.exchangeDetachedRelay(ctx, relay); err != nil {
			slog.Debug("detached control exchange failed", "session_id", sup.Meta.SessionID, "error", err)
			continue
		}
		relay.mu.Lock()
		for _, request := range relay.pending {
			if request.ExpiresAt.IsZero() || request.ExpiresAt.After(time.Now().UTC()) {
				out = append(out, request)
			}
		}
		relay.mu.Unlock()
	}
	return out
}

func (a *App) resolveDetachedControlApproval(ctx context.Context, id string, raw []byte) (int, map[string]any, bool) {
	resolution, err := decodeApprovalResolution(raw)
	if err != nil {
		return http.StatusBadRequest, map[string]any{"error": err.Error()}, true
	}
	var candidates []*detachedRelay
	a.detachedRouteMu.Lock()
	for _, relay := range a.detachedRelays {
		relay.mu.Lock()
		_, pending := relay.pending[id]
		relay.mu.Unlock()
		if pending {
			candidates = append(candidates, relay)
		}
	}
	a.detachedRouteMu.Unlock()
	if len(candidates) == 0 {
		// Refresh discovery once so resolution does not depend on a prior list.
		_ = a.listDetachedApprovals(ctx)
		a.detachedRouteMu.Lock()
		for _, relay := range a.detachedRelays {
			relay.mu.Lock()
			_, pending := relay.pending[id]
			relay.mu.Unlock()
			if pending {
				candidates = append(candidates, relay)
			}
		}
		a.detachedRouteMu.Unlock()
	}
	if len(candidates) == 0 {
		return 0, nil, false
	}
	if len(candidates) != 1 {
		return http.StatusConflict, map[string]any{"error": "approval id is ambiguous across detached incarnations"}, true
	}
	relay := candidates[0]
	relay.mu.Lock()
	if existing, ok := relay.decisions[id]; ok {
		if existing.Resolution == nil || !sameResolutionDecision(*existing.Resolution, resolution) {
			relay.mu.Unlock()
			return http.StatusConflict, map[string]any{"error": "conflicting detached approval resolution replay"}, true
		}
	} else {
		relay.next++
		record, makeErr := detachedtransport.NewApprovalResolution(relay.next, id, resolution)
		if makeErr != nil {
			relay.next--
			relay.mu.Unlock()
			return http.StatusBadRequest, map[string]any{"error": makeErr.Error()}, true
		}
		relay.decisions[id] = record
		relay.outbox[record.Sequence] = record
	}
	relay.mu.Unlock()
	if err := a.exchangeDetachedRelay(ctx, relay); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"error": "detached approval resolution is retained for replay: " + err.Error()}, true
	}
	return http.StatusOK, map[string]any{"ok": true}, true
}

func (a *App) listDetachedSessionEvents(ctx context.Context) []any {
	return a.listDetachedArray(ctx, "/api/v1/session-events")
}

func (a *App) listDetachedArray(ctx context.Context, path string) []any {
	supervisors := a.discoverDetachedSupervisors()
	if len(supervisors) == 0 {
		return nil
	}

	type result struct {
		sup   detachedSupervisor
		items []any
	}
	ch := make(chan result, len(supervisors))
	var wg sync.WaitGroup
	for _, sup := range supervisors {
		sup := sup
		wg.Add(1)
		go func() {
			defer wg.Done()
			var items []any
			if err := a.queryDetachedJSON(ctx, sup, path, &items); err != nil {
				slog.Debug("detached supervisor query failed", "session_id", sup.Meta.SessionID, "path", path, "error", err)
				return
			}
			ch <- result{sup: sup, items: items}
		}()
	}
	wg.Wait()
	close(ch)

	var out []any
	for res := range ch {
		a.recordDetachedRoutes(res.sup, res.items)
		out = append(out, res.items...)
	}
	return out
}

func (a *App) recordDetachedRoutes(sup detachedSupervisor, items []any) {
	if a == nil || len(items) == 0 {
		return
	}
	a.detachedRouteMu.Lock()
	defer a.detachedRouteMu.Unlock()
	if a.detachedRoutes == nil {
		a.detachedRoutes = make(map[string]detachedSupervisor)
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, ok := m["id"].(string)
		id = strings.TrimSpace(id)
		if ok && id != "" {
			a.detachedRoutes[id] = sup
		}
	}
}

func (a *App) lookupDetachedRoute(id string) (detachedSupervisor, bool) {
	if a == nil || strings.TrimSpace(id) == "" {
		return detachedSupervisor{}, false
	}
	a.detachedRouteMu.Lock()
	defer a.detachedRouteMu.Unlock()
	sup, ok := a.detachedRoutes[strings.TrimSpace(id)]
	return sup, ok
}

func detachedForwardID(path string) string {
	path = strings.TrimPrefix(path, "/api/v1/")
	for _, prefix := range []string{"approvals/", "session-events/"} {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		id := rest
		if i := strings.IndexByte(id, '/'); i >= 0 {
			id = id[:i]
		}
		unescaped, err := url.PathUnescape(id)
		if err != nil {
			return id
		}
		return unescaped
	}
	return ""
}

func (a *App) postDetachedRawLogged(ctx context.Context, sup detachedSupervisor, path string, raw []byte) bool {
	if err := a.postDetachedRaw(ctx, sup, path, raw); err == nil {
		return true
	} else if !isHTTPNotFound(err) && !isHTTPBadRequest(err) {
		slog.Debug("detached supervisor post failed", "session_id", sup.Meta.SessionID, "path", path, "error", err)
	}
	return false
}

func (a *App) forwardDetachedRaw(ctx context.Context, path string, raw []byte) bool {
	id := detachedForwardID(path)
	if sup, ok := a.lookupDetachedRoute(id); ok {
		if a.postDetachedRawLogged(ctx, sup, path, raw) {
			return true
		}
	}

	for _, sup := range a.discoverDetachedSupervisors() {
		if routed, ok := a.lookupDetachedRoute(id); ok && routed.Socket == sup.Socket {
			continue
		}
		if a.postDetachedRawLogged(ctx, sup, path, raw) {
			return true
		}
	}
	return false
}

func staleDetachedNetworkSnapshot(report *detached.NetworkEnforcement) *detached.NetworkEnforcement {
	return detached.StaleNetworkEnforcementSnapshot(report)
}

func (a *App) listDetachedSupervisors(w http.ResponseWriter, r *http.Request) {
	supervisors := a.discoverDetachedSupervisors()
	out := make([]map[string]any, 0, len(supervisors))
	for _, sup := range supervisors {
		item := map[string]any{
			"session_id":      sup.Meta.SessionID,
			"state":           sup.Meta.State,
			"policy":          sup.Meta.Policy,
			"workspace_mode":  sup.Meta.WorkspaceMode,
			"real_workspace":  sup.Meta.RealWorkspace,
			"supervisor_sock": sup.Meta.SupervisorSock,
			"owner_pid":       sup.Meta.OwnerPID,
			"created_at":      sup.Meta.CreatedAt,
		}
		var live detached.NetworkEnforcement
		if err := a.queryDetachedJSON(r.Context(), sup, escapedAPIPath("sessions", sup.Meta.SessionID, "network-enforcement"), &live); err == nil {
			live.Normalize()
			item["network_enforcement"] = &live
			item["network_enforcement_source"] = "supervisor-runtime"
			item["network_enforcement_live"] = true
		} else if sup.Meta.NetworkEnforcement != nil {
			item["network_enforcement"] = staleDetachedNetworkSnapshot(sup.Meta.NetworkEnforcement)
			item["network_enforcement_source"] = "metadata-snapshot-stale"
			item["network_enforcement_live"] = false
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

func readRawJSONBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}

func decodeRawJSON(raw []byte, v any) error {
	if len(strings.TrimSpace(string(raw))) == 0 {
		raw = []byte("{}")
	}
	return json.Unmarshal(raw, v)
}

func escapedAPIPath(parts ...string) string {
	var b strings.Builder
	b.WriteString("/api/v1")
	for _, part := range parts {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(part))
	}
	return b.String()
}
