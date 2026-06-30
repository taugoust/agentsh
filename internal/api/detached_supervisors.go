package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/detached"
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

func (a *App) listDetachedApprovals(ctx context.Context) []any {
	return a.listDetachedArray(ctx, "/api/v1/approvals")
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
			ch <- result{items: items}
		}()
	}
	wg.Wait()
	close(ch)

	var out []any
	for res := range ch {
		out = append(out, res.items...)
	}
	return out
}

func (a *App) forwardDetachedRaw(ctx context.Context, path string, raw []byte) bool {
	for _, sup := range a.discoverDetachedSupervisors() {
		if err := a.postDetachedRaw(ctx, sup, path, raw); err == nil {
			return true
		} else if !isHTTPNotFound(err) && !isHTTPBadRequest(err) {
			slog.Debug("detached supervisor post failed", "session_id", sup.Meta.SessionID, "path", path, "error", err)
		}
	}
	return false
}

func (a *App) listDetachedSupervisors(w http.ResponseWriter, r *http.Request) {
	supervisors := a.discoverDetachedSupervisors()
	out := make([]map[string]any, 0, len(supervisors))
	for _, sup := range supervisors {
		out = append(out, map[string]any{
			"session_id":      sup.Meta.SessionID,
			"state":           sup.Meta.State,
			"policy":          sup.Meta.Policy,
			"workspace_mode":  sup.Meta.WorkspaceMode,
			"real_workspace":  sup.Meta.RealWorkspace,
			"supervisor_sock": sup.Meta.SupervisorSock,
			"owner_pid":       sup.Meta.OwnerPID,
			"created_at":      sup.Meta.CreatedAt,
		})
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
