package approvals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	detachedEventURLDefault = "http://127.0.0.1:18080"
	detachedEventTokenEnv   = "AGENTSH_DETACHED_EVENT_TOKEN"
	detachedEventURLEnv     = "AGENTSH_DETACHED_EVENT_URL"
)

type detachedBridgeResolutionResponse struct {
	OK         bool       `json:"ok"`
	Resolved   bool       `json:"resolved"`
	Resolution Resolution `json:"resolution"`
}

func detachedBridgeConfig() (string, string, bool) {
	token := strings.TrimSpace(os.Getenv(detachedEventTokenEnv))
	if token == "" {
		return "", "", false
	}
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv(detachedEventURLEnv)), "/")
	if baseURL == "" {
		baseURL = detachedEventURLDefault
	}
	return baseURL, token, true
}

func (m *Manager) maybeStartDetachedBridge(ctx context.Context, req Request) {
	if m == nil || m.mode != "api" || strings.TrimSpace(req.SessionID) == "" || strings.TrimSpace(req.ID) == "" {
		return
	}
	baseURL, token, ok := detachedBridgeConfig()
	if !ok {
		return
	}
	go m.runDetachedBridge(ctx, baseURL, token, req)
}

func (m *Manager) runDetachedBridge(ctx context.Context, baseURL, token string, req Request) {
	client := &http.Client{Timeout: 2 * time.Second}
	registered := false
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if ctx.Err() != nil || time.Now().UTC().After(req.ExpiresAt) {
			return
		}

		if !registered {
			registered = postDetachedApproval(ctx, client, baseURL, token, req)
		} else if res, resolved := getDetachedApprovalResolution(ctx, client, baseURL, token, req); resolved {
			target := Scope{
				Kind:      strings.TrimSpace(res.ScopeKind),
				Key:       strings.TrimSpace(res.ScopeKey),
				Label:     strings.TrimSpace(res.ScopeLabel),
				Operation: strings.TrimSpace(res.ScopeOperation),
				Path:      strings.TrimSpace(res.ScopePath),
				Rule:      strings.TrimSpace(res.ScopeRule),
				Prefix:    res.ScopePrefix,
			}
			_ = m.ResolveWithScopeTarget(req.ID, res.Approved, res.Reason, res.Scope, target)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func postDetachedApproval(ctx context.Context, client *http.Client, baseURL, token string, req Request) bool {
	payload, err := json.Marshal(req)
	if err != nil {
		return false
	}
	url := fmt.Sprintf("%s/api/v1/detached-sessions/%s/approvals", baseURL, pathEscape(req.SessionID))
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("X-AgentSH-Session-Event-Token", token)
	resp, err := client.Do(hreq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func getDetachedApprovalResolution(ctx context.Context, client *http.Client, baseURL, token string, req Request) (Resolution, bool) {
	url := fmt.Sprintf("%s/api/v1/detached-sessions/%s/approvals/%s/resolution", baseURL, pathEscape(req.SessionID), pathEscape(req.ID))
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Resolution{}, false
	}
	hreq.Header.Set("X-AgentSH-Session-Event-Token", token)
	resp, err := client.Do(hreq)
	if err != nil {
		return Resolution{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Resolution{}, false
	}
	var body detachedBridgeResolutionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Resolution{}, false
	}
	return body.Resolution, body.Resolved
}

func pathEscape(value string) string {
	replacer := strings.NewReplacer("%", "%25", "/", "%2F", "?", "%3F", "#", "%23")
	return replacer.Replace(value)
}
