package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type approvalUIEndpoint struct {
	sessionID string
	path      string
	listener  net.Listener
	app       *App

	mu            sync.RWMutex
	authorizedPID int
	closed        bool
}

type approvalUIRequest struct {
	Op       string          `json:"op"`
	ID       string          `json:"id,omitempty"`
	Decision string          `json:"decision,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Event    json.RawMessage `json:"event,omitempty"`
}

type approvalUIResponse struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Approvals any    `json:"approvals,omitempty"`
	Event     any    `json:"event,omitempty"`
}

func (a *App) startApprovalUIEndpoint(sessionID string, callerUID int) (*approvalUIEndpoint, error) {
	if a.approvals == nil {
		return nil, nil
	}

	dir, err := os.MkdirTemp("", "agentsh-approval-ui-*")
	if err != nil {
		return nil, err
	}
	// The approval UI socket path is deliberately not a bearer secret. The
	// security boundary is SO_PEERCRED below: only the registered wrapped process
	// PID may list or resolve approvals. Keep filesystem permissions permissive
	// enough for the unprivileged wrapped agent to reach the socket even when the
	// server runs as root or caller UID metadata is unavailable/stale.
	if err := wrapChmod(dir, 0711); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if err := validatePermissionMode(dir, 0711, "approval ui directory"); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	path := filepath.Join(dir, "approval-ui.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if err := wrapChmod(path, 0666); err != nil {
		_ = listener.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	if err := validatePermissionMode(path, 0666, "approval ui socket"); err != nil {
		_ = listener.Close()
		os.RemoveAll(dir)
		return nil, err
	}

	ui := &approvalUIEndpoint{
		sessionID: sessionID,
		path:      path,
		listener:  listener,
		app:       a,
	}
	a.registerApprovalUI(sessionID, ui)
	go ui.serve()
	return ui, nil
}

func (a *App) registerApprovalUI(sessionID string, ui *approvalUIEndpoint) {
	a.approvalUIMu.Lock()
	defer a.approvalUIMu.Unlock()
	if a.approvalUIs == nil {
		a.approvalUIs = make(map[string]*approvalUIEndpoint)
	}
	if old := a.approvalUIs[sessionID]; old != nil && old != ui {
		old.Close()
	}
	a.approvalUIs[sessionID] = ui
}

func (a *App) closeApprovalUI(sessionID string) {
	a.approvalUIMu.Lock()
	ui := a.approvalUIs[sessionID]
	if ui != nil {
		delete(a.approvalUIs, sessionID)
	}
	a.approvalUIMu.Unlock()
	if ui != nil {
		ui.Close()
	}
}

func (ui *approvalUIEndpoint) SetAuthorizedPID(pid int) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if pid > 0 && !ui.closed {
		ui.authorizedPID = pid
	}
}

func (ui *approvalUIEndpoint) Close() {
	ui.mu.Lock()
	if ui.closed {
		ui.mu.Unlock()
		return
	}
	ui.closed = true
	listener := ui.listener
	path := ui.path
	ui.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if path != "" {
		_ = os.RemoveAll(filepath.Dir(path))
	}
}

func (ui *approvalUIEndpoint) serve() {
	defer ui.app.closeApprovalUIIfCurrent(ui.sessionID, ui)
	for {
		conn, err := ui.listener.Accept()
		if err != nil {
			ui.mu.RLock()
			closed := ui.closed
			ui.mu.RUnlock()
			if !closed {
				slog.Debug("approval-ui: accept failed", "session_id", ui.sessionID, "error", err)
			}
			return
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		creds := getConnPeerCreds(unixConn)
		ui.mu.RLock()
		authorizedPID := ui.authorizedPID
		ui.mu.RUnlock()
		if authorizedPID <= 0 || creds.PID != authorizedPID {
			slog.Warn("approval-ui: rejecting connection from unauthorized peer", "session_id", ui.sessionID, "peer_pid", creds.PID, "authorized_pid", authorizedPID)
			_ = conn.Close()
			continue
		}
		go ui.handleConn(unixConn)
	}
}

func (a *App) closeApprovalUIIfCurrent(sessionID string, ui *approvalUIEndpoint) {
	a.approvalUIMu.Lock()
	if a.approvalUIs[sessionID] == ui {
		delete(a.approvalUIs, sessionID)
	}
	a.approvalUIMu.Unlock()
	ui.Close()
}

func (ui *approvalUIEndpoint) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	// Keep requests bounded; approval payloads are small.
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	enc := json.NewEncoder(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req approvalUIRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(approvalUIResponse{OK: false, Error: "invalid json"})
			continue
		}
		resp := ui.handleRequest(req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (ui *approvalUIEndpoint) handleRequest(req approvalUIRequest) approvalUIResponse {
	if ui.app.approvals == nil {
		return approvalUIResponse{OK: false, Error: "approvals not enabled"}
	}
	switch strings.ToLower(strings.TrimSpace(req.Op)) {
	case "list":
		return approvalUIResponse{OK: true, Approvals: ui.app.approvals.ListPendingForSession(ui.sessionID)}
	case "publish_event":
		ev, err := decodeSessionEvent(req.Event)
		if err != nil {
			return approvalUIResponse{OK: false, Error: "invalid event"}
		}
		ev.SessionID = ui.sessionID
		if strings.TrimSpace(ev.Type) == "" {
			return approvalUIResponse{OK: false, Error: "missing event type"}
		}
		if strings.TrimSpace(ev.Title) == "" {
			ev.Title = ev.Type
		}
		published := ui.app.publishSessionEvent(ev)
		return approvalUIResponse{OK: true, Event: published}
	case "resolve":
		id := strings.TrimSpace(req.ID)
		if id == "" {
			return approvalUIResponse{OK: false, Error: "missing approval id"}
		}
		decision := strings.ToLower(strings.TrimSpace(req.Decision))
		approved := decision == "approve" || decision == "allow"
		if !approved && decision != "deny" && decision != "reject" {
			return approvalUIResponse{OK: false, Error: fmt.Sprintf("invalid decision %q", req.Decision)}
		}
		if ok := ui.app.approvals.ResolveForSession(ui.sessionID, id, approved, req.Reason); !ok {
			return approvalUIResponse{OK: false, Error: "approval not found for session"}
		}
		return approvalUIResponse{OK: true}
	default:
		return approvalUIResponse{OK: false, Error: "unknown op"}
	}
}
