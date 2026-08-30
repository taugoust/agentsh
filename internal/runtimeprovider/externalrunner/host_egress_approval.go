package externalrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

const hostEgressApprovalTimeout = 5 * time.Minute

func hostEgressApprovalTokenFromEnvironment() (string, error) {
	direct := strings.TrimSpace(os.Getenv(HostEgressApprovalTokenEnv))
	credentialFile := strings.TrimSpace(os.Getenv(HostEgressApprovalCredentialEnv))
	if direct != "" && credentialFile != "" {
		return "", fmt.Errorf("host egress approval token has multiple transports")
	}
	if credentialFile == "" {
		return direct, nil
	}
	before, err := os.Lstat(credentialFile)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 || before.Size() < 1 || before.Size() > 256 || !operatorPolicyOwnerTrusted(credentialFile, before) {
		return "", fmt.Errorf("host egress approval credential file is unsafe")
	}
	file, err := os.Open(credentialFile)
	if err != nil {
		return "", fmt.Errorf("open host egress approval credential: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("host egress approval credential identity changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", fmt.Errorf("read host egress approval credential: %w", err)
	}
	if len(data) > 256 {
		return "", fmt.Errorf("host egress approval credential is too large")
	}
	return strings.TrimSpace(string(data)), nil
}

func hostEgressApprovalBindingFromEnvironment() (*HostEgressApprovalBinding, error) {
	token, err := hostEgressApprovalTokenFromEnvironment()
	if err != nil {
		return nil, err
	}
	binding := HostEgressApprovalBinding{
		ParentSessionID: strings.TrimSpace(os.Getenv(HostEgressApprovalSessionEnv)),
		SupervisorURL:   strings.TrimSpace(os.Getenv(HostEgressApprovalSupervisorEnv)),
		Token:           token,
	}
	present := 0
	for _, value := range []string{binding.ParentSessionID, binding.SupervisorURL, binding.Token} {
		if value != "" {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	if present != 3 || binding.Validate() != nil {
		return nil, fmt.Errorf("host egress approval environment binding is incomplete or invalid")
	}
	return &binding, nil
}

type remoteHostEgressApprovalRequest struct {
	DraftSessionID string `json:"draft_session_id"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	Rule           string `json:"rule"`
	Message        string `json:"message,omitempty"`
}

func newHostEgressApprovalManager(binding *HostEgressApprovalBinding, draftSessionID string, emit approvals.Emitter) (*approvals.Manager, error) {
	if binding == nil {
		return nil, nil
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	manager := approvals.New("remote", hostEgressApprovalTimeout, emit)
	manager.SetDetachedRequestObserver(func(ctx context.Context, req approvals.Request) error {
		resolution, err := requestParentHostEgressApproval(ctx, *binding, remoteHostEgressApprovalRequest{
			DraftSessionID: draftSessionID,
			Kind:           req.Kind,
			Target:         req.Target,
			Rule:           req.Rule,
			Message:        req.Message,
		})
		if err != nil {
			return err
		}
		if !manager.ResolveWithScopeTarget(req.ID, resolution.Approved, resolution.Reason, resolution.Scope, approvals.Scope{
			Kind: resolution.ScopeKind, Key: resolution.ScopeKey, Label: resolution.ScopeLabel,
			Operation: resolution.ScopeOperation, Path: resolution.ScopePath, Rule: resolution.ScopeRule, Prefix: resolution.ScopePrefix,
		}) {
			return fmt.Errorf("remote host egress approval was no longer pending")
		}
		return nil
	})
	return manager, nil
}

func requestParentHostEgressApproval(ctx context.Context, binding HostEgressApprovalBinding, request remoteHostEgressApprovalRequest) (approvals.Resolution, error) {
	if err := binding.Validate(); err != nil {
		return approvals.Resolution{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return approvals.Resolution{}, err
	}
	socketPath := strings.TrimPrefix(binding.SupervisorURL, "unix://")
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	endpoint := "http://unix/api/v1/sessions/" + binding.ParentSessionID + "/tools/request_guest_egress_approval"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return approvals.Resolution{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set(HostEgressApprovalHeader, binding.Token)
	response, err := client.Do(httpRequest)
	if err != nil {
		return approvals.Resolution{}, fmt.Errorf("request parent host egress approval: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return approvals.Resolution{}, fmt.Errorf("parent host egress approval failed with HTTP %d", response.StatusCode)
	}
	var resolution approvals.Resolution
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resolution); err != nil {
		return approvals.Resolution{}, fmt.Errorf("decode parent host egress approval: %w", err)
	}
	if resolution.Scope == "" {
		resolution.Scope = approvals.ScopeOnce
	}
	if resolution.Scope != approvals.ScopeOnce && resolution.Scope != approvals.ScopeSession {
		return approvals.Resolution{}, errors.New("parent host egress approval returned an invalid scope")
	}
	return resolution, nil
}
