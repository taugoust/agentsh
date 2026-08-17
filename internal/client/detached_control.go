package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/detachedtransport"
)

// ExchangeDetachedControl performs one authenticated typed exchange over an
// absolute Unix socket. It deliberately has no TCP, proxy, or redirect path.
func ExchangeDetachedControl(ctx context.Context, socketPath, token string, acknowledged uint64, request detachedtransport.ExchangeRequest, timeout time.Duration) (detachedtransport.ExchangeResponse, error) {
	var response detachedtransport.ExchangeResponse
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || strings.ContainsAny(socketPath, "\x00\r\n") {
		return response, fmt.Errorf("detached control socket path is invalid")
	}
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return response, fmt.Errorf("detached control credential is invalid")
	}
	if request.Credential == "" {
		request.Credential = token
	}
	if request.Credential != token {
		return response, fmt.Errorf("detached control request credential mismatch")
	}
	if err := request.Validate(); err != nil {
		return response, err
	}
	if timeout <= 0 {
		timeout = DefaultClientTimeout
	}
	body, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/api/v1/detached/control/exchange", bytes.NewReader(body))
	if err != nil {
		return response, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set(detachedtransport.ControlTokenHeader, token)
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return response, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(httpResponse.Body, 64<<10))
		return response, &HTTPError{Method: http.MethodPost, Path: "/api/v1/detached/control/exchange", Status: httpResponse.Status, StatusCode: httpResponse.StatusCode, Body: string(data)}
	}
	decoder := json.NewDecoder(io.LimitReader(httpResponse.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return detachedtransport.ExchangeResponse{}, fmt.Errorf("decode detached control response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return detachedtransport.ExchangeResponse{}, fmt.Errorf("detached control response contains trailing data")
	}
	sentMax := acknowledged
	if len(request.Records) > 0 {
		sentMax = request.Records[len(request.Records)-1].Sequence
	}
	if err := response.Validate(request.Identity, acknowledged, sentMax, request.Cursor, len(request.Records) > 0); err != nil {
		return detachedtransport.ExchangeResponse{}, err
	}
	return response, nil
}
