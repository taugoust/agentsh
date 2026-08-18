//go:build (!linux || !cgo) && !windows

package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

var (
	errWrapNotSupported = errors.New("wrap is only supported on Linux")
	errWrapperNotFound  = errors.New("seccomp wrapper binary not found")
)

type peerCreds struct {
	PID int
	UID uint32
}

func recvFDFromConn(sock *os.File) (*os.File, error) {
	return nil, errWrapNotSupported
}

func recvNotifyFDForWrap(conn *net.UnixConn) (*wrapNotifyHandoff, error) {
	return nil, errWrapNotSupported
}

func writeNotifyStatusForWrap(w io.Writer, ok bool) error {
	return errWrapNotSupported
}

func (a *App) acceptNotifyFDLineage(context.Context, net.Listener, string, string, *session.Session, bool, int, bool, *approvalUIEndpoint) bool {
	return false
}

func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, compositionSetup *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) error {
	if notifyFD != nil {
		_ = notifyFD.Close()
	}
	if compositionSetup != nil {
		_ = compositionSetup.Close()
	}
	return errWrapNotSupported
}

func startSignalHandlerForWrap(ctx context.Context, signalFD *os.File, sessionID string, a *App, s *session.Session) {
	if signalFD != nil {
		signalFD.Close()
	}
}

func (a *App) wrapInitWindows(ctx context.Context, s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
}

func getConnPeerCreds(conn *net.UnixConn) peerCreds {
	return peerCreds{}
}

func validateWrapperPIDForNotify(wrapperPID, peerPID int, peerUID uint32) (*os.File, error) {
	return nil, errWrapNotSupported
}

func validateWrapperPIDPinForNotify(pin *os.File) error {
	return errWrapNotSupported
}

func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, socketPath string, sessionID string, expectedUID int, activity *session.WorkspaceActivityLease) {
	activity.Release()
	listener.Close()
}
