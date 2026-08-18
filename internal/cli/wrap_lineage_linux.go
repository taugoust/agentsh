//go:build linux

package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/wraphandoff"
	"golang.org/x/sys/unix"
)

func completeLineageWrapHandoff(control, compositionSetup, signalControl *os.File, notifySocket, signalSocket string, wrapperPID int, commandJail bool, sessionID string, foregroundTTY bool) error {
	if control == nil || wrapperPID <= 0 {
		return errors.New("lineage wrapper control is unavailable")
	}
	prelude, err := wraphandoff.RecvLocalPrelude(control)
	if err != nil {
		return fmt.Errorf("receive lineage prelude: %w", err)
	}
	if prelude.Sender == nil || int(prelude.Sender.Pid) != wrapperPID || prelude.Metadata.CommandJail != commandJail {
		return errors.New("lineage prelude sender or capability mismatch")
	}

	connection, err := net.DialTimeout("unix", notifySocket, notifySetupStatusTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", notifySocket, err)
	}
	defer connection.Close()
	server, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("notify endpoint is not a Unix connection")
	}
	_ = server.SetDeadline(time.Now().Add(notifySetupStatusTimeout))
	if err := wraphandoff.SendPrelude(server, wraphandoff.Metadata{WrapperPID: wrapperPID, CommandJail: commandJail}); err != nil {
		return err
	}
	if err := wraphandoff.ReadStatus(server); err != nil {
		return fmt.Errorf("pre-fork server barrier: %w", err)
	}
	if err := writeWrapControlByte(control, 'G'); err != nil {
		return fmt.Errorf("release wrapper pre-fork barrier: %w", err)
	}

	payload, err := wraphandoff.RecvLocalPayload(control)
	if err != nil {
		return fmt.Errorf("receive child-owned notify handoff: %w", err)
	}
	defer payload.Close()
	if payload.Sender == nil || payload.NotifyFD == nil || payload.Metadata.CommandJail != commandJail {
		return errors.New("incomplete child-owned notify handoff")
	}
	payloadPID := int(payload.Sender.Pid)
	if !localPayloadLineageMatches(payloadPID, wrapperPID) {
		return fmt.Errorf("payload pid %d is not an exact child of wrapper pid %d", payloadPID, wrapperPID)
	}
	setupFD := -1
	if compositionSetup != nil {
		setupFD = int(compositionSetup.Fd())
	}
	lookupFD := -1
	if payload.FileLookup != nil {
		lookupFD = int(payload.FileLookup.Fd())
	}
	if err := wraphandoff.SendPayloadHandoff(server, int(payload.NotifyFD.Fd()), setupFD, lookupFD, wraphandoff.Metadata{
		WrapperPID: wrapperPID, PayloadPID: payloadPID, CommandJail: commandJail,
	}); err != nil {
		return err
	}
	if err := wraphandoff.ReadStatus(server); err != nil {
		return fmt.Errorf("payload notify setup: %w", err)
	}
	if err := writeWrapControlByte(control, 0x01); err != nil {
		return fmt.Errorf("acknowledge child-owned listener: %w", err)
	}
	if compositionSetup != nil {
		_ = compositionSetup.Close()
	}
	if !foregroundTTY {
		slog.Info("wrap: lineage notify capabilities accepted", "session_id", sessionID, "wrapper_pid", wrapperPID, "payload_pid", payloadPID)
	}

	// Signal USER_NOTIF is mutually exclusive with the main listener in current
	// production configurations. Preserve the existing optional forwarding path
	// for a future non-stacked filter composition.
	if signalControl != nil && signalSocket != "" {
		signalFD, signalErr := recvNotifyFD(signalControl)
		if signalErr != nil {
			slog.Warn("wrap: signal filter handoff unavailable", "error", signalErr, "session_id", sessionID)
		} else {
			defer unix.Close(signalFD)
			if signalErr = forwardNotifyFD(signalSocket, signalFD); signalErr != nil {
				slog.Warn("wrap: signal filter forwarding degraded", "error", signalErr, "session_id", sessionID)
			}
		}
	}
	_ = control.Close()
	if signalControl != nil {
		_ = signalControl.Close()
	}
	return nil
}

func localPayloadLineageMatches(payloadPID, wrapperPID int) bool {
	if payloadPID <= 0 || wrapperPID <= 0 || payloadPID == wrapperPID {
		return false
	}
	data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(payloadPID), "status"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false
		}
		parent, err := strconv.Atoi(fields[1])
		return err == nil && parent == wrapperPID
	}
	return false
}
