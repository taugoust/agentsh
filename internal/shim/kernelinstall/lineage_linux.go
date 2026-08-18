//go:build linux

package kernelinstall

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/wraphandoff"
)

func completeKernelLineageHandoff(control, compositionSetup *os.File, notifySocket string, wrapperPID int, commandJail bool) error {
	prelude, err := wraphandoff.RecvLocalPrelude(control)
	if err != nil {
		return err
	}
	if prelude.Sender == nil || int(prelude.Sender.Pid) != wrapperPID || prelude.Metadata.CommandJail != commandJail {
		return errors.New("lineage prelude identity mismatch")
	}
	connection, err := net.DialTimeout("unix", notifySocket, notifySetupStatusTimeout)
	if err != nil {
		return err
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
	if err := writeCommandJailControlByte(control, 'G'); err != nil {
		return err
	}
	payload, err := wraphandoff.RecvLocalPayload(control)
	if err != nil {
		return err
	}
	defer payload.Close()
	if payload.Sender == nil || payload.NotifyFD == nil || payload.Metadata.CommandJail != commandJail {
		return errors.New("incomplete payload handoff")
	}
	payloadPID := int(payload.Sender.Pid)
	if !kernelPayloadLineageMatches(payloadPID, wrapperPID) {
		return errors.New("payload is not the exact wrapper child")
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
		return fmt.Errorf("payload server handoff: %w", err)
	}
	if err := writeCommandJailControlByte(control, 0x01); err != nil {
		return err
	}
	if compositionSetup != nil {
		_ = compositionSetup.Close()
	}
	return nil
}

func kernelPayloadLineageMatches(payloadPID, wrapperPID int) bool {
	if payloadPID <= 0 || wrapperPID <= 0 || payloadPID == wrapperPID {
		return false
	}
	data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(payloadPID), "status"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return false
			}
			parent, err := strconv.Atoi(fields[1])
			return err == nil && parent == wrapperPID
		}
	}
	return false
}
