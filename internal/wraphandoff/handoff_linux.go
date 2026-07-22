//go:build linux

package wraphandoff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	protocolMagic            byte = 0xA7
	metadataCommandJail      byte = 1 << 0
	metadataCompositionSetup byte = 1 << 1
	StatusReject             byte = 0
	StatusOK                 byte = 1
)

type Metadata struct {
	WrapperPID       int
	CommandJail      bool
	CompositionSetup bool
}

// Handoff is the authenticated wrapper-to-supervisor descriptor handoff. The
// composition setup endpoint is optional, but when present its metadata bit and
// descriptor position are fixed so a truncated or reordered handoff fails
// closed.
type Handoff struct {
	NotifyFD         *os.File
	CompositionSetup *os.File
	Metadata         Metadata
	HasMetadata      bool
}

func (h *Handoff) Close() {
	if h == nil {
		return
	}
	if h.NotifyFD != nil {
		_ = h.NotifyFD.Close()
		h.NotifyFD = nil
	}
	if h.CompositionSetup != nil {
		_ = h.CompositionSetup.Close()
		h.CompositionSetup = nil
	}
}

func SendNotifyFD(conn *net.UnixConn, notifyFD int, meta Metadata) error {
	if meta.CompositionSetup {
		return errors.New("composition setup metadata requires a setup descriptor")
	}
	return sendHandoff(conn, notifyFD, -1, meta)
}

// SendNotifyFDWithSetup transfers the seccomp listener and the connected
// wrapper-side composition setup endpoint in one SCM_RIGHTS message. Passing
// the endpoint (rather than relaying later setup objects through the CLI)
// leaves the untrusted relay unable to inspect or alter the trusted setup
// message.
func SendNotifyFDWithSetup(conn *net.UnixConn, notifyFD, setupFD int, meta Metadata) error {
	if setupFD < 0 {
		return fmt.Errorf("invalid composition setup fd %d", setupFD)
	}
	meta.CompositionSetup = true
	return sendHandoff(conn, notifyFD, setupFD, meta)
}

func sendHandoff(conn *net.UnixConn, notifyFD, setupFD int, meta Metadata) error {
	if conn == nil {
		return errors.New("nil unix connection")
	}
	if notifyFD < 0 {
		return fmt.Errorf("invalid notify fd %d", notifyFD)
	}
	if meta.WrapperPID <= 0 {
		return fmt.Errorf("invalid wrapper pid %d", meta.WrapperPID)
	}
	if meta.CompositionSetup != (setupFD >= 0) {
		return errors.New("composition setup metadata and descriptor disagree")
	}

	payload := make([]byte, 6)
	payload[0] = protocolMagic
	binary.LittleEndian.PutUint32(payload[1:], uint32(meta.WrapperPID))
	if meta.CommandJail {
		payload[5] |= metadataCommandJail
	}
	fds := []int{notifyFD}
	if setupFD >= 0 {
		payload[5] |= metadataCompositionSetup
		fds = append(fds, setupFD)
	}
	rights := unix.UnixRights(fds...)
	n, oobn, err := conn.WriteMsgUnix(payload, rights, nil)
	if err != nil {
		return fmt.Errorf("send notify handoff: %w", err)
	}
	if n != len(payload) || oobn != len(rights) {
		return fmt.Errorf("send notify handoff: %w (n=%d/%d, oobn=%d/%d)", io.ErrShortWrite, n, len(payload), oobn, len(rights))
	}
	return nil
}

// RecvHandoff receives either the legacy single notify descriptor or the
// versioned notify-plus-composition handoff. Every received descriptor is
// CLOEXEC before it is exposed to the caller.
func RecvHandoff(conn *net.UnixConn) (*Handoff, error) {
	if conn == nil {
		return nil, errors.New("nil unix connection")
	}

	buf := make([]byte, 16)
	oob := make([]byte, unix.CmsgSpace(4*8))
	// Receive rights with MSG_CMSG_CLOEXEC in the kernel. Setting FD_CLOEXEC
	// only after ReadMsgUnix returns leaves a process-wide fork/exec race in a
	// multithreaded supervisor, which is unacceptable for the composition setup
	// capability endpoint.
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("recvmsg syscall connection: %w", err)
	}
	var n, oobn, flags int
	var recvErr error
	if err := raw.Read(func(fd uintptr) bool {
		n, oobn, flags, _, recvErr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC)
		return recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK
	}); err != nil {
		return nil, fmt.Errorf("recvmsg readiness: %w", err)
	}
	if recvErr != nil {
		return nil, fmt.Errorf("recvmsg: %w", recvErr)
	}
	if n == 0 || oobn == 0 {
		return nil, fmt.Errorf("no fd received (n=%d, oobn=%d)", n, oobn)
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		if flags&unix.MSG_CTRUNC != 0 {
			return nil, fmt.Errorf("truncated control message: %w", err)
		}
		return nil, fmt.Errorf("parse control message: %w", err)
	}

	var receivedFDs []int
	rightsMessages := 0
	for _, message := range msgs {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			closeFDs(receivedFDs)
			return nil, fmt.Errorf("unexpected handoff ancillary level=%d type=%d", message.Header.Level, message.Header.Type)
		}
		rightsMessages++
		fds, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil {
			closeFDs(receivedFDs)
			return nil, fmt.Errorf("parse handoff descriptors: %w", parseErr)
		}
		receivedFDs = append(receivedFDs, fds...)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeFDs(receivedFDs)
		return nil, errors.New("truncated handoff message")
	}
	if rightsMessages != 1 {
		closeFDs(receivedFDs)
		return nil, fmt.Errorf("expected exactly one descriptor control message, received %d", rightsMessages)
	}

	meta := Metadata{}
	hasMeta := buf[0] == protocolMagic
	if hasMeta {
		if n != 6 {
			closeFDs(receivedFDs)
			return nil, fmt.Errorf("invalid metadata handoff payload length %d", n)
		}
		if unknown := buf[5] & ^byte(metadataCommandJail|metadataCompositionSetup); unknown != 0 {
			closeFDs(receivedFDs)
			return nil, fmt.Errorf("unknown handoff metadata flags %#x", unknown)
		}
		meta.WrapperPID = int(binary.LittleEndian.Uint32(buf[1:5]))
		if meta.WrapperPID <= 0 {
			closeFDs(receivedFDs)
			return nil, fmt.Errorf("invalid handoff wrapper pid %d", meta.WrapperPID)
		}
		meta.CommandJail = buf[5]&metadataCommandJail != 0
		meta.CompositionSetup = buf[5]&metadataCompositionSetup != 0
	} else if n != 1 {
		closeFDs(receivedFDs)
		return nil, fmt.Errorf("invalid legacy handoff payload length %d", n)
	}
	expectedFDs := 1
	if meta.CompositionSetup {
		expectedFDs = 2
	}
	if len(receivedFDs) != expectedFDs {
		closeFDs(receivedFDs)
		return nil, fmt.Errorf("expected exactly %d handoff fd(s), received %d", expectedFDs, len(receivedFDs))
	}
	for _, fd := range receivedFDs {
		unix.CloseOnExec(fd)
	}

	handoff := &Handoff{
		NotifyFD:    os.NewFile(uintptr(receivedFDs[0]), "wrap-notif-fd"),
		Metadata:    meta,
		HasMetadata: hasMeta,
	}
	if handoff.NotifyFD == nil {
		closeFDs(receivedFDs)
		return nil, errors.New("retain notify descriptor")
	}
	if meta.CompositionSetup {
		handoff.CompositionSetup = os.NewFile(uintptr(receivedFDs[1]), "wrap-composition-setup")
		if handoff.CompositionSetup == nil {
			handoff.Close()
			return nil, errors.New("retain composition setup descriptor")
		}
	}
	return handoff, nil
}

// RecvNotifyFD preserves the legacy single-descriptor API for callers that do
// not support composition. Receiving a composition endpoint through this API
// is an explicit version mismatch rather than silently dropping authority.
func RecvNotifyFD(conn *net.UnixConn) (*os.File, Metadata, bool, error) {
	handoff, err := RecvHandoff(conn)
	if err != nil {
		return nil, Metadata{}, false, err
	}
	if handoff.CompositionSetup != nil {
		handoff.Close()
		return nil, Metadata{}, false, errors.New("unexpected composition setup descriptor")
	}
	notifyFD := handoff.NotifyFD
	handoff.NotifyFD = nil
	return notifyFD, handoff.Metadata, handoff.HasMetadata, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func WriteStatus(w io.Writer, ok bool) error {
	if w == nil {
		return errors.New("nil writer")
	}

	b := StatusReject
	if ok {
		b = StatusOK
	}
	n, err := w.Write([]byte{b})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func ReadStatus(r io.Reader) error {
	if r == nil {
		return errors.New("nil reader")
	}

	buf := []byte{0}
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("read setup status: %w", err)
	}
	switch buf[0] {
	case StatusOK:
		return nil
	case StatusReject:
		return errors.New("server rejected wrap setup")
	default:
		return fmt.Errorf("unexpected setup status byte %d", buf[0])
	}
}
