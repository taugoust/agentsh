//go:build linux

package wraphandoff

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const (
	localProtocolMagic   uint32 = 0x484c5341 // "ASLH"
	localProtocolVersion uint16 = 1
	localFrameSize              = 16

	localFramePrelude uint16 = 1
	localFramePayload uint16 = 2

	localFlagCommandJail uint32 = 1 << 0
	localFlagFileLookup  uint32 = 1 << 1
)

type LocalMetadata struct {
	CommandJail     bool
	FileLookupReady bool
}

type LocalMessage struct {
	Metadata   LocalMetadata
	Sender     *unix.Ucred
	NotifyFD   *os.File
	FileLookup *os.File
}

func (m *LocalMessage) Close() {
	if m == nil {
		return
	}
	if m.NotifyFD != nil {
		_ = m.NotifyFD.Close()
		m.NotifyFD = nil
	}
	if m.FileLookup != nil {
		_ = m.FileLookup.Close()
		m.FileLookup = nil
	}
}

func EnableLocalCredentials(fd int) error {
	if fd < 0 {
		return fmt.Errorf("invalid local handoff fd %d", fd)
	}
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
}

func SendLocalPrelude(fd int, metadata LocalMetadata) error {
	if fd < 0 {
		return fmt.Errorf("invalid local handoff fd %d", fd)
	}
	if metadata.FileLookupReady {
		return errors.New("file lookup readiness is invalid in a pre-fork frame")
	}
	frame := encodeLocalFrame(localFramePrelude, metadata)
	n, err := unix.SendmsgN(fd, frame, nil, nil, unix.MSG_NOSIGNAL)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

func RecvLocalPrelude(file *os.File) (*LocalMessage, error) {
	return recvLocalMessage(file, localFramePrelude)
}

func RecvLocalPayload(file *os.File) (*LocalMessage, error) {
	return recvLocalMessage(file, localFramePayload)
}

func encodeLocalFrame(frameType uint16, metadata LocalMetadata) []byte {
	frame := make([]byte, localFrameSize)
	binaryPutUint32(frame[0:4], localProtocolMagic)
	binaryPutUint16(frame[4:6], localProtocolVersion)
	binaryPutUint16(frame[6:8], frameType)
	flags := uint32(0)
	if metadata.CommandJail {
		flags |= localFlagCommandJail
	}
	if metadata.FileLookupReady {
		flags |= localFlagFileLookup
	}
	binaryPutUint32(frame[8:12], flags)
	binaryPutUint32(frame[12:16], localFrameSize)
	return frame
}

func recvLocalMessage(file *os.File, expectedType uint16) (*LocalMessage, error) {
	if file == nil {
		return nil, errors.New("nil local handoff socket")
	}
	fd := int(file.Fd())
	if err := EnableLocalCredentials(fd); err != nil {
		return nil, fmt.Errorf("enable local handoff credentials: %w", err)
	}
	frame := make([]byte, localFrameSize)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := unix.Recvmsg(fd, frame, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return nil, err
	}
	var received []int
	closeReceived := func() {
		for _, receivedFD := range received {
			_ = unix.Close(receivedFD)
		}
	}
	if n != localFrameSize || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 ||
		binaryUint32(frame[0:4]) != localProtocolMagic ||
		binaryUint16(frame[4:6]) != localProtocolVersion ||
		binaryUint16(frame[6:8]) != expectedType ||
		binaryUint32(frame[12:16]) != localFrameSize {
		return nil, errors.New("invalid local handoff frame")
	}
	knownFlags := uint32(localFlagCommandJail | localFlagFileLookup)
	frameFlags := binaryUint32(frame[8:12])
	if frameFlags&^knownFlags != 0 || expectedType == localFramePrelude && frameFlags&localFlagFileLookup != 0 {
		return nil, errors.New("invalid local handoff flags")
	}

	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parse local handoff controls: %w", err)
	}
	var credentials *unix.Ucred
	rightsMessages := 0
	for _, message := range messages {
		switch {
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS:
			if credentials != nil {
				closeReceived()
				return nil, errors.New("duplicate local handoff credentials")
			}
			credentials, err = unix.ParseUnixCredentials(&message)
			if err != nil {
				closeReceived()
				return nil, err
			}
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS:
			rightsMessages++
			fds, rightsErr := unix.ParseUnixRights(&message)
			if rightsErr != nil {
				closeReceived()
				return nil, rightsErr
			}
			received = append(received, fds...)
		default:
			closeReceived()
			return nil, fmt.Errorf("unexpected local ancillary level=%d type=%d", message.Header.Level, message.Header.Type)
		}
	}
	if credentials == nil || credentials.Pid <= 0 {
		closeReceived()
		return nil, errors.New("local handoff omitted sender credentials")
	}
	expectedFDs := 0
	if expectedType == localFramePayload {
		expectedFDs = 1
		if frameFlags&localFlagFileLookup != 0 {
			expectedFDs++
		}
	}
	if len(received) != expectedFDs || (expectedFDs > 0 && rightsMessages != 1) || (expectedFDs == 0 && rightsMessages != 0) {
		closeReceived()
		return nil, fmt.Errorf("local handoff received %d descriptors, want %d", len(received), expectedFDs)
	}
	for _, receivedFD := range received {
		unix.CloseOnExec(receivedFD)
	}
	result := &LocalMessage{
		Metadata: LocalMetadata{
			CommandJail:     frameFlags&localFlagCommandJail != 0,
			FileLookupReady: frameFlags&localFlagFileLookup != 0,
		},
		Sender: credentials,
	}
	if len(received) > 0 {
		result.NotifyFD = os.NewFile(uintptr(received[0]), "payload-notify-fd")
		if result.NotifyFD == nil {
			closeReceived()
			return nil, errors.New("retain payload notify descriptor")
		}
	}
	if len(received) > 1 {
		result.FileLookup = os.NewFile(uintptr(received[1]), "payload-file-lookup-broker")
		if result.FileLookup == nil {
			result.Close()
			return nil, errors.New("retain file lookup broker descriptor")
		}
	}
	return result, nil
}

func binaryPutUint16(target []byte, value uint16) {
	target[0] = byte(value)
	target[1] = byte(value >> 8)
}

func binaryPutUint32(target []byte, value uint32) {
	target[0] = byte(value)
	target[1] = byte(value >> 8)
	target[2] = byte(value >> 16)
	target[3] = byte(value >> 24)
}

func binaryUint16(source []byte) uint16 {
	return uint16(source[0]) | uint16(source[1])<<8
}

func binaryUint32(source []byte) uint32 {
	return uint32(source[0]) | uint32(source[1])<<8 | uint32(source[2])<<16 | uint32(source[3])<<24
}
