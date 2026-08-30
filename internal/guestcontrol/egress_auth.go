package guestcontrol

import (
	"crypto/subtle"
	"fmt"
	"io"
)

const egressAuthenticationPrefix = "AGENTSH-EGRESS-V1 "

// ValidEgressAuthenticationToken reports whether token has the fixed secret
// encoding used by the launch manifest and per-stream authentication frame.
func ValidEgressAuthenticationToken(token string) bool { return validHexSecret(token) }

// WriteEgressAuthentication writes the fixed-size launch authentication frame
// that must precede every byte of an HTTP proxy request on a guest-to-host
// egress stream.
func WriteEgressAuthentication(writer io.Writer, token string) error {
	if writer == nil || !validHexSecret(token) {
		return fmt.Errorf("guest egress authentication token is invalid")
	}
	frame := egressAuthenticationPrefix + token + "\n"
	written, err := io.WriteString(writer, frame)
	if err == nil && written != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write guest egress authentication: %w", err)
	}
	return nil
}

// ReadEgressAuthentication consumes exactly one fixed-size authentication
// frame. It never buffers or consumes a following HTTP byte.
func ReadEgressAuthentication(reader io.Reader, expectedToken string) error {
	if reader == nil || !validHexSecret(expectedToken) {
		return fmt.Errorf("host egress authentication token is invalid")
	}
	expected := egressAuthenticationPrefix + expectedToken + "\n"
	frame := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, frame); err != nil {
		return fmt.Errorf("read host egress authentication: %w", err)
	}
	if subtle.ConstantTimeCompare(frame, []byte(expected)) != 1 {
		return fmt.Errorf("host egress authentication failed")
	}
	return nil
}
