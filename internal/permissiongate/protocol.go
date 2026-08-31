package permissiongate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	// ProtocolVersion is the only inherited-FD protocol version understood by
	// this implementation.
	ProtocolVersion = 1

	// EnvFD names the environment variable containing the inherited gate file
	// descriptor in the launched Pi process.
	EnvFD = "AGENTSH_PERMISSION_GATE_FD"

	// MaxFrameBytes bounds every JSONL frame in either direction. Commands have
	// a lower independent bound so response and metadata overhead always fit.
	MaxFrameBytes   = 64 * 1024
	MaxCommandBytes = 32 * 1024
	MaxCWDBytes     = 4 * 1024
	MaxIDBytes      = 256
)

const (
	messageHello     = "hello"
	messageAuthorize = "authorize"
	messageResolve   = "resolve"
	messageCancel    = "cancel"
	messageDecision  = "decision"
	messageComplete  = "complete"
)

var (
	// ErrUnexpectedEOF means the client closed its authority channel without
	// the launched process first being observed as exited.
	ErrUnexpectedEOF = errors.New("permission gate protocol: unexpected EOF")
	// ErrProtocol classifies malformed, oversized, or invalid protocol input.
	ErrProtocol = errors.New("permission gate protocol violation")
)

// HelloRequest starts every protocol connection. Requiring an explicit hello
// prevents an unrelated inherited-fd consumer from being mistaken for Pi.
type HelloRequest struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	Client string `json:"client"`
}

// HelloResponse confirms the protocol and operations available to Pi.
type HelloResponse struct {
	V            int      `json:"v"`
	Type         string   `json:"type"`
	Service      string   `json:"service"`
	Capabilities []string `json:"capabilities"`
}

// AuthorizeRequest asks AgentSH to classify one Bash tool call. ID is a
// protocol correlation ID; ToolCallID is opaque audit metadata supplied by Pi.
type AuthorizeRequest struct {
	V          int    `json:"v"`
	Type       string `json:"type"`
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Command    string `json:"command"`
	CWD        string `json:"cwd,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
}

// ResolveRequest carries Pi's UI resolution for an earlier prompt decision.
type ResolveRequest struct {
	V        int    `json:"v"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Decision string `json:"decision"`
}

// CancelRequest denies an unresolved prompt when its tool call is aborted.
type CancelRequest struct {
	V      int    `json:"v"`
	Type   string `json:"type"`
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

// PromptMetadata is display-only context. Pi remains responsible for showing
// the prompt and sending an allow or deny resolution.
type PromptMetadata struct {
	Title            string   `json:"title"`
	Message          string   `json:"message"`
	Labels           []string `json:"labels"`
	CommandPreview   string   `json:"command_preview"`
	CommandTruncated bool     `json:"command_truncated,omitempty"`
}

// DecisionResponse is returned for an authorize request. Decision is "allow"
// for commands without a dangerous match and "prompt" otherwise.
type DecisionResponse struct {
	V        int             `json:"v"`
	Type     string          `json:"type"`
	ID       string          `json:"id"`
	Decision string          `json:"decision"`
	Prompt   *PromptMetadata `json:"prompt,omitempty"`
}

// CompleteResponse acknowledges that a prompt resolution has been durably
// audited. Pi must wait for this frame before allowing a resolved command.
type CompleteResponse struct {
	V        int    `json:"v"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

type requestEnvelope struct {
	V    int    `json:"v"`
	Type string `json:"type"`
}

// frameReader reads LF-delimited frames without Scanner's token allocation or
// silent final-line behavior. A JSON value without a terminating LF is invalid.
type frameReader struct {
	reader *bufio.Reader
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{reader: bufio.NewReaderSize(r, MaxFrameBytes+1)}
}

func (r *frameReader) read() ([]byte, error) {
	var frame []byte
	for {
		part, err := r.reader.ReadSlice('\n')
		if len(frame)+len(part) > MaxFrameBytes+1 {
			return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrProtocol, MaxFrameBytes)
		}
		frame = append(frame, part...)
		switch {
		case err == nil:
			if len(frame) == 0 || frame[len(frame)-1] != '\n' {
				return nil, fmt.Errorf("%w: frame is not LF terminated", ErrProtocol)
			}
			frame = frame[:len(frame)-1]
			if len(frame) == 0 {
				return nil, fmt.Errorf("%w: empty frame", ErrProtocol)
			}
			if !utf8.Valid(frame) {
				return nil, fmt.Errorf("%w: frame is not valid UTF-8", ErrProtocol)
			}
			return frame, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(frame) == 0 {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("%w: unterminated final frame", ErrProtocol)
		default:
			return nil, err
		}
	}
}

func decodeRequest(frame []byte) (any, error) {
	if err := rejectDuplicateTopLevelFields(frame); err != nil {
		return nil, err
	}
	var envelope requestEnvelope
	if err := json.Unmarshal(frame, &envelope); err != nil {
		return nil, fmt.Errorf("%w: malformed JSON: %v", ErrProtocol, err)
	}
	if envelope.V != ProtocolVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrProtocol, envelope.V)
	}

	switch envelope.Type {
	case messageHello:
		var request HelloRequest
		if err := decodeStrict(frame, &request); err != nil {
			return nil, err
		}
		return request, nil
	case messageAuthorize:
		var request AuthorizeRequest
		if err := decodeStrict(frame, &request); err != nil {
			return nil, err
		}
		return request, nil
	case messageResolve:
		var request ResolveRequest
		if err := decodeStrict(frame, &request); err != nil {
			return nil, err
		}
		return request, nil
	case messageCancel:
		var request CancelRequest
		if err := decodeStrict(frame, &request); err != nil {
			return nil, err
		}
		return request, nil
	default:
		return nil, fmt.Errorf("%w: unsupported message type %q", ErrProtocol, envelope.Type)
	}
}

func decodeStrict(frame []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("%w: invalid message: %v", ErrProtocol, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrProtocol)
		}
		return fmt.Errorf("%w: trailing JSON data: %v", ErrProtocol, err)
	}
	return nil
}

func rejectDuplicateTopLevelFields(frame []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	start, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: malformed JSON: %v", ErrProtocol, err)
	}
	if delimiter, ok := start.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%w: frame must be a JSON object", ErrProtocol)
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: malformed object key: %v", ErrProtocol, err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("%w: object key is not a string", ErrProtocol)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: duplicate field %q", ErrProtocol, key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("%w: malformed field %q: %v", ErrProtocol, key, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%w: malformed object: %v", ErrProtocol, err)
	}
	return ensureJSONEOF(decoder)
}

func writeFrame(w io.Writer, message any) error {
	frame, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal protocol frame: %w", err)
	}
	if len(frame) > MaxFrameBytes {
		return fmt.Errorf("protocol response exceeds %d bytes", MaxFrameBytes)
	}
	frame = append(frame, '\n')
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
