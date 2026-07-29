package composition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolVersion = 1
	Dialect         = "0.11.2"
	Mode            = "bubblewrap-0.11.2"

	BrokerFD   = 3
	PlanFD     = 4
	InjectFD   = 101
	AdapterFD  = 102
	SetupFDEnv = "AGENTSH_COMPOSITION_SETUP_FD"

	ChallengeType           = "challenge"
	NamespaceMapRequestType = "namespace-map"
)

type Challenge struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Nonce   string `json:"nonce"`
}

type NamespaceMapRequest struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Nonce   string `json:"nonce"`
}

type OperationType string

const (
	OperationDirectory OperationType = "directory"
	OperationBind      OperationType = "bind"
	OperationTmpfs     OperationType = "tmpfs"
	OperationProc      OperationType = "proc"
	OperationDev       OperationType = "dev"
	OperationDevBind   OperationType = "dev_bind_identity"
	OperationSymlink   OperationType = "symlink"
	OperationRemountRO OperationType = "remount_ro"
)

type Operation struct {
	Type      OperationType `json:"type"`
	Source    string        `json:"source,omitempty"`
	Target    string        `json:"target"`
	ReadOnly  bool          `json:"read_only,omitempty"`
	Recursive bool          `json:"recursive,omitempty"`
	Try       bool          `json:"try,omitempty"`
}

// NormalizedOperation is the bounded, parser-normalized operation shape used
// for audit and release-gate assertions. It contains only client-supplied mount
// plan paths and flags; payload arguments and environment values are excluded.
type NormalizedOperation struct {
	Index     int           `json:"index"`
	Type      OperationType `json:"type"`
	Source    string        `json:"source,omitempty"`
	Target    string        `json:"target"`
	ReadOnly  bool          `json:"read_only,omitempty"`
	Recursive bool          `json:"recursive,omitempty"`
	Try       bool          `json:"try,omitempty"`
}

// NormalizedPlanSnapshot captures the actual validated plan received by the
// broker, rather than inferring behavior from parser option counts.
type NormalizedPlanSnapshot struct {
	Version        int                   `json:"version"`
	Dialect        string                `json:"dialect"`
	Cwd            string                `json:"cwd"`
	UnsharePID     bool                  `json:"unshare_pid"`
	UnshareIPC     bool                  `json:"unshare_ipc"`
	UnshareUTS     bool                  `json:"unshare_uts"`
	UnshareCgroup  bool                  `json:"unshare_cgroup"`
	OperationCount int                   `json:"operation_count"`
	Operations     []NormalizedOperation `json:"operations"`
	Digest         string                `json:"digest"`
}

type Plan struct {
	Version int    `json:"version"`
	Dialect string `json:"dialect"`
	Nonce   string `json:"nonce,omitempty"`

	UnsharePID    bool `json:"unshare_pid"`
	UnshareIPC    bool `json:"unshare_ipc"`
	UnshareUTS    bool `json:"unshare_uts"`
	UnshareCgroup bool `json:"unshare_cgroup"`
	DieWithParent bool `json:"die_with_parent"`
	NewSession    bool `json:"new_session"`
	AsPID1        bool `json:"as_pid_1,omitempty"`

	Hostname string            `json:"hostname,omitempty"`
	Cwd      string            `json:"cwd,omitempty"`
	ClearEnv bool              `json:"clear_env,omitempty"`
	SetEnv   map[string]string `json:"set_env,omitempty"`
	UnsetEnv []string          `json:"unset_env,omitempty"`
	UID      *int              `json:"uid,omitempty"`
	GID      *int              `json:"gid,omitempty"`

	Operations []Operation `json:"operations"`
	Command    []string    `json:"command"`
}

// PathAlias describes one final mount-boundary attribution. An empty Source is
// a fresh-filesystem barrier: paths below Target must not inherit an enclosing
// bind alias. FreshWritable is set only for a broker-provisioned writable tmpfs;
// it lets the file monitor distinguish private synthetic writes from writes to
// an identity bind with the same visible and source spelling. These records
// never authorize mounts; they let the file monitor evaluate later accesses
// against both their visible and original source paths.
type PathAlias struct {
	Target        string
	Source        string
	FreshWritable bool
}

// PathSymlink records a symlink created by the reviewed plan so source
// attribution can normalize its visible target before applying bind aliases.
type PathSymlink struct {
	Target string
	Source string
}

// PathMappings is the bounded, post-commit attribution snapshot for one
// composed mount namespace.
type PathMappings struct {
	Aliases  []PathAlias
	Symlinks []PathSymlink
}

func SnapshotPlan(plan Plan) (NormalizedPlanSnapshot, error) {
	snapshot := NormalizedPlanSnapshot{
		Version:        plan.Version,
		Dialect:        plan.Dialect,
		Cwd:            plan.Cwd,
		UnsharePID:     plan.UnsharePID,
		UnshareIPC:     plan.UnshareIPC,
		UnshareUTS:     plan.UnshareUTS,
		UnshareCgroup:  plan.UnshareCgroup,
		OperationCount: len(plan.Operations),
		Operations:     make([]NormalizedOperation, len(plan.Operations)),
	}
	for index, operation := range plan.Operations {
		snapshot.Operations[index] = NormalizedOperation{
			Index:     index,
			Type:      operation.Type,
			Source:    operation.Source,
			Target:    operation.Target,
			ReadOnly:  operation.ReadOnly,
			Recursive: operation.Recursive,
			Try:       operation.Try,
		}
	}
	encoded, err := json.Marshal(struct {
		Version        int                   `json:"version"`
		Dialect        string                `json:"dialect"`
		Cwd            string                `json:"cwd"`
		UnsharePID     bool                  `json:"unshare_pid"`
		UnshareIPC     bool                  `json:"unshare_ipc"`
		UnshareUTS     bool                  `json:"unshare_uts"`
		UnshareCgroup  bool                  `json:"unshare_cgroup"`
		OperationCount int                   `json:"operation_count"`
		Operations     []NormalizedOperation `json:"operations"`
	}{
		Version:        snapshot.Version,
		Dialect:        snapshot.Dialect,
		Cwd:            snapshot.Cwd,
		UnsharePID:     snapshot.UnsharePID,
		UnshareIPC:     snapshot.UnshareIPC,
		UnshareUTS:     snapshot.UnshareUTS,
		UnshareCgroup:  snapshot.UnshareCgroup,
		OperationCount: snapshot.OperationCount,
		Operations:     snapshot.Operations,
	})
	if err != nil {
		return NormalizedPlanSnapshot{}, fmt.Errorf("encode normalized plan snapshot: %w", err)
	}
	digest := sha256.Sum256(encoded)
	snapshot.Digest = hex.EncodeToString(digest[:])
	return snapshot, nil
}

type Response struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func typedError(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validateUniqueJSONObject(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeNamespaceMapRequest(payload []byte, nonce string) (NamespaceMapRequest, error) {
	if err := validateUniqueJSONObject(payload); err != nil {
		return NamespaceMapRequest{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "decode namespace map request: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request NamespaceMapRequest
	if err := decoder.Decode(&request); err != nil {
		return NamespaceMapRequest{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "decode namespace map request: %v", err)
	}
	if request.Version != ProtocolVersion || request.Type != NamespaceMapRequestType || request.UID != 1 || request.GID != 1 || request.Nonce != nonce {
		return NamespaceMapRequest{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "invalid namespace map request")
	}
	return request, nil
}

func decodePlanRequest(payload []byte, nonce string, maxOperations int) (Plan, error) {
	if err := validateUniqueJSONObject(payload); err != nil {
		return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "decode plan: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "decode plan: %v", err)
	}
	if plan.Nonce != nonce {
		return Plan{}, typedError("E_COMPOSITION_REQUESTER_CHANGED", "mount-plan nonce does not match this one-shot channel")
	}
	if err := ValidatePlan(plan, maxOperations); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func ErrorResponse(err error) Response {
	if err == nil {
		return Response{OK: true}
	}
	if typed, ok := err.(*Error); ok {
		return Response{Code: typed.Code, Message: typed.Message}
	}
	return Response{Code: "E_COMPOSITION_COMMIT_FAILED", Message: err.Error()}
}
