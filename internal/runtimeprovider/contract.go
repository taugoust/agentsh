// Package runtimeprovider defines the versioned outer-runtime lifecycle used by
// detached AgentSH sessions. Providers own machine/process containment; the
// guest or native AgentSH supervisor continues to own semantic policy and tools.
package runtimeprovider

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
)

const (
	ContractVersion       = 1
	ManifestSchemaVersion = 1
	NativeProvider        = "native"
	DefaultProfile        = "native"
)

type State string

const (
	StateProvisioning State = "provisioning"
	StateRecovering   State = "recovering"
	StateReady        State = "ready"
	StateDegraded     State = "degraded"
	StateStopping     State = "stopping"
	StateStopped      State = "stopped"
	StateFailed       State = "failed"
)

type StopReason string

const (
	StopReasonUser           StopReason = "user"
	StopReasonStartupFailed  StopReason = "startup_failed"
	StopReasonRecoveryFailed StopReason = "recovery_failed"
)

// Request contains only validated logical inputs. Provider constructors carry
// operator-owned executable/profile configuration; callers cannot pass raw
// hypervisor arguments, shares, devices, or arbitrary host paths here.
type Request struct {
	SessionID string                     `json:"session_id"`
	Provider  string                     `json:"provider"`
	Profile   string                     `json:"profile"`
	StateDir  string                     `json:"state_dir"`
	Session   types.CreateSessionRequest `json:"session"`
}

func (r Request) Validate() error {
	if !validName(r.SessionID) || filepath.Base(r.SessionID) != r.SessionID {
		return fmt.Errorf("runtime request has invalid session identity")
	}
	if !validName(r.Provider) {
		return fmt.Errorf("runtime request has invalid provider %q", r.Provider)
	}
	if !validName(r.Profile) {
		return fmt.Errorf("runtime request has invalid profile %q", r.Profile)
	}
	if !filepath.IsAbs(r.StateDir) || filepath.Clean(r.StateDir) != r.StateDir || filepath.Base(r.StateDir) != r.SessionID {
		return fmt.Errorf("runtime request state directory must be clean, absolute, and bound to the exact session")
	}
	if r.Session.ID != r.SessionID {
		return fmt.Errorf("runtime request session identities differ")
	}
	if strings.TrimSpace(r.Session.Workspace) == "" || !filepath.IsAbs(r.Session.Workspace) {
		return fmt.Errorf("runtime request workspace must be absolute")
	}
	return nil
}

type Capabilities struct {
	ContractVersion int      `json:"contract_version"`
	Provider        string   `json:"provider"`
	Recoverable     bool     `json:"recoverable"`
	Transports      []string `json:"transports,omitempty"`
}

type Endpoint struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
}

func (e Endpoint) Validate() error {
	if !validName(e.Transport) || strings.TrimSpace(e.Address) == "" || strings.ContainsAny(e.Address, "\x00\r\n") {
		return fmt.Errorf("runtime endpoint is invalid")
	}
	if e.Transport == "unix" && (!filepath.IsAbs(e.Address) || filepath.Clean(e.Address) != e.Address) {
		return fmt.Errorf("runtime Unix endpoint must be clean and absolute")
	}
	return nil
}

type Identity struct {
	ContractVersion    int    `json:"contract_version"`
	Provider           string `json:"provider"`
	Profile            string `json:"profile"`
	SessionID          string `json:"session_id"`
	Generation         uint64 `json:"generation"`
	IncarnationID      string `json:"incarnation_id"`
	OwnerPID           int    `json:"owner_pid,omitempty"`
	OwnerStartIdentity string `json:"owner_start_identity,omitempty"`
	BootID             string `json:"boot_id,omitempty"`
}

func (i Identity) ValidateComplete() error {
	if i.ContractVersion != ContractVersion {
		return fmt.Errorf("runtime identity contract version %d is unsupported", i.ContractVersion)
	}
	if !validName(i.Provider) || !validName(i.Profile) || !validName(i.SessionID) || filepath.Base(i.SessionID) != i.SessionID {
		return fmt.Errorf("runtime identity names are invalid")
	}
	if i.Generation == 0 || strings.TrimSpace(i.IncarnationID) == "" || strings.ContainsAny(i.IncarnationID, "\x00\r\n") {
		return fmt.Errorf("runtime identity incarnation is incomplete")
	}
	if (i.OwnerStartIdentity == "") != (i.BootID == "") {
		return fmt.Errorf("runtime process identity is incomplete")
	}
	if i.OwnerPID < 0 {
		return fmt.Errorf("runtime owner PID is invalid")
	}
	return nil
}

type Status struct {
	Identity    Identity `json:"identity"`
	Endpoint    Endpoint `json:"endpoint"`
	State       State    `json:"state"`
	Ready       bool     `json:"ready"`
	Recoverable bool     `json:"recoverable"`
	LastError   string   `json:"last_error,omitempty"`
}

// Provider is the version-one runtime-provider contract. Open reconstructs a
// handle without starting or adopting anything; Recover is the only operation
// allowed to create a replacement incarnation from durable state.
type Provider interface {
	Name() string
	Preflight(context.Context, Request) (Capabilities, error)
	Start(context.Context, Request) (Instance, error)
	Open(context.Context, Manifest) (Instance, error)
	Recover(context.Context, Manifest) (Instance, error)
}

type Instance interface {
	Identity() Identity
	Endpoint() Endpoint
	Probe(context.Context) (Status, error)
	Stop(context.Context, StopReason) error
	Destroy(context.Context) error
}

type Registry struct {
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) (*Registry, error) {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("runtime provider is nil")
		}
		name := strings.TrimSpace(provider.Name())
		if !validName(name) {
			return nil, fmt.Errorf("runtime provider name %q is invalid", name)
		}
		if _, exists := r.providers[name]; exists {
			return nil, fmt.Errorf("runtime provider %q is registered more than once", name)
		}
		r.providers[name] = provider
	}
	return r, nil
}

func (r *Registry) Resolve(name string) (Provider, error) {
	if r == nil {
		return nil, fmt.Errorf("runtime provider registry is nil")
	}
	provider, ok := r.providers[strings.TrimSpace(name)]
	if !ok {
		return nil, fmt.Errorf("runtime provider %q is not registered", name)
	}
	return provider, nil
}

func ValidateName(value string) error {
	if !validName(value) {
		return fmt.Errorf("invalid runtime name %q", value)
	}
	return nil
}

func validName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n/\\") {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '.', char == '_', char == '-':
		default:
			return false
		}
	}
	return true
}
