package detached

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const RecoverySchemaVersion = 1

const (
	LifecycleProvisioning = "provisioning"
	LifecycleRecovering   = "recovering"
	LifecycleReady        = "ready"
	LifecycleDegraded     = "degraded"
	LifecycleFinalizing   = "finalizing"
	LifecycleStopping     = "stopping"
	LifecycleStopped      = "stopped"
	LifecycleFinalized    = "finalized"
	LifecycleFailed       = "failed"
)

var (
	ErrRecoveryManifestInvalid  = errors.New("invalid detached recovery manifest")
	ErrSupervisorAlreadyRunning = errors.New("detached supervisor is already running")
)

// LaunchSpec is the non-secret information required to recreate the exact
// supervisor process. Environment values remain in the private EnvironmentFile;
// they are deliberately not duplicated in this manifest.
type LaunchSpec struct {
	Executable      string `json:"executable"`
	ConfigPath      string `json:"config_path,omitempty"`
	WorkingDir      string `json:"working_dir"`
	EnvironmentFile string `json:"environment_file"`
	LogFile         string `json:"log_file"`
	SystemdUnit     string `json:"systemd_unit,omitempty"`
	UsesSystemd     bool   `json:"uses_systemd"`
	PrivateTmp      bool   `json:"private_tmp"`
}

type ShadowRootRecovery struct {
	Name string `json:"name"`
	Real string `json:"real"`
	Work string `json:"work"`
}

type ShadowRecovery struct {
	Real      string               `json:"real"`
	Work      string               `json:"work"`
	Home      string               `json:"home"`
	Tmp       string               `json:"tmp"`
	Roots     []ShadowRootRecovery `json:"roots,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
}

type NethelperRecovery struct {
	SocketPath          string `json:"socket_path"`
	CredentialFile      string `json:"credential_file"`
	BootstrapResultPath string `json:"bootstrap_result_path"`
	Generation          uint64 `json:"generation"`
}

type MutableSessionState struct {
	Cwd                   string            `json:"cwd,omitempty"`
	Environment           map[string]string `json:"environment,omitempty"`
	VolatileEnvironment   []string          `json:"volatile_environment,omitempty"`
	DirenvRefreshRequired bool              `json:"direnv_refresh_required,omitempty"`
}

type InflightCommand struct {
	CommandID            string    `json:"command_id"`
	Operation            string    `json:"operation,omitempty"`
	ParentID             string    `json:"parent_id,omitempty"`
	AdmittedAt           time.Time `json:"admitted_at"`
	StartedAt            time.Time `json:"started_at,omitempty"`
	Sensitive            bool      `json:"sensitive,omitempty"`
	ExternalProcess      bool      `json:"external_process,omitempty"`
	PID                  int       `json:"pid,omitempty"`
	ProcessGroupID       int       `json:"process_group_id,omitempty"`
	ProcessStartIdentity string    `json:"process_start_identity,omitempty"`
	BootID               string    `json:"boot_id,omitempty"`
}

// RecoveryManifest is the versioned, durable authority for exact-session
// recreation. It contains creation and enforcement inputs, but never command
// arguments, command output, helper credential values, or arbitrary secret
// environment values.
type RecoveryManifest struct {
	SchemaVersion int                        `json:"schema_version"`
	SessionID     string                     `json:"session_id"`
	State         string                     `json:"state"`
	CreatedAt     time.Time                  `json:"created_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
	Request       types.CreateSessionRequest `json:"request"`
	Launch        LaunchSpec                 `json:"launch"`

	SessionCreatedAt time.Time           `json:"session_created_at,omitempty"`
	PolicyDigest     string              `json:"policy_digest,omitempty"`
	Shadow           *ShadowRecovery     `json:"shadow,omitempty"`
	Mutable          MutableSessionState `json:"mutable,omitempty"`
	ScopedApprovals  json.RawMessage     `json:"scoped_approvals,omitempty"`
	OutputArtifacts  []string            `json:"output_artifacts,omitempty"`
	Inflight         []InflightCommand   `json:"inflight,omitempty"`
	Interrupted      []InflightCommand   `json:"interrupted,omitempty"`
	Generation       uint64              `json:"generation"`
	IncarnationID    string              `json:"incarnation_id,omitempty"`
	// NethelperGeneration is retained for protocol-v2 manifests written before
	// the path+generation record was made one atomic authority.
	NethelperGeneration uint64             `json:"nethelper_generation,omitempty"`
	Nethelper           *NethelperRecovery `json:"nethelper,omitempty"`
	LastError           string             `json:"last_error,omitempty"`
	LastFailureAt       time.Time          `json:"last_failure_at,omitempty"`
	FinalizedAt         time.Time          `json:"finalized_at,omitempty"`
}

func RecoveryManifestPath(stateDir string) string {
	return filepath.Join(stateDir, "recovery.json")
}

func NewRecoveryManifest(sessionID string, req types.CreateSessionRequest, launch LaunchSpec, now time.Time) RecoveryManifest {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	return RecoveryManifest{
		SchemaVersion: RecoverySchemaVersion,
		SessionID:     strings.TrimSpace(sessionID),
		State:         LifecycleProvisioning,
		CreatedAt:     now,
		UpdatedAt:     now,
		Request:       req,
		Launch:        launch,
	}
}

func validateRecoveryManifest(manifest RecoveryManifest) error {
	if manifest.SchemaVersion != RecoverySchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %d", ErrRecoveryManifestInvalid, manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.SessionID) == "" || manifest.Request.ID != manifest.SessionID {
		return fmt.Errorf("%w: session identity mismatch", ErrRecoveryManifestInvalid)
	}
	if strings.TrimSpace(manifest.Request.Workspace) == "" {
		return fmt.Errorf("%w: request workspace is empty", ErrRecoveryManifestInvalid)
	}
	switch manifest.State {
	case LifecycleProvisioning, LifecycleRecovering, LifecycleReady, LifecycleDegraded,
		LifecycleFinalizing, LifecycleStopping, LifecycleStopped, LifecycleFinalized, LifecycleFailed:
	default:
		return fmt.Errorf("%w: unsupported lifecycle state %q", ErrRecoveryManifestInvalid, manifest.State)
	}
	if strings.TrimSpace(manifest.Launch.Executable) == "" || !filepath.IsAbs(manifest.Launch.Executable) {
		return fmt.Errorf("%w: launch executable must be absolute", ErrRecoveryManifestInvalid)
	}
	if strings.TrimSpace(manifest.Launch.WorkingDir) == "" || !filepath.IsAbs(manifest.Launch.WorkingDir) {
		return fmt.Errorf("%w: launch working directory must be absolute", ErrRecoveryManifestInvalid)
	}
	if strings.TrimSpace(manifest.Launch.EnvironmentFile) == "" || !filepath.IsAbs(manifest.Launch.EnvironmentFile) {
		return fmt.Errorf("%w: launch environment file must be absolute", ErrRecoveryManifestInvalid)
	}
	if manifest.Nethelper != nil {
		binding := manifest.Nethelper
		if manifest.NethelperGeneration > 0 && manifest.NethelperGeneration != binding.Generation {
			return fmt.Errorf("%w: nethelper recovery generations differ", ErrRecoveryManifestInvalid)
		}
		if binding.Generation == 0 || !filepath.IsAbs(binding.SocketPath) || !filepath.IsAbs(binding.CredentialFile) || !filepath.IsAbs(binding.BootstrapResultPath) ||
			filepath.Clean(binding.SocketPath) != binding.SocketPath || filepath.Clean(binding.CredentialFile) != binding.CredentialFile || filepath.Clean(binding.BootstrapResultPath) != binding.BootstrapResultPath ||
			strings.ContainsAny(binding.SocketPath+binding.CredentialFile+binding.BootstrapResultPath, "\x00\r\n") {
			return fmt.Errorf("%w: nethelper recovery identity is invalid", ErrRecoveryManifestInvalid)
		}
	}
	for _, command := range append(append([]InflightCommand(nil), manifest.Inflight...), manifest.Interrupted...) {
		if strings.TrimSpace(command.CommandID) == "" || len(command.CommandID) > 128 || strings.ContainsAny(command.CommandID, "\x00\r\n") {
			return fmt.Errorf("%w: command journal contains an invalid identity", ErrRecoveryManifestInvalid)
		}
		if len(command.ParentID) > 128 || strings.ContainsAny(command.ParentID, "\x00\r\n") {
			return fmt.Errorf("%w: command %s has an invalid parent identity", ErrRecoveryManifestInvalid, command.CommandID)
		}
		if command.ExternalProcess && (command.PID <= 0 || command.ProcessGroupID != command.PID) {
			return fmt.Errorf("%w: command %s has invalid process-group identity", ErrRecoveryManifestInvalid, command.CommandID)
		}
		if (command.ProcessStartIdentity == "") != (command.BootID == "") {
			return fmt.Errorf("%w: command %s has incomplete process identity", ErrRecoveryManifestInvalid, command.CommandID)
		}
	}
	return nil
}

func WriteRecoveryManifest(stateDir string, manifest RecoveryManifest) error {
	if err := validateRecoveryManifest(manifest); err != nil {
		return err
	}
	manifest.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode detached recovery manifest: %w", err)
	}
	if err := atomicWritePrivateFile(RecoveryManifestPath(stateDir), append(data, '\n')); err != nil {
		return fmt.Errorf("write detached recovery manifest: %w", err)
	}
	return nil
}

func ReadRecoveryManifest(stateDir string) (RecoveryManifest, error) {
	path := RecoveryManifestPath(stateDir)
	data, err := readProtectedRegularFile(path, 16<<20)
	if err != nil {
		return RecoveryManifest{}, fmt.Errorf("read detached recovery manifest at %s: %w", path, err)
	}
	var manifest RecoveryManifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return RecoveryManifest{}, fmt.Errorf("%w at %s: %v", ErrRecoveryManifestInvalid, path, err)
	}
	if err := validateRecoveryManifest(manifest); err != nil {
		return RecoveryManifest{}, fmt.Errorf("%w at %s", err, path)
	}
	return manifest, nil
}

// Runtime coordinates one supervisor incarnation with its durable recovery and
// discovery records. All mutations are serialized and atomically replaced.
type Runtime struct {
	mu                 sync.Mutex
	stateDir           string
	manifest           RecoveryManifest
	metadata           Metadata
	recovery           bool
	started            time.Time
	pendingEnvironment map[string]struct{}
	pendingDirenv      bool
}

func BeginRuntime(stateDir string, pid int, startIdentity, bootID string, now time.Time) (*Runtime, error) {
	manifest, err := ReadRecoveryManifest(stateDir)
	if err != nil {
		return nil, err
	}
	meta, _, err := ReadMetadataFromRoot(filepath.Dir(stateDir), manifest.SessionID)
	if err != nil {
		return nil, err
	}
	if meta.SessionID != manifest.SessionID {
		return nil, fmt.Errorf("%w: metadata and recovery identities differ", ErrRecoveryManifestInvalid)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	recovery := manifest.State != LifecycleProvisioning
	// A graceful failure during pre-serve provisioning may have changed the
	// lifecycle to failed without ever advertising or accepting work. It has no
	// durable session identity to reopen and is safe to retry as provisioning;
	// treating it as recovery would require a shadow identity that could not yet
	// have been committed. Once either identity field exists, require both and
	// recover fail-closed rather than silently recopying a served workspace.
	if recovery && manifest.SessionCreatedAt.IsZero() && strings.TrimSpace(manifest.PolicyDigest) == "" {
		if manifest.State != LifecycleFailed {
			return nil, fmt.Errorf("%w: non-failed lifecycle lacks durable session readiness identity", ErrRecoveryManifestInvalid)
		}
		recovery = false
	}
	if manifest.SessionCreatedAt.IsZero() != (strings.TrimSpace(manifest.PolicyDigest) == "") {
		return nil, fmt.Errorf("%w: incomplete durable session readiness identity", ErrRecoveryManifestInvalid)
	}
	if manifest.State == LifecycleFinalizing || manifest.State == LifecycleStopping || manifest.State == LifecycleStopped || manifest.State == LifecycleFinalized {
		return nil, fmt.Errorf("detached session %s is %s and cannot be restarted", manifest.SessionID, manifest.State)
	}
	manifest.Generation++
	manifest.IncarnationID = uuid.NewString()
	manifest.State = LifecycleRecovering
	if !recovery {
		manifest.State = LifecycleProvisioning
	}
	manifest.LastError = ""
	manifest.UpdatedAt = now

	meta.ProtocolVersion = ProtocolVersion
	meta.State = manifest.State
	meta.OwnerPID = pid
	meta.OwnerStartIdentity = startIdentity
	meta.BootID = bootID
	meta.Generation = manifest.Generation
	meta.IncarnationID = manifest.IncarnationID
	meta.IncarnationStartedAt = now
	meta.HeartbeatAt = now
	meta.LastError = ""

	runtime := &Runtime{stateDir: stateDir, manifest: manifest, metadata: meta, recovery: recovery, started: now}
	if recovery {
		runtime.pendingEnvironment = make(map[string]struct{}, len(manifest.Mutable.VolatileEnvironment))
		for _, name := range manifest.Mutable.VolatileEnvironment {
			runtime.pendingEnvironment[name] = struct{}{}
		}
		runtime.pendingDirenv = manifest.Mutable.DirenvRefreshRequired
	}
	if err := runtime.persistLocked(); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *Runtime) StateDir() string { return r.stateDir }
func (r *Runtime) IsRecovery() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recovery
}

func (r *Runtime) Manifest() RecoveryManifest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneRecoveryManifest(r.manifest)
}

func (r *Runtime) Metadata() Metadata {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneMetadata(r.metadata)
}

// SetControlCredential installs the protected detached-control credential read
// from metadata by the trusted launcher. It is never sourced from environment.
func (r *Runtime) SetControlCredential(credential string) error {
	credential = strings.TrimSpace(credential)
	if credential == "" || strings.ContainsAny(credential, "\x00\r\n") {
		return fmt.Errorf("detached control credential is invalid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := strings.TrimSpace(r.metadata.EventToken); existing != "" && existing != credential {
		return fmt.Errorf("detached control credential does not match protected metadata")
	}
	r.metadata.EventToken = credential
	return nil
}

func (r *Runtime) persistLocked() error {
	if err := WriteRecoveryManifest(r.stateDir, r.manifest); err != nil {
		return err
	}
	if err := WriteMetadata(r.stateDir, r.metadata); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) MarkReady(session types.Session, policyDigest string, network *NetworkEnforcement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	r.manifest.State = LifecycleReady
	r.manifest.LastError = ""
	r.manifest.SessionCreatedAt = session.CreatedAt
	r.manifest.PolicyDigest = strings.TrimSpace(policyDigest)
	if session.Shadow != nil {
		shadow := &ShadowRecovery{
			Real: session.Shadow.Real, Work: session.Shadow.Work, Home: session.Shadow.Home,
			Tmp: session.Shadow.Tmp, CreatedAt: session.Shadow.CreatedAt,
		}
		for _, root := range session.Shadow.Roots {
			shadow.Roots = append(shadow.Roots, ShadowRootRecovery{Name: root.Name, Real: root.Real, Work: root.Work})
		}
		r.manifest.Shadow = shadow
	}
	r.manifest.UpdatedAt = now
	r.metadata.State = LifecycleReady
	r.metadata.CreatedAt = session.CreatedAt
	r.metadata.Policy = session.Policy
	r.metadata.RealWorkspace = session.Workspace
	r.metadata.WorkspaceMode = session.WorkspaceMode
	r.metadata.Worktree = session.WorkspaceMount
	r.metadata.RuntimeHome = session.RuntimeHome
	r.metadata.RuntimeTmp = session.RuntimeTmp
	r.metadata.ProcessHome = session.ProcessHome
	r.metadata.RuntimeHomeMode = session.RuntimeHomeMode
	r.metadata.EnvBaseMode = session.EnvBaseMode
	r.metadata.EnvInherit = append([]string(nil), session.EnvInherit...)
	r.metadata.HeartbeatAt = now
	r.metadata.LastError = ""
	if network != nil {
		copy := *network
		copy.Normalize()
		r.metadata.NetworkEnforcement = &copy
	}
	if session.Shadow != nil {
		r.metadata.WorkspaceRoots = nil
		for _, root := range session.Shadow.Roots {
			r.metadata.WorkspaceRoots = append(r.metadata.WorkspaceRoots, WorkspaceRoot{Name: root.Name, Real: root.Real, Work: root.Work})
		}
	}
	return r.persistLocked()
}

func (r *Runtime) MarkDegraded(reason string, network *NetworkEnforcement) error {
	return r.markState(LifecycleDegraded, reason, network)
}

func (r *Runtime) MarkFailed(reason string) error {
	return r.markState(LifecycleFailed, reason, nil)
}

func (r *Runtime) markState(state, reason string, network *NetworkEnforcement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A durable stop decision is absorbing. In particular, concurrent shutdown
	// errors must not rewrite stopping as failed and make an expired supervisor
	// eligible for service-manager recovery.
	switch r.manifest.State {
	case LifecycleStopping:
		if state != LifecycleStopping && state != LifecycleStopped {
			return fmt.Errorf("refusing detached lifecycle transition from %s to %s", r.manifest.State, state)
		}
	case LifecycleStopped, LifecycleFinalized:
		if state != r.manifest.State {
			return fmt.Errorf("refusing detached lifecycle transition from terminal %s to %s", r.manifest.State, state)
		}
	}
	now := time.Now().UTC()
	r.manifest.State = state
	r.manifest.LastError = boundedReason(reason)
	r.manifest.UpdatedAt = now
	if state == LifecycleFailed {
		r.manifest.LastFailureAt = now
	}
	r.metadata.State = state
	r.metadata.LastError = boundedReason(reason)
	r.metadata.HeartbeatAt = now
	switch state {
	case LifecycleStopping, LifecycleStopped, LifecycleFinalized:
		r.metadata.EventToken = ""
	}
	if network != nil {
		copy := *network
		copy.Normalize()
		r.metadata.NetworkEnforcement = &copy
	}
	if err := r.persistLocked(); err != nil {
		return err
	}
	switch state {
	case LifecycleStopping:
		_ = RemoveHeartbeat(r.stateDir)
	case LifecycleStopped, LifecycleFinalized:
		_ = RemoveHeartbeat(r.stateDir)
		_ = os.Remove(r.manifest.Launch.EnvironmentFile)
	}
	return nil
}

func (r *Runtime) MarkFinalizing() error {
	return r.markState(LifecycleFinalizing, "review workspace finalization is in progress", nil)
}
func (r *Runtime) MarkStopping() error { return r.markState(LifecycleStopping, "", nil) }
func (r *Runtime) MarkStopped() error  { return r.markState(LifecycleStopped, "", nil) }
func (r *Runtime) MarkFinalized() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.manifest.State != LifecycleFinalizing {
		return fmt.Errorf("refusing detached lifecycle transition from %s to %s", r.manifest.State, LifecycleFinalized)
	}
	now := time.Now().UTC()
	r.manifest.FinalizedAt = now
	r.manifest.State = LifecycleFinalized
	r.manifest.LastError = "review workspace was finalized"
	r.manifest.UpdatedAt = now
	r.metadata.State = LifecycleFinalized
	r.metadata.LastError = "review workspace was finalized"
	r.metadata.HeartbeatAt = now
	r.metadata.EventToken = ""
	if err := r.persistLocked(); err != nil {
		return err
	}
	_ = RemoveHeartbeat(r.stateDir)
	_ = os.Remove(r.manifest.Launch.EnvironmentFile)
	return nil
}

func (r *Runtime) Heartbeat(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.metadata.State {
	case LifecycleStopping, LifecycleStopped, LifecycleFinalized:
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r.metadata.HeartbeatAt = now.UTC()
	return WriteHeartbeat(r.stateDir, r.metadata)
}

func (r *Runtime) RecordCommand(command InflightCommand) error {
	if strings.TrimSpace(command.CommandID) == "" {
		return fmt.Errorf("command id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.manifest.Inflight {
		if r.manifest.Inflight[i].CommandID == command.CommandID {
			r.manifest.Inflight[i] = command
			return WriteRecoveryManifest(r.stateDir, r.manifest)
		}
	}
	r.manifest.Inflight = append(r.manifest.Inflight, command)
	return WriteRecoveryManifest(r.stateDir, r.manifest)
}

func (r *Runtime) MarkCommandProcess(commandID string, pid, processGroupID int) error {
	if pid <= 0 || processGroupID <= 0 {
		return fmt.Errorf("command process identity is incomplete")
	}
	startIdentity, bootID, identityErr := CurrentProcessIdentity(pid)
	if identityErr != nil {
		return fmt.Errorf("capture command process identity: %w", identityErr)
	}
	if (strings.TrimSpace(startIdentity) == "") != (strings.TrimSpace(bootID) == "") {
		return fmt.Errorf("command process identity is incomplete")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.manifest.Inflight {
		if r.manifest.Inflight[i].CommandID == commandID {
			r.manifest.Inflight[i].ExternalProcess = true
			r.manifest.Inflight[i].PID = pid
			r.manifest.Inflight[i].ProcessGroupID = processGroupID
			r.manifest.Inflight[i].ProcessStartIdentity = startIdentity
			r.manifest.Inflight[i].BootID = bootID
			return WriteRecoveryManifest(r.stateDir, r.manifest)
		}
	}
	return fmt.Errorf("command %s is absent from the detached admission journal", commandID)
}

func (r *Runtime) MarkCommandStarted(commandID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.manifest.Inflight {
		if r.manifest.Inflight[i].CommandID == commandID {
			if at.IsZero() {
				at = time.Now().UTC()
			}
			r.manifest.Inflight[i].StartedAt = at.UTC()
			return WriteRecoveryManifest(r.stateDir, r.manifest)
		}
	}
	return nil
}

func (r *Runtime) CompleteCommand(commandID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.manifest.Inflight[:0]
	for _, command := range r.manifest.Inflight {
		if command.CommandID != commandID {
			out = append(out, command)
		}
	}
	r.manifest.Inflight = out
	return WriteRecoveryManifest(r.stateDir, r.manifest)
}

// TakeInterrupted atomically moves commands left by a dead incarnation into a
// durable interrupted list. The caller then emits terminal audit evidence.
func (r *Runtime) TakeInterrupted() ([]InflightCommand, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.recovery || len(r.manifest.Inflight) == 0 {
		return nil, nil
	}
	commands := append([]InflightCommand(nil), r.manifest.Inflight...)
	r.manifest.Interrupted = append(r.manifest.Interrupted, commands...)
	r.manifest.Inflight = nil
	if err := WriteRecoveryManifest(r.stateDir, r.manifest); err != nil {
		return nil, err
	}
	return commands, nil
}

func (r *Runtime) UpdateMutable(state MutableSessionState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state.Environment = cloneStringMap(state.Environment)
	state.VolatileEnvironment = cleanSortedStrings(state.VolatileEnvironment)
	r.manifest.Mutable = state
	return WriteRecoveryManifest(r.stateDir, r.manifest)
}

func (r *Runtime) AcknowledgeEnvironment(names []string, direnv bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range names {
		delete(r.pendingEnvironment, name)
	}
	if direnv {
		r.pendingDirenv = false
	}
	if len(r.pendingEnvironment) == 0 && !r.pendingDirenv && r.metadata.NetworkEnforcement != nil {
		network := r.metadata.NetworkEnforcement
		if network.Requested != NetworkEnforcementRequestStrict || network.Ready() {
			r.manifest.State = LifecycleReady
			r.manifest.LastError = ""
			r.metadata.State = LifecycleReady
			r.metadata.LastError = ""
		}
	}
	return r.persistLocked()
}

func (r *Runtime) UpdateOutputArtifacts(paths []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifest.OutputArtifacts = cleanSortedStrings(paths)
	return WriteRecoveryManifest(r.stateDir, r.manifest)
}

func (r *Runtime) UpdateScopedApprovals(raw json.RawMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifest.ScopedApprovals = append(json.RawMessage(nil), raw...)
	return WriteRecoveryManifest(r.stateDir, r.manifest)
}

func (r *Runtime) UpdateNethelperGeneration(generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifest.NethelperGeneration = generation
	return WriteRecoveryManifest(r.stateDir, r.manifest)
}

// UpdateNethelperBinding commits replacement control paths and generation in
// one manifest write before rotating the service EnvironmentFile. A crash
// between those writes is safe because the next supervisor applies this
// manifest authority before loading the helper credential.
func (r *Runtime) UpdateNethelperBinding(socketPath, credentialFile, bootstrapResultPath string, generation uint64) error {
	binding := &NethelperRecovery{
		SocketPath: socketPath, CredentialFile: credentialFile,
		BootstrapResultPath: bootstrapResultPath, Generation: generation,
	}
	probe := r.Manifest()
	probe.Nethelper = binding
	if err := validateRecoveryManifest(probe); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifest.Nethelper = binding
	r.manifest.NethelperGeneration = generation
	if err := WriteRecoveryManifest(r.stateDir, r.manifest); err != nil {
		return err
	}
	updates := map[string]string{
		"AGENTSH_NETHELPER_SOCKET":           socketPath,
		"AGENTSH_NETHELPER_CREDENTIAL_FILE":  credentialFile,
		"AGENTSH_NETHELPER_BOOTSTRAP_RESULT": bootstrapResultPath,
	}
	return updateServiceEnvironmentFile(r.manifest.Launch.EnvironmentFile, updates)
}

func (r *Runtime) NethelperRecoveryEnvironment() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.manifest.Nethelper == nil {
		return nil
	}
	return map[string]string{
		"AGENTSH_NETHELPER_SOCKET":           r.manifest.Nethelper.SocketPath,
		"AGENTSH_NETHELPER_CREDENTIAL_FILE":  r.manifest.Nethelper.CredentialFile,
		"AGENTSH_NETHELPER_BOOTSTRAP_RESULT": r.manifest.Nethelper.BootstrapResultPath,
	}
}

func RestartSafeEnvironmentName(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "PATH", "SSH_AUTH_SOCK", "SSH_CONFIG_FILE", "GIT_SSH_COMMAND", "RSYNC_RSH",
		"HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
		"PI_CODING_AGENT_DIR", "AGENTSH_SUBAGENT_COMMAND", "AGENTSH_SUBAGENT_ARGS", "AGENTSH_SUBAGENT_TASK_MODE",
		"AGENTSH_SUBAGENT_PROTOCOL", "AGENTSH_SUBAGENT_MAX_DEPTH", "AGENTSH_SUBAGENT_RUNTIME":
		return true
	default:
		return false
	}
}

func (r *Runtime) ScrubServiceEnvironment(names []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(names) == 0 {
		return nil
	}
	path := r.manifest.Launch.EnvironmentFile
	data, err := readProtectedRegularFile(path, 4<<20)
	if err != nil {
		return err
	}
	assignments, order, err := parsePrivateEnvironmentFile(string(data))
	if err != nil {
		return err
	}
	for _, name := range names {
		delete(assignments, name)
	}
	var content strings.Builder
	for _, name := range order {
		value, ok := assignments[name]
		if !ok {
			continue
		}
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		fmt.Fprintf(&content, "%s=\"%s\"\n", name, value)
	}
	return atomicWritePrivateFile(path, []byte(content.String()))
}

// UpdateServiceEnvironment atomically rotates non-secret control paths used on
// the next supervisor incarnation. Secret values are neither accepted nor
// written by this method.
func (r *Runtime) UpdateServiceEnvironment(updates map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return updateServiceEnvironmentFile(r.manifest.Launch.EnvironmentFile, updates)
}

func updateServiceEnvironmentFile(path string, updates map[string]string) error {
	data, err := readProtectedRegularFile(path, 4<<20)
	if err != nil {
		return fmt.Errorf("read detached supervisor environment: %w", err)
	}
	assignments, order, err := parsePrivateEnvironmentFile(string(data))
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		"AGENTSH_NETHELPER_SOCKET":           true,
		"AGENTSH_NETHELPER_CREDENTIAL_FILE":  true,
		"AGENTSH_NETHELPER_BOOTSTRAP_RESULT": true,
	}
	for name, value := range updates {
		if !allowed[name] || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("unsupported detached supervisor environment update %q", name)
		}
		if _, exists := assignments[name]; !exists {
			order = append(order, name)
		}
		assignments[name] = value
	}
	var content strings.Builder
	for _, name := range order {
		value, ok := assignments[name]
		if !ok {
			continue
		}
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		fmt.Fprintf(&content, "%s=\"%s\"\n", name, value)
	}
	if err := atomicWritePrivateFile(path, []byte(content.String())); err != nil {
		return fmt.Errorf("write detached supervisor environment: %w", err)
	}
	return nil
}

func ReadServiceEnvironment(path string) ([]string, error) {
	data, err := readProtectedRegularFile(path, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("detached supervisor environment is not a protected regular file: %w", err)
	}
	assignments, order, err := parsePrivateEnvironmentFile(string(data))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		out = append(out, name+"="+assignments[name])
	}
	return out, nil
}

func parsePrivateEnvironmentFile(content string) (map[string]string, []string, error) {
	assignments := make(map[string]string)
	var order []string
	for lineNumber, line := range strings.Split(content, "\n") {
		if line == "" {
			continue
		}
		name, encoded, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != name || name == "" || strings.ContainsAny(name, " \t\r\n") || len(encoded) < 2 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
			return nil, nil, fmt.Errorf("invalid detached supervisor environment line %d", lineNumber+1)
		}
		encoded = encoded[1 : len(encoded)-1]
		var value strings.Builder
		escaped := false
		for _, char := range encoded {
			if escaped {
				if char != '\\' && char != '"' {
					return nil, nil, fmt.Errorf("invalid environment escape on line %d", lineNumber+1)
				}
				value.WriteRune(char)
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			value.WriteRune(char)
		}
		if escaped {
			return nil, nil, fmt.Errorf("trailing environment escape on line %d", lineNumber+1)
		}
		if _, duplicate := assignments[name]; duplicate {
			return nil, nil, fmt.Errorf("duplicate detached supervisor environment name %q", name)
		}
		assignments[name] = value.String()
		order = append(order, name)
	}
	return assignments, order, nil
}

func (r *Runtime) UpdateNetwork(network *NetworkEnforcement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if network == nil {
		return nil
	}
	copy := *network
	copy.Normalize()
	r.metadata.NetworkEnforcement = &copy
	if (copy.Requested != NetworkEnforcementRequestStrict || copy.Ready()) && len(r.pendingEnvironment) == 0 && !r.pendingDirenv {
		r.manifest.State = LifecycleReady
		r.manifest.LastError = ""
		r.metadata.State = LifecycleReady
		r.metadata.LastError = ""
	} else if r.metadata.State != LifecycleFailed {
		r.manifest.State = LifecycleDegraded
		r.metadata.State = LifecycleDegraded
	}
	return r.persistLocked()
}

func (r *Runtime) CanRunRecoveryAction(action string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.metadata.State == LifecycleReady {
		return true
	}
	if action != "direnv_refresh" || !r.pendingDirenv || r.metadata.State != LifecycleDegraded {
		return false
	}
	network := r.metadata.NetworkEnforcement
	return network != nil && (network.Requested != NetworkEnforcementRequestStrict || network.Ready())
}

func (r *Runtime) RuntimeStatus() RuntimeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RuntimeStatus{
		ProtocolVersion:       ProtocolVersion,
		SessionID:             r.manifest.SessionID,
		LifecycleState:        r.metadata.State,
		Generation:            r.metadata.Generation,
		IncarnationID:         r.metadata.IncarnationID,
		OwnerPID:              r.metadata.OwnerPID,
		OwnerStartIdentity:    r.metadata.OwnerStartIdentity,
		BootID:                r.metadata.BootID,
		IncarnationStartedAt:  r.metadata.IncarnationStartedAt,
		HeartbeatAt:           r.metadata.HeartbeatAt,
		Recoverable:           r.manifest.State != LifecycleFinalizing && r.manifest.State != LifecycleStopping && r.manifest.State != LifecycleStopped && r.manifest.State != LifecycleFinalized,
		LastError:             r.metadata.LastError,
		RequiredEnvironment:   pendingEnvironmentNames(r.pendingEnvironment),
		DirenvRefreshRequired: r.pendingDirenv,
		NetworkEnforcement:    cloneNetwork(r.metadata.NetworkEnforcement),
	}
}

type RuntimeStatus struct {
	ProtocolVersion       int                 `json:"protocol_version"`
	SessionID             string              `json:"session_id"`
	LifecycleState        string              `json:"lifecycle_state"`
	Generation            uint64              `json:"generation"`
	IncarnationID         string              `json:"incarnation_id"`
	OwnerPID              int                 `json:"owner_pid"`
	OwnerStartIdentity    string              `json:"owner_start_identity,omitempty"`
	BootID                string              `json:"boot_id,omitempty"`
	IncarnationStartedAt  time.Time           `json:"incarnation_started_at"`
	HeartbeatAt           time.Time           `json:"heartbeat_at"`
	Recoverable           bool                `json:"recoverable"`
	LastError             string              `json:"last_error,omitempty"`
	RequiredEnvironment   []string            `json:"required_environment,omitempty"`
	DirenvRefreshRequired bool                `json:"direnv_refresh_required,omitempty"`
	NetworkEnforcement    *NetworkEnforcement `json:"network_enforcement,omitempty"`
}

// ReadTerminalRuntimeStatusFromRoot returns durable exact-session termination
// evidence after the supervisor socket is gone. The recovery manifest is the
// terminal authority: stop writes it only after the exact unit/process has
// stopped and the supervisor lock has been acquired. Metadata independently
// binds that authority to the captured protocol-v2 incarnation.
func ReadTerminalRuntimeStatusFromRoot(root, sessionID string) (RuntimeStatus, error) {
	meta, stateDir, err := ReadMetadataFromRoot(root, sessionID)
	if err != nil {
		return RuntimeStatus{}, err
	}
	manifest, err := ReadRecoveryManifest(stateDir)
	if err != nil {
		return RuntimeStatus{}, err
	}
	if meta.ProtocolVersion < ProtocolVersion || manifest.SessionID != sessionID ||
		meta.Generation == 0 || meta.Generation != manifest.Generation ||
		strings.TrimSpace(meta.IncarnationID) == "" || meta.IncarnationID != manifest.IncarnationID {
		return RuntimeStatus{}, fmt.Errorf("%w: terminal metadata and recovery identities differ", ErrRecoveryManifestInvalid)
	}
	if manifest.State != LifecycleStopped && manifest.State != LifecycleFinalized {
		return RuntimeStatus{}, fmt.Errorf("%w: detached session is not durably terminal", ErrRecoveryManifestInvalid)
	}
	return RuntimeStatus{
		ProtocolVersion: ProtocolVersion, SessionID: sessionID,
		LifecycleState: manifest.State, Generation: manifest.Generation,
		IncarnationID: manifest.IncarnationID, OwnerPID: meta.OwnerPID,
		OwnerStartIdentity: meta.OwnerStartIdentity, BootID: meta.BootID,
		IncarnationStartedAt: meta.IncarnationStartedAt, HeartbeatAt: meta.HeartbeatAt,
		Recoverable: false,
	}, nil
}

func cloneRecoveryManifest(in RecoveryManifest) RecoveryManifest {
	out := in
	out.Request.WorkspaceRoots = append([]types.WorkspaceRoot(nil), in.Request.WorkspaceRoots...)
	out.Request.EnvInherit = append([]string(nil), in.Request.EnvInherit...)
	out.Mutable.Environment = cloneStringMap(in.Mutable.Environment)
	out.Mutable.VolatileEnvironment = append([]string(nil), in.Mutable.VolatileEnvironment...)
	out.ScopedApprovals = append(json.RawMessage(nil), in.ScopedApprovals...)
	out.OutputArtifacts = append([]string(nil), in.OutputArtifacts...)
	out.Inflight = append([]InflightCommand(nil), in.Inflight...)
	out.Interrupted = append([]InflightCommand(nil), in.Interrupted...)
	if in.Shadow != nil {
		shadow := *in.Shadow
		shadow.Roots = append([]ShadowRootRecovery(nil), in.Shadow.Roots...)
		out.Shadow = &shadow
	}
	if in.Nethelper != nil {
		binding := *in.Nethelper
		out.Nethelper = &binding
	}
	return out
}

func cloneMetadata(in Metadata) Metadata {
	out := in
	out.WorkspaceRoots = append([]WorkspaceRoot(nil), in.WorkspaceRoots...)
	out.EnvInherit = append([]string(nil), in.EnvInherit...)
	out.NetworkEnforcement = cloneNetwork(in.NetworkEnforcement)
	return out
}

func cloneNetwork(in *NetworkEnforcement) *NetworkEnforcement {
	if in == nil {
		return nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var out NetworkEnforcement
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	out.Normalize()
	return &out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func pendingEnvironmentNames(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cleanSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func boundedReason(reason string) string {
	reason = strings.TrimSpace(reason)
	const max = 2048
	if len(reason) > max {
		return reason[:max] + "..."
	}
	return reason
}
