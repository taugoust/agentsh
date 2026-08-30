package externalrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/netmonitor"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

const (
	HostEgressAuditName                = "network-egress.jsonl"
	HostEgressAuditMaxBytes      int64 = 64 << 20
	maxHostEgressPolicyBytes           = 4 * 1024 * 1024
	hostEgressMaxConnections           = 64
	hostEgressAuthTimeout              = 5 * time.Second
	hostEgressInitialHTTPTimeout       = 5 * time.Second
)

type hostEgressBroker interface {
	Done() <-chan struct{}
	Err() error
	Close() error
}

type runningHostEgressBroker struct {
	proxy *netmonitor.Proxy
	audit *hostNetworkAudit

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	err      error
}

func newRunningHostEgressBroker(proxy *netmonitor.Proxy, audit *hostNetworkAudit) (*runningHostEgressBroker, error) {
	if proxy == nil || audit == nil || proxy.Done() == nil || audit.Done() == nil {
		return nil, fmt.Errorf("host egress broker health dependencies are incomplete")
	}
	broker := &runningHostEgressBroker{
		proxy: proxy,
		audit: audit,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go broker.monitor()
	return broker, nil
}

func (b *runningHostEgressBroker) monitor() {
	var cause error
	select {
	case <-b.stop:
	case <-b.proxy.Done():
		if err := b.proxy.Err(); err != nil {
			cause = fmt.Errorf("host egress proxy failed: %w", err)
		} else {
			cause = fmt.Errorf("host egress proxy stopped unexpectedly")
		}
	case <-b.audit.Done():
		if err := b.audit.Err(); err != nil {
			cause = fmt.Errorf("host egress audit failed: %w", err)
		} else {
			cause = fmt.Errorf("host egress audit stopped unexpectedly")
		}
	}
	proxyErr := b.proxy.Close()
	auditErr := b.audit.Close()
	b.mu.Lock()
	b.err = errors.Join(cause, proxyErr, auditErr)
	b.mu.Unlock()
	close(b.done)
}

func (b *runningHostEgressBroker) Done() <-chan struct{} {
	if b == nil {
		return nil
	}
	return b.done
}

func (b *runningHostEgressBroker) Err() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *runningHostEgressBroker) Close() error {
	if b == nil {
		return nil
	}
	b.stopOnce.Do(func() { close(b.stop) })
	<-b.done
	return b.Err()
}

func startHostEgressBroker(ctx context.Context, profile Profile, layout HostMonitorLayout, sessionID string, expectedCID, egressPort uint32, egressToken string) (hostEgressBroker, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if profile.Schema != ProfileSchemaV3 || profile.HostEgress == nil || profile.Network.Transport != "vsock-explicit-proxy" || profile.Network.Enforcement != "host-broker-strict" {
		return nil, fmt.Errorf("host egress broker requires an explicit external runner v3 strict profile")
	}
	expectedPort, err := deriveHostEgressPort(profile, expectedCID)
	if err != nil || egressPort != expectedPort || !guestcontrol.ValidEgressAuthenticationToken(egressToken) {
		return nil, fmt.Errorf("host egress broker launch endpoint or token binding is invalid")
	}
	engine, err := compileHostEgressPolicy(*profile.HostEgress)
	if err != nil {
		return nil, err
	}
	audit, err := openHostNetworkAudit(layout.NetworkAudit)
	if err != nil {
		return nil, err
	}
	listener, err := listenHostEgressVSock(egressPort, expectedCID, egressToken, hostEgressAuthTimeout)
	if err != nil {
		return nil, errors.Join(err, audit.Close())
	}
	// No approval manager is installed for v3 yet. The policy engine preserves
	// approve decisions as enforced decisions, and netmonitor converts them to
	// deny before DNS or dial when the manager is nil.
	proxy, _, err := netmonitor.StartProxyWithOptions(netmonitor.ProxyStartOptions{
		Listener:              listener,
		StrictPublicEgress:    true,
		MaxConnections:        hostEgressMaxConnections,
		InitialRequestTimeout: hostEgressInitialHTTPTimeout,
	}, sessionID, nil, engine, nil, audit)
	if err != nil {
		return nil, errors.Join(err, listener.Close(), audit.Close())
	}
	broker, err := newRunningHostEgressBroker(proxy, audit)
	if err != nil {
		return nil, errors.Join(err, proxy.Close(), audit.Close())
	}
	return broker, nil
}

func compileHostEgressPolicy(spec HostEgressSpec) (*policy.Engine, error) {
	policyDocument, err := loadHostEgressPolicySnapshot(spec)
	if err != nil {
		return nil, err
	}
	engine, err := policy.NewEngine(policyDocument, true, true)
	if err != nil {
		return nil, fmt.Errorf("compile host egress policy with approvals enforced: %w", err)
	}
	return engine, nil
}

func loadHostEgressPolicySnapshot(spec HostEgressSpec) (*policy.Policy, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	before, err := os.Lstat(spec.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("inspect host egress policy snapshot: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 || before.Size() < 0 || before.Size() > maxHostEgressPolicyBytes || !operatorPolicyOwnerTrusted(spec.PolicyFile, before) {
		return nil, fmt.Errorf("host egress policy snapshot has unsafe type, ownership, permissions, or size")
	}
	file, err := os.Open(spec.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("open host egress policy snapshot: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Mode().Perm()&0o022 != 0 || !operatorPolicyOwnerTrusted(spec.PolicyFile, opened) {
		return nil, fmt.Errorf("host egress policy snapshot identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxHostEgressPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read host egress policy snapshot: %w", err)
	}
	if len(data) > maxHostEgressPolicyBytes {
		return nil, fmt.Errorf("host egress policy snapshot exceeds limit")
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != spec.PolicySHA256 {
		return nil, fmt.Errorf("host egress policy snapshot digest mismatch")
	}
	document, err := policy.LoadFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("load host egress policy snapshot: %w", err)
	}
	return document, nil
}

type hostNetworkAudit struct {
	mu       sync.Mutex
	file     *os.File
	maxBytes int64
	bytes    int64
	closed   bool
	fatalErr error
	closeErr error
	done     chan struct{}
	doneOnce sync.Once
}

func openHostNetworkAudit(path string) (*hostNetworkAudit, error) {
	return openHostNetworkAuditWithLimit(path, HostEgressAuditMaxBytes)
}

func openHostNetworkAuditWithLimit(path string, maxBytes int64) (*hostNetworkAudit, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("host network audit byte limit is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create durable host network audit: %w", err)
	}
	if err := errors.Join(file.Sync(), syncDirectory(filepath.Dir(path))); err != nil {
		closeErr := file.Close()
		removeErr := os.Remove(path)
		rollbackSyncErr := syncDirectory(filepath.Dir(path))
		return nil, errors.Join(fmt.Errorf("persist durable host network audit identity: %w", err), closeErr, removeErr, rollbackSyncErr)
	}
	return &hostNetworkAudit{file: file, maxBytes: maxBytes, done: make(chan struct{})}, nil
}

func (a *hostNetworkAudit) latch(err error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.latchLocked(err)
}

func (a *hostNetworkAudit) latchLocked(err error) error {
	if err == nil {
		return a.fatalErr
	}
	if a.fatalErr == nil {
		a.fatalErr = err
		a.doneOnce.Do(func() { close(a.done) })
	}
	return a.fatalErr
}

func (a *hostNetworkAudit) AppendEvent(ctx context.Context, event types.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return a.latch(fmt.Errorf("encode host network audit event: %w", err))
	}
	data = append(data, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fatalErr != nil {
		return a.fatalErr
	}
	if a.closed || a.file == nil {
		return fmt.Errorf("host network audit is closed")
	}
	if int64(len(data)) > a.maxBytes-a.bytes {
		return a.latchLocked(fmt.Errorf("host network audit byte limit exceeded"))
	}
	written, writeErr := a.file.Write(data)
	a.bytes += int64(written)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return a.latchLocked(fmt.Errorf("append host network audit event: %w", writeErr))
	}
	return nil
}

// Publish intentionally has no in-memory side effect. The host monitor's
// durable JSONL is the authoritative audit for this isolated broker.
func (*hostNetworkAudit) Publish(types.Event) {}

func (a *hostNetworkAudit) FlushSync(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fatalErr != nil {
		return a.fatalErr
	}
	if a.closed || a.file == nil {
		return fmt.Errorf("host network audit is closed")
	}
	if err := a.file.Sync(); err != nil {
		return a.latchLocked(fmt.Errorf("sync host network audit: %w", err))
	}
	return ctx.Err()
}

func (a *hostNetworkAudit) Done() <-chan struct{} {
	if a == nil {
		return nil
	}
	return a.done
}

func (a *hostNetworkAudit) Err() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fatalErr
}

func (a *hostNetworkAudit) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return errors.Join(a.fatalErr, a.closeErr)
	}
	a.closed = true
	if a.file != nil {
		syncErr := a.file.Sync()
		closeErr := a.file.Close()
		a.closeErr = errors.Join(syncErr, closeErr)
		if a.closeErr != nil {
			a.latchLocked(fmt.Errorf("close host network audit: %w", a.closeErr))
		}
	}
	a.doneOnce.Do(func() { close(a.done) })
	return errors.Join(a.fatalErr, a.closeErr)
}

var _ netmonitor.DurableEmitter = (*hostNetworkAudit)(nil)
