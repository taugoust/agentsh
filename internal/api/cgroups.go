package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/nethelper"
	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type cgroupManager interface {
	Apply(name string, pid int, lim limits.CgroupV2Limits) (*limits.CgroupV2, error)
	Probe() *limits.CgroupProbeResult
}

var (
	ebpfCheckSupport                    = ebpftrace.CheckSupport
	ebpfAttachConnectToCgroup           = ebpftrace.AttachConnectToCgroup
	ebpfAttachConnectToCgroupFailClosed = func(cgroupPath string) (*ebpf.Collection, func() error, error) {
		attachment, err := ebpftrace.AttachConnectToCgroupWithOptions(cgroupPath, ebpftrace.CgroupAttachOptions{FailClosedBeforeAttach: true})
		if err != nil {
			return nil, nil, err
		}
		return attachment.Collection, attachment.Close, nil
	}
	ebpfStartCollector       = ebpftrace.StartCollector
	ebpfCgroupID             = ebpftrace.CgroupID
	ebpfPopulateAllowlist    = ebpftrace.PopulateAllowlist
	ebpfCleanupAllowlist     = ebpftrace.CleanupAllowlist
	nethelperClientForSocket = func(socketPath string) *nethelper.Client { return nethelper.NewClient(socketPath) }
)

// cgroupBestEffortDegradable reports whether an unenforceable resource-limit
// error should degrade to a no-op (run without the limit) rather than fail
// closed. Degradation requires sandbox.cgroups.best_effort AND the absence of
// any eBPF flag — eBPF egress enforcement rides on the cgroup and must stay
// strict. See issue #411.
func cgroupBestEffortDegradable(cfg *config.Config) bool {
	if cfg == nil || !cfg.Sandbox.Cgroups.BestEffort {
		return false
	}
	e := cfg.Sandbox.Network.EBPF
	// EnforceWithoutDNS is intentionally omitted: it is a modifier that has no
	// effect unless Enforce is set, which is already checked above. #411.
	return !e.Enabled && !e.Enforce && !e.Required
}

// emitCgroupDegradedAndContinue logs and emits a single cgroup_limits_degraded
// event, then returns a no-op cleanup so the wrap proceeds without the limit.
// errorType distinguishes the resource-limits-unavailable case from the
// total-cgroup-unavailable case for downstream alerting. See issue #411.
func emitCgroupDegradedAndContinue(ctx context.Context, emit storeEmitter, sessionID, cmdID, errorType, reason string, lim policy.Limits) (func() error, error) {
	slog.Warn("cgroup: enforcement unavailable; running without it (best_effort)",
		"session_id", sessionID, "command_id", cmdID, "error_type", errorType, "reason", reason,
		"max_memory_mb", lim.MaxMemoryMB, "cpu_quota_pct", lim.CPUQuotaPercent, "pids_max", lim.PidsMax)
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      string(events.EventCgroupLimitsDegraded),
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"error_type":    errorType,
			"reason":        reason,
			"max_memory_mb": lim.MaxMemoryMB,
			"cpu_quota_pct": lim.CPUQuotaPercent,
			"pids_max":      lim.PidsMax,
		},
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)
	return func() error { return nil }, nil
}

func reserveLineagePIDs(lim policy.Limits, extra *extraProcConfig) policy.Limits {
	if extra == nil || extra.lineagePIDReserve <= 0 || lim.PidsMax <= 0 {
		return lim
	}
	maxInt := int(^uint(0) >> 1)
	if lim.PidsMax > maxInt-extra.lineagePIDReserve {
		// Do not wrap or reduce the policy limit. The subsequent fork can fail
		// conservatively if an unrepresentable configuration is ever admitted.
		return lim
	}
	lim.PidsMax += extra.lineagePIDReserve
	return lim
}

type networkProxyEndpoints struct {
	ProxyURL    string
	LLMProxyURL string
}

func sessionNetworkProxyEndpoints(app *App, sessionID string) networkProxyEndpoints {
	if app == nil || app.sessions == nil {
		return networkProxyEndpoints{}
	}
	sess, ok := app.sessions.Get(sessionID)
	if !ok || sess == nil {
		return networkProxyEndpoints{}
	}
	return networkProxyEndpoints{ProxyURL: strings.TrimSpace(sess.ProxyURL()), LLMProxyURL: strings.TrimSpace(sess.LLMProxyURL())}
}

func applyCgroupV2(ctx context.Context, emit storeEmitter, app *App, sessionID, cmdID string, pid int, lim policy.Limits, m *metrics.Collector, pol *policy.Engine) (func() error, error) {
	return applyCgroupV2WithProxyEndpoints(ctx, emit, app, sessionID, cmdID, pid, lim, m, pol, nil)
}

// applyCgroupV2WithProxyEndpoints binds a command-specific explicit proxy to
// this command's cgroup registration. A nil override preserves the exclusive
// session proxy path; a non-nil override is authoritative and never falls back.
func applyCgroupV2WithProxyEndpoints(ctx context.Context, emit storeEmitter, app *App, sessionID, cmdID string, pid int, lim policy.Limits, m *metrics.Collector, pol *policy.Engine, proxyOverride *networkProxyEndpoints) (func() error, error) {
	cfg := app.cfg
	proxyEndpoints := sessionNetworkProxyEndpoints(app, sessionID)
	if proxyOverride != nil {
		proxyEndpoints = *proxyOverride
		proxyEndpoints.ProxyURL = strings.TrimSpace(proxyEndpoints.ProxyURL)
		proxyEndpoints.LLMProxyURL = strings.TrimSpace(proxyEndpoints.LLMProxyURL)
	}
	needsCgroup := cfg != nil && (cfg.Sandbox.Cgroups.Enabled ||
		cfg.Sandbox.Network.EBPF.Enabled ||
		cfg.Sandbox.Network.EBPF.Enforce ||
		cfg.Sandbox.Network.EBPF.Required)
	if !needsCgroup {
		return nil, nil
	}

	ebpfEnabled := cfg.Sandbox.Network.EBPF.Enabled
	ebpfRequired := cfg.Sandbox.Network.EBPF.Required
	ebpfEnforce := cfg.Sandbox.Network.EBPF.Enforce
	ebpfStrictSetup := ebpfRequired || ebpfEnforce
	ebpfRequested := ebpfEnabled || ebpfStrictSetup

	memBytes := int64(0)
	if lim.MaxMemoryMB > 0 {
		memBytes = int64(lim.MaxMemoryMB) * 1024 * 1024
	}
	cgLimits := limits.CgroupV2Limits{
		MaxMemoryBytes: memBytes,
		CPUQuotaPct:    lim.CPUQuotaPercent,
		PidsMax:        lim.PidsMax,
	}
	needsConcreteCgroup := !cgLimits.IsEmpty() || ebpfRequested

	if app.cgroupMgr == nil {
		if !needsConcreteCgroup {
			return func() error { return nil }, nil
		}
		return nil, &limits.CgroupUnavailableError{
			Reason: "cgroup manager not initialized",
			Limits: cgLimits,
		}
	}

	cg, err := app.cgroupMgr.Apply("agentsh-"+sanitizeCgroupTag(sessionID)+"-"+sanitizeCgroupTag(cmdID), pid, cgLimits)
	if err != nil {
		var ue *limits.CgroupUnavailableError
		var rlue *limits.CgroupResourceLimitsUnavailableError
		switch {
		case errors.As(err, &rlue):
			if cgroupBestEffortDegradable(cfg) {
				return emitCgroupDegradedAndContinue(ctx, emit, sessionID, cmdID, "resource_limits_unavailable", rlue.Reason, lim)
			}
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      string(events.EventCgroupUnavailableRefusal),
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"reason":                      rlue.Reason,
					"resource_limits_unavailable": true,
					"max_memory_mb":               lim.MaxMemoryMB,
					"cpu_quota_pct":               lim.CPUQuotaPercent,
					"pids_max":                    lim.PidsMax,
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			return nil, err
		case errors.As(err, &ue):
			if cgroupBestEffortDegradable(cfg) {
				return emitCgroupDegradedAndContinue(ctx, emit, sessionID, cmdID, "cgroup_unavailable", ue.Reason, lim)
			}
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      string(events.EventCgroupUnavailableRefusal),
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"reason":        ue.Reason,
					"max_memory_mb": lim.MaxMemoryMB,
					"cpu_quota_pct": lim.CPUQuotaPercent,
					"pids_max":      lim.PidsMax,
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			return nil, err
		default:
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "cgroup_apply_failed",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"error": err.Error(),
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			return nil, err
		}
	}

	// If unavailable mode allowed us with no concrete cgroup need, treat as no-op.
	if cg == nil {
		if needsConcreteCgroup {
			return nil, &limits.CgroupUnavailableError{
				Reason: "cgroup manager returned no cgroup",
				Limits: cgLimits,
			}
		}
		return func() error { return nil }, nil
	}

	cgroupMode := ""
	cgroupRoot := ""
	if probe := app.cgroupMgr.Probe(); probe != nil {
		cgroupMode = string(probe.Mode)
		cgroupRoot = strings.TrimSpace(probe.OwnCgroup)
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "cgroup_applied",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"path":          cg.Path,
			"mode":          cgroupMode,
			"cgroup_root":   cgroupRoot,
			"pid":           pid,
			"max_memory_mb": lim.MaxMemoryMB,
			"cpu_quota_pct": lim.CPUQuotaPercent,
			"pids_max":      lim.PidsMax,
		},
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)

	var ebpfDetach func() error
	var ebpfCollector *ebpftrace.Collector
	var allowlistColl *ebpf.Collection
	var allowCgid uint64
	var refreshCancel context.CancelFunc
	var helperCleanup func() error
	var attachmentEvidence map[string]any
	cleanupEBPFResources := func() error {
		var cleanupErr error
		if refreshCancel != nil {
			refreshCancel()
			refreshCancel = nil
		}
		if ebpfCollector != nil {
			if err := ebpfCollector.Close(); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close eBPF collector: %w", err))
			}
			ebpfCollector = nil
		}
		if helperCleanup != nil {
			if err := helperCleanup(); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
			helperCleanup = nil
		}
		if allowlistColl != nil && allowCgid != 0 {
			// CleanupAllowlist first locks policy state to deny-all. The link is
			// detached only after that lock, so cleanup never opens an allow-all
			// interval for a lingering process in the command cgroup.
			if err := ebpfCleanupAllowlist(allowlistColl, allowCgid); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("lock and clear eBPF policy: %w", err))
			}
			allowlistColl = nil
			allowCgid = 0
		}
		if ebpfDetach != nil {
			if err := ebpfDetach(); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("detach eBPF links: %w", err))
			}
			ebpfDetach = nil
		}
		return cleanupErr
	}
	cleanupCgroup := func() error {
		cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := cg.Close(cctx); err != nil {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "cgroup_cleanup_failed",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"path":                       cg.Path,
					"error":                      err.Error(),
					"phase":                      "cleanup-cgroup",
					"runtime_enforcement_status": "failed",
					"network_policy_enforced":    false,
				},
			}
			_ = emit.AppendEvent(context.Background(), ev)
			emit.Publish(ev)
			app.recordNetworkCleanupFailure(sessionID, cmdID, fmt.Errorf("cgroup cleanup: %w", err))
			return err
		}
		return nil
	}
	cleanupResources := func() error {
		kernelErr := cleanupEBPFResources()
		cgroupErr := cleanupCgroup()
		if kernelErr != nil {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "network_enforcement_cleanup_failed",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"path":                             cg.Path,
					"error":                            kernelErr.Error(),
					"phase":                            "cleanup-kernel-resources",
					"runtime_enforcement_status":       "failed",
					"resources_may_remain_fail_closed": true,
					"network_policy_enforced":          false,
				},
			}
			_ = emit.AppendEvent(context.Background(), ev)
			emit.Publish(ev)
			app.recordNetworkCleanupFailure(sessionID, cmdID, fmt.Errorf("network resource cleanup: %w", kernelErr))
		}
		if kernelErr == nil && cgroupErr == nil {
			// A command attachment is inactive only after both the helper/eBPF
			// resources and the command cgroup have been cleaned. Emitting this
			// earlier can falsely attest successful teardown before a helper
			// cleanup failure is known.
			app.recordNetworkAttachmentEnded(sessionID, cmdID)
		}
		return errors.Join(kernelErr, cgroupErr)
	}
	setupFailure := func(setupErr error) (func() error, error) {
		// Links/maps/helper registrations can be torn down immediately while the
		// child is stopped. Return cgroup cleanup to the runner so it executes
		// after the runner kills/reaps the child; removing a populated cgroup here
		// would otherwise fail and leak it.
		partialCleanupSucceeded := true
		if cleanupErr := cleanupEBPFResources(); cleanupErr != nil {
			partialCleanupSucceeded = false
			setupErr = errors.Join(setupErr, fmt.Errorf("cleanup partial network setup: %w", cleanupErr))
		}
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "network_enforcement_setup_refused",
			SessionID: sessionID,
			CommandID: cmdID,
			Fields: map[string]any{
				"path":                       cg.Path,
				"error":                      setupErr.Error(),
				"phase":                      "pre-resume",
				"runtime_enforcement_status": "failed",
				"fail_closed":                true,
				"child_resumed":              false,
				"partial_cleanup_succeeded":  partialCleanupSucceeded,
				"network_policy_enforced":    false,
			},
		}
		_ = emit.AppendEvent(context.Background(), ev)
		emit.Publish(ev)
		app.recordNetworkEnforcementFailure(sessionID, cmdID, setupErr)
		return cleanupCgroup, setupErr
	}
	refreshInterval := cfg.Sandbox.Network.EBPF.DNSRefreshSeconds
	if refreshInterval <= 0 {
		refreshInterval = 0
	}
	if ebpfRequested {
		helperSock := app.nethelperBindingSnapshot().SocketPath
		if ebpfStrictSetup && helperSock == "" {
			return setupFailure(fmt.Errorf("strict eBPF enforcement requires the installed privileged nethelper socket"))
		}
		if helperSock != "" {
			cleanup, err := setupEBPFViaNethelperWithProxyEndpoints(ctx, emit, app, sessionID, cmdID, cg.Path, pol, proxyEndpoints)
			if err == nil {
				helperCleanup = cleanup
				return cleanupResources, nil
			}
			registrationState := "none"
			partialRegistrationCleaned := true
			var helperFailure *nethelperSetupFailure
			if errors.As(err, &helperFailure) {
				registrationState = helperFailure.registrationState
				partialRegistrationCleaned = helperFailure.partialRegistrationCleaned
			}
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "nethelper_setup_failed",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"error":                        err.Error(),
					"path":                         cg.Path,
					"phase":                        "setup",
					"runtime_enforcement_status":   "failed",
					"fail_closed":                  true,
					"child_resumed":                false,
					"network_policy_enforced":      false,
					"registration_state":           registrationState,
					"partial_registration_cleaned": partialRegistrationCleaned,
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			if ebpfStrictSetup {
				return setupFailure(fmt.Errorf("nethelper eBPF setup failed while required/enforced: %w", err))
			}
		}

		status := ebpfCheckSupport()
		if !status.Supported {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "ebpf_unavailable",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"reason": status.Reason,
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			if m != nil {
				m.IncEBPFUnavailable()
			}
			if ebpfStrictSetup {
				return setupFailure(fmt.Errorf("ebpf required/enforced but unsupported: %s", status.Reason))
			}
		} else {
			attachConnect := ebpfAttachConnectToCgroup
			if ebpfStrictSetup {
				attachConnect = ebpfAttachConnectToCgroupFailClosed
			}
			if coll, detach, err := attachConnect(cg.Path); err != nil {
				ev := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "ebpf_attach_failed",
					SessionID: sessionID,
					CommandID: cmdID,
					Fields: map[string]any{
						"error": err.Error(),
						"path":  cg.Path,
					},
				}
				_ = emit.AppendEvent(ctx, ev)
				emit.Publish(ev)
				if m != nil {
					m.IncEBPFAttachFail()
				}
				if ebpfStrictSetup {
					return setupFailure(fmt.Errorf("ebpf attach failed while required/enforced: %w", err))
				}
			} else {
				ebpfDetach = detach

				// Populate allowlist before starting the collector. When eBPF is
				// required, enforcement setup failures must reject the wrap before
				// the wrapper is ACKed.
				if ebpfStrictSetup {
					cgid, cgErr := ebpfCgroupID(cg.Path)
					if cgErr != nil {
						ev := types.Event{
							ID:        uuid.NewString(),
							Timestamp: time.Now().UTC(),
							Type:      "ebpf_enforce_disabled",
							SessionID: sessionID,
							CommandID: cmdID,
							Fields: map[string]any{
								"error": cgErr.Error(),
							},
						}
						_ = emit.AppendEvent(ctx, ev)
						emit.Publish(ev)
						if ebpfStrictSetup {
							return setupFailure(fmt.Errorf("ebpf enforcement setup failed while required/enforced: cgroup id: %w", cgErr))
						}
					} else {
						allowlistColl = coll
						allowCgid = cgid
						var ep []ebpftrace.AllowKey
						var cidrs []ebpftrace.AllowCIDR
						var denyKeys []ebpftrace.AllowKey
						var denyCidrs []ebpftrace.AllowCIDR
						strict := false
						hasDomains := false
						var ttlHint time.Duration
						proxyRequired := false
						var proxyEndpointIDs []string
						if strings.TrimSpace(proxyEndpoints.ProxyURL) != "" {
							proxyRequired = true
							var proxyErr error
							ep, cidrs, proxyErr = buildProxyOnlyAllowedEndpoints(proxyEndpoints.ProxyURL, proxyEndpoints.LLMProxyURL)
							if proxyErr != nil {
								return setupFailure(fmt.Errorf("build exact proxy-required allowlist: %w", proxyErr))
							}
							if len(cidrs) != 0 {
								return setupFailure(fmt.Errorf("proxy-required allowlist unexpectedly contains CIDR rules"))
							}
							for _, key := range ep {
								if key.Protocol != 6 || key.Dport == 0 {
									return setupFailure(fmt.Errorf("proxy-required allowlist contains a non-TCP or all-port entry"))
								}
								endpointID := allowKeyEndpointID(key)
								if endpointID == "" {
									return setupFailure(fmt.Errorf("proxy-required allowlist contains an unsupported address family"))
								}
								proxyEndpointIDs = append(proxyEndpointIDs, endpointID)
							}
							denyKeys, denyCidrs = nil, nil
							// The proxy is the approval-capable network path. Only its exact
							// TCP listener endpoints are reachable; direct TCP, UDP/QUIC,
							// command-side DNS, and other local TCP services are denied.
							strict = true
							hasDomains = false
							ttlHint = 0
						} else {
							return setupFailure(fmt.Errorf("proxy-required eBPF setup has no ready AgentSH network proxy"))
						}
						if !strict {
							return setupFailure(fmt.Errorf("eBPF enforce mode could not establish a default-deny endpoint set"))
						}
						if err := ebpfPopulateAllowlist(coll, cgid, ep, cidrs, denyKeys, denyCidrs, strict); err != nil {
							ev := types.Event{
								ID:        uuid.NewString(),
								Timestamp: time.Now().UTC(),
								Type:      "ebpf_enforce_disabled",
								SessionID: sessionID,
								CommandID: cmdID,
								Fields: map[string]any{
									"error": err.Error(),
								},
							}
							_ = emit.AppendEvent(ctx, ev)
							emit.Publish(ev)
							if m != nil {
								m.IncEBPFAttachFail()
							}
							if ebpfStrictSetup {
								return setupFailure(fmt.Errorf("ebpf enforcement setup failed while required/enforced: populate allowlist: %w", err))
							}
							// best effort disable default deny and clear entries
							_ = ebpfCleanupAllowlist(coll, cgid)
							allowlistColl = nil
							allowCgid = 0
						}
						if ebpfStrictSetup && proxyRequired {
							ev := types.Event{
								ID:        uuid.NewString(),
								Timestamp: time.Now().UTC(),
								Type:      "ebpf_enforce_proxy_only",
								SessionID: sessionID,
								CommandID: cmdID,
								Fields: map[string]any{
									"reason":                             "proxy-required gate active; only exact AgentSH proxy TCP endpoints are allowed",
									"tier":                               "cgroup-ebpf-proxy-required",
									"runtime_enforcement_status":         "active",
									"cgroup_id":                          cgid,
									"allow_entries":                      len(ep),
									"allow_cidr_rules":                   len(cidrs),
									"proxy_endpoint_ids":                 proxyEndpointIDs,
									"allowed_transport":                  "tcp",
									"exact_proxy_endpoint_only":          true,
									"default_deny":                       true,
									"initial_policy_locked":              true,
									"policy_update_fail_closed":          true,
									"child_stopped_during_setup":         true,
									"direct_bypass_blocked_after_attach": true,
									"direct_tcp_blocked":                 true,
									"local_non_proxy_tcp_blocked":        true,
									"udp_blocked":                        true,
									"quic_blocked":                       true,
									"command_dns_required":               false,
									"unsupported_traffic_action":         "deny",
									"blocked_traffic_classes":            []string{"direct-tcp", "local-non-proxy-tcp", "udp", "quic", "command-dns"},
									"raw_socket_blocking_configured":     true,
									"raw_socket_blocking_proven":         false,
									"unsupported_traffic_blocked":        false,
									"transparent_redirect_supported":     false,
									"network_policy_enforced":            false,
									"proxy_url":                          proxyEndpoints.ProxyURL,
									"llm_proxy_url":                      proxyEndpoints.LLMProxyURL,
								},
							}
							_ = emit.AppendEvent(ctx, ev)
							emit.Publish(ev)
						}

						// Optional DNS refresh loop for domain-based rules.
						if hasDomains && strict && refreshInterval > 0 {
							refreshCtx, cancel := context.WithCancel(ctx)
							refreshCancel = cancel
							go func() {
								base := time.Duration(refreshInterval) * time.Second
								if ttlHint > 0 && ttlHint < base {
									base = ttlHint
								}
								t := time.NewTimer(jitterInterval(base))
								defer t.Stop()
								for {
									select {
									case <-refreshCtx.Done():
										return
									case <-t.C:
										ep2, cidrs2, deny2, denyCidrs2, strict2, _, ttl2 := buildAllowedEndpoints(pol, base)
										if err := ebpfPopulateAllowlist(coll, cgid, ep2, cidrs2, deny2, denyCidrs2, strict2); err != nil {
											ev := types.Event{
												ID:        uuid.NewString(),
												Timestamp: time.Now().UTC(),
												Type:      "ebpf_enforce_refresh_failed",
												SessionID: sessionID,
												CommandID: cmdID,
												Fields: map[string]any{
													"error": err.Error(),
												},
											}
											_ = emit.AppendEvent(ctx, ev)
											emit.Publish(ev)
										}
										next := base
										if ttl2 > 0 && ttl2 < next {
											next = ttl2
										}
										t.Reset(jitterInterval(next))
									}
								}
							}()
						}
						attachmentEvidence = map[string]any{
							"cgroup_id":                          cgid,
							"tier":                               "cgroup-ebpf-proxy-required",
							"runtime_enforcement_status":         "active",
							"default_deny":                       strict,
							"allow_entries":                      len(ep) + len(cidrs),
							"deny_entries":                       len(denyKeys) + len(denyCidrs),
							"initial_policy_locked":              true,
							"policy_update_fail_closed":          true,
							"child_stopped_during_setup":         true,
							"proxy_required":                     proxyRequired,
							"exact_proxy_endpoint_only":          proxyRequired,
							"proxy_endpoint_ids":                 proxyEndpointIDs,
							"allowed_transport":                  "tcp",
							"direct_bypass_blocked_after_attach": proxyRequired && strict,
							"direct_tcp_blocked":                 proxyRequired && strict,
							"local_non_proxy_tcp_blocked":        proxyRequired && strict,
							"udp_blocked":                        proxyRequired && strict,
							"quic_blocked":                       proxyRequired && strict,
							"command_dns_required":               !proxyRequired,
							"unsupported_traffic_action":         "deny",
							"blocked_traffic_classes":            []string{"direct-tcp", "local-non-proxy-tcp", "udp", "quic", "command-dns"},
							"raw_socket_blocking_configured":     true,
							"raw_socket_blocking_proven":         false,
							"unsupported_traffic_blocked":        false,
							"network_policy_enforced":            false,
							"transparent_redirect_supported":     false,
						}
						if !proxyRequired {
							attachmentEvidence["tier"] = "cgroup-ebpf-gate"
						}
						app.recordDirectNetworkAttachment(
							sessionID,
							cmdID,
							cg.Path,
							cgid,
							proxyEndpointIDs,
							len(ep)+len(cidrs),
							len(denyKeys)+len(denyCidrs),
							strict,
							proxyRequired,
						)
					}
				}

				collector, cerr := ebpfStartCollector(coll, 4096)
				if cerr != nil {
					ev := types.Event{
						ID:        uuid.NewString(),
						Timestamp: time.Now().UTC(),
						Type:      "ebpf_collector_failed",
						SessionID: sessionID,
						CommandID: cmdID,
						Fields: map[string]any{
							"error": cerr.Error(),
						},
					}
					_ = emit.AppendEvent(ctx, ev)
					emit.Publish(ev)
					if ebpfRequired {
						return setupFailure(fmt.Errorf("ebpf collector failed and required: %w", cerr))
					}
					// Event collection is not part of the connect/sendmsg decision
					// path. In enforce mode retain the successfully populated gate;
					// detaching it because telemetry failed would be fail open.
					if !ebpfEnforce {
						if cleanupErr := cleanupEBPFResources(); cleanupErr != nil {
							return setupFailure(fmt.Errorf("cleanup after optional collector failure: %w", cleanupErr))
						}
					}
				} else {
					ebpfCollector = collector
					collector.SetOnDrop(func() {
						if m != nil {
							m.IncEBPFDropped()
						}
					})
					go forwardConnectEvents(ctx, collector.Events(), emit, sessionID, cmdID, m)
				}
				attachedFields := map[string]any{"path": cg.Path}
				for key, value := range attachmentEvidence {
					attachedFields[key] = value
				}
				ev := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "ebpf_attached",
					SessionID: sessionID,
					CommandID: cmdID,
					Fields:    attachedFields,
				}
				_ = emit.AppendEvent(ctx, ev)
				emit.Publish(ev)
			}
		}
	}

	return cleanupResources, nil
}

type nethelperSetupFailure struct {
	cause                      error
	registrationState          string
	partialRegistrationCleaned bool
}

func (e *nethelperSetupFailure) Error() string {
	if e == nil || e.cause == nil {
		return "nethelper setup failed"
	}
	return e.cause.Error()
}

func (e *nethelperSetupFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func setupEBPFViaNethelper(ctx context.Context, emit storeEmitter, app *App, sessionID, cmdID, cgroupPath string, pol *policy.Engine) (func() error, error) {
	return setupEBPFViaNethelperWithProxyEndpoints(ctx, emit, app, sessionID, cmdID, cgroupPath, pol, sessionNetworkProxyEndpoints(app, sessionID))
}

func setupEBPFViaNethelperWithProxyEndpoints(ctx context.Context, emit storeEmitter, app *App, sessionID, cmdID, cgroupPath string, pol *policy.Engine, endpoints networkProxyEndpoints) (func() error, error) {
	if app == nil || app.cfg == nil {
		return nil, fmt.Errorf("app config unavailable")
	}
	binding := app.nethelperBindingSnapshot()
	socketPath := strings.TrimSpace(binding.SocketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("nethelper socket is not configured")
	}
	client := nethelperClientForSocket(socketPath)
	proxyGate, err := nethelperProxyGateForEndpoints(endpoints)
	if err != nil {
		return nil, err
	}
	strictSetup := app.cfg.Sandbox.Network.EBPF.Required || app.cfg.Sandbox.Network.EBPF.Enforce
	if strictSetup && proxyGate == nil {
		return nil, fmt.Errorf("proxy-required nethelper setup has no ready AgentSH network proxy")
	}
	proxyRequired := strictSetup
	var proxyEndpoint *nethelper.ProxyEndpoint
	proxyURL := ""
	var proxyAllow []nethelper.PolicyMapEntry
	var proxyEndpointIDs []string
	mode := nethelper.BuiltinModeCgroupConnectGate
	tier := nethelper.EnforcementTierHelperEBPFGate
	if proxyRequired {
		proxyEndpoint = proxyGate.primary
		proxyURL = proxyGate.primaryURL
		proxyAllow = proxyGate.allow
		proxyEndpointIDs = proxyGate.endpointIDs
		tier = nethelper.EnforcementTierHelperEBPFProxyRequired
	}
	supervisorCgroup := ""
	if app.cgroupMgr != nil {
		if probe := app.cgroupMgr.Probe(); probe != nil && strings.TrimSpace(probe.OwnCgroup) != "" {
			supervisorCgroup = probe.OwnCgroup
		}
	}
	if supervisorCgroup == "" {
		supervisorCgroup, _ = limits.CurrentCgroupDir()
	}
	regReq := nethelper.RegisterSessionCgroupRequest{
		ProtocolVersion:          nethelper.CurrentProtocolVersion,
		RequestID:                cmdID,
		SessionID:                sessionID,
		HelperInstanceCredential: nethelperInstanceCredential(app),
		SupervisorPID:            os.Getpid(),
		SupervisorCgroupPath:     supervisorCgroup,
		CgroupPath:               cgroupPath,
		Tier:                     tier,
		Mode:                     mode,
		Proxy:                    proxyEndpoint,
	}
	if strictSetup && strings.TrimSpace(regReq.HelperInstanceCredential) == "" {
		return nil, fmt.Errorf("proxy-required nethelper setup has no helper instance credential")
	}
	regResp, err := client.RegisterSessionCgroup(ctx, regReq)
	if err != nil {
		return nil, &nethelperSetupFailure{
			cause:                      fmt.Errorf("register cgroup with nethelper: %w", err),
			registrationState:          "unknown",
			partialRegistrationCleaned: false,
		}
	}
	if !regResp.OK {
		return nil, fmt.Errorf("register cgroup with nethelper: %s", regResp.Error)
	}
	cleanupRegistration := func(reason nethelper.CleanupReason) error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, cleanupErr := client.CleanupSession(cleanupCtx, nethelper.CleanupSessionRequest{
			ProtocolVersion: nethelper.CurrentProtocolVersion,
			RequestID:       cmdID,
			SessionID:       sessionID,
			RegistrationID:  regResp.RegistrationID,
			CgroupID:        regResp.CgroupID,
			CgroupPath:      cgroupPath,
			Reason:          reason,
		})
		if cleanupErr != nil {
			return fmt.Errorf("nethelper cleanup registration: %w", cleanupErr)
		}
		if !resp.OK {
			return fmt.Errorf("nethelper cleanup registration: %s", resp.Error)
		}
		return nil
	}
	failRegisteredSetup := func(setupErr error) (func() error, error) {
		cleaned := true
		if cleanupErr := cleanupRegistration(nethelper.CleanupReasonRegistrationFailed); cleanupErr != nil {
			cleaned = false
			cleanupEvent := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "nethelper_cleanup_failed",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"path":      cgroupPath,
					"cgroup_id": regResp.CgroupID,
					"phase":     "setup",
					"error":     cleanupErr.Error(),
				},
			}
			_ = emit.AppendEvent(context.Background(), cleanupEvent)
			emit.Publish(cleanupEvent)
			setupErr = errors.Join(setupErr, cleanupErr)
		}
		return nil, &nethelperSetupFailure{
			cause:                      setupErr,
			registrationState:          "registered",
			partialRegistrationCleaned: cleaned,
		}
	}
	if err := validateNethelperRegistrationResponse(regReq, regResp); err != nil {
		return failRegisteredSetup(err)
	}
	if strictSetup {
		if strings.TrimSpace(regResp.RegistrationID) == "" {
			return failRegisteredSetup(fmt.Errorf("nethelper registration response omitted the helper-selected registration_id"))
		}
		if strings.TrimSpace(regResp.PinPath) == "" || !filepath.IsAbs(regResp.PinPath) || filepath.Clean(regResp.PinPath) != regResp.PinPath {
			return failRegisteredSetup(fmt.Errorf("nethelper registration response omitted a canonical helper-selected pin path"))
		}
	}

	allow, deny, defaultDeny, warning := helperPolicyEntries(app, pol, proxyAllow)
	if strictSetup && !defaultDeny {
		return failRegisteredSetup(fmt.Errorf("proxy-required nethelper mode could not establish a default-deny endpoint set"))
	}
	updReq := nethelper.UpdatePolicyMapRequest{
		ProtocolVersion: nethelper.CurrentProtocolVersion,
		RequestID:       cmdID,
		SessionID:       sessionID,
		RegistrationID:  regResp.RegistrationID,
		CgroupID:        regResp.CgroupID,
		CgroupPath:      cgroupPath,
		Mode:            mode,
		DefaultDeny:     defaultDeny,
		Allow:           allow,
		Deny:            deny,
		Proxy:           proxyEndpoint,
	}
	updResp, err := client.UpdatePolicyMap(ctx, updReq)
	if err != nil {
		return failRegisteredSetup(fmt.Errorf("update nethelper policy map: %w", err))
	}
	if !updResp.OK {
		return failRegisteredSetup(fmt.Errorf("update nethelper policy map: %s", updResp.Error))
	}
	if err := validateNethelperUpdateResponse(updReq, updResp); err != nil {
		return failRegisteredSetup(err)
	}

	helperWarnings := append([]string{}, regResp.Warnings...)
	helperWarnings = append(helperWarnings, updResp.Warnings...)
	pinReloaded := warningsContain(helperWarnings, "reloaded pinned")
	helperAuthenticated := strings.TrimSpace(regReq.HelperInstanceCredential) != "" && strings.TrimSpace(regResp.RegistrationID) != ""
	registrationEvidenceID := nethelperRegistrationEvidenceID(regResp.RegistrationID, sessionID, regResp.CgroupID)
	allowedTransport := "policy-map"
	unsupportedTrafficAction := "policy-map"
	var blockedTrafficClasses []string
	if proxyRequired {
		allowedTransport = "tcp"
		unsupportedTrafficAction = "deny"
		blockedTrafficClasses = []string{"direct-tcp", "local-non-proxy-tcp", "udp", "quic", "command-dns"}
	}
	evFields := map[string]any{
		"path":                               cgroupPath,
		"cgroup_id":                          regResp.CgroupID,
		"tier":                               string(tier),
		"runtime_enforcement_status":         "active",
		"mode":                               string(mode),
		"helper_registration_id":             registrationEvidenceID,
		"helper_request_id":                  cmdID,
		"helper_authenticated":               helperAuthenticated,
		"default_deny":                       updResp.DefaultDeny,
		"initial_policy_locked":              true,
		"policy_update_fail_closed":          true,
		"child_stopped_during_setup":         true,
		"allow_entries":                      updResp.AllowEntries,
		"deny_entries":                       updResp.DenyEntries,
		"network_policy_enforced":            false,
		"direct_bypass_blocked_after_attach": proxyRequired && defaultDeny,
		"proxy_approval_path":                proxyRequired,
		"proxy_required":                     proxyRequired,
		"exact_proxy_endpoint_only":          proxyRequired,
		"proxy_endpoint_ids":                 proxyEndpointIDs,
		"allowed_transport":                  allowedTransport,
		"direct_tcp_blocked":                 proxyRequired && defaultDeny,
		"local_non_proxy_tcp_blocked":        proxyRequired && defaultDeny,
		"udp_blocked":                        proxyRequired && defaultDeny,
		"quic_blocked":                       proxyRequired && defaultDeny,
		"command_dns_required":               !proxyRequired,
		"unsupported_traffic_action":         unsupportedTrafficAction,
		"blocked_traffic_classes":            blockedTrafficClasses,
		"raw_socket_blocking_configured":     proxyRequired,
		"raw_socket_blocking_proven":         false,
		"unsupported_traffic_blocked":        false,
		"transparent_redirect_supported":     false,
		"helper_boundary_complete":           false,
		"helper_reported_enforced":           regResp.NetworkPolicyEnforced,
		"pinned":                             regResp.PinPath != "",
		"pin_reloaded":                       pinReloaded,
	}
	if len(helperWarnings) > 0 {
		evFields["helper_warnings"] = helperWarnings
	}
	if proxyURL != "" {
		evFields["proxy_url"] = proxyURL
	}
	if warning != "" {
		evFields["warning"] = warning
	}
	app.recordNetworkAttachment(
		sessionID,
		cmdID,
		cgroupPath,
		regResp.CgroupID,
		types.NetworkEnforcementTier(tier),
		registrationEvidenceID,
		helperAuthenticated,
		proxyEndpointIDs,
		updResp.AllowEntries,
		updResp.DenyEntries,
		defaultDeny,
		proxyRequired,
		regResp.PinPath != "",
		pinReloaded,
	)

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "nethelper_ebpf_attached",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields:    evFields,
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)

	cleanup := func() error {
		return cleanupRegistration(nethelper.CleanupReasonSessionEnded)
	}
	return cleanup, nil
}

func helperPolicyEntries(app *App, pol *policy.Engine, proxyAllow []nethelper.PolicyMapEntry) ([]nethelper.PolicyMapEntry, []nethelper.PolicyMapEntry, bool, string) {
	cfg := app.cfg
	if cfg == nil {
		return nil, nil, false, "config unavailable"
	}
	strictSetup := cfg.Sandbox.Network.EBPF.Required || cfg.Sandbox.Network.EBPF.Enforce
	if strictSetup {
		if len(proxyAllow) == 0 {
			return nil, nil, false, "proxy-required gate has no exact proxy endpoints"
		}
		allow := append([]nethelper.PolicyMapEntry(nil), proxyAllow...)
		for _, entry := range allow {
			if strings.TrimSpace(entry.IP) == "" || strings.TrimSpace(entry.CIDR) != "" || entry.Port <= 0 || entry.Protocol.Normalized() != nethelper.TransportProtocolTCP {
				return nil, nil, false, "proxy-required gate rejected a non-exact, non-TCP, or all-port proxy entry"
			}
		}
		return allow, nil, true, "proxy-required gate active: only exact AgentSH proxy TCP address+port endpoints are allowed; direct TCP, local non-proxy TCP, and UDP/QUIC are default-denied"
	}

	maxTTL := time.Duration(cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds) * time.Second
	allowKeys, allowCIDRs, denyKeys, denyCIDRs, strict, hasDomains, _ := buildAllowedEndpoints(pol, maxTTL)
	if len(allowKeys) == 0 && len(allowCIDRs) == 0 && !cfg.Sandbox.Network.EBPF.EnforceWithoutDNS {
		strict = false
	}
	allow := append(policyEntriesFromAllowKeys(allowKeys), policyEntriesFromAllowCIDRs(allowCIDRs)...)
	deny := append(policyEntriesFromAllowKeys(denyKeys), policyEntriesFromAllowCIDRs(denyCIDRs)...)
	warning := ""
	if hasDomains && strict && cfg.Sandbox.Network.EBPF.DNSRefreshSeconds > 0 {
		warning = "helper map DNS refresh is not implemented in this supervisor path; entries are a startup snapshot"
	}
	return allow, deny, cfg.Sandbox.Network.EBPF.Enforce && strict, warning
}

type nethelperProxyGateConfig struct {
	primary     *nethelper.ProxyEndpoint
	primaryURL  string
	allow       []nethelper.PolicyMapEntry
	endpointIDs []string
}

func nethelperProxyGate(app *App, sessionID string) (*nethelperProxyGateConfig, error) {
	return nethelperProxyGateForEndpoints(sessionNetworkProxyEndpoints(app, sessionID))
}

func nethelperProxyGateForEndpoints(endpoints networkProxyEndpoints) (*nethelperProxyGateConfig, error) {
	proxyURL := strings.TrimSpace(endpoints.ProxyURL)
	if proxyURL == "" {
		return nil, nil
	}
	keys, cidrs, err := buildProxyOnlyAllowedEndpoints(proxyURL, endpoints.LLMProxyURL)
	if err != nil {
		return nil, fmt.Errorf("resolve exact proxy-required endpoints: %w", err)
	}
	if len(cidrs) != 0 {
		return nil, fmt.Errorf("resolve exact proxy-required endpoints: CIDR rules are forbidden")
	}
	primaryAddrPort, err := exactLoopbackProxyAddrPort(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("resolve primary proxy endpoint: %w", err)
	}
	primary := &nethelper.ProxyEndpoint{Host: primaryAddrPort.Addr().String(), Port: int(primaryAddrPort.Port())}
	if err := primary.Validate(); err != nil {
		return nil, fmt.Errorf("validate primary proxy endpoint: %w", err)
	}
	allow := policyEntriesFromAllowKeys(keys)
	if len(allow) != len(keys) {
		return nil, fmt.Errorf("convert exact proxy-required endpoints: converted %d of %d entries", len(allow), len(keys))
	}
	endpointIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		if key.Protocol != 6 || key.Dport == 0 {
			return nil, fmt.Errorf("resolve exact proxy-required endpoints: non-TCP or all-port rule")
		}
		endpointID := allowKeyEndpointID(key)
		if endpointID == "" {
			return nil, fmt.Errorf("resolve exact proxy-required endpoints: unsupported address family")
		}
		endpointIDs = append(endpointIDs, endpointID)
	}
	return &nethelperProxyGateConfig{
		primary:     primary,
		primaryURL:  proxyURL,
		allow:       allow,
		endpointIDs: endpointIDs,
	}, nil
}

func policyEntriesFromAllowKeys(keys []ebpftrace.AllowKey) []nethelper.PolicyMapEntry {
	out := make([]nethelper.PolicyMapEntry, 0, len(keys))
	for _, key := range keys {
		entry, ok := policyEntryFromAllowKey(key)
		if ok {
			out = append(out, entry)
		}
	}
	return out
}

func policyEntryFromAllowKey(key ebpftrace.AllowKey) (nethelper.PolicyMapEntry, bool) {
	port := int(key.Dport)
	protocol := helperTransportProtocol(key.Protocol)
	switch key.Family {
	case 2:
		addr := netip.AddrFrom4([4]byte{key.Addr[0], key.Addr[1], key.Addr[2], key.Addr[3]})
		return nethelper.PolicyMapEntry{IP: addr.String(), Port: port, Protocol: protocol}, true
	case 10:
		var b [16]byte
		copy(b[:], key.Addr[:])
		addr := netip.AddrFrom16(b)
		return nethelper.PolicyMapEntry{IP: addr.String(), Port: port, Protocol: protocol}, true
	default:
		return nethelper.PolicyMapEntry{}, false
	}
}

func policyEntriesFromAllowCIDRs(cidrs []ebpftrace.AllowCIDR) []nethelper.PolicyMapEntry {
	out := make([]nethelper.PolicyMapEntry, 0, len(cidrs))
	for _, cidr := range cidrs {
		entry, ok := policyEntryFromAllowCIDR(cidr)
		if ok {
			out = append(out, entry)
		}
	}
	return out
}

func policyEntryFromAllowCIDR(cidr ebpftrace.AllowCIDR) (nethelper.PolicyMapEntry, bool) {
	port := int(cidr.Dport)
	protocol := helperTransportProtocol(cidr.Protocol)
	switch cidr.Family {
	case 2:
		addr := netip.AddrFrom4([4]byte{cidr.Addr[0], cidr.Addr[1], cidr.Addr[2], cidr.Addr[3]})
		prefix := netip.PrefixFrom(addr, int(cidr.PrefixLen)).Masked()
		return nethelper.PolicyMapEntry{CIDR: prefix.String(), Port: port, Protocol: protocol}, true
	case 10:
		var b [16]byte
		copy(b[:], cidr.Addr[:])
		addr := netip.AddrFrom16(b)
		prefix := netip.PrefixFrom(addr, int(cidr.PrefixLen)).Masked()
		return nethelper.PolicyMapEntry{CIDR: prefix.String(), Port: port, Protocol: protocol}, true
	default:
		return nethelper.PolicyMapEntry{}, false
	}
}

func helperTransportProtocol(protocol uint8) nethelper.TransportProtocol {
	switch protocol {
	case 6:
		return nethelper.TransportProtocolTCP
	case 17:
		return nethelper.TransportProtocolUDP
	default:
		return nethelper.TransportProtocolAny
	}
}

func allowKeyEndpointID(key ebpftrace.AllowKey) string {
	var addr netip.Addr
	switch key.Family {
	case 2:
		addr = netip.AddrFrom4([4]byte{key.Addr[0], key.Addr[1], key.Addr[2], key.Addr[3]})
	case 10:
		var raw [16]byte
		copy(raw[:], key.Addr[:])
		addr = netip.AddrFrom16(raw)
	default:
		return ""
	}
	return netip.AddrPortFrom(addr, key.Dport).String()
}

func validateNethelperRegistrationResponse(req nethelper.RegisterSessionCgroupRequest, resp nethelper.RegisterSessionCgroupResponse) error {
	if resp.ProtocolVersion != nethelper.CurrentProtocolVersion {
		return fmt.Errorf("nethelper registration response protocol_version=%d, want %d", resp.ProtocolVersion, nethelper.CurrentProtocolVersion)
	}
	if resp.CgroupID == 0 {
		return fmt.Errorf("nethelper registration response omitted cgroup_id")
	}
	if resp.SessionID != "" && resp.SessionID != req.SessionID {
		return fmt.Errorf("nethelper registration response session_id mismatch")
	}
	if resp.RequestID != "" && resp.RequestID != req.RequestID {
		return fmt.Errorf("nethelper registration response request_id mismatch")
	}
	if resp.Tier.Normalized() != req.Tier.Normalized() {
		return fmt.Errorf("nethelper registration response tier %q does not match requested %q", resp.Tier.Normalized(), req.Tier.Normalized())
	}
	if resp.Mode.Normalized() != req.Mode.Normalized() {
		return fmt.Errorf("nethelper registration response mode %q does not match requested %q", resp.Mode.Normalized(), req.Mode.Normalized())
	}
	return nil
}

func validateNethelperUpdateResponse(req nethelper.UpdatePolicyMapRequest, resp nethelper.UpdatePolicyMapResponse) error {
	if resp.ProtocolVersion != nethelper.CurrentProtocolVersion {
		return fmt.Errorf("nethelper map response protocol_version=%d, want %d", resp.ProtocolVersion, nethelper.CurrentProtocolVersion)
	}
	if resp.SessionID != "" && resp.SessionID != req.SessionID {
		return fmt.Errorf("nethelper map response session_id mismatch")
	}
	if resp.RequestID != "" && resp.RequestID != req.RequestID {
		return fmt.Errorf("nethelper map response request_id mismatch")
	}
	if resp.DefaultDeny != req.DefaultDeny {
		return fmt.Errorf("nethelper map response default_deny=%t, requested %t", resp.DefaultDeny, req.DefaultDeny)
	}
	if resp.AllowEntries != len(req.Allow) || resp.DenyEntries != len(req.Deny) {
		return fmt.Errorf("nethelper map response entry counts allow=%d deny=%d, requested allow=%d deny=%d", resp.AllowEntries, resp.DenyEntries, len(req.Allow), len(req.Deny))
	}
	return nil
}

func nethelperRegistrationEvidenceID(registrationID, sessionID string, cgroupID uint64) string {
	source := strings.TrimSpace(registrationID)
	if source == "" {
		// Test/degraded helper authorizers may omit the opaque registration ID.
		// Keep the evidence stable without pretending this fallback is an
		// authentication credential.
		source = fmt.Sprintf("%s:%d", strings.TrimSpace(sessionID), cgroupID)
	}
	sum := sha256.Sum256([]byte(source))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func warningsContain(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(strings.ToLower(warning), strings.ToLower(fragment)) {
			return true
		}
	}
	return false
}

func nethelperInstanceCredential(app *App) string {
	return strings.TrimSpace(app.nethelperBindingSnapshot().Credential)
}

func sanitizeCgroupTag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "x"
	}
	// Keep it short and path-safe.
	if len(s) > 32 {
		s = s[:32]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		case r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '_' || r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}
