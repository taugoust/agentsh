package netmonitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	dbevents "github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

// DurableEmitter adds the persistence barrier required by strict public-egress
// mode. FlushSync must not return until all successful prior AppendEvent calls
// are durable.
type DurableEmitter interface {
	Emitter
	FlushSync(ctx context.Context) error
}

// ProxyStartOptions controls new proxy behavior without changing the legacy
// StartProxy and StartCommandProxy APIs. When Listener is provided, ownership
// transfers to the returned Proxy on success; ListenAddr is otherwise used to
// create a TCP listener.
type ProxyStartOptions struct {
	ListenAddr            string
	Listener              net.Listener
	StrictPublicEgress    bool
	MaxConnections        int
	InitialRequestTimeout time.Duration
	TLSClientHelloTimeout time.Duration
}

const defaultStrictTLSClientHelloTimeout = 2 * time.Second

// mcpAddrSource is satisfied by *mcpregistry.Registry.
// Used to check if a connection target is a known MCP server.
type mcpAddrSource interface {
	ServerAddrs() map[string]string
}

type Proxy struct {
	sessionID      string
	fixedCommandID string
	sess           *session.Session
	policy         *policy.Engine
	approvals      *approvals.Manager
	emit           Emitter
	dbBypass       atomic.Pointer[dbevents.BypassEmitter]

	strictPublicEgress    bool
	maxConnections        int
	initialRequestTimeout time.Duration
	tlsClientHelloTimeout time.Duration
	dialContext           func(context.Context, string, string) (net.Conn, error)
	lookupIPAddr          func(context.Context, string) ([]net.IPAddr, error)

	ln           net.Listener
	wg           sync.WaitGroup
	done         chan struct{}
	terminated   chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	shutdownOnce sync.Once
	finishOnce   sync.Once
	closeErr     error

	fatalMu  sync.Mutex
	fatalErr error

	connMu  sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
}

func StartProxy(listenAddr string, sessionID string, sess *session.Session, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*Proxy, string, error) {
	return StartProxyWithOptions(ProxyStartOptions{ListenAddr: listenAddr}, sessionID, sess, engine, approvalsMgr, emit, dbBypass...)
}

// StartProxyWithOptions starts an explicit proxy from either a configured TCP
// address or an already-bound listener. StrictPublicEgress is opt-in; the zero
// value preserves StartProxy behavior.
func StartProxyWithOptions(options ProxyStartOptions, sessionID string, sess *session.Session, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*Proxy, string, error) {
	return startProxy(options, sessionID, "", sess, engine, approvalsMgr, emit, dbBypass...)
}

// StartCommandProxy starts an explicit proxy whose attribution cannot change
// for its lifetime. It is used with one stopped command cgroup whose eBPF gate
// permits only this listener's exact loopback address and port.
func StartCommandProxy(listenAddr string, sessionID string, commandID string, sess *session.Session, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*Proxy, string, error) {
	return StartCommandProxyWithOptions(ProxyStartOptions{ListenAddr: listenAddr}, sessionID, commandID, sess, engine, approvalsMgr, emit, dbBypass...)
}

// StartCommandProxyWithOptions is the command-bound counterpart to
// StartProxyWithOptions.
func StartCommandProxyWithOptions(options ProxyStartOptions, sessionID string, commandID string, sess *session.Session, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*Proxy, string, error) {
	commandID = strings.TrimSpace(commandID)
	if commandID == "" {
		return nil, "", fmt.Errorf("command-bound proxy requires a command ID")
	}
	return startProxy(options, sessionID, commandID, sess, engine, approvalsMgr, emit, dbBypass...)
}

func startProxy(options ProxyStartOptions, sessionID string, commandID string, sess *session.Session, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*Proxy, string, error) {
	if options.MaxConnections < 0 || options.InitialRequestTimeout < 0 || options.TLSClientHelloTimeout < 0 {
		return nil, "", fmt.Errorf("proxy connection limits or timeouts are invalid")
	}
	if options.StrictPublicEgress {
		if _, ok := emit.(DurableEmitter); !ok {
			return nil, "", fmt.Errorf("strict public egress requires an emitter with a durable FlushSync barrier")
		}
		if options.MaxConnections == 0 {
			options.MaxConnections = 64
		}
		if options.InitialRequestTimeout == 0 {
			options.InitialRequestTimeout = 5 * time.Second
		}
		if options.TLSClientHelloTimeout == 0 {
			options.TLSClientHelloTimeout = defaultStrictTLSClientHelloTimeout
		}
	}

	ln := options.Listener
	createdListener := false
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", options.ListenAddr)
		if err != nil {
			return nil, "", err
		}
		createdListener = true
	}
	if ln.Addr() == nil {
		if createdListener {
			_ = ln.Close()
		}
		return nil, "", fmt.Errorf("proxy listener has no address")
	}

	proxyCtx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		sessionID:             sessionID,
		fixedCommandID:        commandID,
		sess:                  sess,
		policy:                engine,
		approvals:             approvalsMgr,
		emit:                  emit,
		strictPublicEgress:    options.StrictPublicEgress,
		maxConnections:        options.MaxConnections,
		initialRequestTimeout: options.InitialRequestTimeout,
		tlsClientHelloTimeout: options.TLSClientHelloTimeout,
		ln:                    ln,
		done:                  make(chan struct{}),
		terminated:            make(chan struct{}),
		ctx:                   proxyCtx,
		cancel:                cancel,
		conns:                 make(map[net.Conn]struct{}),
	}
	if len(dbBypass) > 0 {
		p.SetDBBypassEmitter(dbBypass[0])
	}

	p.wg.Add(1)
	go p.acceptLoop()

	u := url.URL{Scheme: "http", Host: ln.Addr().String()}
	return p, u.String(), nil
}

func (p *Proxy) SetDBBypassEmitter(em *dbevents.BypassEmitter) {
	if p == nil {
		return
	}
	p.dbBypass.Store(em)
}

func (p *Proxy) Close() error {
	if p == nil {
		return nil
	}
	p.initiateShutdown()
	p.finishOnce.Do(func() {
		p.wg.Wait()
		if p.terminated != nil {
			close(p.terminated)
		}
	})
	if p.terminated != nil {
		<-p.terminated
	}
	return errors.Join(p.closeErr, p.Err())
}

// Done closes only after the listener and every accepted handler have exited.
// An unexpected strict-proxy failure also drives this signal without requiring
// an external Close call.
func (p *Proxy) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.terminated
}

// Err returns the first fatal serving or audit error. Normal Close leaves it nil.
func (p *Proxy) Err() error {
	if p == nil {
		return nil
	}
	p.fatalMu.Lock()
	defer p.fatalMu.Unlock()
	return p.fatalErr
}

func (p *Proxy) fail(err error) {
	if p == nil || err == nil {
		return
	}
	p.fatalMu.Lock()
	if p.fatalErr == nil {
		p.fatalErr = err
	}
	p.fatalMu.Unlock()
	// Manually-constructed unit proxies have no serving lifecycle to stop.
	if p.done == nil || p.terminated == nil {
		return
	}
	p.initiateShutdown()
	go func() { _ = p.Close() }()
}

func (p *Proxy) initiateShutdown() {
	if p == nil {
		return
	}
	p.shutdownOnce.Do(func() {
		if p.done != nil {
			close(p.done)
		}
		if p.cancel != nil {
			p.cancel()
		}
		if p.ln != nil {
			p.closeErr = p.ln.Close()
		}
		// Closing accepted streams makes cleanup bounded even when a CONNECT
		// tunnel outlives the process that opened it.
		p.connMu.Lock()
		p.closing = true
		connections := make([]net.Conn, 0, len(p.conns))
		for conn := range p.conns {
			connections = append(connections, conn)
		}
		p.connMu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
}

func (p *Proxy) trackConn(conn net.Conn) bool {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if p.closing || p.maxConnections > 0 && len(p.conns) >= p.maxConnections {
		_ = conn.Close()
		return false
	}
	p.conns[conn] = struct{}{}
	return true
}

func (p *Proxy) untrackConn(conn net.Conn) {
	p.connMu.Lock()
	delete(p.conns, conn)
	p.connMu.Unlock()
}

func (p *Proxy) commandID() string {
	if p == nil {
		return ""
	}
	if p.fixedCommandID != "" {
		return p.fixedCommandID
	}
	if p.sess != nil {
		return p.sess.CurrentCommandID()
	}
	return ""
}

func (p *Proxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				if p.strictPublicEgress {
					p.fail(fmt.Errorf("strict proxy listener failed: %w", err))
					return
				}
				continue
			}
		}
		if !p.trackConn(conn) {
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrackConn(conn)
			_ = p.handleConn(conn)
		}()
	}
}

type bufferedReadConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedReadConn) Read(buf []byte) (int, error) {
	return c.reader.Read(buf)
}

func (p *Proxy) handleConn(c net.Conn) error {
	defer c.Close()
	if p.initialRequestTimeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(p.initialRequestTimeout)); err != nil {
			return err
		}
	}
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	if p.initialRequestTimeout > 0 {
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
	}
	defer req.Body.Close()
	if p.ctx != nil {
		req = req.WithContext(p.ctx)
	}

	if strings.EqualFold(req.Method, http.MethodConnect) {
		// http.ReadRequest may have already buffered tunnel bytes sent with the
		// CONNECT request. Keep that reader in the data path so strict SNI
		// inspection and later forwarding see every byte exactly once.
		return p.handleConnect(&bufferedReadConn{Conn: c, reader: br}, req)
	}
	return p.handleHTTP(c, req)
}

type connectDialTargetInput struct {
	OriginalHostPort string
	ResolvedIP       string
	OriginalPort     string
	Redirect         *policy.ConnectRedirectResult
}

type resolvedConnectDialTarget struct {
	Network string
	Address string
}

func connectDialTarget(in connectDialTargetInput) resolvedConnectDialTarget {
	if in.Redirect != nil && in.Redirect.RedirectToUnix != "" {
		return resolvedConnectDialTarget{Network: "unix", Address: in.Redirect.RedirectToUnix}
	}
	if in.Redirect != nil && in.Redirect.RedirectTo != "" {
		return resolvedConnectDialTarget{Network: "tcp", Address: in.Redirect.RedirectTo}
	}
	if in.ResolvedIP != "" {
		return resolvedConnectDialTarget{
			Network: "tcp",
			Address: net.JoinHostPort(in.ResolvedIP, in.OriginalPort),
		}
	}
	return resolvedConnectDialTarget{Network: "tcp", Address: in.OriginalHostPort}
}

func (p *Proxy) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	if p != nil && p.dialContext != nil {
		return p.dialContext(ctx, network, address)
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	return dialer.DialContext(ctx, network, address)
}

func (p *Proxy) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	if p != nil && p.lookupIPAddr != nil {
		return p.lookupIPAddr(ctx, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// prepareStrictPublicDialTarget resolves and pins TCP targets before validating
// the exact IP that dial will receive. Local sockets and other transports are
// outside the public-egress contract and always fail closed.
func (p *Proxy) prepareStrictPublicDialTarget(ctx context.Context, commandID string, target resolvedConnectDialTarget) (resolvedConnectDialTarget, string, error) {
	if target.Network != "tcp" {
		return target, "", fmt.Errorf("strict public egress rejects non-TCP dial transport %q", target.Network)
	}
	host, port, err := net.SplitHostPort(target.Address)
	if err != nil {
		return target, "", fmt.Errorf("strict public egress requires a TCP host and port: %w", err)
	}
	if host == "" || port == "" {
		return target, "", fmt.Errorf("strict public egress requires a non-empty TCP host and port")
	}

	resolvedIP := ""
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil && ip.Zone() == "" {
		resolvedIP = ip.Unmap().String()
	} else {
		var resolved bool
		resolvedIP, resolved = p.resolveAndEmitDNSChecked(ctx, commandID, host)
		if !resolved {
			return target, "", fmt.Errorf("strict public egress could not resolve dial target %q", host)
		}
	}

	ip, err := netip.ParseAddr(resolvedIP)
	if err != nil {
		return target, resolvedIP, fmt.Errorf("strict public egress received invalid resolved IP %q: %w", resolvedIP, err)
	}
	if err := ValidatePublicEgressIP(ip); err != nil {
		return target, resolvedIP, err
	}
	target.Address = net.JoinHostPort(ip.Unmap().String(), port)
	return target, ip.Unmap().String(), nil
}

func strictPublicEgressDeny(dec policy.Decision, err error) policy.Decision {
	dec.EffectiveDecision = types.DecisionDeny
	dec.Rule = "strict-public-egress-perimeter"
	dec.Message = err.Error()
	return dec
}

func strictPublicEgressSNIDeny(dec policy.Decision, err error) policy.Decision {
	dec.EffectiveDecision = types.DecisionDeny
	dec.Rule = "strict-public-egress-sni-binding"
	dec.Message = err.Error()
	return dec
}

// appendPreDialEvent preserves the legacy best-effort append behavior unless
// strict mode is enabled. Strict mode requires both the append and its durable
// barrier to succeed before the event is published or any dial is attempted.
func (p *Proxy) appendPreDialEvent(ctx context.Context, ev types.Event) error {
	if p == nil || p.emit == nil {
		if p != nil && p.strictPublicEgress {
			return fmt.Errorf("strict public egress requires a durable audit emitter")
		}
		return nil
	}
	if !p.strictPublicEgress {
		_ = p.emit.AppendEvent(context.Background(), ev)
		p.emit.Publish(ev)
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.emit.AppendEvent(ctx, ev); err != nil {
		return fmt.Errorf("append pre-dial audit event: %w", err)
	}
	durable, ok := p.emit.(DurableEmitter)
	if !ok {
		return fmt.Errorf("strict public egress requires an emitter with a durable FlushSync barrier")
	}
	if err := durable.FlushSync(ctx); err != nil {
		return fmt.Errorf("flush pre-dial audit event: %w", err)
	}
	p.emit.Publish(ev)
	return nil
}

var errStrictConnectSNIBinding = errors.New("strict HTTPS CONNECT SNI binding failed")

func (p *Proxy) readAndVerifyStrictConnectClientHello(client net.Conn, connectHost string) ([]byte, tlsClientHelloInfo, string, error) {
	expectedSNI, err := normalizeStrictConnectHost(connectHost)
	if err != nil {
		return nil, tlsClientHelloInfo{}, "", fmt.Errorf("%w: normalize CONNECT authority: %w", errStrictConnectSNIBinding, err)
	}

	timeout := p.tlsClientHelloTimeout
	if timeout <= 0 {
		timeout = defaultStrictTLSClientHelloTimeout
	}
	if err := client.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, tlsClientHelloInfo{}, expectedSNI, fmt.Errorf("%w: set ClientHello deadline: %w", errStrictConnectSNIBinding, err)
	}
	wire, info, readErr := readBoundedTLSClientHello(client, maxStrictTLSClientHelloBytes)
	clearErr := client.SetReadDeadline(time.Time{})
	if readErr != nil {
		return wire, info, expectedSNI, fmt.Errorf("%w: %w", errStrictConnectSNIBinding, readErr)
	}
	if clearErr != nil {
		return wire, info, expectedSNI, fmt.Errorf("%w: clear ClientHello deadline: %w", errStrictConnectSNIBinding, clearErr)
	}

	observedSNI, err := normalizeStrictClientHelloSNI(info.ServerName)
	if err != nil {
		return wire, info, expectedSNI, fmt.Errorf("%w: %w", errStrictConnectSNIBinding, err)
	}
	if observedSNI != expectedSNI {
		nameKind := "ClientHello SNI"
		if info.ECHOffered {
			nameKind = "ECH outer SNI"
		}
		return wire, info, expectedSNI, fmt.Errorf("%w: %s %q does not match CONNECT host %q", errStrictConnectSNIBinding, nameKind, info.ServerName, expectedSNI)
	}
	return wire, info, expectedSNI, nil
}

func normalizeStrictConnectHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return normalizeStrictTLSHostname(host)
}

func normalizeStrictClientHelloSNI(serverName string) (string, error) {
	if strings.HasSuffix(serverName, ".") {
		return "", fmt.Errorf("%w: trailing dot in SNI hostname", ErrMalformedSNI)
	}
	normalized, err := normalizeStrictTLSHostname(serverName)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedSNI, err)
	}
	return normalized, nil
}

func normalizeStrictTLSHostname(host string) (string, error) {
	if host == "" || host != strings.TrimSpace(host) || strings.ContainsAny(host, "\x00\r\n\t @/?#[]") {
		return "", fmt.Errorf("invalid empty or delimited hostname")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return ip.Unmap().String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA hostname %q: %w", host, err)
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid hostname length")
	}
	return ascii, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (p *Proxy) handleConnect(client net.Conn, req *http.Request) error {
	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	host, hostPort, port, err := parseProxyAuthority(authority, 443, true)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return nil
	}
	portStr := strconv.Itoa(port)

	commandID := p.commandID()
	engine := p.policyEngine()

	// Fail-closed check: if the target host is declared as an http_services
	// upstream, deny direct HTTPS regardless of the CheckNetworkCtx decision.
	// The only way to reach the upstream is through the gateway via
	// /svc/<name>/. Services opt out by setting allow_direct: true.
	//
	// Runs BEFORE resolveAndEmitDNS and BEFORE EvaluateConnectRedirect so
	// that blocked requests do not trigger DNS lookups, DNS approval
	// prompts, or redirect side effects.
	if engine != nil {
		if svcName, envVar, ok := engine.DeclaredHTTPServiceHost(host); ok && !engine.DeclaredHTTPServiceAllowsDirect(host) {
			msg := "direct HTTPS to " + host + " is blocked; use " + envVar + " to route through the gateway"
			_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(msg))+"\r\n\r\n"+msg)
			failClosedDec := policy.Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "http_service_declared_fail_closed",
				Message:           msg,
			}
			failClosedFields := map[string]any{
				"method":       "CONNECT",
				"resolved_ip":  "",
				"service_name": svcName,
				"env_var":      envVar,
			}
			netConnectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, failClosedDec, failClosedFields)
			_ = p.emit.AppendEvent(context.Background(), netConnectEv)
			p.emit.Publish(netConnectEv)
			p.emitDBBypassAttempt(context.Background(), commandID, 0, failClosedDec.Rule, failClosedDec.Message)
			p.emitHTTPServiceDeniedDirect(context.Background(), commandID, svcName, envVar, host, "", "CONNECT")
			return nil
		}
	}

	// Check for connect redirect rules before resolving or dialing anything.
	// Hostname policy/approval must complete before the trusted proxy performs
	// DNS or opens an upstream connection.
	var redirectResult *policy.ConnectRedirectResult
	var redirectTLS, redirectSNI string
	if engine != nil {
		result := engine.EvaluateConnectRedirect(hostPort)
		if result.Matched {
			redirectResult = result
			redirectTLS = result.TLSMode
			redirectSNI = result.SNI
			// Emit redirect event if visibility is not silent
			if result.Visibility != "silent" {
				p.emitConnectRedirectEvent(context.Background(), commandID, host, hostPort, port, result)
			}
		}
	}

	ctx := req.Context()
	dec := p.checkConnectNetwork(ctx, commandID, host, hostPort, port, redirectResult)
	eventFields := map[string]any{
		"method":      "CONNECT",
		"resolved_ip": "",
	}
	if redirectResult != nil {
		if redirectResult.RedirectTo != "" {
			eventFields["redirect_to"] = redirectResult.RedirectTo
		}
		if redirectResult.RedirectToUnix != "" {
			eventFields["redirect_to_unix"] = redirectResult.RedirectToUnix
		}
		eventFields["redirect_tls"] = redirectTLS
		if redirectSNI != "" {
			eventFields["redirect_sni"] = redirectSNI
		}
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		dec.EffectiveDecision = types.DecisionDeny
		connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, dec, eventFields)
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		p.emitDBBypassAttempt(context.Background(), commandID, 0, dec.Rule, dec.Message)
		return nil
	}

	resolvedIP := ""
	needsOriginalDNS := redirectResult == nil || (redirectResult.RedirectTo == "" && redirectResult.RedirectToUnix == "")
	if needsOriginalDNS {
		var resolved bool
		resolvedIP, resolved = p.resolveAndEmitDNSChecked(context.Background(), commandID, host)
		if !resolved {
			failed := dec
			failed.EffectiveDecision = types.DecisionDeny
			eventFields["proxy_error"] = "destination resolution was denied or failed"
			connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, failed, eventFields)
			_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			_ = p.emit.AppendEvent(context.Background(), connectEv)
			p.emit.Publish(connectEv)
			return nil
		}
		eventFields["resolved_ip"] = resolvedIP
	}
	// Determine dial target: redirect destination or original.
	dialTarget := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: hostPort,
		ResolvedIP:       resolvedIP,
		OriginalPort:     portStr,
		Redirect:         redirectResult,
	})
	if p.strictPublicEgress {
		var dialResolvedIP string
		dialTarget, dialResolvedIP, err = p.prepareStrictPublicDialTarget(ctx, commandID, dialTarget)
		if err != nil {
			eventFields["strict_public_egress"] = true
			eventFields["proxy_error"] = err.Error()
			if dialResolvedIP != "" {
				eventFields["rejected_ip"] = dialResolvedIP
			}
			denied := strictPublicEgressDeny(dec, err)
			connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, denied, eventFields)
			_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
			if p.emit != nil {
				_ = p.emit.AppendEvent(context.Background(), connectEv)
				p.emit.Publish(connectEv)
			}
			return nil
		}
		eventFields["strict_public_egress"] = true
		if dialResolvedIP != "" {
			eventFields["dial_resolved_ip"] = dialResolvedIP
		}
		exactDecision := p.checkNetworkExactIP(host, dialResolvedIP, port)
		exactDecision = p.maybeApprove(ctx, commandID, exactDecision, "network", hostPort)
		if exactDecision.EffectiveDecision != types.DecisionAllow {
			exactDecision.EffectiveDecision = types.DecisionDeny
			eventFields["policy_ip"] = dialResolvedIP
			connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, exactDecision, eventFields)
			_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
			if p.emit != nil {
				_ = p.emit.AppendEvent(context.Background(), connectEv)
				p.emit.Publish(connectEv)
			}
			return nil
		}
		dec = exactDecision
	}

	strictHTTPS := p.strictPublicEgress && port == 443
	var firstClientHello []byte
	tunnelEstablished := false
	if strictHTTPS {
		// A CONNECT client waits for 200 before starting TLS. Strict mode must
		// therefore establish only the client-side tunnel, inspect its bounded
		// ClientHello, and bind the visible (outer, for ECH) SNI before any
		// upstream socket exists.
		if err := writeAll(client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return nil
		}
		tunnelEstablished = true

		var helloInfo tlsClientHelloInfo
		var expectedSNI string
		firstClientHello, helloInfo, expectedSNI, err = p.readAndVerifyStrictConnectClientHello(client, host)
		eventFields["tls_sni_expected"] = expectedSNI
		if helloInfo.ServerName != "" {
			eventFields["tls_sni"] = helloInfo.ServerName
		}
		if helloInfo.ECHOffered {
			eventFields["tls_ech"] = true
		}
		if err != nil {
			eventFields["proxy_error"] = err.Error()
			denied := strictPublicEgressSNIDeny(dec, err)
			deniedEvent := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, denied, eventFields)
			if auditErr := p.appendPreDialEvent(ctx, deniedEvent); auditErr != nil {
				p.fail(auditErr)
			}
			return nil
		}
	}

	connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, dec, eventFields)
	if err := p.appendPreDialEvent(ctx, connectEv); err != nil {
		if !tunnelEstablished {
			_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		}
		p.fail(err)
		return nil
	}

	emitMCPConnectionIfMatched(context.Background(), p.sess, p.emit, p.sessionID, commandID, host, hostPort, port)

	up, err := p.dial(ctx, dialTarget.Network, dialTarget.Address)
	if err != nil {
		if !tunnelEstablished {
			_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		}
		return nil
	}
	defer up.Close()

	if !tunnelEstablished {
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}

	var initialUpBytes int64
	if strictHTTPS {
		// Forward the exact buffered record framing and bytes only after the
		// pinned dial's allow event has crossed its durable audit barrier.
		if err := writeAll(up, firstClientHello); err != nil {
			return nil
		}
		initialUpBytes = int64(len(firstClientHello))
	} else if redirectTLS == "rewrite_sni" && redirectSNI != "" {
		// Legacy/non-strict redirect behavior remains best-effort.
		if err := sniRewriteFirstRecord(client, up, redirectSNI); err != nil {
			if !isSNIParseError(err) {
				return nil // I/O error, connection broken
			}
			// Parse error: first record forwarded unchanged, continue
		}
	}

	var upBytes, downBytes int64
	upBytes = initialUpBytes
	errCh := make(chan error, 2)
	// Use sync.Once to ensure we only close connections once
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			// Close both sides to unblock any pending io.Copy
			_ = client.Close()
			_ = up.Close()
		})
	}
	go func() {
		n, e := io.Copy(up, client)
		upBytes = initialUpBytes + n
		closeBoth() // Signal other copy to stop
		errCh <- e
	}()
	go func() {
		n, e := io.Copy(client, up)
		downBytes = n
		closeBoth() // Signal other copy to stop
		errCh <- e
	}()
	<-errCh
	<-errCh

	closeEv := p.emitNetEvent(context.Background(), "net_close", commandID, host, hostPort, port, dec, map[string]any{
		"bytes_sent":     upBytes,
		"bytes_received": downBytes,
		"resolved_ip":    resolvedIP,
	})
	_ = p.emit.AppendEvent(context.Background(), closeEv)
	p.emit.Publish(closeEv)
	return nil
}

func (p *Proxy) handleHTTP(client net.Conn, req *http.Request) error {
	if req.URL == nil || req.URL.User != nil || (req.URL.Scheme != "" && !strings.EqualFold(req.URL.Scheme, "http")) {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return nil
	}
	authority := req.URL.Host
	if authority == "" {
		authority = req.Host
	}
	host, hostPort, port, err := parseProxyAuthority(authority, 80, false)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return nil
	}

	commandID := p.commandID()
	engine := p.policyEngine()

	// Fail-closed check: if the target host is declared as an http_services
	// upstream, deny direct HTTP regardless of the CheckNetworkCtx decision.
	// Matches the analogous block in handleConnect. Services opt out by
	// setting allow_direct: true.
	//
	// Runs BEFORE resolveAndEmitDNS and BEFORE net_http_request emission so
	// that blocked requests do not trigger DNS lookups, DNS approval
	// prompts, or observable request-tracking side effects.
	if engine != nil {
		if svcName, envVar, ok := engine.DeclaredHTTPServiceHost(host); ok && !engine.DeclaredHTTPServiceAllowsDirect(host) {
			msg := "direct HTTP to " + host + " is blocked; use " + envVar + " to route through the gateway"
			_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(msg))+"\r\n\r\n"+msg)
			failClosedDec := policy.Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "http_service_declared_fail_closed",
				Message:           msg,
			}
			failClosedFields := map[string]any{
				"method":       req.Method,
				"resolved_ip":  "",
				"service_name": svcName,
				"env_var":      envVar,
			}
			netConnectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, failClosedDec, failClosedFields)
			_ = p.emit.AppendEvent(context.Background(), netConnectEv)
			p.emit.Publish(netConnectEv)
			p.emitDBBypassAttempt(context.Background(), commandID, 0, failClosedDec.Rule, failClosedDec.Message)
			p.emitHTTPServiceDeniedDirect(context.Background(), commandID, svcName, envVar, host, "", req.Method)
			return nil
		}
	}

	ctx := req.Context()
	dec := p.checkNetwork(ctx, host, port)
	dec = p.maybeApprove(ctx, commandID, dec, "network", hostPort)
	connectFields := map[string]any{
		"method":      req.Method,
		"resolved_ip": "",
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		dec.EffectiveDecision = types.DecisionDeny
		connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, dec, connectFields)
		resp := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nblocked by policy\n"
		_, _ = io.WriteString(client, resp)
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		p.emitDBBypassAttempt(context.Background(), commandID, 0, dec.Rule, dec.Message)
		return nil
	}

	resolvedIP, resolved := p.resolveAndEmitDNSChecked(context.Background(), commandID, host)
	if !resolved {
		failed := dec
		failed.EffectiveDecision = types.DecisionDeny
		connectFields["proxy_error"] = "destination resolution was denied or failed"
		connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, failed, connectFields)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		return nil
	}
	connectFields["resolved_ip"] = resolvedIP

	approvedDialTarget := resolvedConnectDialTarget{
		Network: "tcp",
		Address: net.JoinHostPort(resolvedIP, strconv.Itoa(port)),
	}
	if p.strictPublicEgress {
		var dialResolvedIP string
		approvedDialTarget, dialResolvedIP, err = p.prepareStrictPublicDialTarget(ctx, commandID, approvedDialTarget)
		if err != nil {
			connectFields["strict_public_egress"] = true
			connectFields["proxy_error"] = err.Error()
			if dialResolvedIP != "" {
				connectFields["rejected_ip"] = dialResolvedIP
			}
			denied := strictPublicEgressDeny(dec, err)
			connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, denied, connectFields)
			_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
			if p.emit != nil {
				_ = p.emit.AppendEvent(context.Background(), connectEv)
				p.emit.Publish(connectEv)
			}
			return nil
		}
		connectFields["strict_public_egress"] = true
		connectFields["dial_resolved_ip"] = dialResolvedIP
		exactDecision := p.checkNetworkExactIP(host, dialResolvedIP, port)
		exactDecision = p.maybeApprove(ctx, commandID, exactDecision, "network", hostPort)
		if exactDecision.EffectiveDecision != types.DecisionAllow {
			exactDecision.EffectiveDecision = types.DecisionDeny
			connectFields["policy_ip"] = dialResolvedIP
			connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, exactDecision, connectFields)
			_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
			if p.emit != nil {
				_ = p.emit.AppendEvent(context.Background(), connectEv)
				p.emit.Publish(connectEv)
			}
			return nil
		}
		dec = exactDecision
	}

	// Note: HTTPS through an explicit proxy uses CONNECT. This path is plain
	// HTTP, where method/path can be recorded after policy approval and local
	// resolution but before the one approved upstream dial.
	if p.emit != nil {
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "net_http_request",
			SessionID: p.sessionID,
			CommandID: commandID,
			Domain:    strings.ToLower(host),
			Remote:    hostPort,
			Fields: map[string]any{
				"method":      req.Method,
				"path":        req.URL.Path,
				"resolved_ip": resolvedIP,
			},
		}
		_ = p.emit.AppendEvent(context.Background(), ev)
		p.emit.Publish(ev)
	}

	connectEv := p.emitNetEvent(context.Background(), "net_connect", commandID, host, hostPort, port, dec, connectFields)
	if err := p.appendPreDialEvent(ctx, connectEv); err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		p.fail(err)
		return nil
	}

	emitMCPConnectionIfMatched(context.Background(), p.sess, p.emit, p.sessionID, commandID, host, hostPort, port)

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || !strings.EqualFold(address, hostPort) {
				return nil, fmt.Errorf("refusing unapproved proxy dial target %s %s", network, address)
			}
			return p.dial(dialCtx, approvedDialTarget.Network, approvedDialTarget.Address)
		},
	}
	defer transport.CloseIdleConnections()

	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = hostPort

	// Strip hop-by-hop headers per RFC 2616 Section 13.5.1
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, h := range hopByHopHeaders {
		req.Header.Del(h)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return nil
	}
	defer resp.Body.Close()

	if err := resp.Write(client); err != nil {
		return nil
	}
	return nil
}

func (p *Proxy) checkNetwork(ctx context.Context, domain string, port int) policy.Decision {
	engine := p.policyEngine()
	if engine == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	if p.strictPublicEgress {
		// Strict mode's first policy pass is hostname-only. CheckNetworkIP with a
		// nil IP never resolves DNS, unlike CheckNetworkCtx.
		return engine.CheckNetworkIP(domain, nil, port)
	}
	return engine.CheckNetworkCtx(ctx, domain, port)
}

func (p *Proxy) checkNetworkExactIP(domain string, resolvedIP string, port int) policy.Decision {
	engine := p.policyEngine()
	if engine == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	ip := net.ParseIP(resolvedIP)
	if ip == nil {
		return policy.Decision{
			PolicyDecision: types.DecisionDeny, EffectiveDecision: types.DecisionDeny,
			Rule: "strict-public-egress-perimeter", Message: "strict public egress selected an invalid policy IP",
		}
	}
	return engine.CheckNetworkIP(domain, ip, port)
}

func (p *Proxy) checkConnectNetwork(ctx context.Context, commandID string, host string, hostPort string, port int, redirect *policy.ConnectRedirectResult) policy.Decision {
	dec := p.checkNetwork(ctx, host, port)
	if allowUnixRedirectForDBUnavoidability(p.policyEngine(), dec, redirect) {
		return allowConnectRedirectDecision(redirect)
	}
	dec = p.maybeApprove(ctx, commandID, dec, "network", hostPort)
	return dec
}

func (p *Proxy) isDBUnavoidabilityTCPDirectRule(ruleName string) bool {
	if p == nil {
		return false
	}
	return isDBUnavoidabilityTCPDirectRule(p.policyEngine(), ruleName)
}

func (p *Proxy) policyEngine() *policy.Engine {
	if p == nil {
		return nil
	}
	if p.sess != nil {
		if engine := p.sess.PolicyEngine(); engine != nil {
			return engine
		}
	}
	return p.policy
}

func (p *Proxy) emitDBBypassAttempt(ctx context.Context, commandID string, pid int, ruleName string, reason string) {
	if p == nil {
		return
	}
	em := p.dbBypass.Load()
	if em == nil {
		return
	}
	em.EmitIfDBUnavoidabilityDeny(ctx, dbevents.BypassAttempt{
		Engine:          p.policyEngine(),
		SessionID:       p.sessionID,
		CommandID:       commandID,
		ProcessID:       pid,
		ProcessIdentity: dbBypassProcessIdentity(p.sessionID, commandID),
		RuleName:        ruleName,
		Reason:          reason,
	})
}

func dbBypassProcessIdentity(sessionID string, commandID string) string {
	if commandID != "" {
		return "command:" + commandID
	}
	return "session:" + sessionID
}

func allowUnixRedirectForDBUnavoidability(engine *policy.Engine, dec policy.Decision, redirect *policy.ConnectRedirectResult) bool {
	return redirect != nil &&
		redirect.RedirectToUnix != "" &&
		dec.EffectiveDecision == types.DecisionDeny &&
		isDBUnavoidabilityTCPDirectRule(engine, dec.Rule) &&
		isDBUnavoidabilityTCPDirectRule(engine, redirect.Rule)
}

func isDBUnavoidabilityTCPDirectRule(engine *policy.Engine, ruleName string) bool {
	if engine == nil || ruleName == "" {
		return false
	}
	pol := engine.Policy()
	if pol == nil {
		return false
	}
	for _, m := range pol.Metadata {
		if m.RuleName == ruleName && m.Source == "db_unavoidability" && m.BypassMode == "tcp_direct" {
			return true
		}
	}
	return false
}

func allowConnectRedirectDecision(redirect *policy.ConnectRedirectResult) policy.Decision {
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
		Rule:              redirect.Rule,
		Message:           redirect.Message,
	}
}

func (p *Proxy) maybeApprove(ctx context.Context, commandID string, dec policy.Decision, kind string, target string) policy.Decision {
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return dec
	}
	if p.approvals == nil {
		// An approval decision is not permission to connect. If no synchronous
		// resolver is installed, convert it to an effective deny before any DNS or
		// upstream dial can occur.
		dec.EffectiveDecision = types.DecisionDeny
		return dec
	}
	scope, hasScope := approvalScopeFor(kind, target)
	if hasScope {
		if scoped, ok := p.approvals.CheckScoped(ctx, p.sessionID, commandID, scope); ok {
			if scoped.Approved {
				dec.EffectiveDecision = types.DecisionAllow
			} else {
				dec.EffectiveDecision = types.DecisionDeny
			}
			return dec
		}
	}
	fields := map[string]any(nil)
	if hasScope {
		fields = requestFieldsForScope(scope)
	}
	req := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: p.sessionID,
		CommandID: commandID,
		Kind:      kind,
		Target:    target,
		Rule:      dec.Rule,
		Message:   dec.Message,
		Fields:    fields,
	}
	res, err := p.approvals.RequestApproval(ctx, req)
	if dec.Approval != nil {
		dec.Approval.ID = req.ID
	}
	if err != nil || !res.Approved {
		dec.EffectiveDecision = types.DecisionDeny
	} else {
		dec.EffectiveDecision = types.DecisionAllow
	}
	return dec
}

func (p *Proxy) emitNetEvent(ctx context.Context, evType string, commandID string, domain string, remote string, port int, dec policy.Decision, fields map[string]any) types.Event {
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: p.sessionID,
		CommandID: commandID,
		Domain:    strings.ToLower(domain),
		Remote:    remote,
		Fields:    fields,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
			ThreatFeed:        dec.ThreatFeed,
			ThreatMatch:       dec.ThreatMatch,
			ThreatAction:      dec.ThreatAction,
		},
	}
	return ev
}

func (p *Proxy) emitConnectRedirectEvent(ctx context.Context, commandID string, domain string, hostPort string, port int, result *policy.ConnectRedirectResult) {
	if p == nil {
		return
	}
	emitConnectRedirectEvent(ctx, p.emit, p.sessionID, commandID, domain, hostPort, port, result)
}

func emitConnectRedirectEvent(ctx context.Context, emit Emitter, sessionID string, commandID string, domain string, hostPort string, port int, result *policy.ConnectRedirectResult) {
	if emit == nil {
		return
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "connect_redirect",
		SessionID: sessionID,
		CommandID: commandID,
		Domain:    strings.ToLower(domain),
		Remote:    hostPort,
		Fields: map[string]any{
			"rule":       result.Rule,
			"tls_mode":   result.TLSMode,
			"message":    result.Message,
			"visibility": result.Visibility,
		},
	}
	if result.RedirectTo != "" {
		ev.Fields["redirect_to"] = result.RedirectTo
	}
	if result.RedirectToUnix != "" {
		ev.Fields["redirect_to_unix"] = result.RedirectToUnix
	}
	if result.SNI != "" {
		ev.Fields["sni"] = result.SNI
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)
}

// emitMCPConnectionIfMatched checks whether the connection target is a known
// MCP server address and, if so, emits an mcp_network_connection event.
// This is a shared function called from both Proxy and TransparentTCP handlers.
func emitMCPConnectionIfMatched(ctx context.Context, sess *session.Session, emit Emitter, sessionID, commandID, domain, remote string, port int) {
	if sess == nil || emit == nil {
		return
	}
	src, ok := sess.MCPRegistry().(mcpAddrSource)
	if !ok || src == nil {
		return
	}
	addrs := src.ServerAddrs()
	if len(addrs) == 0 {
		return
	}

	hostPort := net.JoinHostPort(domain, strconv.Itoa(port))
	serverID, found := addrs[hostPort]
	if !found {
		serverID, found = addrs[remote]
	}
	if !found {
		return
	}

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "mcp_network_connection",
		SessionID: sessionID,
		CommandID: commandID,
		Domain:    strings.ToLower(domain),
		Remote:    remote,
		Fields: map[string]any{
			"server_id": serverID,
		},
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)
}

// emitHTTPServiceDeniedDirect records an audit event when the fail-closed
// check in handleConnect or handleHTTP refuses a direct request to a
// declared http_services upstream. These events give operators an
// observable signal that a child process attempted to bypass the
// gateway, even though they can take no corrective action in-band.
func (p *Proxy) emitHTTPServiceDeniedDirect(ctx context.Context, commandID, svcName, envVar, host, resolvedIP, method string) {
	if p.emit == nil {
		return
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "http_service_denied_direct",
		SessionID: p.sessionID,
		CommandID: commandID,
		Domain:    strings.ToLower(host),
		Remote:    host,
		Fields: map[string]any{
			"service_name": svcName,
			"env_var":      envVar,
			"request_host": host,
			"resolved_ip":  resolvedIP,
			"method":       method,
		},
	}
	_ = p.emit.AppendEvent(ctx, ev)
	p.emit.Publish(ev)
}

// parseProxyAuthority returns the canonical destination the proxy will dial.
// CONNECT requires an explicit numeric port; plain HTTP may use its protocol
// default. Malformed authorities, userinfo-like whitespace, zones, and
// out-of-range/service-name ports are rejected before policy evaluation.
func parseProxyAuthority(authority string, defaultPort int, requireExplicitPort bool) (host, hostPort string, port int, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" || strings.ContainsAny(authority, "\x00\r\n\t @/?#") {
		return "", "", 0, fmt.Errorf("invalid empty or whitespace-containing proxy authority")
	}

	host, portText, splitErr := net.SplitHostPort(authority)
	if splitErr != nil {
		if requireExplicitPort {
			return "", "", 0, fmt.Errorf("proxy authority requires an explicit numeric port: %w", splitErr)
		}
		port = defaultPort
		switch {
		case strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]"):
			host = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
		case strings.Contains(authority, ":"):
			return "", "", 0, fmt.Errorf("invalid proxy authority %q: %w", authority, splitErr)
		default:
			host = authority
		}
	} else {
		parsed, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || parsed == 0 {
			return "", "", 0, fmt.Errorf("proxy authority port %q must be numeric and between 1 and 65535", portText)
		}
		port = int(parsed)
	}
	if port <= 0 || port > 65535 {
		return "", "", 0, fmt.Errorf("proxy authority port must be between 1 and 65535")
	}
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "\x00\r\n\t @/?#") {
		return "", "", 0, fmt.Errorf("proxy authority host is invalid")
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if ip.Zone() != "" {
			return "", "", 0, fmt.Errorf("proxy authority must not contain an IP zone")
		}
		host = ip.Unmap().String()
	}
	return host, net.JoinHostPort(host, strconv.Itoa(port)), port, nil
}

// resolveAndEmitDNS is retained for focused callers/tests. Proxy forwarding
// uses resolveAndEmitDNSChecked so a denied or failed lookup can never fall
// through to a second implicit resolver inside net.Dial/http.Transport.
func (p *Proxy) resolveAndEmitDNS(ctx context.Context, commandID string, host string) string {
	ip, _ := p.resolveAndEmitDNSChecked(ctx, commandID, host)
	return ip
}

func (p *Proxy) resolveAndEmitDNSChecked(ctx context.Context, commandID string, host string) (string, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	// No DNS resolution or DNS-policy operation is needed for literal IPs.
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return ip.Unmap().String(), true
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	dec := p.checkNetwork(ctx, host, 53)
	// Mirror dns.go behavior: treat default deny as monitor-only unless an
	// explicit DNS rule matched.
	if dec.PolicyDecision == types.DecisionDeny && dec.Rule == "default-deny-network" {
		dec.PolicyDecision = types.DecisionAllow
		dec.EffectiveDecision = types.DecisionAllow
		dec.Rule = "dns-monitor-only"
	}
	dec = p.maybeApprove(ctx, commandID, dec, "dns", host)

	var addrs []net.IPAddr
	var lookupErr error
	if dec.EffectiveDecision == types.DecisionAllow {
		addrs, lookupErr = p.lookup(ctx, host)
	} else {
		dec.EffectiveDecision = types.DecisionDeny
		lookupErr = fmt.Errorf("DNS policy denied resolution")
	}
	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		if parsed, ok := netip.AddrFromSlice(addr.IP); ok && parsed.Zone() == "" {
			ips = append(ips, parsed.Unmap().String())
		}
	}

	if p.emit != nil {
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "dns_query",
			SessionID: p.sessionID,
			CommandID: commandID,
			Domain:    strings.ToLower(host),
			Fields: map[string]any{
				"ips":    ips,
				"source": "proxy",
			},
			Policy: &types.PolicyInfo{
				Decision:          dec.PolicyDecision,
				EffectiveDecision: dec.EffectiveDecision,
				Rule:              dec.Rule,
				Message:           dec.Message,
				Approval:          dec.Approval,
				ThreatFeed:        dec.ThreatFeed,
				ThreatMatch:       dec.ThreatMatch,
				ThreatAction:      dec.ThreatAction,
			},
		}
		if lookupErr != nil {
			ev.Fields["error"] = lookupErr.Error()
		}
		_ = p.emit.AppendEvent(context.Background(), ev)
		p.emit.Publish(ev)
	}

	if lookupErr != nil || len(ips) == 0 {
		return "", false
	}
	return ips[0], true
}

func mustAtoi(s string, def int) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
