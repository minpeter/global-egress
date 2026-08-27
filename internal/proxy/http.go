package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/pool"
)

// HTTPServer serves the pool as an HTTP forward proxy.
//
// It handles both proxy styles:
//
//	CONNECT host:443            tunnelled, used for every https:// request
//	GET http://host/path        absolute-URI, used for plain http://
//
// Clients therefore only need HTTP_PROXY/HTTPS_PROXY pointing here.
type HTTPServer struct {
	deps *Deps
}

// NewHTTP builds an HTTP proxy server.
func NewHTTP(deps Deps) *HTTPServer {
	deps.applyDefaults()
	return &HTTPServer{deps: &deps}
}

// Serve accepts connections until the listener is closed.
func (s *HTTPServer) Serve(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler: s,
		// Proxied sessions can be long-lived, so no global write timeout; idle
		// enforcement happens in the relay instead.
		ReadHeaderTimeout: handshakeTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP implements the proxy.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := s.deps.Logger.With(slog.String("proto", "http"))

	remote, err := addrFromString(r.RemoteAddr)
	if err != nil {
		// Access checks must fail closed. RemoteAddr is normally supplied by the
		// HTTP server as host:port, so an unparsable value is not a valid client.
		log.Warn("client address rejected", errorTypeAttr(err))
		http.Error(w, "client not allowed", http.StatusForbidden)
		return
	}
	if err := s.deps.checkClient(remote); err != nil {
		log.Warn("client rejected", errorTypeAttr(err))
		http.Error(w, "client not allowed", http.StatusForbidden)
		return
	}

	username, password, hadCredentials := proxyCredentials(r)
	pol, err := s.deps.authorize(username, password, hadCredentials)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="global-egress"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		if errors.Is(err, errPolicyRequired) {
			// 407 rather than 400: the directives arrive as proxy credentials, so
			// "send credentials" is both the accurate diagnosis and the fix, and it
			// is the status clients already know how to surface.
			w.Header().Set("Proxy-Authenticate", `Basic realm="global-egress"`)
			http.Error(w, "no selection policy supplied: put the directives in the proxy "+
				"username and give a non-empty password, e.g. \"cc=jp:x\". Several clients "+
				"drop the credentials entirely when the password is empty.",
				http.StatusProxyAuthRequired)
			return
		}
		http.Error(w, "invalid proxy policy", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r, pol, log)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "global-egress is a forward proxy; configure it as HTTP_PROXY/HTTPS_PROXY",
			http.StatusBadRequest)
		return
	}
	s.handleForward(w, r, pol, log)
}

// handleConnect tunnels an arbitrary TCP stream, which is how HTTPS is proxied.
func (s *HTTPServer) handleConnect(w http.ResponseWriter, r *http.Request, pol policy.Policy, log *slog.Logger) {
	host, port, err := splitTargetHostPort(r.Host, 443)
	if err != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}

	started := time.Now()
	upstream, lease, err := s.deps.connectUpstream(r.Context(), pol, host, port)
	if err != nil {
		s.deps.observeRequestPhase(
			pol, lease, requestResult(err), pool.TimeoutPhaseAcquire, time.Since(started))
		log.Warn("connect failed",
			policyLogAttr(pol),
			errorTypeAttr(err))
		http.Error(w, "CONNECT failed", statusCodeFor(err))
		return
	}
	s.deps.observeRequest(pol, lease, pool.RequestSuccess, time.Since(started))
	defer lease.Release()
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Warn("hijack failed", errorTypeAttr(err))
		return
	}
	defer client.Close()

	// Report the chosen egress in the CONNECT response so clients can react to
	// the IP they were given. These headers are manually serialized after hijack,
	// so writeConnectEstablished validates every dynamic value before writing it.
	if err := writeConnectEstablished(client, lease, pol); err != nil {
		return
	}

	// Anything the client pipelined after CONNECT must be forwarded first. Those
	// bytes are relayed too, so they belong in the accounting: a client that sends
	// its TLS hello immediately would otherwise have it silently uncounted.
	var pipelined int64
	if buffered != nil && buffered.Reader.Buffered() > 0 {
		copied, err := io.CopyN(upstream, buffered, int64(buffered.Reader.Buffered()))
		pipelined = copied
		if err != nil {
			s.deps.Pool.RecordTraffic(lease, pipelined, 0)
			return
		}
	}

	started = time.Now()
	sent, received := relay(client, upstream, s.deps.IdleTimeout)
	sent += pipelined
	s.deps.Pool.RecordTraffic(lease, sent, received)
	log.Info("session finished",
		slog.String("slot", lease.Slot.ID),
		slog.Bool("egress_ip_measured", lease.PublicIP.IsValid()),
		policyLogAttr(pol),
		slog.Int64("sent", sent),
		slog.Int64("received", received),
		slog.Duration("duration", time.Since(started)))
}

// hopByHopHeaders must not be forwarded to the origin server.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// handleForward performs a plain http:// request on the client's behalf.
func (s *HTTPServer) handleForward(w http.ResponseWriter, r *http.Request, pol policy.Policy, log *slog.Logger) {
	host, port, err := splitTargetHostPort(r.URL.Host, 80)
	if err != nil {
		http.Error(w, "invalid HTTP proxy target", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "only http:// absolute URIs are supported; use CONNECT for https://",
			http.StatusBadRequest)
		return
	}

	// Reject forbidden destinations before acquiring a lease. Besides avoiding
	// unnecessary work, this prevents denied requests from binding sessions or
	// consuming a unique-batch slot.
	if err := s.deps.Guard.CheckPort(port); err != nil {
		http.Error(w, "HTTP proxy target rejected", http.StatusForbidden)
		return
	}
	if err := s.deps.Guard.CheckHost(host); err != nil {
		http.Error(w, "HTTP proxy target rejected", http.StatusForbidden)
		return
	}

	started := time.Now()
	lease, err := s.deps.Pool.Acquire(r.Context(), pol, host)
	if err != nil {
		s.deps.observeRequestPhase(
			pol, nil, requestResult(err), pool.TimeoutPhaseAcquire, time.Since(started))
		log.Warn("acquire failed", policyLogAttr(pol), errorTypeAttr(err))
		http.Error(w, "egress unavailable", statusCodeFor(err))
		return
	}
	defer lease.Release()

	// One transport per request keeps slot selection honest: a pooled connection
	// would silently pin later requests to an earlier slot.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := lease.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if !lease.Chained {
				if err := s.deps.Guard.CheckResolved(conn.RemoteAddr()); err != nil {
					_ = conn.Close()
					return nil, err
				}
			}
			return conn, nil
		},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	defer transport.CloseIdleConnections()

	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	for _, header := range hopByHopHeaders {
		outbound.Header.Del(header)
	}
	stripEgressHeaders(outbound.Header)
	// Count the request body on its way out so uploads are not invisible.
	var uploaded countingReader
	if outbound.Body != nil {
		uploaded.inner = outbound.Body
		outbound.Body = &uploaded
	}

	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		s.deps.observeRequestPhase(
			pol, lease, upstreamResult(err), pool.TimeoutPhaseUpstream, time.Since(started))
		log.Warn("upstream request failed",
			slog.String("slot", lease.Slot.ID),
			errorTypeAttr(err))
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	s.deps.observeRequest(pol, lease, pool.RequestSuccess, time.Since(started))
	defer resp.Body.Close()

	copyForwardResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, resp.Body)
	s.deps.Pool.RecordTraffic(lease, uploaded.n, written)

	log.Info("request finished",
		slog.String("slot", lease.Slot.ID),
		slog.Bool("egress_ip_measured", lease.PublicIP.IsValid()),
		policyLogAttr(pol),
		slog.Int("status", resp.StatusCode),
		slog.Int64("bytes", written),
		slog.Duration("duration", time.Since(started)))
}

// countingReader tallies a request body as it is streamed upstream, since the
// content length is often unknown until the body has been read.
type countingReader struct {
	inner io.ReadCloser
	n     int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	read, err := c.inner.Read(p)
	c.n += int64(read)
	return read, err
}

func (c *countingReader) Close() error { return c.inner.Close() }

// copyForwardResponseHeaders copies an origin response while reserving the
// X-Egress-* namespace for the CONNECT metadata. Plain HTTP responses must not
// reveal or spoof egress-selection details.
func copyForwardResponseHeaders(destination, source http.Header) {
	for key, values := range source {
		if isEgressHeader(key) {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func stripEgressHeaders(header http.Header) {
	for key := range header {
		if isEgressHeader(key) {
			header.Del(key)
		}
	}
}

func isEgressHeader(key string) bool {
	return strings.HasPrefix(strings.ToLower(key), "x-egress-")
}

// writeConnectEstablished writes CONNECT metadata after validating dynamic
// values. net/http cannot serialize headers once the connection is hijacked, so
// accepting CR, LF, or other control characters here would permit response
// splitting from catalog metadata or a manually constructed policy.
func writeConnectEstablished(w io.Writer, lease *pool.Lease, pol policy.Policy) error {
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 Connection Established\r\n")
	headers := egressHeaders(lease, pol)
	for _, key := range []string{
		"X-Egress-Slot",
		"X-Egress-Country",
		"X-Egress-City",
		"X-Egress-IP",
		"X-Egress-Session",
		"X-Egress-Policy",
	} {
		value, ok := headers[key]
		if !ok || !validHeaderValue(value) {
			continue
		}
		response.WriteString(key)
		response.WriteString(": ")
		response.WriteString(value)
		response.WriteString("\r\n")
	}
	response.WriteString("\r\n")
	_, err := io.WriteString(w, response.String())
	return err
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '\t' || value[i] >= ' ' && value[i] != 0x7f {
			continue
		}
		return false
	}
	return true
}

// egressHeaders describe the chosen slot, and the policy that chose it, to the
// client.
//
// Reporting the policy back matters more than it looks: the directives ride in the
// proxy username, and a client that drops the credentials still gets a perfectly
// good response from an arbitrary exit. Echoing what the server actually parsed is
// what turns that into something a caller can notice.
func egressHeaders(lease *pool.Lease, pol policy.Policy) map[string]string {
	headers := map[string]string{
		"X-Egress-Slot":   lease.Slot.ID,
		"X-Egress-Policy": pol.String(),
	}
	if lease.Slot.Country != "" {
		headers["X-Egress-Country"] = lease.Slot.Country
	}
	if lease.Slot.City != "" {
		headers["X-Egress-City"] = lease.Slot.City
	}
	if lease.PublicIP.IsValid() {
		headers["X-Egress-IP"] = lease.PublicIP.String()
	}
	if lease.Session != "" {
		headers["X-Egress-Session"] = lease.Session
	}
	return headers
}

// proxyCredentials extracts Basic credentials from Proxy-Authorization.
// Authorization is deliberately not accepted as a fallback: on plain HTTP
// proxy requests it belongs to the origin server and may contain unrelated
// credentials that must be forwarded unchanged.
func proxyCredentials(r *http.Request) (username, password string, ok bool) {
	value := r.Header.Get("Proxy-Authorization")
	scheme, encoded, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

// splitTargetHostPort parses "host", "host:port" and "[v6]:port".
func splitTargetHostPort(value string, defaultPort int) (string, int, error) {
	if value == "" {
		return "", 0, errors.New("missing destination host")
	}
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		// No port present, which is normal for an absolute URI host. Fall back to
		// the scheme's default port rather than rejecting the request.
		return strings.Trim(value, "[]"), defaultPort, nil //nolint:nilerr // a missing port is not an error
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid destination port in %q", value)
	}
	return host, port, nil
}

func addrFromString(value string) (net.Addr, error) {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}, nil
}

// statusCodeFor maps pool failures to HTTP status codes.
func statusCodeFor(err error) int {
	switch {
	case errors.Is(err, pool.ErrPolicy):
		return http.StatusBadRequest
	case errors.Is(err, pool.ErrBatchFull):
		// The shared active-batch map is temporarily at capacity.
		return http.StatusServiceUnavailable
	case errors.Is(err, pool.ErrNoCandidate):
		// The request was understood but no egress matches the policy.
		return http.StatusConflict
	case errors.Is(err, pool.ErrBusy), errors.Is(err, pool.ErrSessionFull):
		// Purely load; a client may retry immediately.
		return http.StatusServiceUnavailable
	case errors.Is(err, pool.ErrCapacity), errors.Is(err, pool.ErrTunnelBudget):
		// Retryable: an existing tunnel will free up, or the rate window rolls.
		return http.StatusServiceUnavailable
	case errors.Is(err, pool.ErrExhausted):
		return http.StatusBadGateway
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}
