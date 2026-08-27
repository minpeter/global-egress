package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/netguard"
	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/pool"
)

func TestCheckClient(t *testing.T) {
	deps := &Deps{AllowedClients: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("::1/128"),
	}}

	allowed := []string{"10.0.0.7:5000", "[::1]:5000"}
	for _, addr := range allowed {
		if err := deps.checkClient(mustAddr(t, addr)); err != nil {
			t.Errorf("checkClient(%s) = %v, want allowed", addr, err)
		}
	}
	denied := []string{"192.168.0.5:5000", "127.0.0.1:5000"}
	for _, addr := range denied {
		if err := deps.checkClient(mustAddr(t, addr)); err == nil {
			t.Errorf("checkClient(%s) allowed a client outside the ACL", addr)
		}
	}

	// An empty ACL allows everyone, which is why serve warns about it.
	open := &Deps{}
	if err := open.checkClient(mustAddr(t, "203.0.113.9:1")); err != nil {
		t.Errorf("empty ACL should allow all, got %v", err)
	}
}

func mustAddr(t *testing.T, value string) net.Addr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestAuthorize(t *testing.T) {
	t.Run("no password configured", func(t *testing.T) {
		deps := &Deps{}
		pol, err := deps.authorize("cc=jp", "", false)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		if len(pol.Countries) != 1 || pol.Countries[0] != "jp" {
			t.Errorf("policy not parsed from username: %v", pol)
		}
	})

	t.Run("password required", func(t *testing.T) {
		deps := &Deps{Password: "hunter2"}
		if _, err := deps.authorize("cc=jp", "wrong", true); !errors.Is(err, errUnauthorized) {
			t.Errorf("wrong password error = %v, want errUnauthorized", err)
		}
		if _, err := deps.authorize("cc=jp", "", false); !errors.Is(err, errUnauthorized) {
			t.Errorf("missing credentials error = %v, want errUnauthorized", err)
		}
		if _, err := deps.authorize("cc=jp", "hunter2", true); err != nil {
			t.Errorf("correct password rejected: %v", err)
		}
	})

	t.Run("require auth without password", func(t *testing.T) {
		deps := &Deps{RequireAuth: true}
		if _, err := deps.authorize("", "", false); !errors.Is(err, errUnauthorized) {
			t.Errorf("error = %v, want errUnauthorized", err)
		}
		if _, err := deps.authorize("cc=us", "anything", true); err != nil {
			t.Errorf("credentials present should pass: %v", err)
		}
	})

	t.Run("malformed policy", func(t *testing.T) {
		deps := &Deps{}
		if _, err := deps.authorize("contry=jp", "", false); err == nil {
			t.Error("expected a policy parse error")
		}
	})
}

func TestProxyCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("cc=jp;sess=a:pw"))
	req.Header.Set("Proxy-Authorization", "Basic "+encoded)

	user, pass, ok := proxyCredentials(req)
	if !ok || user != "cc=jp;sess=a" || pass != "pw" {
		t.Fatalf("got (%q, %q, %v)", user, pass, ok)
	}

	// Authorization belongs to the origin server and must not be mistaken for
	// proxy credentials.
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2.Header.Set("Authorization", "Basic "+encoded)
	if _, _, ok := proxyCredentials(req2); ok {
		t.Error("origin Authorization header accepted as proxy credentials")
	}

	req3 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if _, _, ok := proxyCredentials(req3); ok {
		t.Error("credentials reported for a request without any")
	}

	req4 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req4.Header.Set("Proxy-Authorization", "Bearer xyz")
	if _, _, ok := proxyCredentials(req4); ok {
		t.Error("non-Basic scheme accepted")
	}
}

func TestHTTPForwardRejectsDestinationBeforeAcquire(t *testing.T) {
	p, err := pool.NewWithSpecs([]pool.Spec{{
		ID: "relay-1", Kind: pool.KindRelaySocks, SocksAddr: "relay.example:1080",
	}}, []catalog.Slot{{ID: "entry-1"}}, pool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	guard, err := netguard.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := NewHTTP(Deps{Pool: p, Guard: guard})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/private", nil)
	rec := httptest.NewRecorder()

	server.handleForward(rec, req, policy.Policy{Session: "must-not-bind"}, slog.Default())
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	stats := p.Stats()
	if stats.Acquisitions != 0 || stats.Sessions != 0 {
		t.Errorf("denied request changed pool state: %+v", stats)
	}
}

func TestHTTPRejectsUnparseableClientAddress(t *testing.T) {
	server := NewHTTP(Deps{})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "not-an-address"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestSplitTargetHostPort(t *testing.T) {
	cases := []struct {
		in       string
		defPort  int
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com:443", 80, "example.com", 443, false},
		{"example.com", 80, "example.com", 80, false},
		{"[2606:4700::1111]:8443", 80, "2606:4700::1111", 8443, false},
		{"example.com:0", 80, "", 0, true},
		{"example.com:99999", 80, "", 0, true},
		{"", 80, "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := splitTargetHostPort(tc.in, tc.defPort)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitTargetHostPort(%q) succeeded, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitTargetHostPort(%q) = %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitTargetHostPort(%q) = (%q, %d), want (%q, %d)",
				tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestStatusCodeFor(t *testing.T) {
	cases := map[error]int{
		pool.ErrNoCandidate: http.StatusConflict,
		pool.ErrBatchFull:   http.StatusServiceUnavailable,
		pool.ErrSessionFull: http.StatusServiceUnavailable,
		pool.ErrPolicy:      http.StatusBadRequest,
		pool.ErrCapacity:    http.StatusServiceUnavailable,
		pool.ErrExhausted:   http.StatusBadGateway,
		fmt.Errorf("%w: %w", pool.ErrExhausted, context.DeadlineExceeded): http.StatusBadGateway,
		context.DeadlineExceeded:                            http.StatusGatewayTimeout,
		fmt.Errorf("acquire: %w", context.DeadlineExceeded): http.StatusGatewayTimeout,
		errors.New("other"):                                 http.StatusBadGateway,
	}
	for err, want := range cases {
		if got := statusCodeFor(err); got != want {
			t.Errorf("statusCodeFor(%v) = %d, want %d", err, got, want)
		}
	}
}

func TestReplyCodeFor(t *testing.T) {
	cases := map[error]byte{
		nil:                                      repSuccess,
		pool.ErrNoCandidate:                      repNotAllowed,
		pool.ErrBatchFull:                        repGeneralFailure,
		pool.ErrSessionFull:                      repGeneralFailure,
		pool.ErrPolicy:                           repNotAllowed,
		pool.ErrCapacity:                         repNotAllowed,
		pool.ErrExhausted:                        repHostUnreachable,
		context.DeadlineExceeded:                 repHostUnreachable,
		errors.New("connection refused by peer"): repConnectionRefused,
		errors.New("something else"):             repGeneralFailure,
	}
	for err, want := range cases {
		if got := replyCodeFor(err); got != want {
			t.Errorf("replyCodeFor(%v) = %d, want %d", err, got, want)
		}
	}
}

func TestWriteConnectEstablishedSkipsUnsafeHeaderValues(t *testing.T) {
	lease := &pool.Lease{Slot: pool.Spec{
		ID:      "jp-tyo\r\nX-Injected: yes",
		Country: "jp",
		City:    "jp-tyo",
	}}
	var response bytes.Buffer
	if err := writeConnectEstablished(&response, lease, policy.Policy{}); err != nil {
		t.Fatalf("writeConnectEstablished: %v", err)
	}

	text := response.String()
	if !strings.HasPrefix(text, "HTTP/1.1 200 Connection Established\r\n") {
		t.Errorf("CONNECT response = %q", text)
	}
	if strings.Contains(text, "X-Injected") || strings.Contains(text, "\r\nX-Egress-Slot:") {
		t.Errorf("unsafe slot escaped into CONNECT response: %q", text)
	}
	if !strings.Contains(text, "X-Egress-Country: jp\r\n") {
		t.Errorf("safe headers missing from CONNECT response: %q", text)
	}
}

func TestCopyForwardResponseHeadersDropsEgressHeaders(t *testing.T) {
	source := http.Header{
		"Content-Type":    {"text/plain"},
		"X-Egress-Slot":   {"should-not-leak"},
		"X-Egress-Policy": {"should-not-leak"},
	}
	destination := make(http.Header)
	copyForwardResponseHeaders(destination, source)

	if got := destination.Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	for key := range destination {
		if strings.HasPrefix(key, "X-Egress-") {
			t.Errorf("plain HTTP response preserved %s", key)
		}
	}
}

func TestPolicyLogAttributeRedactsExcludedIPs(t *testing.T) {
	pol, err := policy.Parse("cc=jp;not=203.0.113.4|198.51.100.8")
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	logger.Info("request", policyLogAttr(pol))

	for _, ip := range []string{"203.0.113.4", "198.51.100.8"} {
		if strings.Contains(output.String(), ip) {
			t.Errorf("operational log leaked excluded IP %q: %s", ip, output.String())
		}
	}
	if !strings.Contains(output.String(), "not_count=2") {
		t.Errorf("operational log omitted the excluded-IP count: %s", output.String())
	}
}

func TestErrorTypeAttributeRedactsNetworkDetails(t *testing.T) {
	attr := errorTypeAttr(fmt.Errorf("dial 203.0.113.9:443: refused"))
	if got := attr.Value.String(); strings.Contains(got, "203.0.113.9") {
		t.Fatalf("error type attribute leaked network details: %q", got)
	}
}

func TestRequirePolicyRejectsDirectivelessRequests(t *testing.T) {
	// The directives ride in the proxy username. Clients that drop the credentials
	// when the password is empty still get a working response from an arbitrary
	// exit, which is indistinguishable from success. RequirePolicy makes that loud.
	deps := &Deps{RequirePolicy: true}

	if _, err := deps.authorize("", "", false); !errors.Is(err, errPolicyRequired) {
		t.Errorf("no credentials: error = %v, want errPolicyRequired", err)
	}
	if _, err := deps.authorize("someaccount", "pw", true); !errors.Is(err, errPolicyRequired) {
		t.Errorf("credentials without directives: error = %v, want errPolicyRequired", err)
	}
	if _, err := deps.authorize("cc=jp", "x", true); err != nil {
		t.Errorf("a real policy was rejected: %v", err)
	}
}

func TestRequirePolicyOffKeepsTheDefaultBehaviour(t *testing.T) {
	deps := &Deps{}
	pol, err := deps.authorize("", "", false)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !pol.IsZero() {
		t.Error("expected an unconstrained policy")
	}
}

func TestEgressHeadersReportTheAppliedPolicy(t *testing.T) {
	// A client cannot otherwise tell that its directives were dropped in transit.
	lease := &pool.Lease{Slot: pool.Spec{ID: "jp-tyo-wg-socks5-001", Country: "jp", City: "jp-tyo"}}

	pol, err := policy.Parse("cc=jp;sess=job-1")
	if err != nil {
		t.Fatal(err)
	}
	headers := egressHeaders(lease, pol)
	if got := headers["X-Egress-Policy"]; got != "cc=jp;sess=job-1" {
		t.Errorf("X-Egress-Policy = %q", got)
	}

	// The two ways of ending up unconstrained must not look alike in the header:
	// one is a deliberate choice, the other is a policy that never arrived.
	headers = egressHeaders(lease, policy.Policy{})
	if got := headers["X-Egress-Policy"]; got != "(none)" {
		t.Errorf("X-Egress-Policy for an empty policy = %q, want (none)", got)
	}

	deliberate, err := policy.Parse("any=1")
	if err != nil {
		t.Fatal(err)
	}
	headers = egressHeaders(lease, deliberate)
	if got := headers["X-Egress-Policy"]; got != "any=1" {
		t.Errorf("X-Egress-Policy for any=1 = %q, want any=1", got)
	}
}

// TestSOCKS5RejectsWhenPolicyRequired covers the protocol that has no header to fall
// back on: for SOCKS5 the refusal is the only thing standing between a caller that
// dropped its credentials and a silently wrong exit.
func TestSOCKS5RejectsWhenPolicyRequired(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Pool is nil on purpose: the rejection must happen during negotiation, before
	// anything tries to select an exit.
	server := NewSOCKS5(Deps{
		RequirePolicy: true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()

	negotiate := func(username string) byte {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

		// Offer username/password, which is how a policy would be carried.
		if _, err := conn.Write([]byte{socksVersion, 1, methodUserPass}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read greeting reply: %v", err)
		}
		if reply[1] != methodUserPass {
			t.Fatalf("server chose method 0x%02x, want username/password", reply[1])
		}

		request := []byte{userPassVersion, byte(len(username))}
		request = append(request, username...)
		request = append(request, 1, 'x')
		if _, err := conn.Write(request); err != nil {
			t.Fatalf("write credentials: %v", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			t.Fatalf("read auth reply: %v", err)
		}
		return authReply[1]
	}

	if status := negotiate(""); status == 0x00 {
		t.Error("a request with no directives was accepted")
	}
	if status := negotiate("cc=jp"); status != 0x00 {
		t.Errorf("a request carrying cc=jp was rejected with status 0x%02x", status)
	}
}

func TestRequirePolicyAcceptsExplicitAny(t *testing.T) {
	// require_policy exists to catch clients that dropped their directives, not to
	// forbid callers who genuinely want any exit. any=1 is how they say so.
	deps := &Deps{RequirePolicy: true}

	pol, err := deps.authorize("any=1", "x", true)
	if err != nil {
		t.Fatalf("any=1 was rejected: %v", err)
	}
	if !pol.AnyExit {
		t.Error("AnyExit not set")
	}
	if len(pol.Countries) != 0 {
		t.Error("any=1 must not constrain anything")
	}

	if _, err := deps.authorize("", "", false); !errors.Is(err, errPolicyRequired) {
		t.Errorf("silence should still be rejected, got %v", err)
	}
}

func TestRequestedCountry(t *testing.T) {
	tests := []struct {
		name string
		pol  policy.Policy
		want string
	}{
		{name: "unconstrained", want: "any"},
		{name: "explicit any", pol: policy.Policy{AnyExit: true}, want: "any"},
		{name: "one country", pol: policy.Policy{Countries: []string{"JP"}}, want: "jp"},
		{name: "multiple countries", pol: policy.Policy{Countries: []string{"jp", "us"}}, want: "multiple"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestedCountry(tt.pol); got != tt.want {
				t.Errorf("requestedCountry() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestObserveRequestUsesAppliedPolicy(t *testing.T) {
	p, err := pool.NewWithSpecs([]pool.Spec{{
		ID: "relay-1", Kind: pool.KindRelaySocks, SocksAddr: "relay.example:1080",
	}}, []catalog.Slot{{ID: "entry-1"}}, pool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	deps := Deps{Pool: p}

	deps.observeRequest(
		policy.Policy{Countries: []string{"JP"}},
		nil,
		pool.RequestNoCandidate,
		25*time.Millisecond,
	)

	snapshot := p.Metrics()
	if len(snapshot.RequestedCountries) != 1 || snapshot.RequestedCountries[0].Country != "jp" {
		t.Errorf("requested countries = %+v, want jp", snapshot.RequestedCountries)
	}
	if len(snapshot.Requests) != 1 || snapshot.Requests[0].Result != pool.RequestNoCandidate {
		t.Errorf("requests = %+v, want no_candidate", snapshot.Requests)
	}
}

func TestRequestResult(t *testing.T) {
	tests := []struct {
		err  error
		want pool.RequestResult
	}{
		{err: nil, want: pool.RequestSuccess},
		{err: pool.ErrBusy, want: pool.RequestBusy},
		{err: pool.ErrNoCandidate, want: pool.RequestNoCandidate},
		{err: pool.ErrExhausted, want: pool.RequestNoCandidate},
		{err: context.DeadlineExceeded, want: pool.RequestTimeout},
		{err: errors.New("dial failed"), want: pool.RequestDialFailure},
	}
	for _, tt := range tests {
		if got := requestResult(tt.err); got != tt.want {
			t.Errorf("requestResult(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}
