package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Some origins refuse a CONNECT tunnel based on the *client's* TLS signature
// rather than its address, so rotating exits cannot clear it (measured against
// a Cloudflare 1010 on 2026-09-09). Forwarding an absolute https:// URI lets
// the proxy originate TLS with its own stack over the same leased exit, which
// is the existing http:// forward path with one scheme check removed.
func TestForwardRejectsNonHTTPSchemesOtherThanHTTPS(t *testing.T) {
	// A scheme we genuinely cannot serve must still be refused.
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	req.URL.Scheme = "ftp"
	if got := forwardSchemeSupported(req.URL.Scheme); got {
		t.Errorf("forwardSchemeSupported(ftp) = true, want false")
	}
}

func TestForwardSupportsHTTPAndHTTPS(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		if !forwardSchemeSupported(scheme) {
			t.Errorf("forwardSchemeSupported(%s) = false, want true", scheme)
		}
	}
}

func TestForwardDefaultPortMatchesScheme(t *testing.T) {
	// https:// without an explicit port must reach 443, not 80.
	if got := forwardDefaultPort("https"); got != 443 {
		t.Errorf("forwardDefaultPort(https) = %d, want 443", got)
	}
	if got := forwardDefaultPort("http"); got != 80 {
		t.Errorf("forwardDefaultPort(http) = %d, want 80", got)
	}
}

func TestForwardRejectionMentionsSupportedSchemes(t *testing.T) {
	// The operator-facing message has to stay accurate once https is allowed.
	if strings.Contains(forwardSchemeError, "use CONNECT for https://") {
		t.Errorf("rejection message still claims https is unsupported: %q", forwardSchemeError)
	}
}
