package control

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/pool"
)

func newTestServer(t *testing.T, opts Options) (*Server, *pool.Pool) {
	t.Helper()
	bundle := &catalog.Bundle{DistinctKeys: 1}
	for _, spec := range []struct{ id, country, city string }{
		{"jp-tyo-wg-001", "jp", "jp-tyo"},
		{"us-lax-wg-001", "us", "us-lax"},
	} {
		bundle.Slots = append(bundle.Slots, catalog.Slot{
			ID:            spec.id,
			Country:       spec.country,
			City:          spec.city,
			PrivateKey:    "R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=",
			PeerPublicKey: "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=",
			Addresses:     []netip.Addr{netip.MustParseAddr("10.64.0.2")},
			Endpoint:      "198.51.100.1:51820",
		})
	}
	egressPool, err := pool.New(bundle, pool.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	t.Cleanup(egressPool.Close)
	seedTestIPs(t, egressPool)

	opts.Pool = egressPool
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return New(opts), egressPool
}

func seedTestIPs(t *testing.T, egressPool *pool.Pool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.json")
	blob := []byte(`{
		"version": 1,
		"slots": {
			"jp-tyo-wg-001": {
				"public_ip": "203.0.113.10",
				"checked_at": "2099-01-01T00:00:00Z"
			},
			"us-lax-wg-001": {
				"public_ip": "203.0.113.11",
				"checked_at": "2099-01-01T00:00:00Z"
			}
		}
	}`)
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if _, err := egressPool.LoadInventory(path); err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
}

func do(t *testing.T, server *Server, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = "127.0.0.1:40000"
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func TestHealthAndStats(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	if rec := do(t, server, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d", rec.Code)
	}

	rec := do(t, server, http.MethodGet, "/v1/stats", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/stats status = %d", rec.Code)
	}
	var stats pool.Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if stats.Slots != 2 {
		t.Errorf("stats.Slots = %d, want 2", stats.Slots)
	}
}

func TestSlotsFilteringAndLimit(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	var payload struct {
		Count int             `json:"count"`
		Slots []pool.SlotInfo `json:"slots"`
	}
	rec := do(t, server, http.MethodGet, "/v1/slots?country=jp", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 1 || payload.Slots[0].ID != "jp-tyo-wg-001" {
		t.Errorf("unexpected payload %+v", payload)
	}

	rec = do(t, server, http.MethodGet, "/v1/slots?limit=1", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 1 {
		t.Errorf("limit ignored: count = %d", payload.Count)
	}

	if rec := do(t, server, http.MethodGet, "/v1/slots?limit=-4", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("negative limit status = %d, want 400", rec.Code)
	}
}

func TestCountryAcquisitions(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	rec := do(t, server, http.MethodGet, "/v1/country-acquisitions", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload struct {
		Countries []pool.CountryAcquisition `json:"countries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Countries) != 0 {
		t.Errorf("countries = %+v, want no acquisitions yet", payload.Countries)
	}
}

func TestMetricsExposition(t *testing.T) {
	server, egressPool := newTestServer(t, Options{})
	egressPool.ObserveRequest(pool.RequestObservation{
		Result:           pool.RequestNoCandidate,
		RequestedCountry: "jp",
		Duration:         50 * time.Millisecond,
	})

	rec := do(t, server, http.MethodGet, "/v1/metrics", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("content type = %q", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`global_egress_request_results_total{result="no_candidate",country="unknown",entry="none"} 1`,
		`global_egress_requested_country_total{country="jp"} 1`,
		`global_egress_request_duration_seconds_count{result="no_candidate",country="unknown",entry="none"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestMetricsExposesTimeoutPhaseAndEntryHealth(t *testing.T) {
	server, egressPool := newTestServer(t, Options{})
	egressPool.ObserveRequest(pool.RequestObservation{
		Result:           pool.RequestTimeout,
		TimeoutPhase:     pool.TimeoutPhaseAcquire,
		RequestedCountry: "jp",
		Duration:         2 * time.Second,
	})

	rec := do(t, server, http.MethodGet, "/v1/metrics", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE global_egress_request_timeouts_total counter",
		`global_egress_request_timeouts_total{phase="acquire",country="unknown",entry="none"} 1`,
		"# TYPE global_egress_entry_state gauge",
		`global_egress_entry_state{state="open"} 0`,
		`global_egress_entry_state{state="idle"} 0`,
		`global_egress_entry_state{state="disabled"} 0`,
		"# TYPE global_egress_entry_failures_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestWhoamiRequiresSession(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	if rec := do(t, server, http.MethodGet, "/v1/whoami", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("missing sess status = %d, want 400", rec.Code)
	}
	if rec := do(t, server, http.MethodGet, "/v1/whoami?sess=nope", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unbound sess status = %d, want 404", rec.Code)
	}
}

func TestRotateIsIdempotent(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	rec := do(t, server, http.MethodPost, "/v1/sessions/job-1/rotate", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d", rec.Code)
	}
	var payload struct {
		Session string `json:"session"`
		Rotated bool   `json:"rotated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Session != "job-1" || payload.Rotated {
		t.Errorf("unexpected payload %+v (nothing was bound yet)", payload)
	}
}

func TestReportValidation(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	cases := []struct {
		name, body string
		want       int
	}{
		{"not json", "{", http.StatusBadRequest},
		{"neither session nor slot", `{"scope":"example.com"}`, http.StatusBadRequest},
		{"missing scope", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10"}`, http.StatusBadRequest},
		{"missing public IP", `{"slot":"jp-tyo-wg-001","scope":"example.com"}`, http.StatusBadRequest},
		{"bad cooldown", `{"slot":"jp-tyo-wg-001","cooldown":"soon"}`, http.StatusBadRequest},
		{"unknown field", `{"slot":"jp-tyo-wg-001","nope":1}`, http.StatusBadRequest},
		{"unknown slot", `{"slot":"zz-zzz-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731"}`, http.StatusNotFound},
		{"IP mismatch", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.99","scope":"example.com"}`, http.StatusConflict},
		{"valid", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731","reason":"zen_free_quota"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, server, http.MethodPost, "/v1/report", tc.body,
				map[string]string{"Content-Type": "application/json"})
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestReportNormalisesTarget(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	rec := do(t, server, http.MethodPost, "/v1/report",
		`{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"OpenCode-Zen.Flash-0731"}`,
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var result pool.ReportResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Target != "opencode-zen.flash-0731" {
		t.Errorf("Target = %q, want opencode-zen.flash-0731", result.Target)
	}
}

func TestPreferValidation(t *testing.T) {
	server, _ := newTestServer(t, Options{})

	cases := []struct {
		name, body string
		want       int
	}{
		{"missing slot", `{"public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731"}`, http.StatusBadRequest},
		{"missing scope", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10"}`, http.StatusBadRequest},
		{"missing public IP", `{"slot":"jp-tyo-wg-001","scope":"opencode-zen.flash-0731"}`, http.StatusBadRequest},
		{"bad ttl", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731","ttl":"soon"}`, http.StatusBadRequest},
		{"unknown slot", `{"slot":"zz-zzz-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731"}`, http.StatusNotFound},
		{"IP mismatch", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.99","scope":"opencode-zen.flash-0731"}`, http.StatusConflict},
		{"valid", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731","ttl":"10m"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, server, http.MethodPost, "/v1/prefer", tc.body,
				map[string]string{"Content-Type": "application/json"})
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestConcurrentOutcomeFeedbackIsRaceSafe(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func() {
			defer wg.Done()
			path := "/v1/prefer"
			body := `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731","ttl":"10m"}`
			if i%2 == 0 {
				path = "/v1/report"
				body = `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.flash-0731","cooldown":"24h"}`
			}
			rec := do(t, server, http.MethodPost, path, body,
				map[string]string{"Content-Type": "application/json"})
			if rec.Code != http.StatusOK {
				t.Errorf("%s status = %d, body %s", path, rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"example.com":                  "example.com",
		"https://example.com/a/b":      "example.com",
		"http://example.com:8080/x":    "example.com",
		"EXAMPLE.com":                  "example.com",
		"example.com:443":              "example.com",
		"https://user.example.com?q=1": "user.example.com",
	}
	for input, want := range cases {
		if got := normalizeTarget(input); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClientACL(t *testing.T) {
	server, _ := newTestServer(t, Options{
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	req.RemoteAddr = "192.168.5.5:1234"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a client outside the ACL", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an allowed client", rec.Code)
	}
}

func TestBearerToken(t *testing.T) {
	server, _ := newTestServer(t, Options{Token: "s3cret"})

	if rec := do(t, server, http.MethodGet, "/v1/stats", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token status = %d, want 401", rec.Code)
	}
	if rec := do(t, server, http.MethodGet, "/v1/stats", "",
		map[string]string{"Authorization": "Bearer wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", rec.Code)
	}
	if rec := do(t, server, http.MethodGet, "/v1/stats", "",
		map[string]string{"Authorization": "Bearer s3cret"}); rec.Code != http.StatusOK {
		t.Errorf("valid token status = %d, want 200", rec.Code)
	}
}

func TestBearerTokenRejectsEmptyConfiguredToken(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	req := httptest.NewRequest(http.MethodPost, "/v1/report", nil)
	req.Header.Set("Authorization", "Bearer ")
	if server.tokenOK(req) {
		t.Fatal("empty configured token accepted an empty bearer value")
	}
}

func TestNonLoopbackReadOnlyEndpointsRemainOpenWithoutToken(t *testing.T) {
	server, _ := newTestServer(t, Options{})
	for _, path := range []string{"/healthz", "/v1/stats", "/v1/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.0.0.5:40000"
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rec.Code)
		}
	}
}

func TestNonLoopbackMutationsFailClosedWithoutChangingState(t *testing.T) {
	server, egressPool := newTestServer(t, Options{})
	before := egressPool.Stats()
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/v1/sessions/job-1/rotate", ""},
		{http.MethodDelete, "/v1/sessions/job-1", ""},
		{http.MethodPost, "/v1/report", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"example.com"}`},
		{http.MethodPost, "/v1/prefer", `{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"example.com"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.RemoteAddr = "10.0.0.5:40000"
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s status = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
	if after := egressPool.Stats(); after != before {
		t.Errorf("unauthorized mutations changed pool state: before %+v, after %+v", before, after)
	}
}

func TestNonLoopbackMutationWithTokenSucceeds(t *testing.T) {
	server, _ := newTestServer(t, Options{Token: "s3cret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/report", strings.NewReader(
		`{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"example.com"}`))
	req.RemoteAddr = "10.0.0.5:40000"
	req.Header.Set("Authorization", "Bearer s3cret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized report status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
