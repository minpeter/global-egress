package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A container HEALTHCHECK is only useful if the exit status is the answer. The
// probe has to distinguish "the control listener answered 200" from every other
// outcome, because Docker reads nothing but the code.
func TestHealthcheckExitStatus(t *testing.T) {
	t.Parallel()

	// t.Cleanup, not defer: the subtests below are parallel, so they run after
	// this function returns and the servers must outlive it.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ok.Close)

	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unavailable.Close)

	// A listener that is closed again gives us an address nothing answers on,
	// which is what a stopped container looks like from the inside.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"healthy returns nil", []string{"-url", ok.URL + "/healthz"}, false},
		{"non-200 fails", []string{"-url", unavailable.URL + "/healthz"}, true},
		{"unreachable fails", []string{"-url", closedURL + "/healthz"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := runHealthcheck(context.Background(), tc.args)
			if tc.wantErr && err == nil {
				t.Fatal("expected a non-nil error so the process exits nonzero")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected a healthy probe to succeed, got %v", err)
			}
		})
	}
}

// When the control API requires a bearer token, an unauthenticated probe gets 401
// and the container would be marked unhealthy while it is in fact serving. The
// token has to be readable from a file, the same way serve takes it, so that it
// never appears in the image, the compose file, or `docker inspect`.
func TestHealthcheckSendsTokenFromFile(t *testing.T) {
	t.Parallel()

	const token = "s3cr3t-control-token"
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Trailing newline included on purpose: secret files usually have one.
	path := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runHealthcheck(context.Background(), []string{"-url", server.URL + "/healthz", "-token-file", path}); err != nil {
		t.Fatalf("probe with a token file failed: %v", err)
	}
	if gotAuth != "Bearer "+token {
		t.Errorf("Authorization header = %q, want the trimmed token", gotAuth)
	}

	// Without the token the same endpoint answers 401, which must fail.
	if err := runHealthcheck(context.Background(), []string{"-url", server.URL + "/healthz"}); err == nil {
		t.Error("expected 401 to fail the probe")
	}
}

// A missing token file is an operator error, not a reason to report the service
// unhealthy silently; it must fail loudly and without printing the path's contents.
func TestHealthcheckMissingTokenFileFails(t *testing.T) {
	t.Parallel()

	err := runHealthcheck(context.Background(), []string{
		"-url", "http://127.0.0.1:1/healthz",
		"-token-file", filepath.Join(t.TempDir(), "absent"),
	})
	if err == nil {
		t.Fatal("expected a missing token file to fail")
	}
}

// The probe runs inside a container health check with a timeout; it must bound
// itself rather than hanging until Docker kills it.
func TestHealthcheckTimesOut(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer close(release)

	done := make(chan error, 1)
	go func() {
		done <- runHealthcheck(context.Background(), []string{
			"-url", server.URL + "/healthz",
			"-timeout", "50ms",
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the bounded probe to fail on a hanging server")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runHealthcheck ignored -timeout and hung")
	}
}

// The error text reaches container logs and `docker inspect`. It must describe the
// failure without ever echoing the secret.
func TestHealthcheckErrorHidesToken(t *testing.T) {
	t.Parallel()

	const token = "do-not-log-this-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runHealthcheck(context.Background(), []string{
		"-url", server.URL + "/healthz",
		"-token-file", path,
	})
	if err == nil {
		t.Fatal("expected a 500 response to fail the probe")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error message leaks the control token: %q", err)
	}
}

// The default target is the in-container control listener, so the HEALTHCHECK line
// needs no address and cannot drift from the Dockerfile's EXPOSE.
func TestHealthcheckDefaultsToLocalControlPort(t *testing.T) {
	t.Parallel()

	if !strings.Contains(defaultHealthURL, "127.0.0.1:8080") {
		t.Errorf("defaultHealthURL = %q, want the loopback control port", defaultHealthURL)
	}
	if !strings.HasSuffix(defaultHealthURL, "/healthz") {
		t.Errorf("defaultHealthURL = %q, want the /healthz path", defaultHealthURL)
	}
}
