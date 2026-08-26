package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// defaultHealthURL is the control listener as seen from inside the container.
// The Dockerfile's HEALTHCHECK relies on this default, so it carries no address.
const defaultHealthURL = "http://127.0.0.1:8080/healthz"

// runHealthcheck probes the control API's liveness endpoint and reports the
// verdict through the exit status, which is the only channel a container health
// check reads. The image is distroless, so there is no curl or wget to do this
// from a shell; the binary probes itself.
func runHealthcheck(ctx context.Context, args []string) error {
	fs := newFlagSet("healthcheck")
	url := fs.String("url", defaultHealthURL, "liveness endpoint to probe")
	timeout := fs.Duration("timeout", 2*time.Second, "give up after this long")
	tokenFile := fs.String("token-file", "", "file holding the control API bearer token")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A token on the command line would be visible in `docker inspect` and in the
	// process list, so it is only ever read from a file, like serve reads it.
	var token string
	if *tokenFile != "" {
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read control token file: %w", err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return fmt.Errorf("control token file %s is empty", *tokenFile)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// No redirects and no keep-alive: this is a single probe against loopback,
	// and a health check that follows a redirect elsewhere is measuring the wrong
	// service.
	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// The URL is operator-supplied and the error may quote it, but the token
		// never reaches the URL or the transport error, so this stays safe to log.
		return fmt.Errorf("probe %s: %w", *url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s: status %s", *url, resp.Status)
	}
	return nil
}
