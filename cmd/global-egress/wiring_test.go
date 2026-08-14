package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/minpeter/global-egress/internal/config"
	"github.com/minpeter/global-egress/internal/pool"
)

// Every configuration field that limits load has to reach the pool. Twice during
// development a field was added to the config and to the pool but not to the call
// that joins them, which silently disabled the protection while all unit tests
// still passed. This test compares the two ends.
func TestConfigLimitsReachThePool(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	opts := poolOptionsFrom(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	cases := []struct {
		name       string
		configured int
		wired      int
	}{
		{"max_active", cfg.Pool.MaxActive, opts.MaxActive},
		{"max_conns_per_exit", cfg.Pool.MaxConnsPerExit, opts.MaxConnsPerExit},
		{"max_concurrent_conns", cfg.Pool.MaxConcurrentConns, opts.MaxConcurrentConns},
		{"new_tunnels_per_window", cfg.Pool.NewTunnelsPerWindow, opts.NewTunnelBudget},
		{"dial_attempts", cfg.Pool.DialAttempts, opts.DialAttempts},
		{"max_unique_batches", cfg.Pool.MaxUniqueBatches, opts.MaxUniqueBatches},
		{"max_sessions", cfg.Pool.MaxSessions, opts.MaxSessions},
	}
	for _, tc := range cases {
		if tc.configured == 0 {
			t.Errorf("%s: default is 0, which disables the limit", tc.name)
			continue
		}
		if tc.wired != tc.configured {
			t.Errorf("%s: configured %d but the pool received %d", tc.name, tc.configured, tc.wired)
		}
	}

	if opts.IPCheckURL != cfg.Pool.IPCheckURL {
		t.Error("ip_check_url does not reach the pool")
	}
	if opts.Cooldown != cfg.Pool.Cooldown {
		t.Error("cooldown does not reach the pool")
	}
	if opts.PreferredTTL != cfg.Pool.PreferredTTL {
		t.Error("preferred_ttl does not reach the pool")
	}
	if opts.PreferredMax != cfg.Pool.PreferredMax {
		t.Error("preferred_max does not reach the pool")
	}
	if opts.MaxBatchTTL != cfg.Pool.MaxBatchTTL {
		t.Error("max_batch_ttl does not reach the pool")
	}
	if opts.MaxSessionTTL != cfg.Pool.MaxSessionTTL {
		t.Error("max_session_ttl does not reach the pool")
	}
	var zero pool.Options
	if opts.NewTunnelWindow == zero.NewTunnelWindow {
		t.Error("new_tunnel_window does not reach the pool")
	}
}
