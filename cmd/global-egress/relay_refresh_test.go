package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/mullvad"
	"github.com/minpeter/global-egress/internal/pool"
)

func newRefreshTestPool(t *testing.T) *pool.Pool {
	t.Helper()
	p, err := pool.NewWithSpecs(
		pool.SpecsFromExits([]pool.ExitSpec{{
			ID:        "old-wg-socks5-001",
			Country:   "se",
			City:      "se-sto",
			SocksAddr: "old-wg-socks5-001.relays.example:1080",
		}}),
		[]catalog.Slot{{ID: "entry-wg-001"}},
		pool.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
	)
	if err != nil {
		t.Fatalf("NewWithSpecs: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestRefreshRelaySlotsKeepsLastKnownGood(t *testing.T) {
	tests := []struct {
		name  string
		fetch relayListFetcher
	}{
		{
			name: "fetch failure",
			fetch: func(context.Context, string) (*mullvad.List, error) {
				return nil, errors.New("network unavailable at secret-token.example")
			},
		},
		{
			name: "no usable relays",
			fetch: func(context.Context, string) (*mullvad.List, error) {
				return &mullvad.List{Relays: []mullvad.Relay{{
					Hostname:  "inactive-wg-001",
					SocksName: "inactive-wg-socks5-001.relays.example",
					Active:    false,
				}}}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newRefreshTestPool(t)
			cachePath := filepath.Join(t.TempDir(), "relays.json")
			const cached = `[{"hostname":"old-wg-001","active":true}]`
			if err := os.WriteFile(cachePath, []byte(cached), 0o644); err != nil {
				t.Fatalf("write cache: %v", err)
			}

			_, refreshErr := refreshRelaySlots(
				context.Background(),
				p,
				"https://relay-list.invalid",
				cachePath,
				tt.fetch,
			)
			if refreshErr == nil {
				t.Fatal("refreshRelaySlots should fail")
			}
			if strings.Contains(refreshErr.Error(), "secret-token") {
				t.Fatalf("refresh error leaked network detail: %v", refreshErr)
			}
			if p.Len() != 1 {
				t.Fatalf("pool length = %d, want last-known-good length 1", p.Len())
			}
			slots := p.Slots(pool.SlotFilter{})
			if len(slots) != 1 || slots[0].ID != "old-wg-socks5-001" {
				t.Fatalf("slots = %+v, want old-wg-socks5-001", slots)
			}
			gotCache, err := os.ReadFile(cachePath)
			if err != nil {
				t.Fatalf("read cache: %v", err)
			}
			if string(gotCache) != cached {
				t.Fatalf("cache changed on failed refresh: %q", gotCache)
			}
		})
	}
}

func TestMaintainRelaySlotsReconcilesOnTick(t *testing.T) {
	p := newRefreshTestPool(t)
	ticks := make(chan time.Time, 1)
	refreshed := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	go func() {
		maintainRelaySlots(
			ctx,
			ticks,
			func(ctx context.Context) (pool.RelayReconcileResult, error) {
				result, err := refreshRelaySlots(
					ctx,
					p,
					"https://relay-list.invalid",
					"",
					func(context.Context, string) (*mullvad.List, error) {
						return &mullvad.List{Relays: []mullvad.Relay{{
							Hostname:  "new-wg-001",
							Country:   "gb",
							CityCode:  "lon",
							SocksName: "new-wg-socks5-001.relays.example",
							SocksPort: 1080,
							Active:    true,
						}}}, nil
					},
				)
				close(refreshed)
				return result, err
			},
			logger,
		)
		close(done)
	}()

	ticks <- time.Now()
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("relay maintenance did not process a refresh tick")
	}
	slots := p.Slots(pool.SlotFilter{})
	if len(slots) != 1 || slots[0].ID != "new-wg-socks5-001" {
		t.Fatalf("slots after tick = %+v, want new-wg-socks5-001", slots)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay maintenance did not stop after cancellation")
	}
}
