package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/config"
	"github.com/minpeter/global-egress/internal/control"
	"github.com/minpeter/global-egress/internal/mullvad"
	"github.com/minpeter/global-egress/internal/netguard"
	"github.com/minpeter/global-egress/internal/pool"
	"github.com/minpeter/global-egress/internal/proxy"
)

func runServe(ctx context.Context, args []string) error {
	fs := newFlagSet("serve")
	configPath := fs.String("config", "/etc/global-egress/config.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Log)
	startedAt := time.Now()

	bundle := &catalog.Bundle{}
	if cfg.Catalog.Path != "" {
		bundle, err = catalog.Load(cfg.Catalog.Path)
		if err != nil {
			return err
		}
		logger.Info("catalog loaded",
			slog.String("path", cfg.Catalog.Path),
			slog.Int("slots", len(bundle.Slots)),
			slog.Int("countries", len(bundle.Countries())),
			slog.Int("cities", len(bundle.Cities())),
			slog.Int("distinct_keys", bundle.DistinctKeys))
		if bundle.DistinctKeys > 1 {
			logger.Warn("bundle mixes several provider devices; check the concurrency terms of your subscription",
				slog.Int("distinct_keys", bundle.DistinctKeys))
		}
	}

	specs, entrySlots, err := buildSlots(ctx, cfg, bundle, logger)
	if err != nil {
		return err
	}

	guard, err := netguard.New(cfg.Destinations.DeniedCIDRs, cfg.Destinations.AllowedPorts)
	if err != nil {
		return err
	}
	allowedClients, err := cfg.AllowedClientPrefixes()
	if err != nil {
		return err
	}
	if len(allowedClients) == 0 {
		logger.Warn("access.allowed_clients is empty: every host that can reach the listeners may use them")
	}

	egressPool, err := pool.NewWithSpecs(specs, entrySlots, poolOptionsFrom(cfg, logger))
	if err != nil {
		return err
	}
	defer egressPool.Close()

	if path := cfg.InventoryPath(); path != "" {
		if restored, err := egressPool.LoadInventory(path); err != nil {
			logger.Warn("could not load inventory", slog.Any("error", err))
		} else if restored > 0 {
			logger.Info("inventory restored", slog.Int("slots", restored), slog.String("path", path))
		}
	}

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 3)

	deps := proxy.Deps{
		Pool:           egressPool,
		Guard:          guard,
		Logger:         logger,
		AllowedClients: allowedClients,
		Password:       cfg.Access.Password,
		RequireAuth:    cfg.Access.RequireAuth,
		RequirePolicy:  cfg.Access.RequirePolicy,
		DialTimeout:    cfg.Pool.DialTimeout,
		DialAttempts:   cfg.Pool.DialAttempts,
		IdleTimeout:    cfg.Pool.RelayIdleTimeout,
	}

	if cfg.Listen.SOCKS5 != "" {
		listener, err := net.Listen("tcp", cfg.Listen.SOCKS5)
		if err != nil {
			return fmt.Errorf("listen socks5: %w", err)
		}
		logger.Info("socks5 listening", slog.String("address", listener.Addr().String()))
		server := proxy.NewSOCKS5(deps)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Serve(serveCtx, listener); err != nil {
				errs <- fmt.Errorf("socks5: %w", err)
			}
		}()
	}

	if cfg.Listen.HTTP != "" {
		listener, err := net.Listen("tcp", cfg.Listen.HTTP)
		if err != nil {
			return fmt.Errorf("listen http: %w", err)
		}
		logger.Info("http proxy listening", slog.String("address", listener.Addr().String()))
		server := proxy.NewHTTP(deps)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Serve(serveCtx, listener); err != nil {
				errs <- fmt.Errorf("http: %w", err)
			}
		}()
	}

	if cfg.Listen.Control != "" {
		listener, err := net.Listen("tcp", cfg.Listen.Control)
		if err != nil {
			return fmt.Errorf("listen control: %w", err)
		}
		logger.Info("control api listening", slog.String("address", listener.Addr().String()))
		handler := control.New(control.Options{
			Pool:           egressPool,
			Logger:         logger,
			AllowedClients: allowedClients,
			Token:          cfg.Access.ControlToken,
			Version:        buildVersion(),
			StartedAt:      startedAt,
		})
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return serveCtx },
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-serveCtx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = server.Shutdown(shutdownCtx)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("control: %w", err)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		egressPool.Maintain(serveCtx)
	}()
	if cfg.Mode == config.ModeRelaySocks && cfg.Relays.Refresh > 0 && mullvadConfigured(cfg) {
		cachePath := cfg.RelayCachePath()
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(cfg.Relays.Refresh)
			defer ticker.Stop()
			maintainRelaySlots(
				serveCtx,
				ticker.C,
				func(ctx context.Context) (pool.RelayReconcileResult, error) {
					return refreshRelaySlots(
						ctx,
						egressPool,
						cfg.Relays.URL,
						cachePath,
						mullvad.Fetch,
					)
				},
				logger,
			)
		}()
	}

	if cfg.Pool.Preopen > 0 {
		go preopen(serveCtx, egressPool, cfg.Pool.Preopen, logger)
	}

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case runErr = <-errs:
		logger.Error("listener failed", slog.Any("error", runErr))
	}
	cancel()
	wg.Wait()

	if path := cfg.InventoryPath(); path != "" {
		if err := egressPool.SaveInventory(path); err != nil {
			logger.Warn("could not save inventory", slog.Any("error", err))
		} else {
			logger.Info("inventory saved", slog.String("path", path))
		}
	}
	return runErr
}

// preopen warms up a few tunnels so the first client requests do not pay for a
// handshake. Failures are logged and ignored: the pool retries lazily.
func preopen(ctx context.Context, egressPool *pool.Pool, count int, logger *slog.Logger) {
	logger.Info("pre-opening tunnels", slog.Int("requested", count))
	started := time.Now()
	opened := egressPool.Warmup(ctx, count)
	logger.Info("pre-open finished",
		slog.Int("opened", opened),
		slog.Duration("took", time.Since(started).Round(time.Millisecond)))
}

func newLogger(cfg config.LogConfig) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(cfg.Format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// buildSlots assembles the egress slots for the configured mode.
//
// In relay-socks mode the slots come from the provider's relay list and the
// catalog only supplies the entry tunnels. In WireGuard mode every catalog entry
// becomes a slot of its own.
func buildSlots(ctx context.Context, cfg config.Config, bundle *catalog.Bundle, logger *slog.Logger) ([]pool.Spec, []catalog.Slot, error) {
	if cfg.Mode == config.ModeWireGuard {
		specs := pool.SpecsFromBundle(bundle)
		for _, provider := range cfg.Providers() {
			if provider.Type() != config.ProviderSOCKS5 || !provider.Enabled() {
				continue
			}
			direct, err := pool.NewDirectSocksSpec(pool.DirectSocksOptions{ID: provider.ID(), Country: provider.Country(), City: provider.City(), URL: provider.SOCKSURL()})
			if err != nil {
				return nil, nil, fmt.Errorf("external provider %q: %w", provider.ID(), err)
			}
			specs = append(specs, direct)
		}
		logger.Info("mode: wireguard (one tunnel per slot)", slog.Int("slots", len(specs)))
		if len(specs) == 0 {
			return nil, nil, errors.New("providers contain no usable enabled providers")
		}
		return specs, nil, nil
	}

	providers := cfg.Providers()
	var specs []pool.Spec
	var entrySlots []catalog.Slot
	mullvadEnabled := false
	for _, provider := range providers {
		if provider.Type() == config.ProviderMullvad && provider.Enabled() {
			mullvadEnabled = true
			cachePath := cfg.RelayCachePath()
			list, fetched, err := mullvad.LoadOrFetch(ctx, cfg.Relays.URL, cachePath, cfg.Relays.Refresh)
			if err != nil {
				return nil, nil, fmt.Errorf("relay list: %w", err)
			}
			relays := list.Usable()
			if len(relays) == 0 {
				return nil, nil, fmt.Errorf("relay list contains no usable relays")
			}
			specs = append(specs, pool.SpecsFromExits(exitsFromRelays(relays))...)
			logger.Info("Mullvad relay slots loaded",
				slog.Int("exits", len(relays)),
				slog.Int("countries", len(list.Countries())),
				slog.Int("cities", len(list.Cities())),
				slog.Bool("relay_list_refreshed", fetched))
		}
		if provider.Type() == config.ProviderSOCKS5 && provider.Enabled() {
			direct, err := pool.NewDirectSocksSpec(pool.DirectSocksOptions{
				ID: provider.ID(), Country: provider.Country(), City: provider.City(), URL: provider.SOCKSURL(),
			})
			if err != nil {
				return nil, nil, fmt.Errorf("external provider %q: %w", provider.ID(), err)
			}
			specs = append(specs, direct)
		}
	}
	if mullvadEnabled {
		var err error
		entrySlots, err = resolveEntries(bundle, cfg.Entries.Slots, cfg.Entries.Auto)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(specs) == 0 {
		return nil, nil, errors.New("providers contain no usable enabled providers")
	}
	entryNames := make([]string, 0, len(entrySlots))
	for _, slot := range entrySlots {
		entryNames = append(entryNames, slot.ID)
	}
	logger.Info("mode: relay-socks", slog.Int("exits", len(specs)), slog.String("entries", strings.Join(entryNames, ",")))
	return specs, entrySlots, nil
}

func mullvadConfigured(cfg config.Config) bool {
	for _, provider := range cfg.Providers() {
		if provider.Enabled() && provider.Type() == config.ProviderMullvad {
			return true
		}
	}
	return false
}

// exitsFromRelays is the seam between the provider and the pool: it is the only
// place that turns Mullvad's relay description into the pool's neutral one.
func exitsFromRelays(relays []mullvad.Relay) []pool.ExitSpec {
	exits := make([]pool.ExitSpec, 0, len(relays))
	for _, relay := range relays {
		exits = append(exits, pool.ExitSpec{
			ID:        relay.SlotID(),
			Country:   relay.Country,
			City:      relay.City(),
			Provider:  "mullvad",
			SocksAddr: relay.SocksAddr(),
		})
	}
	return exits
}

// poolOptionsFrom maps configuration onto pool options.
//
// It exists as a named function so a test can compare both ends: a limit added to
// the config and to the pool but forgotten here would silently disable itself
// while every other test kept passing.
func poolOptionsFrom(cfg config.Config, logger *slog.Logger) pool.Options {
	return pool.Options{
		MaxActive:               cfg.Pool.MaxActive,
		MaxConnsPerExit:         cfg.Pool.MaxConnsPerExit,
		MaxConcurrentConns:      cfg.Pool.MaxConcurrentConns,
		SessionTTL:              cfg.Pool.SessionTTL,
		MaxSessionTTL:           cfg.Pool.MaxSessionTTL,
		MaxSessions:             cfg.Pool.MaxSessions,
		BatchTTL:                cfg.Pool.BatchTTL,
		MaxBatchTTL:             cfg.Pool.MaxBatchTTL,
		MaxUniqueBatches:        cfg.Pool.MaxUniqueBatches,
		Cooldown:                cfg.Pool.Cooldown,
		PreferredTTL:            cfg.Pool.PreferredTTL,
		PreferredMax:            cfg.Pool.PreferredMax,
		IdleTimeout:             cfg.Pool.IdleTimeout,
		HandshakeTimeout:        cfg.Pool.HandshakeTimeout,
		DialAttempts:            cfg.Pool.DialAttempts,
		FailureBackoff:          cfg.Pool.FailureBackoff,
		NewTunnelBudget:         cfg.Pool.NewTunnelsPerWindow,
		NewTunnelWindow:         cfg.Pool.NewTunnelWindow,
		EntryExploreRate:        cfg.Pool.EntryExploreRate,
		DisableEntryExploration: cfg.Pool.StableEntryRouting,
		IPCheckURL:              cfg.Pool.IPCheckURL,
		IPCheckTimeout:          cfg.Pool.IPCheckTimeout,
		IPRefreshInterval:       cfg.Pool.IPRefreshInterval,
		IPCheckConcurrency:      cfg.Pool.IPCheckConcurrency,
		Logger:                  logger,
	}
}
