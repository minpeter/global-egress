package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/minpeter/global-egress/internal/mullvad"
	"github.com/minpeter/global-egress/internal/pool"
)

type (
	relayListFetcher func(context.Context, string) (*mullvad.List, error)
	relayRefresher   func(context.Context) (pool.RelayReconcileResult, error)
)

func refreshRelaySlots(
	ctx context.Context,
	egressPool *pool.Pool,
	url string,
	cachePath string,
	fetch relayListFetcher,
) (pool.RelayReconcileResult, error) {
	list, err := fetch(ctx, url)
	if err != nil {
		return pool.RelayReconcileResult{}, fmt.Errorf("relay refresh failed (%T)", err)
	}
	if list == nil {
		return pool.RelayReconcileResult{}, errors.New("relay refresh returned no relay list")
	}
	relays := list.Usable()
	if len(relays) == 0 {
		return pool.RelayReconcileResult{}, errors.New("relay refresh returned no usable relays")
	}

	result, err := egressPool.ReconcileRelaySlots(
		pool.SpecsFromExits(exitsFromRelays(relays)),
	)
	if err != nil {
		return pool.RelayReconcileResult{}, err
	}
	if cachePath != "" {
		if err := list.Save(cachePath); err != nil {
			return result, fmt.Errorf("relay cache update failed (%T)", err)
		}
	}
	return result, nil
}

func maintainRelaySlots(
	ctx context.Context,
	ticks <-chan time.Time,
	refresh relayRefresher,
	logger *slog.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			result, err := refresh(ctx)
			if err != nil {
				logger.Warn("relay catalog refresh failed")
				continue
			}
			if result.Added == 0 && result.Removed == 0 {
				continue
			}
			logger.Info("relay catalog reconciled",
				slog.Int("added", result.Added),
				slog.Int("removed", result.Removed),
				slog.Int("retained", result.Retained))
		}
	}
}
