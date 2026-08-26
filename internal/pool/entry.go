package pool

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/georoute"
	"github.com/minpeter/global-egress/internal/socksdial"
	"github.com/minpeter/global-egress/internal/wgtunnel"
)

// entryState is one long-lived WireGuard tunnel used as an entry point for relay
// SOCKS slots.
//
// Entries are the only thing that costs a key association, so there are few of
// them and they stay up. Everything else rides on top.
type entryState struct {
	spec catalog.Slot

	tunnel  *wgtunnel.Tunnel
	opening chan struct{}

	failures      int
	lastError     string
	disabledUntil time.Time
	openedAt      time.Time

	// bytesSent and bytesReceived accumulate traffic carried through this entry,
	// which is how you see whether one entry is carrying the whole pool.
	bytesSent     uint64
	bytesReceived uint64

	// latency holds an exponentially weighted moving average of how long it took
	// to reach exits in a given country through this entry, plus the sample count.
	// Real traffic feeds this, so routing improves without extra probing.
	latency map[string]time.Duration
	samples map[string]int
}

// ewmaAlpha weights new latency samples. 0.3 reacts within a handful of requests
// without letting one slow connection dominate.
const ewmaAlpha = 0.3

// entryFailureThreshold is how many consecutive failed dials through an entry take
// it out of rotation.
//
// An entry whose tunnel is up but no longer carrying traffic is the awkward case:
// nothing about the device object says it is broken, so only the dials that ride on
// it can reveal it. Three is one request's worth of attempts, which means a single
// failed request is enough to move the whole pool off a dead entry.
const entryFailureThreshold = 3

// priorLatency converts a geographic prior into a pseudo-latency so that
// unmeasured entries can be ordered against measured ones. The unit is arbitrary
// but the scale is deliberately pessimistic: a real measurement almost always
// looks better than a guess, which is what we want.
const priorLatencyPerHop = 250 * time.Millisecond

func (e *entryState) score(exitCountry string) time.Duration {
	if measured, ok := e.latency[exitCountry]; ok {
		return measured
	}
	hops := georoute.Cost(e.spec.Country, exitCountry)
	return time.Duration(hops+1) * priorLatencyPerHop
}

func (e *entryState) isOpen() bool { return e.tunnel != nil }

// EntryInfo is the public view of an entry tunnel.
type EntryInfo struct {
	ID       string `json:"id"`
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	Endpoint string `json:"endpoint"`
	Region   string `json:"region,omitempty"`

	Open      bool       `json:"open"`
	OpenedAt  *time.Time `json:"opened_at,omitempty"`
	Failures  int        `json:"failures,omitempty"`
	LastError string     `json:"last_error,omitempty"`

	// Latency lists the measured average per exit country, in milliseconds.
	Latency map[string]int64 `json:"latency_ms,omitempty"`
	// Samples reports how many successful dials each average is based on.
	Samples map[string]int `json:"latency_samples,omitempty"`

	// BytesSent and BytesReceived are the traffic carried through this entry.
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

// entryHealthLocked classifies one entry into a bounded rotation state.
func (e *entryState) entryHealthLocked(now time.Time) EntryHealth {
	switch {
	case now.Before(e.disabledUntil):
		return EntryHealthDisabled
	case e.isOpen():
		return EntryHealthOpen
	default:
		return EntryHealthIdle
	}
}

// Entries returns a snapshot of the entry tunnels and what has been learned about
// them.
func (p *Pool) Entries() []EntryInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]EntryInfo, 0, len(p.entries))
	for _, entry := range p.entries {
		info := EntryInfo{
			ID:            entry.spec.ID,
			Country:       entry.spec.Country,
			City:          entry.spec.City,
			Endpoint:      entry.spec.Endpoint,
			Region:        string(georoute.RegionOf(entry.spec.Country)),
			Open:          entry.isOpen(),
			Failures:      entry.failures,
			LastError:     entry.lastError,
			BytesSent:     entry.bytesSent,
			BytesReceived: entry.bytesReceived,
		}
		if !entry.openedAt.IsZero() {
			at := entry.openedAt
			info.OpenedAt = &at
		}
		if len(entry.latency) > 0 {
			info.Latency = make(map[string]int64, len(entry.latency))
			info.Samples = make(map[string]int, len(entry.samples))
			for country, d := range entry.latency {
				info.Latency[country] = d.Milliseconds()
				info.Samples[country] = entry.samples[country]
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// orderedEntriesLocked returns healthy entries, best first, for reaching an exit
// in exitCountry.
func (p *Pool) orderedEntriesLocked(exitCountry string, now time.Time) []*entryState {
	candidates := make([]*entryState, 0, len(p.entries))
	for _, entry := range p.entries {
		if now.Before(entry.disabledUntil) {
			continue
		}
		candidates = append(candidates, entry)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		si, sj := candidates[i].score(exitCountry), candidates[j].score(exitCountry)
		if si != sj {
			return si < sj
		}
		// Prefer an entry that is already up: it saves a handshake.
		if candidates[i].isOpen() != candidates[j].isOpen() {
			return candidates[i].isOpen()
		}
		return candidates[i].spec.ID < candidates[j].spec.ID
	})

	// Occasionally try the runner-up so alternatives keep getting measured;
	// otherwise the first entry that happens to look good is never challenged.
	if len(candidates) > 1 && p.rng.Float64() < p.opts.EntryExploreRate {
		candidates[0], candidates[1] = candidates[1], candidates[0]
	}
	return candidates
}

// recordEntryLatency folds one observation into an entry's moving average.
func (p *Pool) recordEntryLatency(entry *entryState, exitCountry string, observed time.Duration) {
	if exitCountry == "" || observed <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.latency == nil {
		entry.latency = make(map[string]time.Duration)
		entry.samples = make(map[string]int)
	}
	previous, seen := entry.latency[exitCountry]
	if !seen {
		entry.latency[exitCountry] = observed
	} else {
		entry.latency[exitCountry] = time.Duration(
			ewmaAlpha*float64(observed) + (1-ewmaAlpha)*float64(previous))
	}
	entry.samples[exitCountry]++
	// A dial that completed is proof the entry works, so forget earlier failures.
	entry.failures = 0
	entry.lastError = ""
}

// noteEntryFailure records a failed dial through an entry and reports whether the
// entry was taken out of rotation as a result.
//
// Blaming the entry matters twice over: it moves traffic off a dead path within one
// request, and it stops the exits from being blamed for a fault that was never
// theirs. Without it a single broken entry slowly marks hundreds of healthy relays
// as failing.
func (p *Pool) noteEntryFailure(entryID string, err error) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	var entry *entryState
	for _, candidate := range p.entries {
		if candidate.spec.ID == entryID {
			entry = candidate
			break
		}
	}
	if entry == nil {
		return false
	}

	entry.failures++
	entry.lastError = redactedError(err)
	p.observeEntryDialFailureLocked()
	if entry.failures < entryFailureThreshold {
		return false
	}

	backoff := p.opts.FailureBackoff << min(entry.failures-entryFailureThreshold, 5)
	if maxBackoff := 10 * time.Minute; backoff > maxBackoff {
		backoff = maxBackoff
	}
	entry.disabledUntil = time.Now().Add(backoff)

	// Drop the tunnel so the next use re-handshakes rather than reusing a device
	// that is up but not carrying traffic.
	if entry.tunnel != nil {
		tunnel := entry.tunnel
		entry.tunnel = nil
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			_ = tunnel.Close()
		}()
	}

	p.log.Warn("entry taken out of rotation",
		slog.String("entry", entryID),
		slog.Int("consecutive_failures", entry.failures),
		slog.Duration("backoff", backoff),
		slog.String("error_type", redactedError(err)))
	return true
}

// ensureEntryOpen brings an entry tunnel up, or returns the live one. Only one
// caller opens a given entry; others wait for it.
func (p *Pool) ensureEntryOpen(ctx context.Context, entry *entryState) (*wgtunnel.Tunnel, error) {
	for {
		p.mu.Lock()
		if entry.tunnel != nil {
			tunnel := entry.tunnel
			p.mu.Unlock()
			return tunnel, nil
		}
		if waiting := entry.opening; waiting != nil {
			p.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if err := p.reserveCapacityLocked(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if err := p.reserveTunnelOpenLocked(time.Now()); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		done := make(chan struct{})
		entry.opening = done
		spec := entry.spec
		p.mu.Unlock()

		if err := ctx.Err(); err != nil {
			p.rollbackTunnelOpen()
			p.mu.Lock()
			entry.opening = nil
			p.mu.Unlock()
			close(done)
			return nil, err
		}
		p.commitTunnelOpen()
		tunnel, err := p.openTunnelForCapacity(ctx, spec, TunnelRoleEntry)

		p.mu.Lock()
		entry.opening = nil
		if err == nil {
			entry.tunnel = tunnel
			entry.openedAt = time.Now()
			entry.failures = 0
			entry.lastError = ""
		} else {
			entry.failures++
			entry.lastError = redactedError(err)
			p.observeEntryOpenFailureLocked()
			backoff := p.opts.FailureBackoff << min(entry.failures-1, 5)
			if maxBackoff := 10 * time.Minute; backoff > maxBackoff {
				backoff = maxBackoff
			}
			entry.disabledUntil = time.Now().Add(backoff)
		}
		p.mu.Unlock()
		close(done)

		if err != nil {
			p.log.Warn("entry tunnel failed",
				slog.String("entry", spec.ID),
				slog.Int("failures", entry.failures),
				slog.String("error_type", redactedError(err)))
			return nil, err
		}
		p.log.Info("entry tunnel up",
			slog.String("entry", spec.ID),
			slog.String("country", spec.Country))
		return tunnel, nil
	}
}

// dialerForSocksSlot builds a dialer that reaches the slot's SOCKS proxy through
// the best available entry, and reports the observed latency back so future
// choices improve.
func (p *Pool) dialerForSocksSlot(ctx context.Context, state *slotState) (Dialer, string, error) {
	p.mu.Lock()
	candidates := p.orderedEntriesLocked(state.spec.Country, time.Now())
	p.mu.Unlock()

	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("%w: no healthy entry tunnel", ErrExhausted)
	}

	var lastErr error
	for _, entry := range candidates {
		tunnel, err := p.ensureEntryOpen(ctx, entry)
		if err != nil {
			lastErr = err
			continue
		}
		exitCountry := state.spec.Country
		dialer := &measuringDialer{
			inner: &socksdial.Dialer{
				Base:      tunnel,
				ProxyAddr: state.spec.SocksAddr,
				Timeout:   p.opts.HandshakeTimeout,
			},
			observe: func(d time.Duration) { p.recordEntryLatency(entry, exitCountry, d) },
		}
		return dialer, entry.spec.ID, nil
	}
	if lastErr != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrExhausted, lastErr)
	}
	return nil, "", ErrExhausted
}

// measuringDialer times each successful dial. The SOCKS negotiation traverses the
// whole path we care about, so this is a free measurement of entry quality.
type measuringDialer struct {
	inner   Dialer
	observe func(time.Duration)
}

func (m *measuringDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	started := time.Now()
	conn, err := m.inner.DialContext(ctx, network, address)
	if err == nil && m.observe != nil {
		m.observe(time.Since(started))
	}
	return conn, err
}

// closeEntriesLocked tears down every entry tunnel.
func (p *Pool) closeEntriesLocked(reason string) {
	for _, entry := range p.entries {
		if entry.tunnel == nil {
			continue
		}
		tunnel := entry.tunnel
		entry.tunnel = nil
		id := entry.spec.ID
		p.log.Debug("closing entry tunnel", slog.String("entry", id), slog.String("reason", reason))
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := tunnel.Close(); err != nil {
				p.log.Warn("entry close failed",
					slog.String("entry", id),
					slog.String("error_type", redactedError(err)))
			}
		}()
	}
}
