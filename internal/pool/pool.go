// Package pool owns every egress slot: their tunnels, their health, their
// measured public IP, and the policy that decides which one serves a request.
//
// The pool is the reason this project exists. Bringing up a userspace WireGuard
// tunnel is a solved problem; deciding *which* of several hundred tunnels a
// given connection should use — while honouring sticky sessions, unique-IP
// batches and per-target cooldowns — is the part that has to be built.
package pool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/georoute"
	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/socksdial"
	"github.com/minpeter/global-egress/internal/wgtunnel"
)

// Errors returned by Acquire.
var (
	// ErrNoCandidate means the policy matched no usable slot.
	ErrNoCandidate = errors.New("pool: no slot satisfies the requested policy")
	// ErrExhausted means every candidate failed to come up.
	ErrExhausted = errors.New("pool: all candidate slots failed")
	// ErrCapacity means the active-tunnel budget is fully used by live requests.
	ErrCapacity = errors.New("pool: tunnel capacity exhausted")
	// ErrTunnelBudget means the new-tunnel rate budget is spent. Serving from an
	// already-open tunnel is still possible; only opening another one is not.
	ErrTunnelBudget = errors.New("pool: new-tunnel rate budget exhausted")
	// ErrBusy means the concurrent-connection limit is reached. Unlike the other
	// failures this one is purely about load and clears as connections finish.
	ErrBusy = errors.New("pool: too many concurrent connections")
	// ErrBatchFull means the active unique-IP batch limit has been reached.
	ErrBatchFull = errors.New("pool: active unique-IP batch limit reached")
	// ErrPolicy means a client policy exceeds a server-configured safety bound.
	ErrPolicy = errors.New("pool: policy exceeds configured limits")
	// ErrSessionFull means the sticky-session map reached its configured cap.
	ErrSessionFull = errors.New("pool: active sticky-session limit reached")
	// ErrIdentityMismatch means feedback named a slot whose measured public IP
	// differs from the identity observed by the client.
	ErrIdentityMismatch = errors.New("pool: egress identity mismatch")
)

// Options configures a Pool.
type Options struct {
	// MaxActive caps how many tunnels may be up at once. Zero means "all slots".
	MaxActive int
	// MaxConnsPerExit caps concurrent connections through one exit. Zero disables
	// the limit.
	//
	// In relay-socks mode an exit is a provider proxy shared with every other
	// customer, and nothing else here would stop a client pointing hundreds of
	// connections at a single relay. Spreading load is both politer and less
	// likely to look like abuse.
	MaxConnsPerExit int
	// MaxConcurrentConns caps concurrent connections across the whole pool. Zero
	// disables the limit. This is the backstop that keeps a runaway client from
	// turning into pressure on the provider.
	MaxConcurrentConns int
	// SessionTTL is the default lifetime of a sticky session.
	SessionTTL time.Duration
	// MaxSessionTTL caps a client-selected sticky-session lifetime.
	MaxSessionTTL time.Duration
	// MaxSessions caps retained and pending sticky-session names.
	MaxSessions int
	// BatchTTL is how long a unique-IP batch remembers the IPs it used.
	BatchTTL time.Duration
	// MaxBatchTTL caps a client-selected unique-batch lifetime.
	MaxBatchTTL time.Duration
	// MaxUniqueBatches caps concurrently active unique-IP batches. Zero uses the
	// safe default.
	MaxUniqueBatches int
	// Cooldown is the default per-target cooldown applied by Report.
	Cooldown time.Duration
	// PreferredTTL is how long a destination remembers a last-good slot.
	// Zero uses the default. Preferred slots are tried first on the next
	// Acquire for that destination, then the usual random pick.
	PreferredTTL time.Duration
	// PreferredMax is how many last-good slots a destination keeps.
	// Concurrent requests spread across the ring instead of piling onto one
	// IP and burning its quota together. Zero uses the default.
	PreferredMax int
	// IdleTimeout closes tunnels that have served nothing for this long.
	// Zero disables idle eviction.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds how long Acquire waits for a new tunnel.
	HandshakeTimeout time.Duration
	// DialAttempts is how many candidate slots Acquire tries before failing.
	DialAttempts int
	// FailureBackoff is the base backoff applied to a slot after a failure.
	FailureBackoff time.Duration
	// NewTunnelBudget caps how many tunnels may be *opened* per
	// NewTunnelWindow. Zero disables the limit.
	//
	// This exists because providers restrict how quickly one device key may
	// associate with new relays. Exceeding that looks like key sharing and can
	// get the key blocked for hours, which is far worse than a slow rotation.
	// The cap counts attempts, since a failed handshake still contacts a relay.
	NewTunnelBudget int
	// NewTunnelWindow is the period NewTunnelBudget applies to.
	NewTunnelWindow time.Duration
	// EntryExploreRate is the probability of trying the second-best entry instead
	// of the best one, so alternatives keep being measured. Zero selects the
	// default; use DisableEntryExploration to turn it off.
	EntryExploreRate float64
	// DisableEntryExploration pins selection to the best known entry. Useful for
	// reproducible tests and for operators who prefer stable routing over
	// self-correcting routing.
	DisableEntryExploration bool
	// IPCheckURL returns the caller's public address. Empty disables IP checks,
	// which also disables unique-IP guarantees.
	IPCheckURL string
	// IPCheckTimeout bounds a single public-IP measurement.
	IPCheckTimeout time.Duration
	// IPRefreshInterval is how long a measured public IP stays trusted.
	IPRefreshInterval time.Duration
	// IPCheckConcurrency caps simultaneous public-IP measurements. This is a
	// courtesy limit: the check hits a third-party service.
	IPCheckConcurrency int
	// Logger receives pool events.
	Logger *slog.Logger
	// Rand, when non-nil, makes selection deterministic for tests.
	Rand *rand.Rand
}

func (o *Options) applyDefaults() {
	if o.SessionTTL <= 0 {
		o.SessionTTL = 10 * time.Minute
	}
	if o.MaxSessionTTL <= 0 {
		o.MaxSessionTTL = 24 * time.Hour
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = 10_000
	}
	if o.BatchTTL <= 0 {
		o.BatchTTL = 15 * time.Minute
	}
	if o.MaxBatchTTL <= 0 {
		o.MaxBatchTTL = o.BatchTTL
	}
	if o.MaxUniqueBatches <= 0 {
		o.MaxUniqueBatches = 10_000
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 15 * time.Minute
	}
	if o.PreferredTTL <= 0 {
		o.PreferredTTL = 30 * time.Minute
	}
	if o.PreferredMax <= 0 {
		o.PreferredMax = 8
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 12 * time.Second
	}
	if o.DialAttempts <= 0 {
		o.DialAttempts = 3
	}
	if o.FailureBackoff <= 0 {
		o.FailureBackoff = 30 * time.Second
	}
	if o.NewTunnelWindow <= 0 {
		o.NewTunnelWindow = 10 * time.Minute
	}
	// A negative rate cannot be expressed as "off" here, because zero has to mean
	// "use the default"; DisableEntryExploration is the explicit switch.
	if o.MaxConnsPerExit < 0 {
		o.MaxConnsPerExit = 0
	}
	if o.MaxConcurrentConns < 0 {
		o.MaxConcurrentConns = 0
	}
	if o.EntryExploreRate <= 0 {
		o.EntryExploreRate = 0.1
	}
	if o.DisableEntryExploration {
		o.EntryExploreRate = 0
	}
	if o.IPCheckTimeout <= 0 {
		o.IPCheckTimeout = 15 * time.Second
	}
	if o.IPRefreshInterval <= 0 {
		o.IPRefreshInterval = 6 * time.Hour
	}
	if o.IPCheckConcurrency <= 0 {
		o.IPCheckConcurrency = 4
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// slotState is the mutable bookkeeping for one slot.
type slotState struct {
	spec Spec

	tunnel  *wgtunnel.Tunnel
	opening chan struct{} // non-nil while an Open is in flight

	openedAt time.Time
	lastUsed time.Time
	leases   int
	// pendingLeases reserves connection capacity between selection and dialer
	// setup. Without it, concurrent Acquire calls can all pass the limits before
	// any of them commits a live lease.
	pendingLeases int

	publicIP    netip.Addr
	ipCheckedAt time.Time
	ipChecking  bool

	failures      int
	lastError     string
	disabledUntil time.Time

	// cooldowns maps a destination host to the time the slot may serve it again.
	cooldowns map[string]time.Time

	// bytesSent and bytesReceived accumulate relayed traffic for this slot.
	bytesSent     uint64
	bytesReceived uint64
}

func (s *slotState) isOpen() bool { return s.tunnel != nil }

// ready reports whether the slot can serve a request without opening a tunnel.
// Relay-socks slots ride on the shared entries, so they never need one; a
// WireGuard slot only qualifies while its own tunnel is up.
func (s *slotState) ready() bool {
	return s.spec.Kind == KindRelaySocks || s.isOpen()
}

func (s *slotState) coolingDown(target string, now time.Time) bool {
	if target == "" || len(s.cooldowns) == 0 {
		return false
	}
	until, ok := s.cooldowns[target]
	return ok && now.Before(until)
}

type session struct {
	slotID    string
	expiresAt time.Time
}

// preferredExit is one last-good slot for a destination.
// CONNECT success is not enough: the client reports this after a 200.
type preferredExit struct {
	slotID    string
	publicIP  netip.Addr
	expiresAt time.Time
}

// preferredSet is the ring of last-good slots for one destination.
// Concurrent requests pick the least-loaded member so they do not all
// burn the same exit quota.
type preferredSet struct {
	slots []preferredExit
}

type batch struct {
	usedIPs   map[netip.Addr]struct{}
	usedSlots map[string]struct{}
	// slotIPs retains the addresses attributed to each reservation so a failed
	// dial can release only its own addresses after a measurement backfill.
	slotIPs   map[string]map[netip.Addr]struct{}
	expiresAt time.Time
}

type batchReservation struct {
	name   string
	batch  *batch
	slotID string
}

type acquisitionReservation struct {
	batch   *batchReservation
	session string
	state   *slotState
	active  bool
}

func redactedError(err error) string {
	return fmt.Sprintf("%T", err)
}

func newBatch(expiresAt time.Time) *batch {
	return &batch{
		usedIPs:   make(map[netip.Addr]struct{}),
		usedSlots: make(map[string]struct{}),
		slotIPs:   make(map[string]map[netip.Addr]struct{}),
		expiresAt: expiresAt,
	}
}

func (b *batch) reserve(slotID string, ip netip.Addr) {
	if b.usedSlots == nil {
		b.usedSlots = make(map[string]struct{})
	}
	b.usedSlots[slotID] = struct{}{}
	b.addIP(slotID, ip)
}

func (b *batch) addIP(slotID string, ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	if b.usedIPs == nil {
		b.usedIPs = make(map[netip.Addr]struct{})
	}
	if b.slotIPs == nil {
		b.slotIPs = make(map[string]map[netip.Addr]struct{})
	}
	ips := b.slotIPs[slotID]
	if ips == nil {
		ips = make(map[netip.Addr]struct{})
		b.slotIPs[slotID] = ips
	}
	if _, exists := ips[ip]; exists {
		return
	}
	ips[ip] = struct{}{}
	b.usedIPs[ip] = struct{}{}
}

func (b *batch) release(slotID string) {
	ips := b.slotIPs[slotID]
	delete(b.slotIPs, slotID)
	delete(b.usedSlots, slotID)
	for ip := range ips {
		stillUsed := false
		for _, other := range b.slotIPs {
			if _, exists := other[ip]; exists {
				stillUsed = true
				break
			}
		}
		if !stillUsed {
			delete(b.usedIPs, ip)
		}
	}
}

// Pool manages the whole slot inventory.
type Pool struct {
	opts Options
	log  *slog.Logger

	ipCheckSem chan struct{}

	mu       sync.Mutex
	rng      *rand.Rand
	slots    map[string]*slotState
	order    []string // slot IDs in stable (sorted) order
	sessions map[string]*session
	// pendingSessions counts in-flight acquisitions by new session name.
	pendingSessions map[string]int
	batches         map[string]*batch
	// preferred maps a destination host to last-good slots a client
	// reported as actually serving that destination (CONNECT success is not enough).
	preferred map[string]*preferredSet
	// ipCooldowns applies target health to the measured public IP rather than
	// one slot, so duplicate slots cannot re-offer the same quota-burned exit.
	ipCooldowns map[string]map[netip.Addr]time.Time
	// entries are the WireGuard tunnels that relay-socks slots ride on. Empty in
	// pure WireGuard mode.
	entries []*entryState
	// opens holds the timestamps of recent tunnel openings, newest last, pruned
	// to NewTunnelWindow.
	opens              []time.Time
	pendingTunnelOpens int
	probeTunnels       int
	// closing is set by Close so background work stops starting.
	closing bool

	// baseCtx is cancelled by Close. Background work such as public-IP checks
	// derives from it, so a shutdown does not leave requests in flight against
	// tunnels that are being torn down. Holding a context in a struct is a
	// deliberate exception, justified the same way http.Server justifies
	// BaseContext: the object has an explicit lifetime ended by Close.
	baseCtx   context.Context
	cancelAll context.CancelFunc
	// wg tracks every goroutine the pool owns, so Close can wait for them.
	wg sync.WaitGroup

	// leased is the number of connections currently held across all slots.
	leased        int
	pendingLeases int

	ensureDialerForAcquire func(context.Context, *slotState) (Dialer, string, error)
	openTunnelForCapacity  func(context.Context, catalog.Slot, TunnelRole) (*wgtunnel.Tunnel, error)

	// counters, protected by mu
	statAcquired          uint64
	statBusy              uint64
	statSent              uint64
	statReceived          uint64
	statRotated           uint64
	statReports           uint64
	statFailures          uint64
	statAcquiredByCountry map[string]uint64
	metrics               metricsState
}

// New builds a pool where every slot owns a WireGuard tunnel.
func New(bundle *catalog.Bundle, opts Options) (*Pool, error) {
	if bundle == nil || len(bundle.Slots) == 0 {
		return nil, errors.New("pool: bundle contains no slots")
	}
	return NewWithSpecs(SpecsFromBundle(bundle), nil, opts)
}

// NewWithSpecs builds a pool from explicit slot specifications.
//
// entries are the WireGuard tunnels that relay-socks slots are reached through.
// They are required if any spec is KindRelaySocks and ignored otherwise.
func NewWithSpecs(specs []Spec, entries []catalog.Slot, opts Options) (*Pool, error) {
	if len(specs) == 0 {
		return nil, errors.New("pool: no slots")
	}
	needsEntry := false
	for _, spec := range specs {
		if spec.Kind == KindRelaySocks {
			needsEntry = true
			break
		}
	}
	if needsEntry && len(entries) == 0 {
		return nil, errors.New("pool: relay-socks slots require at least one entry tunnel")
	}
	opts.applyDefaults()

	rng := opts.Rand
	if rng == nil {
		// math/rand/v2 seeds itself from the runtime, so there is nothing to seed
		// here; a fresh generator only exists so tests can substitute their own.
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}

	baseCtx, cancelAll := context.WithCancel(context.Background())
	p := &Pool{
		baseCtx:               baseCtx,
		cancelAll:             cancelAll,
		opts:                  opts,
		log:                   opts.Logger,
		ipCheckSem:            make(chan struct{}, opts.IPCheckConcurrency),
		rng:                   rng,
		slots:                 make(map[string]*slotState, len(specs)),
		sessions:              make(map[string]*session),
		pendingSessions:       make(map[string]int),
		batches:               make(map[string]*batch),
		preferred:             make(map[string]*preferredSet),
		ipCooldowns:           make(map[string]map[netip.Addr]time.Time),
		statAcquiredByCountry: make(map[string]uint64),
	}
	for _, spec := range specs {
		if _, dup := p.slots[spec.ID]; dup {
			return nil, fmt.Errorf("pool: duplicate slot id %q", spec.ID)
		}
		p.slots[spec.ID] = &slotState{spec: spec, cooldowns: make(map[string]time.Time)}
		p.order = append(p.order, spec.ID)
	}
	sort.Strings(p.order)

	for _, entry := range entries {
		p.entries = append(p.entries, &entryState{
			spec:    entry,
			latency: make(map[string]time.Duration),
			samples: make(map[string]int),
		})
	}
	p.ensureDialerForAcquire = p.ensureDialer
	p.openTunnelForCapacity = p.openTunnel
	return p, nil
}

// Len returns the number of known slots.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.slots)
}

// Lease is a slot borrowed for one connection. Release must always be called.
type Lease struct {
	pool   *Pool
	state  *slotState
	dialer Dialer

	// Slot describes the chosen egress.
	Slot Spec
	// Entry is the entry tunnel used, for relay-socks slots.
	Entry string
	// Chained reports that traffic leaves through a proxy rather than directly
	// out of a tunnel. The connection's remote address is then the proxy, not the
	// destination, so callers must not treat it as the resolved destination.
	Chained bool
	// PublicIP is the last measured public address, invalid when unknown.
	PublicIP netip.Addr
	// Session is the sticky session the lease belongs to, if any.
	Session string

	released bool
}

// DialContext connects to address through the leased egress.
func (l *Lease) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return l.dialer.DialContext(ctx, network, address)
}

// Release returns the slot to the pool.
func (l *Lease) Release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	l.pool.mu.Lock()
	if l.state.leases > 0 {
		l.state.leases--
	}
	if l.pool.leased > 0 {
		l.pool.leased--
	}
	l.state.lastUsed = time.Now()
	l.pool.mu.Unlock()
}

// Acquire selects a slot for a connection to target (a host name or IP, used for
// per-target cooldown bookkeeping; it may be empty).
func (p *Pool) Acquire(ctx context.Context, pol policy.Policy, target string) (*Lease, error) {
	attempts := p.opts.DialAttempts
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		state, sticky, reservation, err := p.pick(pol, target)
		if err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}

		dialer, entryID, err := p.ensureDialerForAcquire(ctx, state)
		if err != nil {
			p.rollbackAcquisition(reservation)
			p.noteFailure(state, err)
			lastErr = err
			// A sticky session pointing at a broken slot must not pin the client
			// to it; drop the binding so the next attempt is free to move on.
			if sticky && pol.Session != "" {
				p.dropSession(pol.Session)
			}
			continue
		}

		p.mu.Lock()
		p.commitAcquisitionLocked(reservation)
		state.leases++
		p.leased++
		state.lastUsed = time.Now()
		state.failures = 0
		state.lastError = ""
		publicIP := state.publicIP
		p.bindSession(pol, state.ID())
		p.recordAcquisitionLocked(state)
		p.mu.Unlock()

		p.maybeCheckIP(state)

		return &Lease{
			pool:     p,
			state:    state,
			dialer:   dialer,
			Slot:     state.spec,
			Entry:    entryID,
			Chained:  state.spec.Kind == KindRelaySocks,
			PublicIP: publicIP,
			Session:  pol.Session,
		}, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrExhausted, lastErr)
	}
	return nil, ErrExhausted
}

func (p *Pool) recordAcquisitionLocked(state *slotState) {
	country := strings.ToLower(state.spec.Country)
	if country == "" {
		country = "unknown"
	}
	p.statAcquired++
	p.statAcquiredByCountry[country]++
}

// ID returns the slot ID.
func (s *slotState) ID() string { return s.spec.ID }

// pick chooses the next slot to try. The returned bool reports whether the
// choice came from a sticky session.
func (p *Pool) pick(
	pol policy.Policy,
	target string,
) (*slotState, bool, *acquisitionReservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	p.expireLocked(now)
	if pol.TTL > p.opts.MaxSessionTTL {
		return nil, false, nil, fmt.Errorf(
			"%w: ttl %s exceeds maximum %s",
			ErrPolicy,
			pol.TTL,
			p.opts.MaxSessionTTL,
		)
	}
	if pol.BatchTTL > p.opts.MaxBatchTTL {
		return nil, false, nil, fmt.Errorf(
			"%w: bttl %s exceeds maximum %s",
			ErrPolicy,
			pol.BatchTTL,
			p.opts.MaxBatchTTL,
		)
	}
	if pol.HealthScope != "" {
		target = pol.HealthScope
	}

	if p.opts.MaxConcurrentConns > 0 &&
		p.leased+p.pendingLeases >= p.opts.MaxConcurrentConns {
		p.statBusy++
		return nil, false, nil, ErrBusy
	}
	// A live sticky session wins, as long as the slot is still usable.
	if pol.Session != "" {
		if sess, ok := p.sessions[pol.Session]; ok && now.Before(sess.expiresAt) {
			if state, ok := p.slots[sess.slotID]; ok && p.eligibleLocked(state, pol, target, now) {
				sess.expiresAt = now.Add(p.sessionTTL(pol))
				reservation, err := p.reserveAcquisitionLocked(pol, state, now)
				if err != nil {
					return nil, false, nil, err
				}
				return state, true, reservation, nil
			}
			// The pinned slot became unusable: fall through and re-pick.
			delete(p.sessions, pol.Session)
		}
	}

	// A destination's last-good slots beat a unique-batch walk. CONNECT
	// success is not enough — Prefer records this after the origin answered.
	// Preferred slots ignore uniq= so a 200'd IP can be reused; dest cooldown
	// still applies so a later 429 drops that member.
	if target != "" {
		if state, reservation, err := p.pickPreferredLocked(pol, target, now); err != nil {
			return nil, false, nil, err
		} else if state != nil {
			return state, false, reservation, nil
		}
	}

	candidates := make([]*slotState, 0, 32)
	for _, id := range p.order {
		state := p.slots[id]
		if p.eligibleLocked(state, pol, target, now) {
			candidates = append(candidates, state)
		}
	}
	if len(candidates) == 0 {
		return nil, false, nil, ErrNoCandidate
	}

	// Prefer slots that need no handshake: relay-socks slots always, and
	// WireGuard slots whose tunnel is already up. With a healthy active set there
	// is still plenty of IP diversity among them.
	ready := candidates[:0:0]
	for _, state := range candidates {
		if state.ready() {
			ready = append(ready, state)
		}
	}
	if len(ready) > 0 {
		state := pickNearestReady(ready, p.rng)
		reservation, err := p.reserveAcquisitionLocked(pol, state, now)
		if err != nil {
			return nil, false, nil, err
		}
		return state, false, reservation, nil
	}

	if !p.tunnelBudgetAvailableLocked(now) {
		return nil, false, nil, ErrTunnelBudget
	}
	if err := p.reserveCapacityLocked(); err != nil {
		return nil, false, nil, err
	}
	state := pickNearestReady(candidates, p.rng)
	reservation, err := p.reserveAcquisitionLocked(pol, state, now)
	if err != nil {
		return nil, false, nil, err
	}
	return state, false, reservation, nil
}

// eligibleLocked applies every filter that can be evaluated without I/O.
func (p *Pool) eligibleLocked(state *slotState, pol policy.Policy, target string, now time.Time) bool {
	if state == nil {
		return false
	}
	if now.Before(state.disabledUntil) {
		return false
	}
	if pol.Slot != "" && state.spec.ID != pol.Slot {
		return false
	}
	if len(pol.Countries) > 0 && !containsFold(pol.Countries, state.spec.Country) {
		return false
	}
	if len(pol.Cities) > 0 && !containsFold(pol.Cities, state.spec.City) {
		return false
	}
	if state.coolingDown(target, now) {
		return false
	}
	if p.ipCoolingDownLocked(target, state.publicIP, now) {
		return false
	}
	// Spread load: an exit already at its connection limit is not a candidate,
	// even if it is otherwise the best match.
	if p.opts.MaxConnsPerExit > 0 &&
		state.leases+state.pendingLeases >= p.opts.MaxConnsPerExit {
		return false
	}
	requiresFreshIP := pol.UniqueBatch != "" || len(pol.ExcludeIPs) > 0
	ipFresh := state.publicIP.IsValid() &&
		!state.ipCheckedAt.IsZero() &&
		now.Before(state.ipCheckedAt.Add(p.opts.IPRefreshInterval))
	if requiresFreshIP && !ipFresh {
		return false
	}
	if len(pol.ExcludeIPs) > 0 {
		for _, excluded := range pol.ExcludeIPs {
			if excluded == state.publicIP {
				return false
			}
		}
	}
	if pol.UniqueBatch != "" {
		if b, ok := p.batches[pol.UniqueBatch]; ok && now.Before(b.expiresAt) {
			if _, used := b.usedSlots[state.spec.ID]; used {
				return false
			}
			if _, used := b.usedIPs[state.publicIP]; used {
				return false
			}
		}
	}
	return true
}

// nearbyHuntRegions are the exits a KR/JP lab should try first when walking
// unused IPs. A random US/EU first hop is why one-shot hunts miss 2s TTFT.
var nearbyHuntRegions = map[georoute.Region]struct{}{
	georoute.EastAsia:  {},
	georoute.SouthAsia: {},
}

func pickNearestReady(ready []*slotState, rng *rand.Rand) *slotState {
	if len(ready) == 1 {
		return ready[0]
	}
	near := ready[:0:0]
	for _, state := range ready {
		if _, ok := nearbyHuntRegions[georoute.RegionOf(state.spec.Country)]; ok {
			near = append(near, state)
		}
	}
	if len(near) > 0 {
		return near[rng.IntN(len(near))]
	}
	return ready[rng.IntN(len(ready))]
}

// eligiblePreferredLocked is eligibleLocked without the unique-batch check.
// A 200'd exit must stay reusable even if this request's uniq= already saw it.
func (p *Pool) eligiblePreferredLocked(state *slotState, pol policy.Policy, target string, now time.Time) bool {
	if state == nil {
		return false
	}
	withoutBatch := pol
	withoutBatch.UniqueBatch = ""
	return p.eligibleLocked(state, withoutBatch, target, now)
}

func (p *Pool) pickPreferredLocked(pol policy.Policy, target string, now time.Time) (*slotState, *acquisitionReservation, error) {
	set := p.preferred[target]
	if set == nil {
		return nil, nil, nil
	}
	set.prune(now)
	var best *slotState
	bestLoad := int(^uint(0) >> 1)
	kept := set.slots[:0]
	for _, pref := range set.slots {
		state, ok := p.slots[pref.slotID]
		if !ok ||
			!pref.publicIP.IsValid() ||
			state.publicIP != pref.publicIP ||
			!p.eligiblePreferredLocked(state, pol, target, now) {
			continue
		}
		kept = append(kept, pref)
		load := state.leases + state.pendingLeases
		if best == nil || load < bestLoad {
			best = state
			bestLoad = load
		}
	}
	set.slots = kept
	if len(set.slots) == 0 {
		delete(p.preferred, target)
		return nil, nil, nil
	}
	if best == nil {
		return nil, nil, nil
	}
	set.rotateToTail(best.spec.ID)
	reservation, err := p.reserveAcquisitionLocked(pol, best, now)
	if err != nil {
		return nil, nil, err
	}
	return best, reservation, nil
}

func (s *preferredSet) remember(slotID string, publicIP netip.Addr, until time.Time, max int) {
	if max <= 0 {
		max = 8
	}
	for i, pref := range s.slots {
		if pref.publicIP == publicIP {
			s.slots[i].slotID = slotID
			s.slots[i].expiresAt = until
			return
		}
	}
	s.slots = append(s.slots, preferredExit{
		slotID:    slotID,
		publicIP:  publicIP,
		expiresAt: until,
	})
	if len(s.slots) > max {
		s.slots = s.slots[len(s.slots)-max:]
	}
}

func (s *preferredSet) removeIP(publicIP netip.Addr) {
	kept := s.slots[:0]
	for _, pref := range s.slots {
		if pref.publicIP != publicIP {
			kept = append(kept, pref)
		}
	}
	s.slots = kept
}

func (s *preferredSet) rotateToTail(slotID string) {
	for i, pref := range s.slots {
		if pref.slotID != slotID || i == len(s.slots)-1 {
			continue
		}
		copy(s.slots[i:], s.slots[i+1:])
		s.slots[len(s.slots)-1] = pref
		return
	}
}

func (s *preferredSet) prune(now time.Time) {
	kept := s.slots[:0]
	for _, pref := range s.slots {
		if now.Before(pref.expiresAt) {
			kept = append(kept, pref)
		}
	}
	s.slots = kept
}

func (p *Pool) ipCoolingDownLocked(target string, ip netip.Addr, now time.Time) bool {
	if target == "" || !ip.IsValid() {
		return false
	}
	byIP := p.ipCooldowns[target]
	until, ok := byIP[ip]
	if !ok {
		return false
	}
	if now.Before(until) {
		return true
	}
	delete(byIP, ip)
	if len(byIP) == 0 {
		delete(p.ipCooldowns, target)
	}
	return false
}

func (p *Pool) setIPCooldownLocked(target string, ip netip.Addr, until time.Time) {
	if target == "" || !ip.IsValid() {
		return
	}
	byIP := p.ipCooldowns[target]
	if byIP == nil {
		byIP = make(map[netip.Addr]time.Time)
		p.ipCooldowns[target] = byIP
	}
	if current := byIP[ip]; current.Before(until) {
		byIP[ip] = until
	}
}

// reserveCapacityLocked checks whether another tunnel may be opened, closing an
// idle one if the budget is full.
func (p *Pool) reserveCapacityLocked() error {
	if p.opts.MaxActive <= 0 {
		return nil
	}
	openCount := 0
	for _, state := range p.slots {
		if state.isOpen() || state.opening != nil {
			openCount++
		}
	}
	for _, entry := range p.entries {
		if entry.isOpen() || entry.opening != nil {
			openCount++
		}
	}
	openCount += p.probeTunnels
	if openCount < p.opts.MaxActive {
		return nil
	}

	// Evict the least recently used idle tunnel.
	var victim *slotState
	for _, state := range p.slots {
		if !state.isOpen() || state.leases+state.pendingLeases > 0 {
			continue
		}
		if victim == nil || state.lastUsed.Before(victim.lastUsed) {
			victim = state
		}
	}
	if victim == nil {
		return ErrCapacity
	}
	p.closeLocked(victim, "evicted to free capacity")
	return nil
}

// closeLocked tears down a tunnel. Caller must hold mu.
func (p *Pool) closeLocked(state *slotState, reason string) {
	if state.tunnel == nil {
		return
	}
	tunnel := state.tunnel
	state.tunnel = nil
	state.openedAt = time.Time{}
	id := state.spec.ID
	p.log.Debug("closing tunnel", slog.String("slot", id), slog.String("reason", reason))
	// Tear down off the lock, because a device close joins its own goroutines.
	// Registered with the WaitGroup so Close can wait for it.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := tunnel.Close(); err != nil {
			p.log.Warn("tunnel close failed",
				slog.String("slot", id),
				slog.String("error_type", redactedError(err)))
		}
	}()
}

// ensureDialer returns something that can reach the internet as this slot, plus
// the entry tunnel used (empty for WireGuard slots).
func (p *Pool) ensureDialer(ctx context.Context, state *slotState) (Dialer, string, error) {
	if state.spec.Kind == KindRelaySocks {
		return p.dialerForSocksSlot(ctx, state)
	}
	tunnel, err := p.ensureOpen(ctx, state)
	if err != nil {
		return nil, "", err
	}
	return tunnel, "", nil
}

// ensureOpen returns a live tunnel for the slot, opening one if needed. Only one
// caller opens a given slot; the others wait for it.
func (p *Pool) ensureOpen(ctx context.Context, state *slotState) (*wgtunnel.Tunnel, error) {
	for {
		p.mu.Lock()
		if state.tunnel != nil {
			tunnel := state.tunnel
			p.mu.Unlock()
			return tunnel, nil
		}
		if waiting := state.opening; waiting != nil {
			p.mu.Unlock()
			select {
			case <-waiting:
				continue // re-check: the opener either succeeded or failed
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
		state.opening = done
		spec := state.spec.WG
		p.mu.Unlock()

		if err := ctx.Err(); err != nil {
			p.rollbackTunnelOpen()
			p.mu.Lock()
			state.opening = nil
			p.mu.Unlock()
			close(done)
			return nil, err
		}
		p.commitTunnelOpen()
		tunnel, err := p.openTunnelForCapacity(ctx, spec, TunnelRoleDirect)

		p.mu.Lock()
		state.opening = nil
		if err == nil {
			state.tunnel = tunnel
			state.openedAt = time.Now()
		}
		p.mu.Unlock()
		close(done)

		if err != nil {
			return nil, err
		}
		return tunnel, nil
	}
}

// tunnelBudgetAvailableLocked reports whether another tunnel may be opened now.
func (p *Pool) tunnelBudgetAvailableLocked(now time.Time) bool {
	if p.opts.NewTunnelBudget <= 0 {
		return true
	}
	p.pruneOpensLocked(now)
	return len(p.opens)+p.pendingTunnelOpens < p.opts.NewTunnelBudget
}

func (p *Pool) reserveTunnelOpenLocked(now time.Time) error {
	if !p.tunnelBudgetAvailableLocked(now) {
		return ErrTunnelBudget
	}
	p.pendingTunnelOpens++
	return nil
}

// commitTunnelOpen charges the provider-contact budget before dialing because
// failed handshakes consume the same association quota as successful ones.
func (p *Pool) commitTunnelOpen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pendingTunnelOpens > 0 {
		p.pendingTunnelOpens--
	}
	now := time.Now()
	p.pruneOpensLocked(now)
	p.opens = append(p.opens, now)
}

func (p *Pool) rollbackTunnelOpen() {
	p.mu.Lock()
	if p.pendingTunnelOpens > 0 {
		p.pendingTunnelOpens--
	}
	p.mu.Unlock()
}

func (p *Pool) pruneOpensLocked(now time.Time) {
	cutoff := now.Add(-p.opts.NewTunnelWindow)
	keep := 0
	for _, at := range p.opens {
		if at.After(cutoff) {
			break
		}
		keep++
	}
	if keep > 0 {
		p.opens = append(p.opens[:0], p.opens[keep:]...)
	}
}

// noteTunnelOpen records one relay contact against the rate budget.
func (p *Pool) noteTunnelOpen(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneOpensLocked(now)
	p.opens = append(p.opens, now)
}

func (p *Pool) openTunnel(
	ctx context.Context,
	spec catalog.Slot,
	role TunnelRole,
) (*wgtunnel.Tunnel, error) {
	openCtx, cancel := context.WithTimeout(ctx, p.opts.HandshakeTimeout)
	defer cancel()

	started := time.Now()
	tunnel, err := wgtunnel.Open(openCtx, spec, p.log)
	if err != nil {
		p.observeTunnelOpen(role, TunnelFailure, time.Since(started))
		return nil, err
	}
	if err := tunnel.WaitHandshake(openCtx); err != nil {
		_ = tunnel.Close()
		p.observeTunnelOpen(role, TunnelFailure, time.Since(started))
		return nil, err
	}
	p.observeTunnelOpen(role, TunnelSuccess, time.Since(started))
	p.log.Info("tunnel up",
		slog.String("slot", spec.ID),
		slog.Duration("took", time.Since(started)))
	return tunnel, nil
}

func (p *Pool) noteFailure(state *slotState, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state.failures++
	state.lastError = redactedError(err)
	p.statFailures++
	// Exponential backoff, capped, so a dead server stops being retried without
	// being removed from the catalog.
	backoff := p.opts.FailureBackoff << min(state.failures-1, 5)
	if maxBackoff := 30 * time.Minute; backoff > maxBackoff {
		backoff = maxBackoff
	}
	state.disabledUntil = time.Now().Add(backoff)
	if state.tunnel != nil {
		p.closeLocked(state, "failure")
	}
	p.log.Warn("slot failed",
		slog.String("slot", state.spec.ID),
		slog.Int("failures", state.failures),
		slog.Duration("backoff", backoff),
		slog.String("error_type", redactedError(err)))
}

func (p *Pool) sessionTTL(pol policy.Policy) time.Duration {
	if pol.TTL > 0 {
		return pol.TTL
	}
	return p.opts.SessionTTL
}

func (p *Pool) batchTTL(pol policy.Policy) time.Duration {
	if pol.BatchTTL > 0 {
		return pol.BatchTTL
	}
	return p.opts.BatchTTL
}

// bindSession records the sticky mapping. Caller must hold mu.
func (p *Pool) bindSession(pol policy.Policy, slotID string) {
	if pol.Session == "" {
		return
	}
	p.sessions[pol.Session] = &session{slotID: slotID, expiresAt: time.Now().Add(p.sessionTTL(pol))}
}

func (p *Pool) reserveSessionLocked(pol policy.Policy) (string, error) {
	if pol.Session == "" {
		return "", nil
	}
	if _, exists := p.sessions[pol.Session]; exists {
		return "", nil
	}
	if pending := p.pendingSessions[pol.Session]; pending > 0 {
		p.pendingSessions[pol.Session] = pending + 1
		return pol.Session, nil
	}
	if len(p.sessions)+len(p.pendingSessions) >= p.opts.MaxSessions {
		return "", ErrSessionFull
	}
	p.pendingSessions[pol.Session] = 1
	return pol.Session, nil
}

func (p *Pool) releasePendingSessionLocked(name string) {
	if name == "" {
		return
	}
	if pending := p.pendingSessions[name]; pending > 1 {
		p.pendingSessions[name] = pending - 1
		return
	}
	delete(p.pendingSessions, name)
}

// reserveBatchLocked atomically records a unique batch's selected slot and its
// current measured public IP. pick has already expired stale batches before
// calling this, so the active-batch cap covers only live entries. Caller holds mu.
func (p *Pool) reserveBatchLocked(
	pol policy.Policy,
	state *slotState,
	now time.Time,
) (*batchReservation, error) {
	if pol.UniqueBatch == "" {
		return nil, nil
	}
	b, ok := p.batches[pol.UniqueBatch]
	if !ok || now.After(b.expiresAt) {
		if ok {
			delete(p.batches, pol.UniqueBatch)
		}
		if len(p.batches) >= p.opts.MaxUniqueBatches {
			return nil, ErrBatchFull
		}
		b = newBatch(now.Add(p.batchTTL(pol)))
		p.batches[pol.UniqueBatch] = b
	}
	b.expiresAt = now.Add(p.batchTTL(pol))
	b.reserve(state.spec.ID, state.publicIP)
	return &batchReservation{
		name:   pol.UniqueBatch,
		batch:  b,
		slotID: state.spec.ID,
	}, nil
}

func (p *Pool) reserveAcquisitionLocked(
	pol policy.Policy,
	state *slotState,
	now time.Time,
) (*acquisitionReservation, error) {
	session, err := p.reserveSessionLocked(pol)
	if err != nil {
		return nil, err
	}
	batch, err := p.reserveBatchLocked(pol, state, now)
	if err != nil {
		p.releasePendingSessionLocked(session)
		return nil, err
	}
	state.pendingLeases++
	p.pendingLeases++
	return &acquisitionReservation{
		batch:   batch,
		session: session,
		state:   state,
		active:  true,
	}, nil
}

func (p *Pool) commitAcquisitionLocked(reservation *acquisitionReservation) {
	if reservation == nil || !reservation.active {
		return
	}
	reservation.active = false
	p.releasePendingSessionLocked(reservation.session)
	if reservation.state.pendingLeases > 0 {
		reservation.state.pendingLeases--
	}
	if p.pendingLeases > 0 {
		p.pendingLeases--
	}
}

func (p *Pool) rollbackAcquisition(reservation *acquisitionReservation) {
	if reservation == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.commitAcquisitionLocked(reservation)
	p.rollbackBatchLocked(reservation.batch)
}

func (p *Pool) rollbackBatchLocked(reservation *batchReservation) {
	if reservation == nil {
		return
	}
	b, ok := p.batches[reservation.name]
	if !ok || b != reservation.batch {
		return
	}
	b.release(reservation.slotID)
	if len(b.usedSlots) == 0 {
		delete(p.batches, reservation.name)
	}
}

func (p *Pool) dropSession(name string) {
	p.mu.Lock()
	delete(p.sessions, name)
	p.mu.Unlock()
}

// RecordTraffic accounts bytes relayed for a finished connection.
//
// Counting here rather than at the network interface matters: proxied traffic
// crosses the guest's NIC twice, once from the client and once inside the tunnel,
// so interface counters read roughly double and cannot be attributed to a country,
// an exit or an entry.
//
// sent is client to internet, received is internet to client.
func (p *Pool) RecordTraffic(lease *Lease, sent, received int64) {
	if lease == nil || lease.state == nil || (sent <= 0 && received <= 0) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if sent > 0 {
		p.statSent += uint64(sent)
		lease.state.bytesSent += uint64(sent)
	}
	if received > 0 {
		p.statReceived += uint64(received)
		lease.state.bytesReceived += uint64(received)
	}
	p.recordPayloadLocked(lease, sent, received)
	if lease.Entry == "" {
		return
	}
	for _, entry := range p.entries {
		if entry.spec.ID == lease.Entry {
			if sent > 0 {
				entry.bytesSent += uint64(sent)
			}
			if received > 0 {
				entry.bytesReceived += uint64(received)
			}
			return
		}
	}
}

// NoteDialFailure records that a leased egress could not reach its destination.
//
// The failure is attributed to the entry tunnel first when the lease used one. A
// dead entry makes every exit behind it look broken, so blaming the exits would
// both hide the real fault and slowly disable a healthy catalogue.
func (p *Pool) NoteDialFailure(lease *Lease, err error) {
	if lease == nil || lease.state == nil || err == nil {
		return
	}
	if lease.Entry != "" && !errors.Is(err, socksdial.ErrDestination) {
		// A failure before the relay proxy answered belongs to the shared entry
		// path, not to one of the hundreds of exits behind it. Count every such
		// failure against the entry; noteEntryFailure applies the threshold.
		p.noteEntryFailure(lease.Entry, err)
		return
	}
	// A SOCKS refusal proves the entry path worked. Attribute it to this exit so
	// a dead or refusing relay is retried elsewhere without taking an entry down.
	p.noteFailure(lease.state, err)
}

// Rotate forgets a sticky session so the next request picks a new slot. It
// reports whether the session existed.
func (p *Pool) Rotate(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, existed := p.sessions[name]
	delete(p.sessions, name)
	if existed {
		p.statRotated++
	}
	return existed
}

// ReportInput describes a client-observed problem with an egress.
type ReportInput struct {
	// Session identifies the sticky session to rotate. Optional.
	Session string
	// Slot names the slot directly. Optional when Session is set.
	Slot string
	// PublicIP is the exit identity observed on the proxy handshake.
	PublicIP netip.Addr
	// Target is the destination host the block was observed on. When empty the
	// cooldown applies to every destination.
	Target string
	// Reason is free-form, for logs only.
	Reason string
	// Cooldown overrides the configured default.
	Cooldown time.Duration
}

// ReportResult describes what a report changed.
type ReportResult struct {
	Slot     string        `json:"slot"`
	Target   string        `json:"target,omitempty"`
	Until    time.Time     `json:"cooldown_until"`
	Cooldown time.Duration `json:"cooldown"`
	Rotated  bool          `json:"session_rotated"`
}

// Report puts a slot on cooldown for a destination and rotates the reporting
// session. Blocks are usually per-site, so the slot stays available for every
// other destination.
func (p *Pool) Report(in ReportInput) (ReportResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	slotID := in.Slot
	if slotID == "" && in.Session != "" {
		sess, ok := p.sessions[in.Session]
		if !ok {
			return ReportResult{}, fmt.Errorf("pool: unknown session %q", in.Session)
		}
		slotID = sess.slotID
	}
	state, ok := p.slots[slotID]
	if !ok {
		return ReportResult{}, fmt.Errorf("pool: unknown slot %q", slotID)
	}
	if in.PublicIP.IsValid() && state.publicIP != in.PublicIP {
		return ReportResult{}, fmt.Errorf(
			"%w: slot %q public IP does not match",
			ErrIdentityMismatch,
			slotID,
		)
	}
	cooldown := in.Cooldown
	if cooldown <= 0 {
		cooldown = p.opts.Cooldown
	}
	until := time.Now().Add(cooldown)

	if in.Target == "" {
		// A global complaint: back the slot off entirely.
		state.disabledUntil = until
	} else {
		state.cooldowns[in.Target] = until
		p.setIPCooldownLocked(in.Target, state.publicIP, until)
		if pref, ok := p.preferred[in.Target]; ok {
			pref.removeIP(state.publicIP)
			if len(pref.slots) == 0 {
				delete(p.preferred, in.Target)
			}
		}
	}
	p.releaseSlotFromBatchesLocked(slotID)

	rotated := false
	if in.Session != "" {
		if _, existed := p.sessions[in.Session]; existed {
			delete(p.sessions, in.Session)
			rotated = true
			p.statRotated++
		}
	}
	p.statReports++

	p.log.Info("egress reported",
		slog.String("slot", slotID),
		slog.Bool("target_scoped", in.Target != ""),
		slog.Bool("reason_present", in.Reason != ""),
		slog.Duration("cooldown", cooldown))

	return ReportResult{
		Slot:     slotID,
		Target:   in.Target,
		Until:    until,
		Cooldown: cooldown,
		Rotated:  rotated,
	}, nil
}

// PreferInput names a slot that actually served a destination.
type PreferInput struct {
	// Slot is the egress that answered. Required.
	Slot string
	// PublicIP is the exit identity observed on the proxy handshake.
	PublicIP netip.Addr
	// Target is the destination host that succeeded. Required.
	Target string
	// TTL overrides the configured preferred lifetime.
	TTL time.Duration
}

// PreferResult describes the recorded last-good mapping.
type PreferResult struct {
	Slot   string        `json:"slot"`
	Target string        `json:"target"`
	Until  time.Time     `json:"preferred_until"`
	TTL    time.Duration `json:"ttl"`
}

// Prefer records that a slot actually served a destination so the next
// Acquire for that host tries it first. CONNECT success is not enough —
// the client must call this after the origin answered.
func (p *Pool) Prefer(in PreferInput) (PreferResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if in.Target == "" {
		return PreferResult{}, fmt.Errorf("pool: prefer requires a target")
	}
	if _, ok := p.slots[in.Slot]; !ok {
		return PreferResult{}, fmt.Errorf("pool: unknown slot %q", in.Slot)
	}
	state := p.slots[in.Slot]
	if !state.publicIP.IsValid() {
		return PreferResult{}, fmt.Errorf("pool: slot %q has no measured public IP", in.Slot)
	}
	if in.PublicIP.IsValid() && state.publicIP != in.PublicIP {
		return PreferResult{}, fmt.Errorf(
			"%w: slot %q public IP does not match",
			ErrIdentityMismatch,
			in.Slot,
		)
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = p.opts.PreferredTTL
	}
	until := time.Now().Add(ttl)
	set := p.preferred[in.Target]
	if set == nil {
		set = &preferredSet{}
		p.preferred[in.Target] = set
	}
	set.remember(in.Slot, state.publicIP, until, p.opts.PreferredMax)
	p.log.Info("egress preferred",
		slog.String("slot", in.Slot),
		slog.Bool("target_scoped", true),
		slog.Duration("ttl", ttl),
		slog.Int("preferred_count", len(set.slots)))
	return PreferResult{Slot: in.Slot, Target: in.Target, Until: until, TTL: ttl}, nil
}

func (p *Pool) releaseSlotFromBatchesLocked(slotID string) {
	for name, b := range p.batches {
		if _, used := b.usedSlots[slotID]; !used {
			continue
		}
		b.release(slotID)
		if len(b.usedSlots) == 0 {
			delete(p.batches, name)
		}
	}
}

// SessionInfo describes a sticky session.
type SessionInfo struct {
	Session   string     `json:"session"`
	Slot      string     `json:"slot"`
	Country   string     `json:"country,omitempty"`
	City      string     `json:"city,omitempty"`
	PublicIP  string     `json:"public_ip,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	CheckedAt *time.Time `json:"ip_checked_at,omitempty"`
}

// Session returns the current binding for a sticky session name.
func (p *Pool) Session(name string) (SessionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sess, ok := p.sessions[name]
	if !ok || time.Now().After(sess.expiresAt) {
		return SessionInfo{}, false
	}
	state, ok := p.slots[sess.slotID]
	if !ok {
		return SessionInfo{}, false
	}
	info := SessionInfo{
		Session:   name,
		Slot:      state.spec.ID,
		Country:   state.spec.Country,
		City:      state.spec.City,
		ExpiresAt: sess.expiresAt,
	}
	if state.publicIP.IsValid() {
		info.PublicIP = state.publicIP.String()
	}
	if !state.ipCheckedAt.IsZero() {
		at := state.ipCheckedAt
		info.CheckedAt = &at
	}
	return info, true
}

// Warmup opens up to count distinct tunnels so early requests do not pay for a
// handshake. It returns the number of tunnels that came up.
//
// Acquire cannot be used for this: it deliberately prefers tunnels that are
// already open, so calling it in a loop would keep reusing the first one.
func (p *Pool) Warmup(ctx context.Context, count int) int {
	if count <= 0 {
		return 0
	}
	// In relay mode the expensive resource is the entry tunnels, not the slots,
	// so warming means bringing the entries up.
	if len(p.entries) > 0 {
		return p.warmupEntries(ctx)
	}
	if p.opts.MaxActive > 0 && count > p.opts.MaxActive {
		count = p.opts.MaxActive
	}

	p.mu.Lock()
	now := time.Now()
	if p.opts.NewTunnelBudget > 0 {
		p.pruneOpensLocked(now)
		if remaining := p.opts.NewTunnelBudget -
			len(p.opens) -
			p.pendingTunnelOpens; remaining < count {
			count = remaining
		}
	}
	if count <= 0 {
		p.mu.Unlock()
		return 0
	}
	var targets []*slotState
	for _, id := range p.order {
		state := p.slots[id]
		if state.isOpen() || state.opening != nil || now.Before(state.disabledUntil) {
			continue
		}
		targets = append(targets, state)
	}
	// Warm a random spread rather than the alphabetically first slots, so the
	// initial active set is not always the same handful of servers.
	p.rng.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	if len(targets) > count {
		targets = targets[:count]
	}
	p.mu.Unlock()

	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for _, state := range targets {
		wg.Add(1)
		go func(st *slotState) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			if _, err := p.ensureOpen(ctx, st); err != nil {
				p.noteFailure(st, err)
				return
			}
			mu.Lock()
			opened++
			mu.Unlock()
			p.maybeCheckIP(st)
		}(state)
	}
	wg.Wait()
	return opened
}

// warmupEntries opens every entry tunnel that the budget allows.
func (p *Pool) warmupEntries(ctx context.Context) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for _, entry := range p.entries {
		wg.Add(1)
		go func(e *entryState) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			if _, err := p.ensureEntryOpen(ctx, e); err != nil {
				return
			}
			mu.Lock()
			opened++
			mu.Unlock()
		}(entry)
	}
	wg.Wait()
	return opened
}

// Close tears down every tunnel and waits for the pool's own goroutines to
// finish. It is safe to call more than once.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	for _, state := range p.slots {
		p.closeLocked(state, "shutdown")
	}
	p.closeEntriesLocked("shutdown")
	p.mu.Unlock()

	// Cancel in-flight background work, such as public-IP measurements, before
	// waiting: otherwise a check with a long timeout would hold up shutdown.
	p.cancelAll()
	p.wg.Wait()
}

// background runs fn in a goroutine the pool owns, so Close can wait for it. It
// reports false if the pool is already closing, in which case fn does not run.
func (p *Pool) background(fn func()) bool {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return false
	}
	p.wg.Add(1)
	p.mu.Unlock()

	go func() {
		defer p.wg.Done()
		fn()
	}()
	return true
}

// expireLocked drops stale sessions, batches and cooldowns.
func (p *Pool) expireLocked(now time.Time) {
	for name, sess := range p.sessions {
		if now.After(sess.expiresAt) {
			delete(p.sessions, name)
		}
	}
	for name, b := range p.batches {
		if now.After(b.expiresAt) {
			delete(p.batches, name)
		}
	}
	for target, set := range p.preferred {
		set.prune(now)
		if len(set.slots) == 0 {
			delete(p.preferred, target)
		}
	}
	for _, state := range p.slots {
		for target, until := range state.cooldowns {
			if now.After(until) {
				delete(state.cooldowns, target)
			}
		}
	}
	for target, byIP := range p.ipCooldowns {
		for ip, until := range byIP {
			if now.After(until) {
				delete(byIP, ip)
			}
		}
		if len(byIP) == 0 {
			delete(p.ipCooldowns, target)
		}
	}
}

func containsFold(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}
