package pool

import (
	"strings"
	"time"
)

// RequestResult is a bounded proxy request outcome label.
type RequestResult string

const (
	RequestSuccess         RequestResult = "success"
	RequestBusy            RequestResult = "busy"
	RequestNoCandidate     RequestResult = "no_candidate"
	RequestDialFailure     RequestResult = "dial_failure"
	RequestUpstreamFailure RequestResult = "upstream_failure"
	RequestTimeout         RequestResult = "timeout"
)

// TimeoutPhase names the stage a timed-out request died in.
//
// A timeout during setup and a timeout mid-stream are different faults with
// different fixes — the first is pool capacity or handshake latency, the second
// is the exit or the destination — but both arrive as context.DeadlineExceeded
// and collapse into one result label. The enum is closed on purpose: the point is
// a phase breakdown you can alert on, not a free-form annotation.
type TimeoutPhase string

const (
	// TimeoutPhaseUnknown covers a timeout whose caller did not name a phase, so
	// the series stays bounded instead of carrying an empty label.
	TimeoutPhaseUnknown TimeoutPhase = "unknown"
	// TimeoutPhaseAcquire is a timeout before the upstream was ready: slot
	// selection, tunnel handshake, or the dial to the destination.
	TimeoutPhaseAcquire TimeoutPhase = "acquire"
	// TimeoutPhaseUpstream is a timeout after the upstream was established, while
	// the request was being served through it.
	TimeoutPhaseUpstream TimeoutPhase = "upstream"
)

// EntryHealth is a bounded rotation state for one entry tunnel.
//
// Entries are the scarce resource — each one costs a key association — so what
// matters operationally is how many are up, how many are spare and how many the
// pool has benched. Entry identity is deliberately absent: the count is bounded by
// the three states, whereas a per-entry label grows with the provider's fleet.
type EntryHealth string

const (
	// EntryHealthOpen is an entry with a live tunnel, available for routing.
	EntryHealthOpen EntryHealth = "open"
	// EntryHealthIdle is an entry eligible for routing whose tunnel is not up yet.
	EntryHealthIdle EntryHealth = "idle"
	// EntryHealthDisabled is an entry backed off after repeated failures.
	EntryHealthDisabled EntryHealth = "disabled"
)

// EntryFailureReason is a bounded cause for taking an entry off the happy path.
type EntryFailureReason string

const (
	// EntryFailureOpen is a failure to bring the entry tunnel up at all.
	EntryFailureOpen EntryFailureReason = "open"
	// EntryFailureDial is a failure dialling through an entry whose tunnel is up,
	// which is the fault that would otherwise be blamed on the exits.
	EntryFailureDial EntryFailureReason = "dial"
)

// TunnelRole identifies a bounded class of WireGuard tunnel.
type TunnelRole string

const (
	TunnelRoleEntry  TunnelRole = "entry"
	TunnelRoleDirect TunnelRole = "direct"
)

// TunnelResult is a bounded tunnel-open outcome label.
type TunnelResult string

const (
	TunnelSuccess TunnelResult = "success"
	TunnelFailure TunnelResult = "failure"
)

var (
	requestDurationBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	tunnelDurationBuckets  = []float64{0.1, 0.25, 0.5, 1, 2, 3, 5, 8, 12, 20, 30}
)

type requestMetricKey struct {
	result  RequestResult
	country string
	entry   string
}

type timeoutMetricKey struct {
	phase   TimeoutPhase
	country string
	entry   string
}

type fallbackMetricKey struct {
	requested string
	selected  string
}

type payloadMetricKey struct {
	country string
	entry   string
}

type tunnelMetricKey struct {
	role   TunnelRole
	result TunnelResult
}

type histogramMetric struct {
	buckets []uint64
	sum     float64
	count   uint64
}

func (h *histogramMetric) observe(bounds []float64, value float64) {
	if h.buckets == nil {
		h.buckets = make([]uint64, len(bounds)+1)
	}
	for i, bound := range bounds {
		if value <= bound {
			h.buckets[i]++
		}
	}
	h.buckets[len(bounds)]++
	h.sum += value
	h.count++
}

type payloadTotals struct {
	sent     uint64
	received uint64
}

type metricsState struct {
	requests           map[requestMetricKey]uint64
	requestDurations   map[requestMetricKey]*histogramMetric
	requestTimeouts    map[timeoutMetricKey]uint64
	requestedCountries map[string]uint64
	selectedCountries  map[string]uint64
	fallbacks          map[fallbackMetricKey]uint64
	payloads           map[payloadMetricKey]payloadTotals
	tunnelOpens        map[tunnelMetricKey]uint64
	tunnelDurations    map[tunnelMetricKey]*histogramMetric
	entryFailures      map[EntryFailureReason]uint64
}

func (m *metricsState) ensure() {
	if m.requests != nil {
		return
	}
	m.requests = make(map[requestMetricKey]uint64)
	m.requestDurations = make(map[requestMetricKey]*histogramMetric)
	m.requestTimeouts = make(map[timeoutMetricKey]uint64)
	m.requestedCountries = make(map[string]uint64)
	m.selectedCountries = make(map[string]uint64)
	m.fallbacks = make(map[fallbackMetricKey]uint64)
	m.payloads = make(map[payloadMetricKey]payloadTotals)
	m.tunnelOpens = make(map[tunnelMetricKey]uint64)
	m.tunnelDurations = make(map[tunnelMetricKey]*histogramMetric)
	m.entryFailures = make(map[EntryFailureReason]uint64)
}

// RequestObservation describes one completed proxy setup attempt.
type RequestObservation struct {
	Result           RequestResult
	RequestedCountry string
	Lease            *Lease
	Duration         time.Duration
	// TimeoutPhase names where a RequestTimeout was hit. It is ignored for every
	// other result, so callers on the success path need not set it.
	TimeoutPhase TimeoutPhase
}

// ObserveRequest records one bounded request outcome and setup duration.
func (p *Pool) ObserveRequest(observation RequestObservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.ensure()

	requested := normalizeMetricLabel(observation.RequestedCountry, "any")
	country, entry := leaseMetricLabels(observation.Lease)
	key := requestMetricKey{result: observation.Result, country: country, entry: entry}
	p.metrics.requests[key]++
	histogram := p.metrics.requestDurations[key]
	if histogram == nil {
		histogram = &histogramMetric{}
		p.metrics.requestDurations[key] = histogram
	}
	histogram.observe(requestDurationBuckets, observation.Duration.Seconds())
	if observation.Result == RequestTimeout {
		phase := observation.TimeoutPhase
		if phase == "" {
			phase = TimeoutPhaseUnknown
		}
		p.metrics.requestTimeouts[timeoutMetricKey{phase: phase, country: country, entry: entry}]++
	}
	p.metrics.requestedCountries[requested]++
	if observation.Lease != nil {
		p.metrics.selectedCountries[country]++
		if isCountryCode(requested) && requested != country {
			p.metrics.fallbacks[fallbackMetricKey{requested: requested, selected: country}]++
		}
	}
}

func (p *Pool) observeTunnelOpen(role TunnelRole, result TunnelResult, duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.ensure()
	key := tunnelMetricKey{role: role, result: result}
	p.metrics.tunnelOpens[key]++
	histogram := p.metrics.tunnelDurations[key]
	if histogram == nil {
		histogram = &histogramMetric{}
		p.metrics.tunnelDurations[key] = histogram
	}
	histogram.observe(tunnelDurationBuckets, duration.Seconds())
}

// observeEntryOpenFailureLocked records that an entry tunnel could not be brought
// up. The caller already holds p.mu because it is applying that entry's backoff.
func (p *Pool) observeEntryOpenFailureLocked() {
	p.metrics.ensure()
	p.metrics.entryFailures[EntryFailureOpen]++
}

// observeEntryDialFailureLocked records a failed dial through a live entry. The
// caller already holds p.mu because it is updating that entry's own state.
func (p *Pool) observeEntryDialFailureLocked() {
	p.metrics.ensure()
	p.metrics.entryFailures[EntryFailureDial]++
}

func (p *Pool) recordPayloadLocked(lease *Lease, sent, received int64) {
	p.metrics.ensure()
	country, entry := leaseMetricLabels(lease)
	key := payloadMetricKey{country: country, entry: entry}
	totals := p.metrics.payloads[key]
	if sent > 0 {
		totals.sent += uint64(sent)
	}
	if received > 0 {
		totals.received += uint64(received)
	}
	p.metrics.payloads[key] = totals
}

func leaseMetricLabels(lease *Lease) (string, string) {
	if lease == nil {
		return "unknown", "none"
	}
	country := normalizeMetricLabel(lease.Slot.Country, "unknown")
	entry := normalizeMetricLabel(lease.Entry, "direct")
	return country, entry
}

func normalizeMetricLabel(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func isCountryCode(value string) bool {
	if len(value) != 2 {
		return false
	}
	for _, r := range value {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}
