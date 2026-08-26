package pool

import (
	"errors"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/wgtunnel"
)

func TestObserveRequestRecordsResultAndDuration(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.ObserveRequest(RequestObservation{
		Result:           RequestSuccess,
		RequestedCountry: "jp",
		Lease:            lease,
		Duration:         125 * time.Millisecond,
	})

	snapshot := p.Metrics()
	if len(snapshot.Requests) != 1 {
		t.Fatalf("requests = %+v, want one series", snapshot.Requests)
	}
	request := snapshot.Requests[0]
	if request.Result != RequestSuccess || request.Country != "jp" || request.Entry != "entry-jp" || request.Count != 1 {
		t.Errorf("request = %+v, want successful jp request through entry-jp", request)
	}
	if len(snapshot.RequestDurations) != 1 {
		t.Fatalf("durations = %+v, want one series", snapshot.RequestDurations)
	}
	duration := snapshot.RequestDurations[0]
	if duration.Count != 1 || duration.Sum != 0.125 {
		t.Errorf("duration = %+v, want count=1 sum=0.125", duration)
	}
	if got := duration.Buckets[len(duration.Buckets)-1]; got.UpperBound != "+Inf" || got.Count != 1 {
		t.Errorf("last bucket = %+v, want +Inf=1", got)
	}
}

func TestObserveRequestRecordsRequestedSelectedAndFallbackCountries(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.ObserveRequest(RequestObservation{
		Result:           RequestSuccess,
		RequestedCountry: "us",
		Lease:            lease,
		Duration:         time.Second,
	})

	snapshot := p.Metrics()
	if got := snapshot.RequestedCountries; len(got) != 1 || got[0].Country != "us" || got[0].Count != 1 {
		t.Errorf("requested countries = %+v, want us=1", got)
	}
	if got := snapshot.SelectedCountries; len(got) != 1 || got[0].Country != "jp" || got[0].Count != 1 {
		t.Errorf("selected countries = %+v, want jp=1", got)
	}
	if got := snapshot.CountryFallbacks; len(got) != 1 || got[0].Requested != "us" || got[0].Selected != "jp" || got[0].Count != 1 {
		t.Errorf("fallbacks = %+v, want us->jp=1", got)
	}
}

func TestObserveTunnelOpenRecordsResultAndDuration(t *testing.T) {
	p := newTestPool(t, Options{})

	p.observeTunnelOpen(TunnelRoleEntry, TunnelSuccess, 750*time.Millisecond)
	p.observeTunnelOpen(TunnelRoleEntry, TunnelFailure, 2*time.Second)

	snapshot := p.Metrics()
	if len(snapshot.TunnelOpens) != 2 {
		t.Fatalf("tunnel opens = %+v, want success and failure", snapshot.TunnelOpens)
	}
	if snapshot.TunnelOpens[0].Role != TunnelRoleEntry || snapshot.TunnelOpens[0].Result != TunnelFailure || snapshot.TunnelOpens[0].Count != 1 {
		t.Errorf("first tunnel result = %+v, want entry failure=1", snapshot.TunnelOpens[0])
	}
	if snapshot.TunnelOpens[1].Result != TunnelSuccess || snapshot.TunnelOpens[1].Count != 1 {
		t.Errorf("second tunnel result = %+v, want success=1", snapshot.TunnelOpens[1])
	}
	if len(snapshot.TunnelDurations) != 2 {
		t.Errorf("tunnel durations = %+v, want two result series", snapshot.TunnelDurations)
	}
}

func TestObserveRequestRecordsTimeoutPhase(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.ObserveRequest(RequestObservation{
		Result:       RequestTimeout,
		TimeoutPhase: TimeoutPhaseAcquire,
		Duration:     2 * time.Second,
	})
	p.ObserveRequest(RequestObservation{
		Result:       RequestTimeout,
		TimeoutPhase: TimeoutPhaseUpstream,
		Lease:        lease,
		Duration:     3 * time.Second,
	})
	// A non-timeout result must not land in the timeout series at all.
	p.ObserveRequest(RequestObservation{
		Result:   RequestSuccess,
		Lease:    lease,
		Duration: time.Second,
	})

	timeouts := p.Metrics().RequestTimeouts
	if len(timeouts) != 2 {
		t.Fatalf("timeouts = %+v, want acquire and upstream series", timeouts)
	}
	if got := timeouts[0]; got.Phase != TimeoutPhaseAcquire ||
		got.Country != "unknown" || got.Entry != "none" || got.Count != 1 {
		t.Errorf("acquire timeout = %+v, want phase=acquire country=unknown entry=none count=1", got)
	}
	if got := timeouts[1]; got.Phase != TimeoutPhaseUpstream ||
		got.Country != "jp" || got.Entry != "entry-jp" || got.Count != 1 {
		t.Errorf("upstream timeout = %+v, want phase=upstream country=jp entry=entry-jp count=1", got)
	}
}

func TestObserveRequestDefaultsTimeoutPhaseToUnknown(t *testing.T) {
	p := newTestPool(t, Options{})

	// A caller that reports a timeout without naming the phase still has to land
	// on a bounded label rather than an empty one.
	p.ObserveRequest(RequestObservation{Result: RequestTimeout, Duration: time.Second})

	timeouts := p.Metrics().RequestTimeouts
	if len(timeouts) != 1 || timeouts[0].Phase != TimeoutPhaseUnknown {
		t.Fatalf("timeouts = %+v, want a single unknown-phase series", timeouts)
	}
}

func TestObserveRequestClampsOutOfSetTimeoutPhaseToUnknown(t *testing.T) {
	p := newTestPool(t, Options{})

	// TimeoutPhase is a string alias, so a caller can pass any value. The scrape
	// still has to emit only the closed set; a free-form label would grow with
	// whoever typed it.
	p.ObserveRequest(RequestObservation{
		Result:       RequestTimeout,
		TimeoutPhase: TimeoutPhase("request-user-value"),
		Duration:     time.Second,
	})

	timeouts := p.Metrics().RequestTimeouts
	if len(timeouts) != 1 {
		t.Fatalf("timeouts = %+v, want a single unknown-phase series", timeouts)
	}
	if timeouts[0].Phase != TimeoutPhaseUnknown {
		t.Fatalf("timeout phase = %q, want %q", timeouts[0].Phase, TimeoutPhaseUnknown)
	}
}

func TestEntryStatesReportBoundedHealthCounts(t *testing.T) {
	p := newRelayPool(t, Options{})

	// Every entry starts idle: the pool has them, none is up, none is benched.
	if got := entryStateCounts(p.Metrics().EntryStates); got[EntryHealthIdle] != 2 ||
		got[EntryHealthOpen] != 0 || got[EntryHealthDisabled] != 0 {
		t.Fatalf("initial entry states = %+v, want two idle", got)
	}

	p.mu.Lock()
	p.entries[0].tunnel = &wgtunnel.Tunnel{}
	p.entries[1].disabledUntil = time.Now().Add(time.Minute)
	p.mu.Unlock()

	states := p.Metrics().EntryStates
	if len(states) != 3 {
		t.Fatalf("entry states = %+v, want open/idle/disabled series", states)
	}
	counts := entryStateCounts(states)
	if counts[EntryHealthOpen] != 1 {
		t.Errorf("open entries = %d, want 1", counts[EntryHealthOpen])
	}
	if counts[EntryHealthDisabled] != 1 {
		t.Errorf("disabled entries = %d, want 1", counts[EntryHealthDisabled])
	}
	if counts[EntryHealthIdle] != 0 {
		t.Errorf("idle entries = %d, want 0", counts[EntryHealthIdle])
	}

	// The tunnel is detached before Close so the fake never gets shut down.
	p.mu.Lock()
	p.entries[0].tunnel = nil
	p.mu.Unlock()
}

func entryStateCounts(states []EntryStateMetric) map[EntryHealth]uint64 {
	counts := make(map[EntryHealth]uint64, len(states))
	for _, state := range states {
		counts[state.State] = state.Count
	}
	return counts
}

func TestEntryFailuresCountByBoundedReason(t *testing.T) {
	p := newRelayPool(t, Options{})
	p.mu.Lock()
	entryID := p.entries[0].spec.ID
	p.mu.Unlock()

	p.noteEntryFailure(entryID, errors.New("dial refused"))
	p.mu.Lock()
	p.observeEntryOpenFailureLocked()
	p.observeEntryOpenFailureLocked()
	p.mu.Unlock()

	failures := p.Metrics().EntryFailures
	if len(failures) != 2 {
		t.Fatalf("entry failures = %+v, want dial and open series", failures)
	}
	counts := make(map[EntryFailureReason]uint64, len(failures))
	for _, failure := range failures {
		counts[failure.Reason] = failure.Count
	}
	if counts[EntryFailureDial] != 1 {
		t.Errorf("dial failures = %d, want 1", counts[EntryFailureDial])
	}
	if counts[EntryFailureOpen] != 2 {
		t.Errorf("open failures = %d, want 2", counts[EntryFailureOpen])
	}
}

func TestRecordTrafficGroupsPayloadBytesByCountryAndEntry(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.RecordTraffic(lease, 128, 256)

	payloads := p.Metrics().Payloads
	if len(payloads) != 1 {
		t.Fatalf("payloads = %+v, want one series", payloads)
	}
	if got := payloads[0]; got.Country != "jp" || got.Entry != "entry-jp" || got.Sent != 128 || got.Received != 256 {
		t.Errorf("payload = %+v, want jp/entry-jp sent=128 received=256", got)
	}
}
