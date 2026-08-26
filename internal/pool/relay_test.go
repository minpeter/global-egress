package pool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/socksdial"
)

func testExits() []ExitSpec {
	return []ExitSpec{
		{
			ID: "jp-tyo-wg-socks5-001", Country: "jp", City: "jp-tyo",
			SocksAddr: "jp-tyo-wg-socks5-001.relays.example:1080",
		},
		{
			ID: "de-fra-wg-socks5-001", Country: "de", City: "de-fra",
			SocksAddr: "de-fra-wg-socks5-001.relays.example:1080",
		},
		{
			ID: "us-lax-wg-socks5-001", Country: "us", City: "us-lax",
			SocksAddr: "us-lax-wg-socks5-001.relays.example:1080",
		},
	}
}

func testEntrySlots() []catalog.Slot {
	entries := []struct{ id, country, city string }{
		{"jp-tyo-wg-001", "jp", "jp-tyo"},
		{"us-lax-wg-001", "us", "us-lax"},
	}
	out := make([]catalog.Slot, 0, len(entries))
	for i, e := range entries {
		out = append(out, catalog.Slot{
			ID:            e.id,
			Country:       e.country,
			City:          e.city,
			PrivateKey:    "R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=",
			PeerPublicKey: "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=",
			Addresses:     []netip.Addr{netip.MustParseAddr("10.73.84.67")},
			Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("198.51.100.9"), uint16(51820+i)).String(),
			MTU:           catalog.DefaultMTU,
		})
	}
	return out
}

func newRelayPool(t *testing.T, opts Options) *Pool {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Rand == nil {
		opts.Rand = rand.New(rand.NewPCG(2, 2))
	}
	// Pin selection to the best entry so ordering assertions are deterministic.
	opts.DisableEntryExploration = true
	p, err := NewWithSpecs(SpecsFromExits(testExits()), testEntrySlots(), opts)
	if err != nil {
		t.Fatalf("NewWithSpecs: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestSpecsFromExits(t *testing.T) {
	specs := SpecsFromExits(testExits())
	if len(specs) != 3 {
		t.Fatalf("len(specs) = %d, want 3", len(specs))
	}
	for _, spec := range specs {
		if spec.Kind != KindRelaySocks {
			t.Errorf("%s has kind %v, want relay-socks", spec.ID, spec.Kind)
		}
		if spec.SocksAddr == "" || spec.Target() != spec.SocksAddr {
			t.Errorf("%s has no proxy address", spec.ID)
		}
	}
	// IDs come from the provider's proxy name, not the WireGuard hostname, so a
	// proxy slot can never collide with a WireGuard slot for the same relay.
	if specs[0].ID != "jp-tyo-wg-socks5-001" {
		t.Errorf("specs[0].ID = %q", specs[0].ID)
	}
	if specs[0].City != "jp-tyo" {
		t.Errorf("specs[0].City = %q, want jp-tyo", specs[0].City)
	}
}

func TestRelaySlotsRequireAnEntry(t *testing.T) {
	_, err := NewWithSpecs(SpecsFromExits(testExits()), nil, Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("relay-socks slots without an entry tunnel should be rejected")
	}
}

func TestWireGuardSlotsNeedNoEntry(t *testing.T) {
	bundle := testBundle(t)
	if _, err := NewWithSpecs(SpecsFromBundle(bundle), nil, Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}); err != nil {
		t.Fatalf("WireGuard-only pool should not need entries: %v", err)
	}
}

func TestNewWithSpecsRejectsDuplicates(t *testing.T) {
	specs := SpecsFromExits(testExits())
	specs = append(specs, specs[0])
	if _, err := NewWithSpecs(specs, testEntrySlots(), Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}); err == nil {
		t.Fatal("duplicate slot IDs should be rejected")
	}
}

func TestReconcileRelaySlotsReplacesActiveSet(t *testing.T) {
	p := newRelayPool(t, Options{})
	const retainedID = "jp-tyo-wg-socks5-001"
	const removedID = "de-fra-wg-socks5-001"
	const addedID = "gb-lon-wg-socks5-001"
	retainedIP := netip.MustParseAddr("192.0.2.10")
	cooldownUntil := time.Now().Add(time.Hour)

	p.mu.Lock()
	retained := p.slots[retainedID]
	retained.publicIP = retainedIP
	retained.cooldowns["api.example"] = cooldownUntil
	p.sessions["removed-session"] = &session{
		slotID:    removedID,
		expiresAt: time.Now().Add(time.Hour),
	}
	p.mu.Unlock()

	next := SpecsFromExits([]ExitSpec{
		{
			ID: retainedID, Country: "jp", City: "jp-tyo",
			SocksAddr: "jp-tyo-wg-socks5-001.changed.example:1080",
		},
		{
			ID: addedID, Country: "gb", City: "gb-lon",
			SocksAddr: "gb-lon-wg-socks5-001.relays.example:1080",
		},
	})
	result, err := p.ReconcileRelaySlots(next)
	if err != nil {
		t.Fatalf("ReconcileRelaySlots: %v", err)
	}
	if result.Added != 1 || result.Removed != 2 || result.Retained != 1 {
		t.Fatalf("result = %+v, want added=1 removed=2 retained=1", result)
	}

	slots := p.Slots(SlotFilter{})
	if len(slots) != 2 {
		t.Fatalf("len(slots) = %d, want 2", len(slots))
	}
	if slots[0].ID != addedID || slots[1].ID != retainedID {
		t.Fatalf("slot IDs = [%s %s], want [%s %s]", slots[0].ID, slots[1].ID, addedID, retainedID)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.slots[retainedID] != retained {
		t.Fatal("retained slot state was replaced")
	}
	if got := retained.spec.SocksAddr; got != next[0].SocksAddr {
		t.Errorf("retained SocksAddr = %q, want %q", got, next[0].SocksAddr)
	}
	if retained.publicIP != retainedIP {
		t.Errorf("retained public IP = %s, want %s", retained.publicIP, retainedIP)
	}
	if got := retained.cooldowns["api.example"]; !got.Equal(cooldownUntil) {
		t.Errorf("retained cooldown = %s, want %s", got, cooldownUntil)
	}
	if _, ok := p.sessions["removed-session"]; ok {
		t.Error("session pinned to a removed slot was not cleared")
	}
}

func TestReconcileRelaySlotsDrainsActiveLease(t *testing.T) {
	p := newRelayPool(t, Options{})
	const removedID = "jp-tyo-wg-socks5-001"

	p.mu.Lock()
	removed := p.slots[removedID]
	removed.leases = 1
	p.leased = 1
	lease := &Lease{
		pool:  p,
		state: removed,
		Slot:  removed.spec,
	}
	p.mu.Unlock()

	next := SpecsFromExits([]ExitSpec{{
		ID:        "gb-lon-wg-socks5-001",
		Country:   "gb",
		City:      "gb-lon",
		SocksAddr: "gb-lon-wg-socks5-001.relays.example:1080",
	}})
	if _, err := p.ReconcileRelaySlots(next); err != nil {
		t.Fatalf("ReconcileRelaySlots: %v", err)
	}

	p.mu.Lock()
	_, stillSelectable := p.slots[removedID]
	leasedBeforeRelease := p.leased
	p.mu.Unlock()
	if stillSelectable {
		t.Fatal("removed slot remains selectable while its old lease drains")
	}
	if leasedBeforeRelease != 1 {
		t.Fatalf("pool leased count = %d, want 1 before release", leasedBeforeRelease)
	}

	release := make(chan struct{})
	released := make(chan struct{})
	go func() {
		<-release
		lease.Release()
		close(released)
	}()
	close(release)
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("active lease did not release after its slot was removed")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if removed.leases != 0 {
		t.Errorf("removed slot leases = %d, want 0", removed.leases)
	}
	if p.leased != 0 {
		t.Errorf("pool leased count = %d, want 0", p.leased)
	}
}

func TestSlotsReportKindAndTarget(t *testing.T) {
	p := newRelayPool(t, Options{})
	slots := p.Slots(SlotFilter{Country: "jp"})
	if len(slots) != 1 {
		t.Fatalf("got %d jp slots, want 1", len(slots))
	}
	if slots[0].Kind != "relay-socks" {
		t.Errorf("Kind = %q", slots[0].Kind)
	}
	if slots[0].Target == "" {
		t.Error("Target should carry the proxy address")
	}
}

func TestEntryOrderingUsesGeographicPrior(t *testing.T) {
	p := newRelayPool(t, Options{})
	now := time.Now()

	p.mu.Lock()
	forJP := p.orderedEntriesLocked("jp", now)
	forUS := p.orderedEntriesLocked("us", now)
	p.mu.Unlock()

	if forJP[0].spec.ID != "jp-tyo-wg-001" {
		t.Errorf("a Japanese exit should prefer the Japanese entry, got %s", forJP[0].spec.ID)
	}
	if forUS[0].spec.ID != "us-lax-wg-001" {
		t.Errorf("an American exit should prefer the American entry, got %s", forUS[0].spec.ID)
	}
}

func TestMeasuredLatencyBeatsPrior(t *testing.T) {
	p := newRelayPool(t, Options{})

	var jp, us *entryState
	p.mu.Lock()
	for _, entry := range p.entries {
		switch entry.spec.ID {
		case "jp-tyo-wg-001":
			jp = entry
		case "us-lax-wg-001":
			us = entry
		}
	}
	p.mu.Unlock()

	// The prior favours the Japanese entry for a Japanese exit. Real traffic that
	// says otherwise must win: this is what makes routing self-correcting.
	p.recordEntryLatency(jp, "jp", 900*time.Millisecond)
	p.recordEntryLatency(us, "jp", 120*time.Millisecond)

	p.mu.Lock()
	ordered := p.orderedEntriesLocked("jp", time.Now())
	p.mu.Unlock()

	if ordered[0].spec.ID != "us-lax-wg-001" {
		t.Errorf("measured latency ignored: first entry is %s", ordered[0].spec.ID)
	}
}

func TestRecordEntryLatencySmoothsSamples(t *testing.T) {
	p := newRelayPool(t, Options{})
	p.mu.Lock()
	entry := p.entries[0]
	p.mu.Unlock()

	p.recordEntryLatency(entry, "jp", 100*time.Millisecond)
	p.recordEntryLatency(entry, "jp", 1000*time.Millisecond)

	p.mu.Lock()
	got := entry.latency["jp"]
	samples := entry.samples["jp"]
	p.mu.Unlock()

	// One slow sample must move the average without dominating it.
	if got <= 100*time.Millisecond || got >= 1000*time.Millisecond {
		t.Errorf("smoothed latency = %s, want it between the two samples", got)
	}
	if samples != 2 {
		t.Errorf("samples = %d, want 2", samples)
	}

	// Ignore nonsense rather than poisoning the average.
	p.recordEntryLatency(entry, "", time.Second)
	p.recordEntryLatency(entry, "jp", 0)
	p.mu.Lock()
	unchanged := entry.latency["jp"] == got && entry.samples["jp"] == 2
	p.mu.Unlock()
	if !unchanged {
		t.Error("invalid samples should be ignored")
	}
}

func TestDisabledEntriesAreSkipped(t *testing.T) {
	p := newRelayPool(t, Options{})
	p.mu.Lock()
	p.entries[0].disabledUntil = time.Now().Add(time.Minute)
	remaining := len(p.orderedEntriesLocked("jp", time.Now()))
	p.mu.Unlock()
	if remaining != 1 {
		t.Errorf("ordered entries = %d, want 1 after disabling one", remaining)
	}
}

func TestEntriesSnapshot(t *testing.T) {
	p := newRelayPool(t, Options{})
	p.recordEntryLatency(entryByID(t, p, "jp-tyo-wg-001"), "jp", 200*time.Millisecond)

	infos := p.Entries()
	if len(infos) != 2 {
		t.Fatalf("Entries() = %d, want 2", len(infos))
	}
	if infos[0].ID != "jp-tyo-wg-001" {
		t.Errorf("entries are not sorted: %q first", infos[0].ID)
	}
	if infos[0].Region != "east-asia" {
		t.Errorf("Region = %q", infos[0].Region)
	}
	if infos[0].Latency["jp"] != 200 {
		t.Errorf("Latency = %v, want jp=200ms", infos[0].Latency)
	}
	if infos[0].Samples["jp"] != 1 {
		t.Errorf("Samples = %v, want jp=1", infos[0].Samples)
	}
	if infos[0].Open {
		t.Error("no entry should be reported open in this test")
	}
}

func entryByID(t *testing.T, p *Pool, id string) *entryState {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.entries {
		if entry.spec.ID == id {
			return entry
		}
	}
	t.Fatalf("entry %q not found", id)
	return nil
}

func TestAcquireRelaySlotFailsWithoutReachableEntry(t *testing.T) {
	// The test entries point at unroutable endpoints, so acquiring must fail
	// rather than hang: every entry is tried and reported as exhausted.
	p := newRelayPool(t, Options{
		HandshakeTimeout: 300 * time.Millisecond,
		DialAttempts:     1,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := p.Acquire(ctx, policy.Policy{Countries: []string{"jp"}}, "example.com")
	if err == nil {
		t.Fatal("expected an error when no entry can be established")
	}
	if !errors.Is(err, ErrExhausted) {
		t.Errorf("error = %v, want it to wrap ErrExhausted", err)
	}
}

func TestStatsReportsEntries(t *testing.T) {
	p := newRelayPool(t, Options{})
	stats := p.Stats()
	if stats.Entries != 2 {
		t.Errorf("Entries = %d, want 2", stats.Entries)
	}
	if stats.EntriesOpen != 0 {
		t.Errorf("EntriesOpen = %d, want 0", stats.EntriesOpen)
	}
	if stats.Slots != 3 {
		t.Errorf("Slots = %d, want 3", stats.Slots)
	}
}

func TestTunnelBudgetDoesNotGateRelaySlots(t *testing.T) {
	// Relay-socks slots exit through the shared entries, so serving one opens no
	// tunnel. Spending the new-tunnel budget must therefore not stop them being
	// selected; only opening an entry is subject to it.
	p := newRelayPool(t, Options{NewTunnelBudget: 1, NewTunnelWindow: time.Hour})
	now := time.Now()
	p.noteTunnelOpen(now)

	p.mu.Lock()
	budgetLeft := p.tunnelBudgetAvailableLocked(now)
	p.mu.Unlock()
	if budgetLeft {
		t.Fatal("test setup failed: the budget should be spent")
	}

	state, _, _, err := p.pick(policy.Policy{}, "example.com")
	if err != nil {
		t.Fatalf("pick returned %v; a relay slot needs no new tunnel", err)
	}
	if state == nil {
		t.Fatal("pick returned no slot")
		return
	}
	if state.spec.Kind != KindRelaySocks {
		t.Errorf("picked kind %v, want relay-socks", state.spec.Kind)
	}
}

func TestWireGuardSlotsStillGatedByBudget(t *testing.T) {
	// The same budget must still apply to slots that do open a tunnel.
	p := newTestPool(t, Options{NewTunnelBudget: 1, NewTunnelWindow: time.Hour})
	p.noteTunnelOpen(time.Now())

	if _, _, _, err := p.pick(policy.Policy{}, "example.com"); !errors.Is(err, ErrTunnelBudget) {
		t.Fatalf("pick error = %v, want ErrTunnelBudget", err)
	}
}

func TestPerExitConnectionLimitSpreadsLoad(t *testing.T) {
	// An exit at its connection limit must stop being a candidate, so load moves
	// to another relay instead of piling onto one.
	p := newRelayPool(t, Options{MaxConnsPerExit: 2})
	now := time.Now()

	p.mu.Lock()
	state := p.slots["jp-tyo-wg-socks5-001"]
	state.leases = 2
	atLimit := p.eligibleLocked(state, policy.Policy{}, "example.com", now)
	other := p.slots["de-fra-wg-socks5-001"]
	stillFree := p.eligibleLocked(other, policy.Policy{}, "example.com", now)
	p.mu.Unlock()

	if atLimit {
		t.Error("an exit at its per-exit limit should not be eligible")
	}
	if !stillFree {
		t.Error("an idle exit should remain eligible")
	}

	// With the country pinned to the saturated exit there is nothing left to pick.
	if _, err := p.Acquire(context.Background(), policy.Policy{Countries: []string{"jp"}}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Errorf("error = %v, want ErrNoCandidate once the only jp exit is saturated", err)
	}
}

func TestGlobalConnectionLimitRefusesWithErrBusy(t *testing.T) {
	p := newRelayPool(t, Options{MaxConcurrentConns: 3})

	p.mu.Lock()
	p.leased = 3
	p.mu.Unlock()

	_, err := p.Acquire(context.Background(), policy.Policy{}, "example.com")
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("error = %v, want ErrBusy", err)
	}
	if got := p.Stats().Busy; got == 0 {
		t.Error("refusals should be counted in stats")
	}

	// The limit is about load, so it clears as connections finish.
	p.mu.Lock()
	p.leased = 0
	p.mu.Unlock()
	if _, _, _, err := p.pick(policy.Policy{}, "example.com"); err != nil {
		t.Errorf("pick after the load cleared = %v, want success", err)
	}
}

func TestStatsReportConnectionLimits(t *testing.T) {
	p := newRelayPool(t, Options{MaxConnsPerExit: 4, MaxConcurrentConns: 64})
	stats := p.Stats()
	if stats.MaxConnsPerExit != 4 || stats.MaxConcurrentConns != 64 {
		t.Errorf("limits not reported: %+v", stats)
	}
}

func TestEntryFailuresTakeTheEntryOutOfRotation(t *testing.T) {
	// An entry whose tunnel is up but no longer carries traffic can only be
	// detected through the dials that ride on it. Repeated failures must blame the
	// entry, not the exits behind it.
	p := newRelayPool(t, Options{FailureBackoff: time.Minute})
	entry := entryByID(t, p, "jp-tyo-wg-001")

	failure := errors.New("i/o timeout")
	for i := 1; i < entryFailureThreshold; i++ {
		if p.noteEntryFailure(entry.spec.ID, failure) {
			t.Fatalf("entry removed after only %d failures", i)
		}
	}
	if !p.noteEntryFailure(entry.spec.ID, failure) {
		t.Fatalf("entry still in rotation after %d failures", entryFailureThreshold)
	}

	p.mu.Lock()
	disabled := time.Now().Before(entry.disabledUntil)
	remaining := len(p.orderedEntriesLocked("jp", time.Now()))
	p.mu.Unlock()

	if !disabled {
		t.Error("entry should be backed off")
	}
	if remaining != 1 {
		t.Errorf("ordered entries = %d, want 1 after disabling one of two", remaining)
	}
}

func TestSuccessfulDialClearsEntryFailures(t *testing.T) {
	p := newRelayPool(t, Options{})
	entry := entryByID(t, p, "jp-tyo-wg-001")

	p.noteEntryFailure(entry.spec.ID, errors.New("transient"))
	p.recordEntryLatency(entry, "jp", 200*time.Millisecond)

	p.mu.Lock()
	failures := entry.failures
	p.mu.Unlock()
	if failures != 0 {
		t.Errorf("failures = %d after a successful dial, want 0", failures)
	}
}

func TestDialFailureBlamesEntryNotExit(t *testing.T) {
	p := newRelayPool(t, Options{FailureBackoff: time.Minute})
	state := p.slots["jp-tyo-wg-socks5-001"]
	lease := &Lease{pool: p, state: state, Slot: state.spec, Entry: "jp-tyo-wg-001", Chained: true}

	failure := errors.New("i/o timeout")
	for range entryFailureThreshold {
		p.NoteDialFailure(lease, failure)
	}

	p.mu.Lock()
	entryFailures := entryByIDLocked(p, "jp-tyo-wg-001").failures
	slotFailures := state.failures
	p.mu.Unlock()

	if entryFailures < entryFailureThreshold {
		t.Errorf("entry failures = %d, want at least %d", entryFailures, entryFailureThreshold)
	}
	if slotFailures != 0 {
		t.Errorf("exit failures = %d, want 0 when the entry path failed", slotFailures)
	}
}

func TestDestinationRefusalDoesNotBlameEntry(t *testing.T) {
	p := newRelayPool(t, Options{FailureBackoff: time.Minute})
	state := p.slots["jp-tyo-wg-socks5-001"]
	lease := &Lease{pool: p, state: state, Slot: state.spec, Entry: "jp-tyo-wg-001", Chained: true}

	p.NoteDialFailure(lease, fmt.Errorf("wrapped: %w", socksdial.ErrDestination))

	p.mu.Lock()
	entryFailures := entryByIDLocked(p, "jp-tyo-wg-001").failures
	slotFailures := state.failures
	p.mu.Unlock()
	if entryFailures != 0 {
		t.Errorf("entry failures = %d, want 0 after destination refusal", entryFailures)
	}
	if slotFailures != 1 {
		t.Errorf("exit failures = %d, want 1 after destination refusal", slotFailures)
	}
}

func entryByIDLocked(p *Pool, id string) *entryState {
	for _, entry := range p.entries {
		if entry.spec.ID == id {
			return entry
		}
	}
	return nil
}

func TestRecordTrafficAttributesToPoolSlotAndEntry(t *testing.T) {
	// Counting at the proxy rather than the interface is the point: proxied bytes
	// cross the guest NIC twice, so interface counters cannot say which exit or
	// entry carried them.
	p := newRelayPool(t, Options{})
	state := p.slots["jp-tyo-wg-socks5-001"]
	lease := &Lease{pool: p, state: state, Slot: state.spec, Entry: "jp-tyo-wg-001", Chained: true}

	p.RecordTraffic(lease, 1000, 4000)
	p.RecordTraffic(lease, 500, 1500)

	stats := p.Stats()
	if stats.BytesSentTotal != 1500 || stats.BytesReceivedTotal != 5500 {
		t.Errorf("pool totals = %d/%d, want 1500/5500", stats.BytesSentTotal, stats.BytesReceivedTotal)
	}

	var slot SlotInfo
	for _, info := range p.Slots(SlotFilter{Country: "jp"}) {
		if info.ID == "jp-tyo-wg-socks5-001" {
			slot = info
		}
	}
	if slot.BytesSent != 1500 || slot.BytesReceived != 5500 {
		t.Errorf("slot totals = %d/%d", slot.BytesSent, slot.BytesReceived)
	}

	for _, entry := range p.Entries() {
		want := uint64(0)
		if entry.ID == "jp-tyo-wg-001" {
			want = 1500
		}
		if entry.BytesSent != want {
			t.Errorf("entry %s sent = %d, want %d", entry.ID, entry.BytesSent, want)
		}
	}
}

func TestRecordTrafficIgnoresNothingToCount(t *testing.T) {
	p := newRelayPool(t, Options{})
	state := p.slots["jp-tyo-wg-socks5-001"]
	lease := &Lease{pool: p, state: state, Slot: state.spec}

	p.RecordTraffic(nil, 10, 10)
	p.RecordTraffic(lease, 0, 0)
	p.RecordTraffic(lease, -5, -5)

	if stats := p.Stats(); stats.BytesSentTotal != 0 || stats.BytesReceivedTotal != 0 {
		t.Errorf("totals moved on no-op calls: %d/%d", stats.BytesSentTotal, stats.BytesReceivedTotal)
	}
}
