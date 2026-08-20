package pool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/policy"
)

// testBundle builds a bundle without touching the network. The keys are
// syntactically valid but never used, because these tests exercise selection
// bookkeeping only: anything that would dial is arranged to fail earlier.
func testBundle(t *testing.T) *catalog.Bundle {
	t.Helper()
	specs := []struct{ id, country, city string }{
		{"jp-tyo-wg-001", "jp", "jp-tyo"},
		{"jp-osa-wg-001", "jp", "jp-osa"},
		{"us-lax-wg-001", "us", "us-lax"},
		{"us-lax-wg-002", "us", "us-lax"},
		{"de-fra-wg-001", "de", "de-fra"},
	}
	bundle := &catalog.Bundle{DistinctKeys: 1}
	for i, spec := range specs {
		bundle.Slots = append(bundle.Slots, catalog.Slot{
			ID:            spec.id,
			Country:       spec.country,
			City:          spec.city,
			PrivateKey:    "R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=",
			PeerPublicKey: "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=",
			Addresses:     []netip.Addr{netip.MustParseAddr("10.64.0.2")},
			Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(51820+i)).String(),
			MTU:           catalog.DefaultMTU,
		})
	}
	return bundle
}

func newTestPool(t *testing.T, opts Options) *Pool {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Rand == nil {
		opts.Rand = rand.New(rand.NewPCG(1, 1))
	}
	p, err := New(testBundle(t), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func setFreshPublicIP(state *slotState, ip netip.Addr) {
	state.publicIP = ip
	state.ipCheckedAt = time.Now()
}

func TestNewRejectsEmptyBundle(t *testing.T) {
	if _, err := New(&catalog.Bundle{}, Options{}); err == nil {
		t.Fatal("expected an error for an empty bundle")
	}
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("expected an error for a nil bundle")
	}
}

func TestSlotsFiltering(t *testing.T) {
	p := newTestPool(t, Options{})

	if got := len(p.Slots(SlotFilter{})); got != 5 {
		t.Errorf("unfiltered Slots() = %d, want 5", got)
	}
	if got := len(p.Slots(SlotFilter{Country: "jp"})); got != 2 {
		t.Errorf("Slots(country=jp) = %d, want 2", got)
	}
	if got := len(p.Slots(SlotFilter{City: "us-lax"})); got != 2 {
		t.Errorf("Slots(city=us-lax) = %d, want 2", got)
	}
	if got := len(p.Slots(SlotFilter{OpenOnly: true})); got != 0 {
		t.Errorf("Slots(open) = %d, want 0 before anything is opened", got)
	}
	if got := len(p.Slots(SlotFilter{WithIP: true})); got != 0 {
		t.Errorf("Slots(with_ip) = %d, want 0 before any measurement", got)
	}
	if p.Len() != 5 {
		t.Errorf("Len() = %d, want 5", p.Len())
	}
}

func TestPolicyGeographyMatchingIsCaseInsensitive(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	state.spec.Country = "JP"
	state.spec.City = "JP-TYO"

	p.mu.Lock()
	eligible := p.eligibleLocked(state, policy.Policy{
		Countries: []string{"jp"},
		Cities:    []string{"jp-tyo"},
	}, "", time.Now())
	p.mu.Unlock()
	if !eligible {
		t.Error("lowercase policy did not match uppercase catalog metadata")
	}
}

func TestStatsCountsGeography(t *testing.T) {
	p := newTestPool(t, Options{MaxActive: 3})
	stats := p.Stats()
	if stats.Slots != 5 {
		t.Errorf("Slots = %d, want 5", stats.Slots)
	}
	if stats.Countries != 3 {
		t.Errorf("Countries = %d, want 3", stats.Countries)
	}
	if stats.Cities != 4 {
		t.Errorf("Cities = %d, want 4", stats.Cities)
	}
	if stats.MaxActive != 3 {
		t.Errorf("MaxActive = %d, want 3", stats.MaxActive)
	}
}

func TestCountryAcquisitionsCountSelectedExitCountry(t *testing.T) {
	p := newTestPool(t, Options{})

	p.mu.Lock()
	p.recordAcquisitionLocked(p.slots["jp-tyo-wg-001"])
	p.recordAcquisitionLocked(p.slots["jp-osa-wg-001"])
	p.recordAcquisitionLocked(p.slots["us-lax-wg-001"])
	p.mu.Unlock()

	got := p.CountryAcquisitions()
	if len(got) != 2 {
		t.Fatalf("CountryAcquisitions() = %+v, want two countries", got)
	}
	if got[0].Country != "jp" || got[0].Acquisitions != 2 {
		t.Errorf("first country = %+v, want jp=2", got[0])
	}
	if got[1].Country != "us" || got[1].Acquisitions != 1 {
		t.Errorf("second country = %+v, want us=1", got[1])
	}
	if p.Stats().Acquisitions != 3 {
		t.Errorf("total acquisitions = %d, want 3", p.Stats().Acquisitions)
	}
}

func TestAcquireRejectsImpossiblePolicy(t *testing.T) {
	p := newTestPool(t, Options{})
	ctx := context.Background()

	// No slot has this country, so selection fails before any dial is attempted.
	if _, err := p.Acquire(ctx, policy.Policy{Countries: []string{"zz"}}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Acquire(cc=zz) error = %v, want ErrNoCandidate", err)
	}
	if _, err := p.Acquire(ctx, policy.Policy{Slot: "nope"}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Acquire(slot=nope) error = %v, want ErrNoCandidate", err)
	}
	if _, err := p.Acquire(ctx, policy.Policy{Cities: []string{"xx-yyy"}}, ""); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Acquire(city=xx-yyy) error = %v, want ErrNoCandidate", err)
	}
}

func TestExcludedIPRemovesCandidate(t *testing.T) {
	p := newTestPool(t, Options{})
	ip := netip.MustParseAddr("203.0.113.9")

	p.mu.Lock()
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], ip)
	p.slots["jp-tyo-wg-001"].ipCheckedAt = time.Now()
	p.mu.Unlock()

	pol := policy.Policy{Slot: "jp-tyo-wg-001", ExcludeIPs: []netip.Addr{ip}}
	if _, err := p.Acquire(context.Background(), pol, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("error = %v, want ErrNoCandidate when the only slot's IP is excluded", err)
	}
}

func TestExcludedIPRequiresMeasuredCandidate(t *testing.T) {
	p := newTestPool(t, Options{})
	pol := policy.Policy{
		Slot:       "jp-tyo-wg-001",
		ExcludeIPs: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
	}

	if _, err := p.Acquire(context.Background(), pol, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("error = %v, want ErrNoCandidate while the candidate IP is unknown", err)
	}
}

func TestReportPutsSlotOnCooldownPerTarget(t *testing.T) {
	p := newTestPool(t, Options{Cooldown: time.Hour})

	result, err := p.Report(ReportInput{Slot: "us-lax-wg-001", Target: "example.com", Reason: "http_403"})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if result.Slot != "us-lax-wg-001" || result.Cooldown != time.Hour {
		t.Fatalf("unexpected result %+v", result)
	}

	// The slot is unavailable for that destination...
	pol := policy.Policy{Slot: "us-lax-wg-001"}
	if _, err := p.Acquire(context.Background(), pol, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Errorf("slot was still offered for the reported target: %v", err)
	}
	// ...but remains a candidate everywhere else, which is why cooldowns are
	// scoped per target rather than global.
	p.mu.Lock()
	stillEligible := p.eligibleLocked(p.slots["us-lax-wg-001"], pol, "other.example", time.Now())
	p.mu.Unlock()
	if !stillEligible {
		t.Error("a per-target cooldown must not disable the slot for other targets")
	}
}

func TestReportWithoutTargetDisablesSlot(t *testing.T) {
	p := newTestPool(t, Options{Cooldown: time.Minute})
	if _, err := p.Report(ReportInput{Slot: "de-fra-wg-001"}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	p.mu.Lock()
	disabled := time.Now().Before(p.slots["de-fra-wg-001"].disabledUntil)
	p.mu.Unlock()
	if !disabled {
		t.Error("a report without a target should back the slot off entirely")
	}
}

func TestPreferPinsSlotForDestination(t *testing.T) {
	p := newTestPool(t, Options{PreferredTTL: time.Hour})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["de-fra-wg-001"], netip.MustParseAddr("198.51.100.11"))

	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	state, sticky, reservation, err := p.pick(policy.Policy{}, "opencode.ai")
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	if sticky {
		t.Fatal("destination preference is not a sticky session")
	}
	if state.spec.ID != "us-lax-wg-001" {
		t.Fatalf("pick slot = %s, want the preferred us-lax-wg-001", state.spec.ID)
	}
}

func TestPreferSkipsSlotUsedInActiveUniqueBatch(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour, PreferredTTL: time.Hour})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["us-lax-wg-002"], netip.MustParseAddr("198.51.100.12"))

	p.mu.Lock()
	if _, err := p.reserveBatchLocked(policy.Policy{UniqueBatch: "b1"}, p.slots["us-lax-wg-001"], time.Now()); err != nil {
		p.mu.Unlock()
		t.Fatalf("reserveBatchLocked: %v", err)
	}
	p.mu.Unlock()

	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	state, _, reservation, err := p.pick(
		policy.Policy{Countries: []string{"us"}, UniqueBatch: "b1"},
		"opencode.ai",
	)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	if state.spec.ID != "us-lax-wg-002" {
		t.Fatalf("preferred slot used in active batch = %s, want us-lax-wg-002", state.spec.ID)
	}
}

func TestPreferSkipsIPUsedByAnotherSlotInActiveUniqueBatch(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour, PreferredTTL: time.Hour})
	sharedIP := netip.MustParseAddr("198.51.100.10")
	setFreshPublicIP(p.slots["us-lax-wg-001"], sharedIP)
	setFreshPublicIP(p.slots["us-lax-wg-002"], sharedIP)
	setFreshPublicIP(p.slots["de-fra-wg-001"], netip.MustParseAddr("198.51.100.11"))

	p.mu.Lock()
	for id, state := range p.slots {
		if id != "us-lax-wg-001" && id != "us-lax-wg-002" && id != "de-fra-wg-001" {
			state.disabledUntil = time.Now().Add(time.Hour)
		}
	}
	if _, err := p.reserveBatchLocked(policy.Policy{UniqueBatch: "b1"}, p.slots["us-lax-wg-002"], time.Now()); err != nil {
		p.mu.Unlock()
		t.Fatalf("reserveBatchLocked: %v", err)
	}
	p.mu.Unlock()

	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	state, _, reservation, err := p.pick(policy.Policy{UniqueBatch: "b1"}, "opencode.ai")
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	if state.spec.ID != "de-fra-wg-001" {
		t.Fatalf("preferred IP used in active batch selected slot %s, want de-fra-wg-001", state.spec.ID)
	}
}

func TestPreferRemainsEligibleForLaterUniqueBatch(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour, PreferredTTL: time.Hour})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["us-lax-wg-002"], netip.MustParseAddr("198.51.100.12"))

	p.mu.Lock()
	if _, err := p.reserveBatchLocked(policy.Policy{UniqueBatch: "b1"}, p.slots["us-lax-wg-001"], time.Now()); err != nil {
		p.mu.Unlock()
		t.Fatalf("reserveBatchLocked: %v", err)
	}
	p.mu.Unlock()

	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	first, _, firstReservation, err := p.pick(
		policy.Policy{Countries: []string{"us"}, UniqueBatch: "b1"},
		"opencode.ai",
	)
	if err != nil {
		t.Fatalf("first pick: %v", err)
	}
	second, _, secondReservation, err := p.pick(
		policy.Policy{Countries: []string{"us"}, UniqueBatch: "b2"},
		"opencode.ai",
	)
	if err != nil {
		t.Fatalf("later-batch pick: %v", err)
	}
	t.Cleanup(func() {
		p.rollbackAcquisition(firstReservation)
		p.rollbackAcquisition(secondReservation)
	})
	if first.spec.ID != "us-lax-wg-002" {
		t.Fatalf("first batch selected %s, want us-lax-wg-002", first.spec.ID)
	}
	if second.spec.ID != "us-lax-wg-001" {
		t.Fatalf("preferred slot became ineligible for later batch: %s", second.spec.ID)
	}
}

func TestPreferRingSpreadsLoad(t *testing.T) {
	p := newTestPool(t, Options{PreferredTTL: time.Hour, PreferredMax: 2})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["us-lax-wg-002"], netip.MustParseAddr("198.51.100.12"))
	setFreshPublicIP(p.slots["de-fra-wg-001"], netip.MustParseAddr("198.51.100.11"))

	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer first: %v", err)
	}
	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-002", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer second: %v", err)
	}

	first, _, res1, err := p.pick(policy.Policy{}, "opencode.ai")
	if err != nil {
		t.Fatalf("first pick: %v", err)
	}
	second, _, res2, err := p.pick(policy.Policy{}, "opencode.ai")
	if err != nil {
		t.Fatalf("second pick: %v", err)
	}
	t.Cleanup(func() {
		p.rollbackAcquisition(res1)
		p.rollbackAcquisition(res2)
	})
	if first.spec.ID == second.spec.ID {
		t.Fatalf("preferred ring piled both picks on %s", first.spec.ID)
	}
	seen := map[string]struct{}{first.spec.ID: {}, second.spec.ID: {}}
	if _, ok := seen["us-lax-wg-001"]; !ok {
		t.Error("ring missed us-lax-wg-001")
	}
	if _, ok := seen["us-lax-wg-002"]; !ok {
		t.Error("ring missed us-lax-wg-002")
	}
}

func TestPreferRingRotatesEqualLoadAfterRelease(t *testing.T) {
	p := newTestPool(t, Options{PreferredTTL: time.Hour, PreferredMax: 2})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["us-lax-wg-002"], netip.MustParseAddr("198.51.100.12"))

	for _, slot := range []string{"us-lax-wg-001", "us-lax-wg-002"} {
		if _, err := p.Prefer(PreferInput{Slot: slot, Target: "opencode-zen.flash-0731"}); err != nil {
			t.Fatalf("Prefer(%s): %v", slot, err)
		}
	}

	var picked []string
	for range 4 {
		state, _, reservation, err := p.pick(policy.Policy{}, "opencode-zen.flash-0731")
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		picked = append(picked, state.spec.ID)
		p.rollbackAcquisition(reservation)
	}

	want := []string{
		"us-lax-wg-001",
		"us-lax-wg-002",
		"us-lax-wg-001",
		"us-lax-wg-002",
	}
	if strings.Join(picked, ",") != strings.Join(want, ",") {
		t.Fatalf("equal-load preferred picks = %v, want round-robin %v", picked, want)
	}
}

func TestHealthScopeSelectsModelSpecificPreference(t *testing.T) {
	p := newTestPool(t, Options{PreferredTTL: time.Hour})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], netip.MustParseAddr("198.51.100.11"))

	const scope = "opencode-zen.deepseek-v4-flash-0731"
	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: scope}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	state, _, reservation, err := p.pick(
		policy.Policy{HealthScope: scope},
		"opencode.ai",
	)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	if state.spec.ID != "us-lax-wg-001" {
		t.Fatalf("health-scoped pick = %s, want preferred us-lax-wg-001", state.spec.ID)
	}
}

func TestUnknownHealthCandidatesExploreGlobally(t *testing.T) {
	p := newTestPool(t, Options{})
	ready := []*slotState{
		p.slots["jp-tyo-wg-001"],
		p.slots["us-lax-wg-001"],
	}
	rng := rand.New(rand.NewPCG(7, 11))
	seen := make(map[string]bool)
	for range 64 {
		seen[pickReady(ready, rng).spec.ID] = true
	}
	if !seen["jp-tyo-wg-001"] || !seen["us-lax-wg-001"] {
		t.Fatalf("unknown-health exploration stayed region-pinned: %v", seen)
	}
}

func TestReportRemovesOnlyOnePreferredMember(t *testing.T) {
	p := newTestPool(t, Options{PreferredTTL: time.Hour, Cooldown: time.Hour})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))
	setFreshPublicIP(p.slots["us-lax-wg-002"], netip.MustParseAddr("198.51.100.12"))

	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer first: %v", err)
	}
	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-002", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer second: %v", err)
	}
	if _, err := p.Report(ReportInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Report: %v", err)
	}

	state, _, reservation, err := p.pick(policy.Policy{}, "opencode.ai")
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	if state.spec.ID != "us-lax-wg-002" {
		t.Fatalf("remaining preferred slot = %s, want us-lax-wg-002", state.spec.ID)
	}
}

func TestReportCoolsEverySlotSharingThePublicIP(t *testing.T) {
	p := newTestPool(t, Options{Cooldown: time.Hour})
	sharedIP := netip.MustParseAddr("198.51.100.10")
	setFreshPublicIP(p.slots["us-lax-wg-001"], sharedIP)
	setFreshPublicIP(p.slots["us-lax-wg-002"], sharedIP)

	const scope = "opencode-zen.deepseek-v4-flash-0731"
	if _, err := p.Report(ReportInput{
		Slot:   "us-lax-wg-001",
		Target: scope,
		Reason: "zen_free_quota",
	}); err != nil {
		t.Fatalf("Report: %v", err)
	}

	_, _, _, err := p.pick(
		policy.Policy{
			HealthScope: scope,
			Slot:        "us-lax-wg-002",
		},
		"opencode.ai",
	)
	if !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("shared-IP pick error = %v, want ErrNoCandidate", err)
	}
}

func TestPreferDoesNotClearActiveIPCooldown(t *testing.T) {
	p := newTestPool(t, Options{Cooldown: time.Hour, PreferredTTL: time.Hour})
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("198.51.100.10"))

	const scope = "opencode-zen.deepseek-v4-flash-0731"
	if _, err := p.Report(ReportInput{
		Slot:   "us-lax-wg-001",
		Target: scope,
		Reason: "zen_free_quota",
	}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: scope}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	_, _, _, err := p.pick(
		policy.Policy{
			HealthScope: scope,
			Slot:        "us-lax-wg-001",
		},
		"opencode.ai",
	)
	if !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("cooled preferred pick error = %v, want ErrNoCandidate", err)
	}
}

func TestPreferUsesSlotAfterDestinationCooldownExpires(t *testing.T) {
	p := newTestPool(t, Options{PreferredTTL: time.Hour, Cooldown: time.Hour})
	ip := netip.MustParseAddr("198.51.100.10")
	setFreshPublicIP(p.slots["us-lax-wg-001"], ip)
	setFreshPublicIP(p.slots["de-fra-wg-001"], netip.MustParseAddr("198.51.100.11"))

	if _, err := p.Report(ReportInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	p.mu.Lock()
	p.slots["us-lax-wg-001"].cooldowns["opencode.ai"] = time.Now().Add(-time.Second)
	p.ipCooldowns["opencode.ai"][ip] = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: "opencode.ai"}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}

	state, _, reservation, err := p.pick(policy.Policy{}, "opencode.ai")
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	if state.spec.ID != "us-lax-wg-001" {
		t.Fatalf("expired cooldown preferred slot = %s, want us-lax-wg-001", state.spec.ID)
	}
}

func TestUnusedHuntExploresAllRegions(t *testing.T) {
	p := newTestPool(t, Options{})
	for i, id := range []string{"jp-tyo-wg-001", "jp-osa-wg-001", "us-lax-wg-001", "de-fra-wg-001"} {
		setFreshPublicIP(p.slots[id], netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i+20)))
	}

	seen := map[string]int{}
	for i := 0; i < 128; i++ {
		state, _, reservation, err := p.pick(policy.Policy{}, "opencode.ai")
		if err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
		seen[state.spec.Country]++
		p.rollbackAcquisition(reservation)
	}
	if seen["jp"] == 0 || seen["us"] == 0 || seen["de"] == 0 {
		t.Fatalf("unused hunt stayed region-pinned: %v", seen)
	}
}

func TestReportReleasesSlotFromUniqueBatch(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour, Cooldown: time.Hour})
	state := p.slots["us-lax-wg-001"]
	ip := netip.MustParseAddr("198.51.100.50")
	setFreshPublicIP(state, ip)
	setFreshPublicIP(p.slots["de-fra-wg-001"], netip.MustParseAddr("198.51.100.51"))

	p.mu.Lock()
	if _, err := p.reserveBatchLocked(policy.Policy{UniqueBatch: "b1"}, state, time.Now()); err != nil {
		p.mu.Unlock()
		t.Fatalf("reserveBatchLocked: %v", err)
	}
	p.mu.Unlock()

	if _, err := p.Report(ReportInput{
		Slot:   "us-lax-wg-001",
		Target: "opencode.ai",
		Reason: "zen_free_quota",
	}); err != nil {
		t.Fatalf("Report: %v", err)
	}

	p.mu.Lock()
	stillUsed := p.eligibleLocked(state, policy.Policy{UniqueBatch: "b1"}, "other.example", time.Now())
	cooled := p.eligibleLocked(state, policy.Policy{UniqueBatch: "b1"}, "opencode.ai", time.Now())
	p.mu.Unlock()
	if !stillUsed {
		t.Error("a reported slot must rejoin its unique batch after cooldown is destination-scoped")
	}
	if cooled {
		t.Error("the reported destination must still cool the slot")
	}
}

func TestReportUnknownTargets(t *testing.T) {
	p := newTestPool(t, Options{})
	if _, err := p.Report(ReportInput{Slot: "does-not-exist"}); err == nil {
		t.Error("expected an error for an unknown slot")
	}
	if _, err := p.Report(ReportInput{Session: "never-bound"}); err == nil {
		t.Error("expected an error for an unknown session")
	}
}

func TestOperationalLogsRedactNetworkDetails(t *testing.T) {
	var output bytes.Buffer
	p := newTestPool(t, Options{})
	p.log = slog.New(slog.NewTextHandler(&output, nil))

	state := p.slots["jp-tyo-wg-001"]
	p.noteFailure(state, errors.New("dial 203.0.113.9:443: refused"))
	if _, err := p.Report(ReportInput{
		Slot:   state.spec.ID,
		Target: "198.51.100.4:443",
		Reason: "exit 192.0.2.8 exhausted",
	}); err != nil {
		t.Fatalf("Report: %v", err)
	}

	for _, raw := range []string{"203.0.113.9", "198.51.100.4", "192.0.2.8"} {
		if strings.Contains(output.String(), raw) {
			t.Fatalf("operational log leaked %q: %s", raw, output.String())
		}
		if strings.Contains(state.lastError, raw) {
			t.Fatalf("last error leaked %q: %s", raw, state.lastError)
		}
	}
}

func TestRotateAndSessionLookup(t *testing.T) {
	p := newTestPool(t, Options{SessionTTL: time.Minute})

	if p.Rotate("unknown") {
		t.Error("Rotate on an unbound session should report false")
	}
	if _, ok := p.Session("unknown"); ok {
		t.Error("Session on an unbound name should report false")
	}

	// Simulate a binding the way Acquire would.
	p.mu.Lock()
	p.bindSession(policy.Policy{Session: "job-1"}, "jp-tyo-wg-001")
	p.mu.Unlock()

	info, ok := p.Session("job-1")
	if !ok {
		t.Fatal("Session(job-1) not found after binding")
	}
	if info.Slot != "jp-tyo-wg-001" || info.Country != "jp" {
		t.Errorf("unexpected session info %+v", info)
	}
	if !p.Rotate("job-1") {
		t.Error("Rotate should report true for a bound session")
	}
	if _, ok := p.Session("job-1"); ok {
		t.Error("session survived rotation")
	}
	if p.Stats().Rotations != 1 {
		t.Errorf("Rotations = %d, want 1", p.Stats().Rotations)
	}
}

func TestExpiredSessionIsNotReturned(t *testing.T) {
	p := newTestPool(t, Options{})
	p.mu.Lock()
	p.sessions["stale"] = &session{slotID: "jp-tyo-wg-001", expiresAt: time.Now().Add(-time.Second)}
	p.mu.Unlock()

	if _, ok := p.Session("stale"); ok {
		t.Error("an expired session must not be reported as bound")
	}
}

func TestSessionLimitIncludesPendingNames(t *testing.T) {
	p := newTestPool(t, Options{MaxSessions: 1})

	_, _, first, err := p.pick(policy.Policy{Session: "first"}, "example.com")
	if err != nil {
		t.Fatalf("first pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(first) })

	if _, _, _, err := p.pick(
		policy.Policy{Session: "second"},
		"example.com",
	); !errors.Is(err, ErrSessionFull) {
		t.Fatalf("second pick error = %v, want %v", err, ErrSessionFull)
	}
}

func TestSessionTTLOverMaximumIsRejected(t *testing.T) {
	p := newTestPool(t, Options{
		MaxSessions:   10,
		MaxSessionTTL: time.Hour,
	})

	if _, _, _, err := p.pick(policy.Policy{
		Session: "too-long",
		TTL:     2 * time.Hour,
	}, "example.com"); !errors.Is(err, ErrPolicy) {
		t.Fatalf("pick error = %v, want %v", err, ErrPolicy)
	}
}

func TestUniqueBatchExcludesUsedSlotsAndIPs(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour})
	ip := netip.MustParseAddr("198.51.100.50")

	p.mu.Lock()
	state := p.slots["us-lax-wg-001"]
	setFreshPublicIP(state, ip)
	// Record the slot as already served within this batch.
	if _, err := p.reserveBatchLocked(policy.Policy{UniqueBatch: "b1"}, state, time.Now()); err != nil {
		t.Fatalf("reserveBatchLocked: %v", err)
	}
	// A different slot that happens to share the same public IP.
	other := p.slots["us-lax-wg-002"]
	setFreshPublicIP(other, ip)
	setFreshPublicIP(p.slots["de-fra-wg-001"], netip.MustParseAddr("198.51.100.51"))
	now := time.Now()
	usedSlot := p.eligibleLocked(state, policy.Policy{UniqueBatch: "b1"}, "", now)
	sharedIP := p.eligibleLocked(other, policy.Policy{UniqueBatch: "b1"}, "", now)
	freeSlot := p.eligibleLocked(p.slots["de-fra-wg-001"], policy.Policy{UniqueBatch: "b1"}, "", now)
	p.mu.Unlock()

	if usedSlot {
		t.Error("a slot already used in the batch must not be reused")
	}
	if sharedIP {
		t.Error("a different slot sharing an already-used public IP must not be reused")
	}
	if !freeSlot {
		t.Error("an unused slot must remain eligible")
	}
}

func TestUniqueBatchUsesClientTTL(t *testing.T) {
	p := newTestPool(t, Options{
		BatchTTL:    time.Hour,
		MaxBatchTTL: time.Hour,
	})
	for index, id := range p.order {
		setFreshPublicIP(
			p.slots[id],
			netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", index+1)),
		)
	}

	before := time.Now().Add(30 * time.Second)
	_, _, reservation, err := p.pick(policy.Policy{
		UniqueBatch: "short",
		BatchTTL:    30 * time.Second,
	}, "example.com")
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	t.Cleanup(func() { p.rollbackAcquisition(reservation) })
	after := time.Now().Add(30 * time.Second)

	p.mu.Lock()
	expiresAt := p.batches["short"].expiresAt
	p.mu.Unlock()
	if expiresAt.Before(before) || expiresAt.After(after) {
		t.Fatalf("batch expiry = %s, want between %s and %s", expiresAt, before, after)
	}
}

func TestUniqueBatchTTLOverMaximumIsRejected(t *testing.T) {
	p := newTestPool(t, Options{
		BatchTTL:    time.Minute,
		MaxBatchTTL: time.Hour,
	})

	if _, _, _, err := p.pick(policy.Policy{
		UniqueBatch: "too-long",
		BatchTTL:    2 * time.Hour,
	}, "example.com"); !errors.Is(err, ErrPolicy) {
		t.Fatalf("pick error = %v, want %v", err, ErrPolicy)
	}
}

func TestUniqueBatchRequiresMeasuredIP(t *testing.T) {
	p := newTestPool(t, Options{})

	if _, _, _, err := p.pick(policy.Policy{Slot: "jp-tyo-wg-001", UniqueBatch: "b1"}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("pick error = %v, want ErrNoCandidate for an unmeasured slot", err)
	}
	if got := p.Stats().Batches; got != 0 {
		t.Errorf("unmeasured unique selection created %d batches, want 0", got)
	}
}

func TestUniqueBatchRequiresFreshMeasuredIP(t *testing.T) {
	p := newTestPool(t, Options{IPRefreshInterval: time.Hour})
	state := p.slots["jp-tyo-wg-001"]
	setFreshPublicIP(state, netip.MustParseAddr("203.0.113.10"))
	state.ipCheckedAt = time.Now().Add(-2 * time.Hour)

	if _, _, _, err := p.pick(policy.Policy{Slot: state.spec.ID, UniqueBatch: "b1"}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("pick(stale IP) error = %v, want ErrNoCandidate", err)
	}
}

func TestUniqueBatchReservationIsAtomicAndRollsBack(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour})
	pol := policy.Policy{Slot: "jp-tyo-wg-001", UniqueBatch: "b1"}
	ip := netip.MustParseAddr("198.51.100.50")

	p.mu.Lock()
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], ip)
	p.mu.Unlock()

	start := make(chan struct{})
	type result struct {
		reservation *acquisitionReservation
		err         error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, reservation, err := p.pick(pol, "example.com")
			results <- result{reservation: reservation, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	var winningReservation *acquisitionReservation
	for result := range results {
		if result.err == nil {
			successes++
			winningReservation = result.reservation
			continue
		}
		if !errors.Is(result.err, ErrNoCandidate) {
			t.Errorf("concurrent pick error = %v, want ErrNoCandidate", result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent picks succeeded %d times, want exactly one", successes)
	}

	p.mu.Lock()
	batch := p.batches[pol.UniqueBatch]
	reservedSlot := false
	reservedIP := false
	if batch != nil {
		_, reservedSlot = batch.usedSlots["jp-tyo-wg-001"]
		_, reservedIP = batch.usedIPs[ip]
	}
	p.mu.Unlock()
	if !reservedSlot || !reservedIP {
		t.Fatalf("selection did not atomically reserve slot and IP: %+v", batch)
	}

	p.rollbackAcquisition(winningReservation)
	if _, _, _, err := p.pick(pol, "example.com"); err != nil {
		t.Fatalf("pick after rollback = %v, want the released slot", err)
	}
}

func TestUniqueBatchRollbackCannotReleaseRecreatedBatch(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour})
	state := p.slots["jp-tyo-wg-001"]
	setFreshPublicIP(state, netip.MustParseAddr("203.0.113.10"))
	pol := policy.Policy{Slot: state.spec.ID, UniqueBatch: "recreated"}

	_, _, oldReservation, err := p.pick(pol, "example.com")
	if err != nil {
		t.Fatalf("first pick: %v", err)
	}
	oldBatch := p.batches[pol.UniqueBatch]
	oldBatch.expiresAt = time.Now().Add(-time.Second)

	if _, _, _, err := p.pick(pol, "example.com"); err != nil {
		t.Fatalf("recreated pick: %v", err)
	}
	if p.batches[pol.UniqueBatch] == oldBatch {
		t.Fatal("expected the expired batch to be replaced")
	}

	p.rollbackAcquisition(oldReservation)
	if _, _, _, err := p.pick(pol, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("third pick after stale rollback = %v, want ErrNoCandidate", err)
	}
}

func TestMeasurementBackfillsConsumingUniqueBatches(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour})
	pol := policy.Policy{Slot: "jp-tyo-wg-001", UniqueBatch: "b1"}
	oldIP := netip.MustParseAddr("198.51.100.50")
	newIP := netip.MustParseAddr("198.51.100.51")

	p.mu.Lock()
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], oldIP)
	p.mu.Unlock()
	state, _, _, err := p.pick(pol, "example.com")
	if err != nil {
		t.Fatalf("pick: %v", err)
	}

	p.mu.Lock()
	p.setPublicIPLocked(state, newIP, time.Now())
	batch := p.batches[pol.UniqueBatch]
	_, oldReserved := batch.usedIPs[oldIP]
	_, newReserved := batch.usedIPs[newIP]
	p.mu.Unlock()
	if !oldReserved || !newReserved {
		t.Errorf("batch IPs = %+v, want both previous and freshly measured address", batch.usedIPs)
	}
}

func TestUniqueBatchCountLimitIsAtomic(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour, MaxUniqueBatches: 1})
	p.mu.Lock()
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], netip.MustParseAddr("198.51.100.50"))
	p.mu.Unlock()

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, batch := range []string{"b1", "b2"} {
		wg.Add(1)
		go func(batch string) {
			defer wg.Done()
			<-start
			_, _, _, err := p.pick(policy.Policy{UniqueBatch: batch}, "example.com")
			errs <- err
		}(batch)
	}
	close(start)
	wg.Wait()
	close(errs)

	successes := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrBatchFull) {
			t.Errorf("concurrent batch creation error = %v, want ErrBatchFull", err)
		}
	}
	if successes != 1 {
		t.Fatalf("created %d batches, want exactly one", successes)
	}
	if got := p.Stats().Batches; got != 1 {
		t.Errorf("active batches = %d, want 1", got)
	}
}

func TestUniqueBatchCountLimitPrunesExpiredBatches(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour, MaxUniqueBatches: 1})
	p.mu.Lock()
	p.batches["expired"] = newBatch(time.Now().Add(-time.Second))
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], netip.MustParseAddr("198.51.100.50"))
	p.mu.Unlock()

	if _, _, _, err := p.pick(policy.Policy{UniqueBatch: "fresh"}, "example.com"); err != nil {
		t.Fatalf("pick after expiry pruning: %v", err)
	}
	if got := p.Stats().Batches; got != 1 {
		t.Errorf("active batches = %d, want 1 after pruning expired entry", got)
	}
	p.mu.Lock()
	_, hasFresh := p.batches["fresh"]
	_, hasExpired := p.batches["expired"]
	p.mu.Unlock()
	if !hasFresh || hasExpired {
		t.Errorf("batch map after pruning has fresh=%t expired=%t, want true false", hasFresh, hasExpired)
	}
}

func TestInventoryRoundTrip(t *testing.T) {
	p := newTestPool(t, Options{})
	path := filepath.Join(t.TempDir(), "state", "inventory.json")

	checked := time.Now().Truncate(time.Second)
	p.mu.Lock()
	setFreshPublicIP(p.slots["jp-tyo-wg-001"], netip.MustParseAddr("203.0.113.1"))
	p.slots["jp-tyo-wg-001"].ipCheckedAt = checked
	setFreshPublicIP(p.slots["us-lax-wg-001"], netip.MustParseAddr("203.0.113.2"))
	p.slots["us-lax-wg-001"].ipCheckedAt = checked
	p.mu.Unlock()

	if err := p.SaveInventory(path); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}
	if got := p.UniquePublicIPs(); len(got) != 2 {
		t.Errorf("UniquePublicIPs() = %v, want 2 entries", got)
	}

	restored := newTestPool(t, Options{})
	count, err := restored.LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if count != 2 {
		t.Fatalf("LoadInventory restored %d slots, want 2", count)
	}
	if got := restored.Stats().UniqueIPs; got != 2 {
		t.Errorf("UniqueIPs after restore = %d, want 2", got)
	}
}

func TestHealthStatePersistsAcrossInventoryRoundTrip(t *testing.T) {
	p := newTestPool(t, Options{
		Cooldown:     time.Hour,
		PreferredTTL: time.Hour,
	})
	path := filepath.Join(t.TempDir(), "state", "inventory.json")
	successIP := netip.MustParseAddr("203.0.113.10")
	blockedIP := netip.MustParseAddr("203.0.113.11")
	setFreshPublicIP(p.slots["us-lax-wg-001"], successIP)
	setFreshPublicIP(p.slots["us-lax-wg-002"], blockedIP)

	const scope = "opencode-zen.deepseek-v4-flash-0731"
	if _, err := p.Prefer(PreferInput{Slot: "us-lax-wg-001", Target: scope}); err != nil {
		t.Fatalf("Prefer: %v", err)
	}
	if _, err := p.Report(ReportInput{
		Slot:   "us-lax-wg-002",
		Target: scope,
		Reason: "zen_free_quota",
	}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if err := p.SaveInventory(path); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}

	restored := newTestPool(t, Options{})
	if _, err := restored.LoadInventory(path); err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}

	restored.mu.Lock()
	defer restored.mu.Unlock()
	preferred := restored.preferred[scope]
	if preferred == nil || len(preferred.slots) != 1 ||
		preferred.slots[0].publicIP != successIP {
		t.Fatalf("restored preferred = %#v, want %s", preferred, successIP)
	}
	if until := restored.ipCooldowns[scope][blockedIP]; !time.Now().Before(until) {
		t.Fatalf("restored cooldown = %s, want future deadline", until)
	}
}

func TestLoadInventoryMissingFileIsNotAnError(t *testing.T) {
	p := newTestPool(t, Options{})
	count, err := p.LoadInventory(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestSaveInventoryWithNothingMeasured(t *testing.T) {
	p := newTestPool(t, Options{})
	// Nothing has been measured yet, so there is nothing worth persisting and
	// no file should be required.
	if err := p.SaveInventory(filepath.Join(t.TempDir(), "inv.json")); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}
}

func TestExpireLockedDropsStaleEntries(t *testing.T) {
	p := newTestPool(t, Options{})
	past := time.Now().Add(-time.Hour)

	p.mu.Lock()
	p.sessions["old"] = &session{slotID: "jp-tyo-wg-001", expiresAt: past}
	p.batches["old"] = &batch{usedIPs: map[netip.Addr]struct{}{}, usedSlots: map[string]struct{}{}, expiresAt: past}
	p.slots["jp-tyo-wg-001"].cooldowns["example.com"] = past
	p.expireLocked(time.Now())
	sessions, batches, cooldowns := len(p.sessions), len(p.batches), len(p.slots["jp-tyo-wg-001"].cooldowns)
	p.mu.Unlock()

	if sessions != 0 || batches != 0 || cooldowns != 0 {
		t.Errorf("stale entries survived: sessions=%d batches=%d cooldowns=%d", sessions, batches, cooldowns)
	}
}

func TestWarmupWithZeroCount(t *testing.T) {
	p := newTestPool(t, Options{})
	if got := p.Warmup(context.Background(), 0); got != 0 {
		t.Errorf("Warmup(0) = %d, want 0", got)
	}
}
