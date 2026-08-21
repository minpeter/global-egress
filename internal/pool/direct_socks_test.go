package pool

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/policy"
)

func TestReconcileRelaySlotsPreservesDirectSlots(t *testing.T) {
	proxyURL, err := url.Parse("socks5h://dummy-user:dummy-pass@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := NewDirectSocksSpec(DirectSocksOptions{
		ID: "external-test", Country: "us", City: "us-nyc", URL: proxyURL,
	})
	if err != nil {
		t.Fatalf("NewDirectSocksSpec: %v", err)
	}
	specs := append(SpecsFromExits(testExits()[:1]), direct)
	p, err := NewWithSpecs(specs, testEntrySlots(), Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewWithSpecs: %v", err)
	}
	t.Cleanup(p.Close)

	_, err = p.ReconcileRelaySlots(SpecsFromExits([]ExitSpec{{
		ID: "new-wg-socks5-001", Country: "gb", City: "gb-lon",
		SocksAddr: "new-wg-socks5-001.relays.example:1080",
	}}))
	if err != nil {
		t.Fatalf("ReconcileRelaySlots in mixed pool: %v", err)
	}
	slots := p.Slots(SlotFilter{})
	if len(slots) != 2 {
		t.Fatalf("slots after relay refresh = %+v, want two slots", slots)
	}
	if slots[0].ID != "external-test" || slots[1].ID != "new-wg-socks5-001" {
		t.Fatalf("slot IDs after refresh = [%s %s]", slots[0].ID, slots[1].ID)
	}
}

func TestProviderPolicySelectsDirectSocksSlot(t *testing.T) {
	proxyURL, err := url.Parse("socks5h://dummy-user:dummy-pass@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := NewDirectSocksSpec(DirectSocksOptions{ID: "external-test", URL: proxyURL})
	if err != nil {
		t.Fatal(err)
	}
	relay := SpecsFromExits(testExits()[:1])
	p, err := NewWithSpecs(append(relay, direct), testEntrySlots(), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	state, _, reservation, err := p.pick(policy.Policy{Provider: "external-test"}, "example.com")
	if err != nil {
		t.Fatalf("pick provider: %v", err)
	}
	if state.spec.Kind != KindDirectSocks || state.spec.Provider != "external-test" {
		t.Fatalf("picked slot = %+v, want direct external-test", state.spec)
	}
	p.rollbackAcquisition(reservation)
}

func TestDirectSocksInventoryDoesNotExposeCredentials(t *testing.T) {
	proxyURL, err := url.Parse("socks5://dummy-user:dummy-pass@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewDirectSocksSpec(DirectSocksOptions{ID: "external-test", URL: proxyURL})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewWithSpecs([]Spec{spec}, nil, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	info := p.Slots(SlotFilter{})[0]
	if info.Kind != "direct-socks" || info.Target != "proxy.example:1080" {
		t.Fatalf("inventory = %+v", info)
	}
	if info.Target == "dummy-user:dummy-pass@proxy.example:1080" {
		t.Fatal("inventory exposed credentials")
	}
}

func TestNewDirectSocksSpecAddsStickySessionToProviderUsername(t *testing.T) {
	proxyURL, err := url.Parse("socks5h://dummy-user:dummy-pass@proxy.example:10000")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewDirectSocksSpec(DirectSocksOptions{
		ID:       "external-test-session-001",
		Provider: "external-test",
		Session:  "ge001",
		URL:      proxyURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID != "external-test-session-001" || spec.Provider != "external-test" {
		t.Fatalf("identity = id %q provider %q", spec.ID, spec.Provider)
	}
	if spec.socksUsername != "dummy-user-session-ge001" {
		t.Fatalf("username = %q, want sticky session suffix", spec.socksUsername)
	}
}

func TestDirectSocksSessionsPreserveUniqueBatchIPs(t *testing.T) {
	specs := make([]Spec, 0, 3)
	for i := 1; i <= 3; i++ {
		proxyURL, err := url.Parse("socks5h://dummy-user:dummy-pass@proxy.example:10000")
		if err != nil {
			t.Fatal(err)
		}
		spec, err := NewDirectSocksSpec(DirectSocksOptions{
			ID:       "external-test-session-" + string(rune('0'+i)),
			Provider: "external-test",
			Session:  "ge00" + string(rune('0'+i)),
			URL:      proxyURL,
		})
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, spec)
	}
	p, err := NewWithSpecs(specs, nil, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	now := time.Now()
	p.mu.Lock()
	for i, id := range p.order {
		p.slots[id].publicIP = netip.MustParseAddr("192.0.2." + string(rune('1'+i)))
		p.slots[id].ipCheckedAt = now
	}
	p.mu.Unlock()

	seen := make(map[string]struct{}, len(specs))
	for range specs {
		state, _, reservation, err := p.pick(policy.Policy{Provider: "external-test", UniqueBatch: "batch"}, "")
		if err != nil {
			t.Fatalf("pick unique session: %v", err)
		}
		seen[state.spec.ID] = struct{}{}
		p.mu.Lock()
		p.commitAcquisitionLocked(reservation)
		p.mu.Unlock()
	}
	if len(seen) != len(specs) {
		t.Fatalf("unique batch selected %d sessions, want %d", len(seen), len(specs))
	}
}

func TestRotatingDirectSocksIsNotStableUniqueIdentity(t *testing.T) {
	proxyURL, err := url.Parse("socks5h://dummy-user:dummy-pass@proxy.example:10000")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewDirectSocksSpec(DirectSocksOptions{
		ID: "rotating", URL: proxyURL, Rotating: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewWithSpecs([]Spec{spec}, nil, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.mu.Lock()
	p.slots[spec.ID].publicIP = netip.MustParseAddr("192.0.2.99")
	p.slots[spec.ID].ipCheckedAt = time.Now()
	p.mu.Unlock()

	stats := p.Stats()
	if stats.KnownIPs != 0 || stats.UniqueIPs != 0 {
		t.Fatalf("rotating stats = known %d unique %d, want zero", stats.KnownIPs, stats.UniqueIPs)
	}
	if slots := p.Slots(SlotFilter{WithIP: true}); len(slots) != 0 {
		t.Fatalf("rotating slot listed as stable IP: %+v", slots)
	}
	if _, _, _, err := p.pick(policy.Policy{UniqueBatch: "batch"}, ""); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("unique pick error = %v, want ErrNoCandidate", err)
	}
}
