package pool

import (
	"io"
	"log/slog"
	"net/url"
	"testing"

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
