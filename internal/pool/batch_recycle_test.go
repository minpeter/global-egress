package pool

import (
	"net/netip"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/policy"
)

// A long batch TTL is what makes a burned exit stay excluded long enough to be
// useful, but it also means a busy caller can consume the whole pool before the
// TTL expires and then get nothing. Recycling turns the exhausted batch into a
// ring: the exit burned longest ago comes back first, because it is the one
// most likely to have recovered whatever per-IP limit burned it.
func burnEveryExit(t *testing.T, p *Pool, pol policy.Policy, at time.Time) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for index, id := range p.order {
		state := p.slots[id]
		setFreshPublicIP(state, netip.MustParseAddr("203.0.113."+itoa(index+1)))
		// Stagger the burns so "oldest" is unambiguous.
		reservation, err := p.reserveBatchLocked(pol, state, at.Add(time.Duration(index)*time.Minute))
		if err != nil {
			t.Fatalf("reserveBatchLocked(%s): %v", id, err)
		}
		_ = reservation
	}
}

func itoa(v int) string {
	if v < 10 {
		return string(rune('0' + v))
	}
	return string(rune('0'+v/10)) + string(rune('0'+v%10))
}

func TestExhaustedBatchWithoutRecycleStillRefuses(t *testing.T) {
	// The documented guarantee: uniq= never repeats an IP in a batch. Callers
	// that did not opt in must keep it, exhaustion and all.
	p := newTestPool(t, Options{BatchTTL: 6 * time.Hour, MaxBatchTTL: 6 * time.Hour})
	pol := policy.Policy{UniqueBatch: "strict", BatchTTL: 6 * time.Hour}
	start := time.Now()
	burnEveryExit(t, p, pol, start)

	_, _, _, err := p.pick(pol, "")
	if err == nil {
		t.Fatal("expected ErrNoCandidate once every exit is burned")
	}
}

func TestExhaustedBatchRecyclesOldestFirst(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: 6 * time.Hour, MaxBatchTTL: 6 * time.Hour})
	pol := policy.Policy{
		UniqueBatch:  "ring",
		BatchTTL:     6 * time.Hour,
		RecycleBatch: true,
	}
	start := time.Now()
	burnEveryExit(t, p, pol, start)

	// The first exit burned is the oldest, so it must come back first.
	state, _, _, err := p.pick(pol, "")
	if err != nil {
		t.Fatalf("recycling batch should still serve a slot: %v", err)
	}
	if state == nil {
		t.Fatal("expected a recycled slot")
	}
	if got, want := state.spec.ID, p.order[0]; got != want {
		t.Errorf("recycled %s, want the oldest burn %s", got, want)
	}
}

func TestRecycledExitGoesToTheBackOfTheRing(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: 6 * time.Hour, MaxBatchTTL: 6 * time.Hour})
	pol := policy.Policy{
		UniqueBatch:  "ring",
		BatchTTL:     6 * time.Hour,
		RecycleBatch: true,
	}
	start := time.Now()
	burnEveryExit(t, p, pol, start)

	// Two consecutive recycles must not hand back the same exit: re-stamping
	// moves the first one to the back, so the second-oldest is next.
	first, _, _, err := p.pick(pol, "")
	if err != nil {
		t.Fatalf("first recycle: %v", err)
	}
	second, _, _, err := p.pick(pol, "")
	if err != nil {
		t.Fatalf("second recycle: %v", err)
	}
	if first.spec.ID == second.spec.ID {
		t.Errorf("recycled %s twice in a row; the ring did not advance", first.spec.ID)
	}
}
