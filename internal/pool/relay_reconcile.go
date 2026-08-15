package pool

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// RelayReconcileResult summarizes one atomic relay membership update.
type RelayReconcileResult struct {
	// Added is the number of newly selectable relay slots.
	Added int
	// Removed is the number of relay slots detached from new selection.
	Removed int
	// Retained is the number of existing relay slots whose state was preserved.
	Retained int
}

// ReconcileRelaySlots atomically replaces the selectable relay-socks set.
//
// Existing slotState values are retained by ID so measured addresses, health,
// counters, and active leases survive a provider catalog refresh. Removed slots
// disappear from new selection immediately; leases already holding their state
// pointer can still release normally.
func (p *Pool) ReconcileRelaySlots(specs []Spec) (RelayReconcileResult, error) {
	if len(specs) == 0 {
		return RelayReconcileResult{}, errors.New("pool: relay refresh contains no slots")
	}

	nextSpecs := make(map[string]Spec, len(specs))
	order := make([]string, 0, len(specs))
	for _, spec := range specs {
		if spec.Kind != KindRelaySocks {
			return RelayReconcileResult{}, errors.New("pool: relay refresh contains a non-relay slot")
		}
		if spec.ID == "" {
			return RelayReconcileResult{}, errors.New("pool: relay refresh contains an empty slot ID")
		}
		if _, exists := nextSpecs[spec.ID]; exists {
			return RelayReconcileResult{}, fmt.Errorf("pool: duplicate slot %q", spec.ID)
		}
		nextSpecs[spec.ID] = spec
		order = append(order, spec.ID)
	}
	sort.Strings(order)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return RelayReconcileResult{}, errors.New("pool: closed")
	}
	for _, state := range p.slots {
		if state.spec.Kind != KindRelaySocks {
			return RelayReconcileResult{}, errors.New("pool: cannot reconcile mixed slot kinds")
		}
	}

	result := RelayReconcileResult{}
	next := make(map[string]*slotState, len(nextSpecs))
	for id, spec := range nextSpecs {
		if state, exists := p.slots[id]; exists {
			state.spec = spec
			next[id] = state
			result.Retained++
			continue
		}
		next[id] = &slotState{
			spec:      spec,
			cooldowns: make(map[string]time.Time),
		}
		result.Added++
	}
	result.Removed = len(p.slots) - result.Retained

	p.slots = next
	p.order = order
	for name, sess := range p.sessions {
		if _, exists := next[sess.slotID]; !exists {
			delete(p.sessions, name)
		}
	}
	return result, nil
}
