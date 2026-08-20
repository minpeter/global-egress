package pool

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// RelayReconcileResult summarizes one atomic Mullvad relay membership update.
type RelayReconcileResult struct {
	// Added is the number of newly selectable Mullvad relay slots.
	Added int
	// Removed is the number of Mullvad relay slots detached from new selection.
	Removed int
	// Retained is the number of existing Mullvad relay states preserved by ID.
	Retained int
}

// ReconcileRelaySlots replaces only Mullvad relay-socks slots. Direct external
// SOCKS slots and WireGuard slots remain selectable and keep their state.
func (p *Pool) ReconcileRelaySlots(specs []Spec) (RelayReconcileResult, error) {
	if len(specs) == 0 {
		return RelayReconcileResult{}, errors.New("pool: relay refresh contains no slots")
	}
	nextSpecs := make(map[string]Spec, len(specs))
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
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return RelayReconcileResult{}, errors.New("pool: closed")
	}

	result := RelayReconcileResult{}
	next := make(map[string]*slotState, len(p.slots)+len(nextSpecs))
	for id, state := range p.slots {
		if state.spec.Kind != KindRelaySocks {
			next[id] = state
		}
	}
	for id, spec := range nextSpecs {
		if state, exists := p.slots[id]; exists {
			if state.spec.Kind != KindRelaySocks {
				return RelayReconcileResult{}, fmt.Errorf("pool: relay slot collides with non-relay slot %q", id)
			}
			state.spec = spec
			next[id] = state
			result.Retained++
			continue
		}
		next[id] = &slotState{spec: spec, cooldowns: make(map[string]time.Time)}
		result.Added++
	}
	oldRelayCount := 0
	for _, state := range p.slots {
		if state.spec.Kind == KindRelaySocks {
			oldRelayCount++
		}
	}
	result.Removed = oldRelayCount - result.Retained
	order := make([]string, 0, len(next))
	for id := range next {
		order = append(order, id)
	}
	sort.Strings(order)
	p.slots = next
	p.order = order
	for name, sess := range p.sessions {
		if _, exists := next[sess.slotID]; !exists {
			delete(p.sessions, name)
		}
	}
	return result, nil
}
