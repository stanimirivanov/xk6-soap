package fixture

import (
	"fmt"
	"sync"
)

// ExchangeMarkers tracks the exact set for a single local per-VU workload.
type ExchangeMarkers struct {
	mu        sync.Mutex
	remaining map[string]struct{}
	invalid   int
}

func NewExchangeMarkers(vus, iterations int) *ExchangeMarkers {
	tally := &ExchangeMarkers{remaining: make(map[string]struct{}, vus*iterations)}
	for vu := 1; vu <= vus; vu++ {
		for iteration := range iterations {
			tally.remaining[fmt.Sprintf("%d-%d", vu, iteration)] = struct{}{}
		}
	}
	return tally
}

// Record consumes one expected marker. Duplicate and unknown values are
// counted without retaining their contents.
func (tally *ExchangeMarkers) Record(marker string) bool {
	tally.mu.Lock()
	defer tally.mu.Unlock()
	if _, ok := tally.remaining[marker]; !ok {
		tally.invalid++
		return false
	}
	delete(tally.remaining, marker)
	return true
}

func (tally *ExchangeMarkers) Check() error {
	tally.mu.Lock()
	defer tally.mu.Unlock()
	if len(tally.remaining) != 0 || tally.invalid != 0 {
		return fmt.Errorf("receiver markers: %d missing, %d duplicate or unexpected", len(tally.remaining), tally.invalid)
	}
	return nil
}
