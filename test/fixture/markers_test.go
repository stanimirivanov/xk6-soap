package fixture

import "testing"

func TestExchangeMarkerCoverage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		markers []string
		ok      bool
	}{
		{name: "complete in any order", markers: []string{"2-0", "1-0", "1-1", "2-1"}, ok: true},
		{name: "missing", markers: []string{"2-0", "1-0", "1-1"}},
		{name: "duplicate", markers: []string{"2-0", "1-0", "1-1", "2-1", "2-1"}},
		{name: "unexpected", markers: []string{"2-0", "1-0", "1-1", "2-1", "3-0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tally := NewExchangeMarkers(2, 2)
			for _, marker := range tc.markers {
				tally.Record(marker)
			}
			if err := tally.Check(); (err == nil) != tc.ok {
				t.Fatalf("marker coverage: got %v, want success %t", err, tc.ok)
			}
		})
	}
}
