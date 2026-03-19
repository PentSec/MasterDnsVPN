// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"testing"

	"masterdnsvpn-go/internal/config"
)

func TestBinarySearchMTUSkipsDuplicateChecks(t *testing.T) {
	c := New(config.ClientConfig{
		MTUTestRetries: 1,
	}, nil, nil)

	calls := make(map[int]int)
	best := c.binarySearchMTU(30, 100, func(value int) (bool, error) {
		calls[value]++
		return value <= 73, nil
	})

	if best != 73 {
		t.Fatalf("unexpected binary search result: got=%d want=%d", best, 73)
	}
	for value, count := range calls {
		if count != 1 {
			t.Fatalf("mtu candidate %d checked more than once: %d", value, count)
		}
	}
}
