// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/security"
)

func TestBestEffortSessionCloseUsesUpToTenUniqueResolvers(t *testing.T) {
	resolvers := make([]config.ResolverAddress, 0, 12)
	for idx := 1; idx <= 12; idx++ {
		resolvers = append(resolvers, config.ResolverAddress{
			IP:   "10.0.0." + strconv.Itoa(idx),
			Port: 53,
		})
	}

	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		Domains: []string{
			"a.example.com",
			"b.example.com",
		},
		Resolvers: resolvers,
	}, nil, codec)
	c.BuildConnectionMap()
	c.sessionReady = true
	c.sessionID = 7
	c.sessionCookie = 9

	var (
		mu      sync.Mutex
		targets = make(map[string]int)
	)
	c.sendOneWayPacketFn = func(conn Connection, packet []byte, deadline time.Time) error {
		if conn.ResolverLabel == "" {
			t.Fatal("resolver label must not be empty")
		}
		if len(packet) == 0 {
			t.Fatal("session close packet must not be empty")
		}
		if deadline.IsZero() {
			t.Fatal("session close deadline must be set")
		}

		mu.Lock()
		targets[conn.ResolverLabel]++
		mu.Unlock()
		return nil
	}

	c.BestEffortSessionClose(50 * time.Millisecond)

	if got := len(targets); got != 10 {
		t.Fatalf("unexpected unique resolver fanout: got=%d want=10", got)
	}
	for resolverLabel, count := range targets {
		if count != 1 {
			t.Fatalf("resolver %s received duplicate shutdown notifications: %d", resolverLabel, count)
		}
	}
}

func TestBestEffortSessionCloseSkipsWithoutEstablishedSession(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		Domains: []string{"a.example.com"},
		Resolvers: []config.ResolverAddress{
			{IP: "8.8.8.8", Port: 53},
		},
	}, nil, codec)
	c.BuildConnectionMap()

	var calls int
	c.sendOneWayPacketFn = func(Connection, []byte, time.Time) error {
		calls++
		return nil
	}

	c.BestEffortSessionClose(20 * time.Millisecond)

	if calls != 0 {
		t.Fatalf("expected no shutdown packets without an established session, got=%d", calls)
	}
}
