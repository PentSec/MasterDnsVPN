// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"testing"
	"time"
)

func TestDNSInflightBeginDedupesWithinTimeout(t *testing.T) {
	manager := newDNSInflightManager(10 * time.Second)
	now := time.Unix(1700000000, 0)
	key := []byte("example")

	if !manager.Begin(key, now) {
		t.Fatal("first begin should succeed")
	}
	if manager.Begin(key, now.Add(5*time.Second)) {
		t.Fatal("second begin within timeout should be deduped")
	}
	if !manager.Begin(key, now.Add(11*time.Second)) {
		t.Fatal("begin after timeout should succeed again")
	}
}

func TestDNSInflightCompleteReleasesKey(t *testing.T) {
	manager := newDNSInflightManager(10 * time.Second)
	now := time.Unix(1700000000, 0)
	key := []byte("example")

	if !manager.Begin(key, now) {
		t.Fatal("first begin should succeed")
	}
	manager.Complete(key)
	if !manager.Begin(key, now.Add(time.Second)) {
		t.Fatal("begin after complete should succeed")
	}
}

func TestDNSInflightAcquireAndWait(t *testing.T) {
	manager := newDNSInflightManager(10 * time.Second)
	now := time.Unix(1700000000, 0)
	key := []byte("example")

	entry, leader := manager.Acquire(key, now)
	if !leader || entry == nil {
		t.Fatal("first acquire should create leader entry")
	}

	followerEntry, leader := manager.Acquire(key, now.Add(time.Second))
	if leader || followerEntry != entry {
		t.Fatal("second acquire should join existing inflight entry")
	}

	done := make(chan bool, 1)
	go func() {
		done <- manager.Wait(followerEntry, time.Second)
	}()

	manager.Resolve(key)
	if !<-done {
		t.Fatal("wait should unblock after resolve")
	}
}
