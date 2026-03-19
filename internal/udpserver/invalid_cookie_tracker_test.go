// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"
	"time"
)

func trackerLookup(cookie uint8, state sessionLookupState) sessionLookupResult {
	return sessionLookupResult{
		Cookie: cookie,
		State:  state,
	}
}

func TestInvalidCookieTrackerEmitsOnlyAfterThreshold(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now()
	lookup := trackerLookup(10, sessionLookupActive)
	window := 2 * time.Second
	windowNanos := window.Nanoseconds()

	if tracker.Note(7, lookup, true, 22, now.UnixNano(), windowNanos, 3) {
		t.Fatal("first invalid cookie attempt must not emit")
	}
	if tracker.Note(7, lookup, true, 22, now.Add(100*time.Millisecond).UnixNano(), windowNanos, 3) {
		t.Fatal("second invalid cookie attempt must not emit")
	}
	if !tracker.Note(7, lookup, true, 22, now.Add(200*time.Millisecond).UnixNano(), windowNanos, 3) {
		t.Fatal("third invalid cookie attempt must emit")
	}
	if tracker.Note(7, lookup, true, 22, now.Add(300*time.Millisecond).UnixNano(), windowNanos, 3) {
		t.Fatal("tracker must rate-limit repeated emits inside the same window")
	}
}

func TestInvalidCookieTrackerCleanupRemovesExpiredAttempts(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now()
	lookup := trackerLookup(10, sessionLookupActive)
	window := time.Second
	windowNanos := window.Nanoseconds()

	if tracker.Note(7, lookup, true, 33, now.UnixNano(), windowNanos, 2) {
		t.Fatal("first invalid cookie attempt must not emit")
	}

	tracker.Cleanup(now.Add(2*time.Second), time.Second)
	if tracker.Note(7, lookup, true, 33, now.Add(2*time.Second).UnixNano(), windowNanos, 2) {
		t.Fatal("expired attempts must be cleaned before threshold is reached again")
	}
	if !tracker.Note(7, lookup, true, 33, now.Add(2100*time.Millisecond).UnixNano(), windowNanos, 2) {
		t.Fatal("second fresh attempt after cleanup must emit")
	}
}

func TestInvalidCookieTrackerSeparatesClosedSessionState(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now()
	activeLookup := trackerLookup(10, sessionLookupActive)
	closedLookup := trackerLookup(10, sessionLookupClosed)
	window := time.Second
	windowNanos := window.Nanoseconds()

	if tracker.Note(7, activeLookup, true, 55, now.UnixNano(), windowNanos, 2) {
		t.Fatal("first active invalid cookie attempt must not emit")
	}
	if tracker.Note(7, closedLookup, true, 55, now.Add(100*time.Millisecond).UnixNano(), windowNanos, 2) {
		t.Fatal("closed-session attempts must be tracked separately from active ones")
	}
	if !tracker.Note(7, closedLookup, true, 55, now.Add(200*time.Millisecond).UnixNano(), windowNanos, 2) {
		t.Fatal("second closed-session attempt should emit for its own bucket")
	}
}
