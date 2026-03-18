// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"sync"
	"time"
)

type dnsResolveInflightEntry struct {
	createdAt time.Time
	ready     chan struct{}
	response  []byte
}

type dnsResolveInflightManager struct {
	timeout       time.Duration
	cleanupWindow time.Duration
	nextCleanupAt time.Time
	mu            sync.Mutex
	items         map[string]*dnsResolveInflightEntry
}

func newDNSResolveInflightManager(timeout time.Duration) *dnsResolveInflightManager {
	if timeout <= 0 {
		timeout = 16 * time.Second
	}
	cleanupWindow := timeout / 4
	if cleanupWindow < time.Second {
		cleanupWindow = time.Second
	}
	return &dnsResolveInflightManager{
		timeout:       timeout,
		cleanupWindow: cleanupWindow,
		items:         make(map[string]*dnsResolveInflightEntry, 32),
	}
}

func (m *dnsResolveInflightManager) Acquire(cacheKey []byte, now time.Time) (*dnsResolveInflightEntry, bool) {
	if m == nil || len(cacheKey) == 0 {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(cacheKey)
	if m.nextCleanupAt.IsZero() || !now.Before(m.nextCleanupAt) {
		for existingKey, entry := range m.items {
			if entry == nil || now.Sub(entry.createdAt) >= m.timeout {
				delete(m.items, existingKey)
			}
		}
		m.nextCleanupAt = now.Add(m.cleanupWindow)
	}

	if entry, ok := m.items[key]; ok && entry != nil && now.Sub(entry.createdAt) < m.timeout {
		return entry, false
	}

	entry := &dnsResolveInflightEntry{
		createdAt: now,
		ready:     make(chan struct{}),
	}
	m.items[key] = entry
	return entry, true
}

func (m *dnsResolveInflightManager) Resolve(cacheKey []byte, response []byte) {
	if m == nil || len(cacheKey) == 0 {
		return
	}

	m.mu.Lock()
	entry := m.items[string(cacheKey)]
	delete(m.items, string(cacheKey))
	if entry != nil && len(response) != 0 {
		entry.response = append([]byte(nil), response...)
	}
	m.mu.Unlock()

	if entry != nil {
		close(entry.ready)
	}
}

func (m *dnsResolveInflightManager) Wait(entry *dnsResolveInflightEntry, timeout time.Duration) ([]byte, bool) {
	if entry == nil {
		return nil, false
	}
	if timeout <= 0 {
		timeout = m.timeout
	}
	if timeout <= 0 {
		timeout = 16 * time.Second
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-entry.ready:
		if len(entry.response) == 0 {
			return nil, true
		}
		return append([]byte(nil), entry.response...), true
	case <-timer.C:
		return nil, false
	}
}
