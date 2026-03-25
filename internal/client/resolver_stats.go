package client

import (
	"encoding/binary"
	"net"
	"time"
)

type resolverSampleKey struct {
	resolverAddr string
	dnsID        uint16
}

type resolverSample struct {
	serverKey string
	sentAt    time.Time
}

func (c *Client) resolverSampleTTL() time.Duration {
	if c == nil {
		return 15 * time.Second
	}

	ttl := c.tunnelPacketTimeout * 3
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	if ttl > 45*time.Second {
		ttl = 45 * time.Second
	}
	return ttl
}

func (c *Client) noteResolverSend(serverKey string) {
	if c == nil || serverKey == "" || c.balancer == nil {
		return
	}
	c.balancer.ReportSend(serverKey)
}

func (c *Client) noteResolverSuccess(serverKey string, rtt time.Duration) {
	if c == nil || serverKey == "" || c.balancer == nil {
		return
	}
	if rtt < 0 {
		rtt = 0
	}
	c.balancer.ReportSuccess(serverKey, rtt)
}

func (c *Client) trackResolverSend(packet []byte, resolverAddr string, serverKey string, sentAt time.Time) {
	if c == nil || len(packet) < 2 || resolverAddr == "" || serverKey == "" {
		return
	}

	key := resolverSampleKey{
		resolverAddr: resolverAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	c.resolverStatsMu.Lock()
	c.evictExpiredResolverSamplesLocked(sentAt)
	c.resolverPending[key] = resolverSample{
		serverKey: serverKey,
		sentAt:    sentAt,
	}
	c.resolverStatsMu.Unlock()

	c.noteResolverSend(serverKey)
}

func (c *Client) trackResolverSuccess(packet []byte, addr *net.UDPAddr, receivedAt time.Time) {
	if c == nil || len(packet) < 2 || addr == nil {
		return
	}

	key := resolverSampleKey{
		resolverAddr: addr.String(),
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	c.resolverStatsMu.Lock()
	c.evictExpiredResolverSamplesLocked(receivedAt)
	sample, ok := c.resolverPending[key]
	if ok {
		delete(c.resolverPending, key)
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" {
		return
	}

	c.noteResolverSuccess(sample.serverKey, receivedAt.Sub(sample.sentAt))
}

func (c *Client) evictExpiredResolverSamplesLocked(now time.Time) {
	if c == nil || len(c.resolverPending) == 0 {
		return
	}

	cutoff := now.Add(-c.resolverSampleTTL())
	for key, sample := range c.resolverPending {
		if sample.sentAt.Before(cutoff) {
			delete(c.resolverPending, key)
		}
	}
}
