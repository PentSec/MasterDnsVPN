// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrSessionInitFailed = errors.New("session init failed")

const (
	sessionInitPayloadSize   = 10
	sessionAcceptPayloadSize = 7
)

func (c *Client) InitializeSession(maxAttempts int) error {
	if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
		return ErrSessionInitFailed
	}

	if maxAttempts < 1 {
		maxAttempts = 1
	}

	initPayload, responseBase64, verifyCode, err := c.buildSessionInitPayload()
	if err != nil {
		return err
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		conn, ok := c.GetBestConnection()
		if !ok {
			return ErrNoValidConnections
		}

		query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
		if err != nil {
			c.SetConnectionValidity(conn.Key, false)
			continue
		}

		transport, err := newUDPQueryTransport(conn.ResolverLabel)
		if err != nil {
			c.SetConnectionValidity(conn.Key, false)
			continue
		}

		response, err := exchangeUDPQuery(transport, query, time.Duration(c.cfg.MTUTestTimeout*float64(time.Second)))
		_ = transport.conn.Close()
		if err != nil {
			c.SetConnectionValidity(conn.Key, false)
			continue
		}

		packet, err := DnsParser.ExtractVPNResponse(response, responseBase64)
		if err != nil || !c.validateServerPacket(packet) || packet.PacketType != Enums.PACKET_SESSION_ACCEPT || len(packet.Payload) < sessionAcceptPayloadSize {
			c.SetConnectionValidity(conn.Key, false)
			continue
		}

		if !bytes.Equal(packet.Payload[3:7], verifyCode[:]) {
			continue
		}

		c.sessionID = packet.Payload[0]
		c.sessionCookie = packet.Payload[1]
		c.responseMode = initPayload[0]
		c.uploadCompression, c.downloadCompression = compression.SplitPair(packet.Payload[2])
		c.applySessionCompressionPolicy()
		return nil
	}

	return ErrSessionInitFailed
}

func (c *Client) buildSessionInitPayload() ([]byte, bool, [4]byte, error) {
	var verifyCode [4]byte
	randomPart, err := randomBytes(len(verifyCode))
	if err != nil {
		return nil, false, verifyCode, err
	}
	copy(verifyCode[:], randomPart)

	payload := make([]byte, sessionInitPayloadSize)
	if c.cfg.BaseEncodeData {
		payload[0] = mtuProbeBase64Reply
	}
	payload[1] = compression.PackPair(c.uploadCompression, c.downloadCompression)
	binary.BigEndian.PutUint16(payload[2:4], uint16(c.syncedUploadMTU))
	binary.BigEndian.PutUint16(payload[4:6], uint16(c.syncedDownloadMTU))
	copy(payload[6:10], verifyCode[:])
	return payload, payload[0] == mtuProbeBase64Reply, verifyCode, nil
}

func (c *Client) buildSessionQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelQuery(domain, 0, packetType, payload)
}

func (c *Client) buildTunnelQuery(domain string, sessionID uint8, packetType uint8, payload []byte) ([]byte, error) {
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:  sessionID,
		PacketType: packetType,
		Payload:    payload,
	}, c.codec)
	if err != nil {
		return nil, err
	}

	name, err := DnsParser.BuildTunnelQuestionName(domain, encoded)
	if err != nil {
		return nil, err
	}
	return DnsParser.BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
}
