// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func isPreSessionResponseType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_MTU_UP_RES, Enums.PACKET_MTU_DOWN_RES, Enums.PACKET_SESSION_ACCEPT:
		return true
	default:
		return false
	}
}

func (c *Client) validateServerPacket(packet VpnProto.Packet) bool {
	if isPreSessionResponseType(packet.PacketType) {
		return true
	}
	if c == nil || !c.sessionReady {
		return false
	}
	return packet.SessionID == c.sessionID && packet.SessionCookie == c.sessionCookie
}
