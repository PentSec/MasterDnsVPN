// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func buildTunnelTXTQuestion(domain string, encoded string) ([]byte, error) {
	name, err := DnsParser.BuildTunnelQuestionName(domain, encoded)
	if err != nil {
		return nil, err
	}
	return DnsParser.BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
}

func (c *Client) buildTunnelTXTQueryRaw(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	encoded, err := VpnProto.BuildEncoded(options, c.codec)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestion(domain, encoded)
}
