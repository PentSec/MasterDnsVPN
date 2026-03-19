// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package enums

import "strconv"

func DNSRecordTypeName(qType uint16) string {
	switch qType {
	case DNS_RECORD_TYPE_A:
		return "A"
	case DNS_RECORD_TYPE_AAAA:
		return "AAAA"
	case DNS_RECORD_TYPE_CNAME:
		return "CNAME"
	case DNS_RECORD_TYPE_MX:
		return "MX"
	case DNS_RECORD_TYPE_NS:
		return "NS"
	case DNS_RECORD_TYPE_PTR:
		return "PTR"
	case DNS_RECORD_TYPE_SRV:
		return "SRV"
	case DNS_RECORD_TYPE_SVCB:
		return "SVCB"
	case DNS_RECORD_TYPE_CAA:
		return "CAA"
	case DNS_RECORD_TYPE_NAPTR:
		return "NAPTR"
	case DNS_RECORD_TYPE_SOA:
		return "SOA"
	case DNS_RECORD_TYPE_TXT:
		return "TXT"
	case DNS_RECORD_TYPE_HTTPS:
		return "HTTPS"
	default:
		return "TYPE" + strconv.FormatUint(uint64(qType), 10)
	}
}

func PacketTypeName(packetType uint8) string {
	switch packetType {
	case PACKET_MTU_UP_REQ:
		return "MTU_UP_REQ"
	case PACKET_MTU_UP_RES:
		return "MTU_UP_RES"
	case PACKET_MTU_DOWN_REQ:
		return "MTU_DOWN_REQ"
	case PACKET_MTU_DOWN_RES:
		return "MTU_DOWN_RES"
	case PACKET_SESSION_INIT:
		return "SESSION_INIT"
	case PACKET_SESSION_ACCEPT:
		return "SESSION_ACCEPT"
	case PACKET_PING:
		return "PING"
	case PACKET_PONG:
		return "PONG"
	case PACKET_STREAM_SYN:
		return "STREAM_SYN"
	case PACKET_STREAM_SYN_ACK:
		return "STREAM_SYN_ACK"
	case PACKET_STREAM_DATA:
		return "STREAM_DATA"
	case PACKET_STREAM_DATA_ACK:
		return "STREAM_DATA_ACK"
	case PACKET_STREAM_RESEND:
		return "STREAM_RESEND"
	case PACKET_PACKED_CONTROL_BLOCKS:
		return "PACKED_CONTROL_BLOCKS"
	case PACKET_STREAM_FIN:
		return "STREAM_FIN"
	case PACKET_STREAM_FIN_ACK:
		return "STREAM_FIN_ACK"
	case PACKET_STREAM_RST:
		return "STREAM_RST"
	case PACKET_STREAM_RST_ACK:
		return "STREAM_RST_ACK"
	case PACKET_SOCKS5_SYN:
		return "SOCKS5_SYN"
	case PACKET_SOCKS5_SYN_ACK:
		return "SOCKS5_SYN_ACK"
	case PACKET_SOCKS5_CONNECT_FAIL:
		return "SOCKS5_CONNECT_FAIL"
	case PACKET_SOCKS5_RULESET_DENIED:
		return "SOCKS5_RULESET_DENIED"
	case PACKET_SOCKS5_NETWORK_UNREACHABLE:
		return "SOCKS5_NETWORK_UNREACHABLE"
	case PACKET_SOCKS5_HOST_UNREACHABLE:
		return "SOCKS5_HOST_UNREACHABLE"
	case PACKET_SOCKS5_CONNECTION_REFUSED:
		return "SOCKS5_CONNECTION_REFUSED"
	case PACKET_SOCKS5_TTL_EXPIRED:
		return "SOCKS5_TTL_EXPIRED"
	case PACKET_SOCKS5_COMMAND_UNSUPPORTED:
		return "SOCKS5_COMMAND_UNSUPPORTED"
	case PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED:
		return "SOCKS5_ADDRESS_TYPE_UNSUPPORTED"
	case PACKET_SOCKS5_AUTH_FAILED:
		return "SOCKS5_AUTH_FAILED"
	case PACKET_SOCKS5_UPSTREAM_UNAVAILABLE:
		return "SOCKS5_UPSTREAM_UNAVAILABLE"
	case PACKET_DNS_QUERY_REQ:
		return "DNS_QUERY_REQ"
	case PACKET_DNS_QUERY_RES:
		return "DNS_QUERY_RES"
	case PACKET_ERROR_DROP:
		return "ERROR_DROP"
	default:
		return "PACKET_" + strconv.FormatUint(uint64(packetType), 10)
	}
}
