// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"bytes"
	"encoding/binary"
	"testing"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	ENUMS "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VPNProto "masterdnsvpn-go/internal/vpnproto"
)

func TestHandlePacketDropsDNSResponses(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x1001, "vpn.a.com", ENUMS.DNSRecordTypeTXT)
	packet[2] |= 0x80

	if response := srv.handlePacket(packet); response != nil {
		t.Fatal("handlePacket should drop DNS response packets")
	}
}

func TestHandlePacketReturnsNoDataForUnauthorizedDomain(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x2002, "evil.com", ENUMS.DNSRecordTypeTXT)
	response := srv.handlePacket(packet)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a DNS response for unauthorized DNS queries")
	}

	if got := binary.BigEndian.Uint16(response[0:2]); got != 0x2002 {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0x2002)
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x000F != ENUMS.DNSRCodeNoError {
		t.Fatalf("unexpected rcode: got=%d want=%d", flags&0x000F, ENUMS.DNSRCodeNoError)
	}
}

func TestHandlePacketRespondsToMTUUpProbe(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x11, 0x22, 0x33, 0x44}
	payload := append([]byte{0}, verifyCode...)
	payload = append(payload, bytes.Repeat([]byte{0xAB}, 64)...)
	query := buildTunnelQuery(t, codec, "a.com", ENUMS.PacketMTUUpReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != ENUMS.PacketMTUUpRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, ENUMS.PacketMTUUpRes)
	}
	if len(packet.Payload) != 6 {
		t.Fatalf("unexpected mtu-up response length: got=%d want=%d", len(packet.Payload), 6)
	}
	if !bytes.Equal(packet.Payload[:4], verifyCode) {
		t.Fatalf("unexpected echoed verify code: got=%v want=%v", packet.Payload[:4], verifyCode)
	}
	if got := int(binary.BigEndian.Uint16(packet.Payload[4:6])); got != len(payload) {
		t.Fatalf("unexpected echoed mtu size: got=%d want=%d", got, len(payload))
	}
}

func TestHandlePacketRespondsToMTUDownProbe(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	payload := make([]byte, 128)
	payload[0] = 0
	copy(payload[1:5], verifyCode)
	binary.BigEndian.PutUint16(payload[5:7], 128)
	copy(payload[7:], bytes.Repeat([]byte{0xAB}, len(payload)-7))
	query := buildTunnelQuery(t, codec, "a.com", ENUMS.PacketMTUDownReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-down response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != ENUMS.PacketMTUDownRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, ENUMS.PacketMTUDownRes)
	}
	if len(packet.Payload) != 128 {
		t.Fatalf("unexpected mtu-down payload length: got=%d want=%d", len(packet.Payload), 128)
	}
	if !bytes.Equal(packet.Payload[:4], verifyCode) {
		t.Fatalf("unexpected mtu-down verify prefix: got=%v want=%v", packet.Payload[:4], verifyCode)
	}
	if got := int(binary.BigEndian.Uint16(packet.Payload[4:6])); got != 128 {
		t.Fatalf("unexpected mtu-down echoed size: got=%d want=%d", got, 128)
	}
}

func TestHandlePacketRespondsToMTUUpProbeBaseEncoded(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x10, 0x20, 0x30, 0x40}
	payload := append([]byte{1}, verifyCode...)
	payload = append(payload, bytes.Repeat([]byte{0xAB}, 40)...)
	query := buildTunnelQuery(t, codec, "a.com", ENUMS.PacketMTUUpReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != ENUMS.PacketMTUUpRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, ENUMS.PacketMTUUpRes)
	}
	if !bytes.Equal(packet.Payload[:4], verifyCode) {
		t.Fatalf("unexpected echoed verify code: got=%v want=%v", packet.Payload[:4], verifyCode)
	}
}

func buildServerTestQuery(id uint16, name string, qtype uint16) []byte {
	qname := encodeServerTestName(name)
	packet := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)

	offset := 12
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], ENUMS.DNSQClassIN)
	return packet
}

func encodeServerTestName(name string) []byte {
	encoded := make([]byte, 0, len(name)+2)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}
		encoded = append(encoded, byte(i-labelStart))
		encoded = append(encoded, name[labelStart:i]...)
		labelStart = i + 1
	}
	return append(encoded, 0)
}

func buildTunnelQuery(t *testing.T, codec *security.Codec, name string, packetType uint8, payload []byte) []byte {
	t.Helper()

	encoded, err := VPNProto.BuildEncoded(VPNProto.BuildOptions{
		SessionID:      255,
		PacketType:     packetType,
		StreamID:       1,
		SequenceNum:    1,
		TotalFragments: 1,
		Payload:        payload,
	}, codec)
	if err != nil {
		t.Fatalf("BuildEncoded returned error: %v", err)
	}

	questionName, err := DnsParser.BuildTunnelQuestionName(name, encoded)
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}

	query, err := DnsParser.BuildTXTQuestionPacket(questionName, ENUMS.DNSRecordTypeTXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	return query
}
