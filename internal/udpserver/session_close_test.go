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

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestHandlePacketSessionCloseCleansSessionState(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:              65535,
		Domain:                     []string{"a.com"},
		MinVPNLabelLength:          3,
		ClosedSessionRetentionSecs: 600.0,
	}, nil, codec)

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	now := time.Unix(1700000000, 0)

	if _, ok := srv.streams.EnsureOpen(sessionID, 7, now); !ok {
		t.Fatal("expected stream state to open")
	}
	if !srv.queueMainSessionPacket(sessionID, VpnProto.Packet{PacketType: Enums.PACKET_PING}) {
		t.Fatal("expected outbound packet to enqueue")
	}

	if _, ready, completed := srv.collectDNSQueryFragments(sessionID, 31, []byte{0xAA}, 0, 2, now); ready || completed {
		t.Fatalf("expected first fragment to remain incomplete, ready=%v completed=%v", ready, completed)
	}

	closeQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_SESSION_CLOSE, nil)
	if response := srv.handlePacket(closeQuery); len(response) != 0 {
		t.Fatal("session close notifications must not produce a response")
	}

	if srv.sessions.HasActive(sessionID) {
		t.Fatal("session should be removed after session close")
	}
	if srv.streams.Exists(sessionID, 7) {
		t.Fatal("stream state should be cleared after session close")
	}
	if srv.queueMainSessionPacket(sessionID, VpnProto.Packet{PacketType: Enums.PACKET_PING}) {
		t.Fatal("closed session must reject new outbound packets")
	}

	lookup, known := srv.sessions.Lookup(sessionID)
	if !known || lookup.State != sessionLookupClosed {
		t.Fatalf("expected closed session retention marker, known=%v state=%d", known, lookup.State)
	}

	if _, ready, completed := srv.collectDNSQueryFragments(sessionID, 31, []byte{0xBB}, 1, 2, now.Add(time.Second)); ready || completed {
		t.Fatalf("expected session fragment cache to be cleared, ready=%v completed=%v", ready, completed)
	}
}
