// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"errors"

	ENUMS "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
)

var (
	ErrPacketTooShort     = errors.New("vpn packet too short")
	ErrInvalidPacketType  = errors.New("invalid vpn packet type")
	ErrInvalidHeaderCheck = errors.New("invalid vpn header check")
	ErrInvalidEncodedData = errors.New("invalid encoded vpn labels")
	ErrCodecUnavailable   = errors.New("vpn codec unavailable")
)

const (
	integrityLength = 2
	minHeaderLength = 4

	packetFlagValid = 1 << iota
	packetFlagStream
	packetFlagSequence
	packetFlagFragment
	packetFlagCompression
)

var packetFlags = buildPacketFlags()

// Header layout copied from the Python parser, with one change:
// `total_data_length` has been removed from the fragment extension.
//
// Base header:
//   [0] Session ID     (1 byte)
//   [1] Packet Type    (1 byte)
//
// Optional extensions by packet type:
//   Stream extension:
//     [2..3] Stream ID         (2 bytes)
//   Sequence extension:
//     [+2]   Sequence Number   (2 bytes)
//   Fragment extension:
//     [+1]   Fragment ID       (1 byte)
//     [+1]   Total Fragments   (1 byte)
//   Compression extension:
//     [+1]   Compression Type  (1 byte)
//
// Integrity footer:
//   [+1] Session Cookie  (1 byte)
//   [+1] Header Check    (1 byte)
//
// Payload starts immediately after the header check byte.

type Packet struct {
	SessionID     uint8
	PacketType    uint8
	SessionCookie uint8

	HasStreamID bool
	StreamID    uint16

	HasSequenceNum bool
	SequenceNum    uint16

	HasFragmentInfo bool
	FragmentID      uint8
	TotalFragments  uint8

	HasCompressionType bool
	CompressionType    uint8

	HeaderLength int
	Payload      []byte
}

func ParseFromLabels(labels string, codec *security.Codec) (Packet, error) {
	if codec == nil {
		return Packet{}, ErrCodecUnavailable
	}
	if labels == "" {
		return Packet{}, ErrInvalidEncodedData
	}

	raw, err := codec.DecodeLowerBase36StringAndDecrypt(labels)
	if err != nil {
		return Packet{}, err
	}

	return Parse(raw)
}

func Parse(data []byte) (Packet, error) {
	return ParseAtOffset(data, 0)
}

func ParseAtOffset(data []byte, offset int) (Packet, error) {
	if offset < 0 || offset >= len(data) {
		return Packet{}, ErrPacketTooShort
	}
	return parseFrom(data, offset)
}

func parseFrom(data []byte, start int) (Packet, error) {
	data = data[start:]
	if len(data) < minHeaderLength {
		return Packet{}, ErrPacketTooShort
	}

	packetType := data[1]
	flags := packetFlags[packetType]
	if flags&packetFlagValid == 0 {
		return Packet{}, ErrInvalidPacketType
	}

	packet := Packet{
		SessionID:  data[0],
		PacketType: packetType,
	}

	offset := 2
	if flags&packetFlagStream != 0 {
		if len(data) < offset+2 {
			return Packet{}, ErrPacketTooShort
		}
		packet.HasStreamID = true
		packet.StreamID = (uint16(data[offset]) << 8) | uint16(data[offset+1])
		offset += 2
	}

	if flags&packetFlagSequence != 0 {
		if len(data) < offset+2 {
			return Packet{}, ErrPacketTooShort
		}
		packet.HasSequenceNum = true
		packet.SequenceNum = (uint16(data[offset]) << 8) | uint16(data[offset+1])
		offset += 2
	}

	if flags&packetFlagFragment != 0 {
		if len(data) < offset+2 {
			return Packet{}, ErrPacketTooShort
		}
		packet.HasFragmentInfo = true
		packet.FragmentID = data[offset]
		packet.TotalFragments = data[offset+1]
		offset += 2
	}

	if flags&packetFlagCompression != 0 {
		if len(data) < offset+1 {
			return Packet{}, ErrPacketTooShort
		}
		packet.HasCompressionType = true
		packet.CompressionType = data[offset]
		offset++
	}

	if len(data) < offset+integrityLength {
		return Packet{}, ErrPacketTooShort
	}

	packet.SessionCookie = data[offset]
	checkByte := data[offset+1]
	expected := computeHeaderCheckByte(data[:offset+1])
	if checkByte != expected {
		return Packet{}, ErrInvalidHeaderCheck
	}

	packet.HeaderLength = offset + integrityLength
	packet.Payload = data[packet.HeaderLength:]
	return packet, nil
}

func computeHeaderCheckByte(header []byte) byte {
	acc := byte((len(header)*17 + 0x5D) & 0xFF)
	for idx, value := range header {
		acc = byte((int(acc) + int(value) + idx) & 0xFF)
		acc ^= byte((int(value) << (idx & 0x03)) & 0xFF)
	}
	return acc
}

func isValidPacketType(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagValid != 0
}

func hasStreamExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagStream != 0
}

func hasSequenceExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagSequence != 0
}

func hasFragmentExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagFragment != 0
}

func hasCompressionExtension(packetType uint8) bool {
	return packetFlags[packetType]&packetFlagCompression != 0
}

func buildPacketFlags() [256]uint8 {
	var flags [256]uint8

	setValid := func(packetType uint8) {
		flags[packetType] |= packetFlagValid
	}
	set := func(packetType uint8, extra uint8) {
		flags[packetType] |= packetFlagValid | extra
	}

	validOnly := [...]uint8{
		ENUMS.PacketMTUUpRes,
		ENUMS.PacketMTUDownReq,
		ENUMS.PacketSessionInit,
		ENUMS.PacketSessionAccept,
		ENUMS.PacketSetMTUReq,
		ENUMS.PacketSetMTURes,
		ENUMS.PacketPing,
		ENUMS.PacketPong,
		ENUMS.PacketErrorDrop,
	}
	for _, packetType := range validOnly {
		setValid(packetType)
	}

	streamAndSeq := [...]uint8{
		ENUMS.PacketStreamSyn,
		ENUMS.PacketStreamSynAck,
		ENUMS.PacketStreamData,
		ENUMS.PacketStreamDataAck,
		ENUMS.PacketStreamResend,
		ENUMS.PacketStreamFin,
		ENUMS.PacketStreamFinAck,
		ENUMS.PacketStreamRST,
		ENUMS.PacketStreamRSTAck,
		ENUMS.PacketStreamKeepalive,
		ENUMS.PacketStreamKeepaliveAck,
		ENUMS.PacketStreamWindowUpdate,
		ENUMS.PacketStreamWindowUpdateAck,
		ENUMS.PacketStreamProbe,
		ENUMS.PacketStreamProbeAck,
		ENUMS.PacketMTUUpReq,
		ENUMS.PacketMTUDownRes,
		ENUMS.PacketSocks5Syn,
		ENUMS.PacketSocks5SynAck,
		ENUMS.PacketSocks5ConnectFail,
		ENUMS.PacketSocks5ConnectFailAck,
		ENUMS.PacketSocks5RulesetDenied,
		ENUMS.PacketSocks5RulesetDeniedAck,
		ENUMS.PacketSocks5NetworkUnreachable,
		ENUMS.PacketSocks5NetworkUnreachableAck,
		ENUMS.PacketSocks5HostUnreachable,
		ENUMS.PacketSocks5HostUnreachableAck,
		ENUMS.PacketSocks5ConnectionRefused,
		ENUMS.PacketSocks5ConnectionRefusedAck,
		ENUMS.PacketSocks5TTLExpired,
		ENUMS.PacketSocks5TTLExpiredAck,
		ENUMS.PacketSocks5CommandUnsupported,
		ENUMS.PacketSocks5CommandUnsupportedAck,
		ENUMS.PacketSocks5AddressTypeUnsupported,
		ENUMS.PacketSocks5AddressTypeUnsupportedAck,
		ENUMS.PacketSocks5AuthFailed,
		ENUMS.PacketSocks5AuthFailedAck,
		ENUMS.PacketSocks5UpstreamUnavailable,
		ENUMS.PacketSocks5UpstreamUnavailableAck,
		ENUMS.PacketDNSQueryReq,
		ENUMS.PacketDNSQueryRes,
	}
	for _, packetType := range streamAndSeq {
		set(packetType, packetFlagStream|packetFlagSequence)
	}

	frag := [...]uint8{
		ENUMS.PacketStreamData,
		ENUMS.PacketStreamResend,
		ENUMS.PacketMTUUpReq,
		ENUMS.PacketMTUDownRes,
		ENUMS.PacketSocks5Syn,
		ENUMS.PacketDNSQueryReq,
		ENUMS.PacketDNSQueryRes,
	}
	for _, packetType := range frag {
		flags[packetType] |= packetFlagFragment
	}

	comp := [...]uint8{
		ENUMS.PacketStreamData,
		ENUMS.PacketStreamResend,
		ENUMS.PacketPackedControlBlocks,
		ENUMS.PacketDNSQueryReq,
		ENUMS.PacketDNSQueryRes,
	}
	for _, packetType := range comp {
		flags[packetType] |= packetFlagValid | packetFlagCompression
	}

	return flags
}
