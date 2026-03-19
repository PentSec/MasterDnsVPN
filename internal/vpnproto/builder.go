// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import "masterdnsvpn-go/internal/security"

type BuildOptions struct {
	SessionID       uint8
	PacketType      uint8
	SessionCookie   uint8
	StreamID        uint16
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
}

func BuildRaw(opts BuildOptions) ([]byte, error) {
	flags := packetFlags[opts.PacketType]
	if flags&packetFlagValid == 0 {
		return nil, ErrInvalidPacketType
	}

	headerLen := HeaderRawSize(opts.PacketType)
	raw := make([]byte, 0, headerLen+len(opts.Payload))
	raw = append(raw, opts.SessionID, opts.PacketType)

	if flags&packetFlagStream != 0 {
		raw = append(raw, byte(opts.StreamID>>8), byte(opts.StreamID))
	}
	if flags&packetFlagSequence != 0 {
		raw = append(raw, byte(opts.SequenceNum>>8), byte(opts.SequenceNum))
	}
	if flags&packetFlagFragment != 0 {
		raw = append(raw, opts.FragmentID, opts.TotalFragments)
	}
	if flags&packetFlagCompression != 0 {
		raw = append(raw, opts.CompressionType)
	}

	raw = append(raw, opts.SessionCookie)
	raw = append(raw, computeHeaderCheckByte(raw))
	raw = append(raw, opts.Payload...)
	return raw, nil
}

func BuildEncoded(opts BuildOptions, codec *security.Codec) (string, error) {
	raw, err := BuildRaw(opts)
	if err != nil {
		return "", err
	}
	if codec == nil {
		return "", ErrCodecUnavailable
	}
	return codec.EncryptAndEncodeLowerBase36(raw)
}

func HeaderRawSize(packetType uint8) int {
	flags := packetFlags[packetType]
	if flags&packetFlagValid == 0 {
		return 0
	}

	size := 2 + integrityLength
	if flags&packetFlagStream != 0 {
		size += 2
	}
	if flags&packetFlagSequence != 0 {
		size += 2
	}
	if flags&packetFlagFragment != 0 {
		size += 2
	}
	if flags&packetFlagCompression != 0 {
		size++
	}
	return size
}

func MaxHeaderRawSize() int {
	maxSize := 0
	for packetType := range len(packetFlags) {
		size := HeaderRawSize(uint8(packetType))
		if size > maxSize {
			maxSize = size
		}
	}
	return maxSize
}

func MaxHeaderPacketType() uint8 {
	var bestType uint8
	maxSize := 0
	for packetType := range len(packetFlags) {
		size := HeaderRawSize(uint8(packetType))
		if size > maxSize {
			maxSize = size
			bestType = uint8(packetType)
		}
	}
	return bestType
}
