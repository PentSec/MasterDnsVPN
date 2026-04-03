// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import (
	"errors"
)

var (
	ErrInvalidLowerBase36 = errors.New("invalid lower base36 data")

	lowerBase36Alphabet = [36]byte{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
		'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z',
	}
	lowerBase36DecodeMap = newLowerBase36DecodeMap()
)

func EncodedLenLowerBase36(n int) int {
	if n <= 0 {
		return 0
	}
	// Blocks of 8 bytes -> 13 chars.
	// Remainder mapping:
	// 1:2, 2:4, 3:5, 4:7, 5:8, 6:10, 7:11
	blocks := n / 8
	rem := n % 8
	count := blocks * 13
	switch rem {
	case 1:
		count += 2
	case 2:
		count += 4
	case 3:
		count += 5
	case 4:
		count += 7
	case 5:
		count += 8
	case 6:
		count += 10
	case 7:
		count += 11
	}
	return count
}

func EncodeLowerBase36To(dst []byte, data []byte) int {
	if len(data) == 0 {
		return 0
	}

	offset := 0
	src := data

	// Process in 8-byte blocks
	for len(src) >= 8 {
		val := uint64(src[0])<<56 | uint64(src[1])<<48 |
			uint64(src[2])<<40 | uint64(src[3])<<32 |
			uint64(src[4])<<24 | uint64(src[5])<<16 |
			uint64(src[6])<<8 | uint64(src[7])

		writeBase36Block(dst[offset:], val, 13)
		offset += 13
		src = src[8:]
	}

	// Process remainder
	if len(src) > 0 {
		var val uint64
		for _, b := range src {
			val = (val << 8) | uint64(b)
		}

		charCount := 0
		switch len(src) {
		case 1:
			charCount = 2
		case 2:
			charCount = 4
		case 3:
			charCount = 5
		case 4:
			charCount = 7
		case 5:
			charCount = 8
		case 6:
			charCount = 10
		case 7:
			charCount = 11
		}
		writeBase36Block(dst[offset:], val, charCount)
		offset += charCount
	}

	return offset
}

func writeBase36Block(dst []byte, val uint64, count int) {
	for i := count - 1; i >= 0; i-- {
		dst[i] = lowerBase36Alphabet[val%36]
		val /= 36
	}
}

func EncodeLowerBase36Bytes(data []byte) []byte {
	out := make([]byte, EncodedLenLowerBase36(len(data)))
	n := EncodeLowerBase36To(out, data)
	return out[:n]
}

func EncodeLowerBase36(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return string(EncodeLowerBase36Bytes(data))
}

func DecodeLowerBase36(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	var out []byte
	src := data

	for len(src) > 0 {
		var blockSize, charCount int
		// Since we use fixed lengths for remainders (2, 4, 5, 7, 8, 10, 11)
		// and full blocks are 13, we can decode greedily from the end OR check the total length.
		// Actually, standard block decoding processes from start.
		// We need to know if the current chunk is a full block or the final remainder.

		if len(src) >= 13 {
			// If it's the last 13 chars, it's a block.
			// If it's more than 13 chars, the first 13 MUST be a block.
			blockSize, charCount = 8, 13
		} else {
			// Remainder case
			charCount = len(src)
			switch charCount {
			case 11:
				blockSize = 7
			case 10:
				blockSize = 6
			case 8:
				blockSize = 5
			case 7:
				blockSize = 4
			case 5:
				blockSize = 3
			case 4:
				blockSize = 2
			case 2:
				blockSize = 1
			default:
				// Invalid length for our block encoding
				return nil, ErrInvalidLowerBase36
			}
		}

		val, err := readBase36Block(src[:charCount])
		if err != nil {
			return nil, err
		}

		temp := make([]byte, blockSize)
		for i := blockSize - 1; i >= 0; i-- {
			temp[i] = byte(val)
			val >>= 8
		}
		out = append(out, temp...)
		src = src[charCount:]
	}

	return out, nil
}

func readBase36Block(data []byte) (uint64, error) {
	var val uint64
	for _, ch := range data {
		digit := lowerBase36DecodeMap[ch]
		if digit == 0xFF {
			return 0, ErrInvalidLowerBase36
		}
		val = val*36 + uint64(digit)
	}
	return val, nil
}

func DecodeLowerBase36String(data string) ([]byte, error) {
	return DecodeLowerBase36([]byte(data))
}

func newLowerBase36DecodeMap() [256]byte {
	var table [256]byte
	for i := range table {
		table[i] = 0xFF
	}
	for i, ch := range lowerBase36Alphabet {
		table[ch] = byte(i)
		if ch >= 'a' && ch <= 'z' {
			table[ch-'a'+'A'] = byte(i)
		}
	}
	return table
}

func reverseBytes(data []byte) {
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
}

func fillASCII(data []byte, value byte) {
	for i := 0; i < len(data); i++ {
		data[i] = value
	}
}

func decodeLowerBase36Small(data []byte, leadingZeros int) ([]byte, error) {
	// Not used anymore but kept signatures for compatibility if needed
	return DecodeLowerBase36(data)
}

func decodeLowerBase36SmallString(data string, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36String(data)
}

func decodeLowerBase36LargeBytes(data []byte, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36(data)
}

func decodeLowerBase36LargeString(data string, leadingZeros int) ([]byte, error) {
	return DecodeLowerBase36String(data)
}
