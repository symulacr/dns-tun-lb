package main

import (
	"strings"
	"unsafe"
)

// hasSuffixDomain reports whether name equals suffix or ends with "." + suffix.
// Case-insensitive; both name and suffix may have trailing dots.
// Zero-allocation: manual byte scan + EqualFold.
func hasSuffixDomain(name, suffix string) bool {
	for len(name) > 0 && name[len(name)-1] == '.' { name = name[:len(name)-1] }
	for len(suffix) > 0 && suffix[len(suffix)-1] == '.' { suffix = suffix[:len(suffix)-1] }
	if len(name) < len(suffix) { return false }
	if len(name) == len(suffix) { return strings.EqualFold(name, suffix) }
	if name[len(name)-len(suffix)-1] == '.' {
		return strings.EqualFold(name[len(name)-len(suffix):], suffix)
	}
	return false
}


// base32DecodeChar decodes a single RFC 4648 base32 character to its 5-bit value.
func base32DecodeChar(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= '2' && c <= '7':
		return c - '2' + 26, true
	case c == '=':
		return 0, true // padding
	default:
		return 0, false // invalid
	}
}

// base32DecodeNoAlloc decodes RFC 4648 base32 (no padding, no newlines)
// into dst and returns the number of bytes written.
// Returns 0 on invalid input. Zero-alloc: all stack buffers.
func base32DecodeNoAlloc(dst, src []byte) int {
	dsti := 0
	for len(src) >= 8 {
		var dbuf [8]uint32
		for j, c := range src[:8] {
			v, ok := base32DecodeChar(c)
			if !ok {
				return 0
			}
			dbuf[j] = uint32(v)
		}
		dst[dsti+0] = byte(dbuf[0]<<3 | dbuf[1]>>2)
		dst[dsti+1] = byte(dbuf[1]<<6 | dbuf[2]<<1 | dbuf[3]>>4)
		dst[dsti+2] = byte(dbuf[3]<<4 | dbuf[4]>>1)
		dst[dsti+3] = byte(dbuf[4]<<7 | dbuf[5]<<2 | dbuf[6]>>3)
		dst[dsti+4] = byte(dbuf[6]<<5 | dbuf[7])
		dsti += 5
		src = src[8:]
	}

	// Handle remaining (< 8 chars)
	if len(src) > 0 {
		var dbuf [8]uint32
		for j, c := range src {
			v, ok := base32DecodeChar(c)
			if !ok {
				return 0
			}
			dbuf[j] = uint32(v)
		}
		switch len(src) {
		case 2:
			dst[dsti] = byte(dbuf[0]<<3 | dbuf[1]>>2)
			dsti++
		case 3, 4:
			dst[dsti+0] = byte(dbuf[0]<<3 | dbuf[1]>>2)
			dst[dsti+1] = byte(dbuf[1]<<6 | dbuf[2]<<1 | dbuf[3]>>4)
			dsti += 2
		case 5, 6:
			dst[dsti+0] = byte(dbuf[0]<<3 | dbuf[1]>>2)
			dst[dsti+1] = byte(dbuf[1]<<6 | dbuf[2]<<1 | dbuf[3]>>4)
			dst[dsti+2] = byte(dbuf[3]<<4 | dbuf[4]>>1)
			dsti += 3
		case 7:
			dst[dsti+0] = byte(dbuf[0]<<3 | dbuf[1]>>2)
			dst[dsti+1] = byte(dbuf[1]<<6 | dbuf[2]<<1 | dbuf[3]>>4)
			dst[dsti+2] = byte(dbuf[3]<<4 | dbuf[4]>>1)
			dst[dsti+3] = byte(dbuf[4]<<7 | dbuf[5]<<2 | dbuf[6]>>3)
			dsti += 4
		}
	}

	return dsti
}


// decodeQnamePrefixPayloadBytes decodes the base32 payload from qname into dst (zero-alloc).
// Returns the number of bytes written to dst, or (0, false) on error.
func decodeQnamePrefixPayloadBytes(qname []byte, suffix string, dst []byte) (int, bool) {
	for len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}
	for len(suffix) > 0 && suffix[len(suffix)-1] == '.' {
		suffix = suffix[:len(suffix)-1]
	}

	if len(suffix) == 0 || len(qname) < len(suffix) {
		return 0, false
	}

	suffixStart := len(qname) - len(suffix)

	// Quick dot check: prefix must be separated from suffix by a dot
	if suffixStart > 0 && qname[suffixStart-1] != '.' {
		return 0, false
	}

	// Verify suffix bytes match (case-insensitive) — O(len(suffix))
	suffixBytes := unsafeStringToBytes(suffix)
	for i := range suffixBytes {
		if qname[suffixStart+i]|0x20 != suffixBytes[i]|0x20 {
			return 0, false
		}
	}

	// No prefix means no payload
	if suffixStart == 0 {
		return 0, false
	}

	// Build encoded prefix from labels — O(len(prefix))
	var encBuf [255]byte
	epos := 0
	labelStart := 0

	for i := 0; i < suffixStart; i++ {
		if qname[i] == '.' {
			if i > labelStart {
				for _, bc := range qname[labelStart:i] {
					if bc >= 'a' && bc <= 'z' {
						bc &^= 0x20
					}
					encBuf[epos] = bc
					epos++
				}
			}
			labelStart = i + 1
		}
	}

	if epos == 0 {
		return 0, false
	}

	// Decode without allocation
	n := base32DecodeNoAlloc(dst, encBuf[:epos])
	if n == 0 {
		return 0, false
	}
	return n, true
}

// unsafeStringToBytes converts a string to a []byte without allocation.
// The caller must not modify the returned slice.
func unsafeStringToBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func extractSessionID(qname, suffix string, protocol string) ([8]byte, bool) {
	var decBuf [160]byte
	n, ok := decodeQnamePrefixPayloadBytes(unsafeStringToBytes(qname), suffix, decBuf[:])
	if !ok || n < 8 {
		return [8]byte{}, false
	}
	var sid [8]byte
	copy(sid[:], decBuf[:8])
	return sid, true
}

// extractSlipstreamSessionIDFromPayload extracts an 8-byte connection ID from a pre-decoded QUIC payload.
// Uses DCID (or SCID if DCID empty) for long header, DCID for short header.
func extractSlipstreamSessionIDFromPayload(payload []byte) ([8]byte, bool) {
	if len(payload) < 7 {
		return [8]byte{}, false
	}
	var id [8]byte
	if payload[0]&0x80 != 0 {
		dcidLen := int(payload[5])
		if len(payload) < 6+dcidLen+1 {
			return [8]byte{}, false
		}
		if dcidLen > 0 {
			dcid := payload[6 : 6+dcidLen]
			copy(id[:], dcid)
			return id, true
		}
		scidLen := int(payload[6+dcidLen])
		const maxCIDLen = 20
		if scidLen <= 0 || scidLen > maxCIDLen || len(payload) < 7+dcidLen+scidLen {
			return [8]byte{}, false
		}
		scid := payload[7+dcidLen : 7+dcidLen+scidLen]
		copy(id[:], scid)
		return id, true
	}
	if len(payload) < 9 {
		return [8]byte{}, false
	}
	copy(id[:], payload[1:9])
	return id, true
}


// decodeSlipstreamQUICLBServerIDFromPayload decodes the QUIC-LB server_id from a pre-decoded payload.
// QUIC-LB CIDs use first octet (config_rotation<<6)|(length-1) with config_rotation=0 and length>=2;
// server_id is at DCID index 1.
func decodeSlipstreamQUICLBServerIDFromPayload(payload []byte) (serverID uint8, ok bool, reason string) {
	if len(payload) < 7 {
		return 0, false, "payload_too_short"
	}
	flags := payload[0]
	if flags&0x80 != 0 {
		dcidLen := int(payload[5])
		if dcidLen < 2 {
			return 0, false, "long_header_dcid_len<2"
		}
		if len(payload) < 6+dcidLen {
			return 0, false, "long_header_payload_short"
		}
		first := payload[6]
		if (first&0xC0) != 0 || (first&0x3F) < 1 {
			return 0, false, "long_header_dcid_not_quiclb"
		}
		return payload[7], true, ""
	}
	first := payload[1]
	if (first&0xC0) != 0 || (first&0x3F) < 1 || len(payload) < 3 {
		return 0, false, "short_header_dcid_not_quiclb"
	}
	return payload[2], true, ""
}
