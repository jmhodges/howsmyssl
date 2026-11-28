package h3

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// This is the part of QPACK (RFC 9204) that a peer with no dynamic table
// needs. We tell the peer our dynamic table capacity is zero (the default),
// so every field line it sends us must be a static table reference or a
// literal. We encode only literals, which needs no table at all.

var errQPACK = errors.New("h3: bad QPACK field section")

// headerField is one decoded field line.
type headerField struct {
	Name, Value string
}

// decodeFieldSection decodes an encoded field section (the payload of a
// HEADERS frame). maxSize bounds the decoded size, counted as RFC 9114
// Section 4.2.2 says: name and value lengths plus 32 bytes per field.
func decodeFieldSection(b []byte, maxSize int) ([]headerField, error) {
	// Required Insert Count, then the sign bit and Delta Base.
	ric, b, err := readPrefixInt(b, 8)
	if err != nil {
		return nil, err
	}
	if ric != 0 {
		return nil, fmt.Errorf("%w: dynamic table reference with a zero capacity table", errQPACK)
	}
	if _, b, err = readPrefixInt(b, 7); err != nil {
		return nil, err
	}
	var fields []headerField
	size := 0
	for len(b) > 0 {
		var f headerField
		c := b[0]
		switch {
		case c&0x80 != 0: // Indexed field line: 1Txxxxxx
			if c&0x40 == 0 {
				return nil, fmt.Errorf("%w: dynamic table reference", errQPACK)
			}
			var idx uint64
			idx, b, err = readPrefixInt(b, 6)
			if err != nil {
				return nil, err
			}
			if idx >= uint64(len(staticTable)) {
				return nil, fmt.Errorf("%w: static index %d out of range", errQPACK, idx)
			}
			f = staticTable[idx]
		case c&0xc0 == 0x40: // Literal field line with name reference: 01NTxxxx
			if c&0x10 == 0 {
				return nil, fmt.Errorf("%w: dynamic table reference", errQPACK)
			}
			var idx uint64
			idx, b, err = readPrefixInt(b, 4)
			if err != nil {
				return nil, err
			}
			if idx >= uint64(len(staticTable)) {
				return nil, fmt.Errorf("%w: static index %d out of range", errQPACK, idx)
			}
			f.Name = staticTable[idx].Name
			f.Value, b, err = readString(b, 7)
			if err != nil {
				return nil, err
			}
		case c&0xe0 == 0x20: // Literal field line with literal name: 001NHxxx
			f.Name, b, err = readString(b, 3)
			if err != nil {
				return nil, err
			}
			f.Value, b, err = readString(b, 7)
			if err != nil {
				return nil, err
			}
		default: // 0001xxxx and 0000xxxx are post-base, dynamic table, references.
			return nil, fmt.Errorf("%w: dynamic table reference", errQPACK)
		}
		size += len(f.Name) + len(f.Value) + 32
		if size > maxSize {
			return nil, errHeaderTooLarge
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// readPrefixInt reads an HPACK-style prefixed integer (RFC 7541, Section
// 5.1) whose prefix is the low n bits of b[0].
func readPrefixInt(b []byte, n uint) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, fmt.Errorf("%w: truncated integer", errQPACK)
	}
	mask := uint64(1)<<n - 1
	v := uint64(b[0]) & mask
	b = b[1:]
	if v < mask {
		return v, b, nil
	}
	var shift uint
	for i, c := range b {
		if shift > 56 {
			break
		}
		v += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b[i+1:], nil
		}
		shift += 7
	}
	return 0, nil, fmt.Errorf("%w: bad integer", errQPACK)
}

// readString reads a string literal whose Huffman flag is the bit just above
// an n-bit length prefix in b[0].
func readString(b []byte, n uint) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, fmt.Errorf("%w: truncated string", errQPACK)
	}
	huffman := b[0]&(1<<n) != 0
	l, b, err := readPrefixInt(b, n)
	if err != nil {
		return "", nil, err
	}
	if l > uint64(len(b)) {
		return "", nil, fmt.Errorf("%w: string longer than its field section", errQPACK)
	}
	raw := b[:l]
	b = b[l:]
	if !huffman {
		return string(raw), b, nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %s", errQPACK, err)
	}
	return s, b, nil
}

// appendFieldSection encodes fields as a field section that uses no table:
// a zero prefix and a literal field line with a literal name for each field.
// Names must already be lowercase.
func appendFieldSection(b []byte, fields []headerField) []byte {
	b = append(b, 0, 0) // Required Insert Count 0, Delta Base 0.
	for _, f := range fields {
		b = appendPrefixInt(b, 0x20, 3, uint64(len(f.Name)))
		b = append(b, f.Name...)
		b = appendPrefixInt(b, 0, 7, uint64(len(f.Value)))
		b = append(b, f.Value...)
	}
	return b
}

// appendPrefixInt appends v as an HPACK-style integer with an n-bit prefix,
// putting flags in the bits of the first byte above the prefix.
func appendPrefixInt(b []byte, flags byte, n uint, v uint64) []byte {
	mask := uint64(1)<<n - 1
	if v < mask {
		return append(b, flags|byte(v))
	}
	b = append(b, flags|byte(mask))
	v -= mask
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// staticTable is the QPACK static table, RFC 9204 Appendix A.
var staticTable = [...]headerField{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}
