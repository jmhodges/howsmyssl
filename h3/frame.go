package h3

import (
	"errors"
	"fmt"
	"io"
)

// Frame types, RFC 9114 Section 7.2.
const (
	frameData        = 0x00
	frameHeaders     = 0x01
	frameCancelPush  = 0x03
	frameSettings    = 0x04
	framePushPromise = 0x05
	frameGoAway      = 0x07
	frameMaxPushID   = 0x0d
)

// Unidirectional stream types, RFC 9114 Section 6.2 and RFC 9204 Section 4.2.
const (
	streamControl      = 0x00
	streamPush         = 0x01
	streamQPACKEncoder = 0x02
	streamQPACKDecoder = 0x03
)

// Error codes, RFC 9114 Section 8.1 and RFC 9204 Section 6.
const (
	errCodeNoError              = 0x100
	errCodeGeneralProtocol      = 0x101
	errCodeInternal             = 0x102
	errCodeStreamCreation       = 0x103
	errCodeClosedCriticalStream = 0x104
	errCodeFrameUnexpected      = 0x105
	errCodeFrame                = 0x106
	errCodeExcessiveLoad        = 0x107
	errCodeMissingSettings      = 0x10a
	errCodeRequestRejected      = 0x10b
	errCodeRequestIncomplete    = 0x10d
	errCodeMessage              = 0x10e
	errCodeQPACKDecompression   = 0x200
)

var errHeaderTooLarge = errors.New("h3: header section too large")

// h3Error is a connection or stream error with its HTTP/3 error code.
type h3Error struct {
	code uint64
	msg  string
}

func (e *h3Error) Error() string { return fmt.Sprintf("h3: %s (code %#x)", e.msg, e.code) }

// readVarint reads a QUIC variable-length integer (RFC 9000, Section 16).
func readVarint(r io.ByteReader) (uint64, error) {
	c, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (c >> 6)
	v := uint64(c & 0x3f)
	for i := 1; i < n; i++ {
		c, err = r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// appendVarint appends v as a QUIC variable-length integer. v must be less
// than 2^62.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x40|byte(v>>8), byte(v))
	case v < 1<<30:
		return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, 0xc0|byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// appendFrameHeader appends a frame's type and length.
func appendFrameHeader(b []byte, typ, length uint64) []byte {
	b = appendVarint(b, typ)
	return appendVarint(b, length)
}

// byteReadReader is what a QUIC stream gives us.
type byteReadReader interface {
	io.Reader
	io.ByteReader
}

// readFrameHeader reads a frame's type and length. It returns io.EOF only
// when the stream ends cleanly before a new frame.
func readFrameHeader(r io.ByteReader) (typ, length uint64, err error) {
	typ, err = readVarint(r)
	if err != nil {
		return 0, 0, err
	}
	length, err = readVarint(r)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return typ, length, err
}

// isReservedHTTP2Frame reports whether typ is a frame type that HTTP/2 used
// and HTTP/3 reserves; receiving one is a connection error (RFC 9114,
// Section 7.2.8).
func isReservedHTTP2Frame(typ uint64) bool {
	switch typ {
	case 0x02, 0x06, 0x08, 0x09:
		return true
	}
	return false
}

// discard reads and drops n bytes from r.
func discard(r io.Reader, n uint64) error {
	_, err := io.CopyN(io.Discard, r, int64(n))
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}
