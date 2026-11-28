package h3

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/http2/hpack"
)

func TestDecodeFieldSection(t *testing.T) {
	huffName := hpack.AppendHuffmanString(nil, "x-test")
	huffValue := hpack.AppendHuffmanString(nil, "a Huffman-coded value")
	tests := []struct {
		name string
		in   []byte
		want []headerField
	}{
		{
			name: "indexed static",
			// :method GET (17), :scheme https (23), :path / (1)
			in:   []byte{0, 0, 0xc0 | 17, 0xc0 | 23, 0xc0 | 1},
			want: []headerField{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}},
		},
		{
			name: "indexed static past the 6-bit prefix",
			// user-agent "" (95) and x-frame-options sameorigin (98).
			in:   []byte{0, 0, 0xff, 95 - 63, 0xff, 98 - 63},
			want: []headerField{{"user-agent", ""}, {"x-frame-options", "sameorigin"}},
		},
		{
			name: "literal with static name reference",
			// :authority (0) = "example.com"
			in:   append([]byte{0, 0, 0x50 | 0, 11}, "example.com"...),
			want: []headerField{{":authority", "example.com"}},
		},
		{
			name: "literal with static name reference past the 4-bit prefix",
			// user-agent (95) = "ua"
			in:   append([]byte{0, 0, 0x5f, 95 - 15, 2}, "ua"...),
			want: []headerField{{"user-agent", "ua"}},
		},
		{
			name: "literal with literal name",
			in:   append(append([]byte{0, 0, 0x20 | 6}, "x-test"...), append([]byte{3}, "abc"...)...),
			want: []headerField{{"x-test", "abc"}},
		},
		{
			name: "literal with Huffman name and value",
			in: append(append(append([]byte{0, 0, 0x28 | byte(len(huffName))}, huffName...),
				0x80|byte(len(huffValue))), huffValue...),
			want: []headerField{{"x-test", "a Huffman-coded value"}},
		},
		{
			name: "nonzero delta base is ignored",
			in:   []byte{0, 0x85, 0xc0 | 17},
			want: []headerField{{":method", "GET"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeFieldSection(tc.in, DefaultMaxHeaderBytes)
			if err != nil {
				t.Fatalf("decodeFieldSection: %s", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("fields (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecodeFieldSectionErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"required insert count", []byte{1, 0, 0xc0 | 17}},
		{"indexed dynamic", []byte{0, 0, 0x80 | 1}},
		{"name reference dynamic", []byte{0, 0, 0x40 | 1, 0}},
		{"indexed post-base", []byte{0, 0, 0x10}},
		{"literal post-base name", []byte{0, 0, 0x00}},
		{"static index out of range", []byte{0, 0, 0xff, 99 - 63}},
		{"name reference out of range", []byte{0, 0, 0x5f, 99 - 15, 0}},
		{"string longer than section", []byte{0, 0, 0x50, 10, 'a'}},
		{"truncated integer", []byte{0, 0, 0xff}},
		{"integer too long", []byte{0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
		{"bad Huffman", []byte{0, 0, 0x50, 0x81, 0xff}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeFieldSection(tc.in, DefaultMaxHeaderBytes)
			if !errors.Is(err, errQPACK) {
				t.Errorf("decodeFieldSection: want an errQPACK error, got %v", err)
			}
		})
	}
}

func TestDecodeFieldSectionSizeLimit(t *testing.T) {
	in := appendFieldSection(nil, []headerField{{"a", "b"}, {"c", "d"}})
	// Each field counts as 1 + 1 + 32 = 34.
	if _, err := decodeFieldSection(in, 68); err != nil {
		t.Errorf("at the limit: %s", err)
	}
	if _, err := decodeFieldSection(in, 67); !errors.Is(err, errHeaderTooLarge) {
		t.Errorf("over the limit: want errHeaderTooLarge, got %v", err)
	}
}

func TestFieldSectionRoundTrip(t *testing.T) {
	long := string(make([]byte, 300))
	want := []headerField{
		{":status", "200"},
		{"content-type", "application/json"},
		{"x-long-name-to-pass-the-three-bit-prefix", long},
		{"empty", ""},
	}
	got, err := decodeFieldSection(appendFieldSection(nil, want), 1<<20)
	if err != nil {
		t.Fatalf("decodeFieldSection: %s", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("fields (-want +got):\n%s", diff)
	}
}

func TestPrefixIntRoundTrip(t *testing.T) {
	for _, n := range []uint{3, 4, 6, 7, 8} {
		for _, v := range []uint64{0, 1, 1<<n - 2, 1<<n - 1, 1 << n, 127, 128, 300, 1 << 20, 1<<40 + 3} {
			b := appendPrefixInt(nil, 0, n, v)
			got, rest, err := readPrefixInt(b, n)
			if err != nil || got != v || len(rest) != 0 {
				t.Errorf("n=%d v=%d: got %d, %d bytes left, err %v", n, v, got, len(rest), err)
			}
		}
	}
}

func TestStaticTableSize(t *testing.T) {
	// RFC 9204 Appendix A has 99 entries. Their contents were checked against
	// ls-qpack's table when this was written.
	if len(staticTable) != 99 {
		t.Errorf("static table has %d entries, want 99", len(staticTable))
	}
	if staticTable[17] != (headerField{":method", "GET"}) || staticTable[98] != (headerField{"x-frame-options", "sameorigin"}) {
		t.Errorf("static table entries out of place")
	}
}

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1} {
		b := appendVarint(nil, v)
		got, err := readVarint(&byteSliceReader{b: b})
		if err != nil || got != v {
			t.Errorf("v=%d: got %d, err %v", v, got, err)
		}
	}
}

type byteSliceReader struct{ b []byte }

func (r *byteSliceReader) ReadByte() (byte, error) {
	if len(r.b) == 0 {
		return 0, errors.New("EOF")
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}
