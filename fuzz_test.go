package main

import (
	stdtls "crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// The fuzz tests here hand attacker-shaped ClientHellos to the same code a
// request goes through: the forked TLS server's handshake (which runs on the
// connection's own goroutine in howhttp, outside net/http's per-request panic
// recovery), the report built from what the fork kept, and the JSON, JSONP and
// HTML renderings of it. Their seed corpora run as plain tests in CI. To fuzz:
//
//	go test -mod=vendor -run '^$' -fuzz '^FuzzClientHelloReport$' -fuzztime 10m .
//	go test -mod=vendor -run '^$' -fuzz '^FuzzClientInfoFromState$' -fuzztime 10m .

// postBadCutover is after every rating cutover, so the date-based downgrades
// all apply.
var postBadCutover = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

// FuzzClientHelloReport feeds raw bytes, as if a client sent them on a fresh
// connection, to the forked TLS server with the production config, and then
// builds and renders the report from whatever ClientHello the fork kept. The
// handshake can never finish (nothing answers the server's flight), but the
// fork keeps the ClientHello as soon as it has read one, which is all the
// report reads.
func FuzzClientHelloReport(f *testing.F) {
	for _, hello := range seedClientHellos(f) {
		f.Add(hello, "")
		f.Add(hello, "cb_1")
	}
	f.Fuzz(func(t *testing.T, stream []byte, callback string) {
		conn := &replayConn{r: strings.NewReader(string(stream))}
		srv := tls.Server(conn, serverConf)
		// The error is expected: either the bytes aren't a hello the fork
		// accepts, or the stream ends before the client's second flight.
		_ = srv.Handshake()
		st := srv.ConnectionState()
		checkReport(t, st, callback)
	})
}

// FuzzClientInfoFromState reaches clientInfoFromState with lists the fork's
// parser may never produce (any length, any values, any version), so the
// report code's own assumptions get tested apart from the fork's.
func FuzzClientInfoFromState(f *testing.F) {
	for _, hello := range seedClientHellos(f) {
		conn := &replayConn{r: strings.NewReader(string(hello))}
		srv := tls.Server(conn, serverConf)
		_ = srv.Handshake()
		f.Add(encodeState(srv.ConnectionState()))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		checkReport(t, decodeState(data), "")
	})
}

var loadIndexOnce sync.Once

func checkReport(t *testing.T, st tls.ConnectionState, callback string) {
	t.Helper()
	loadIndexOnce.Do(func() {
		if index == nil {
			index = loadIndex()
		}
	})
	inputLen := len(st.ClientCipherSuites) + len(st.CompressionMethods) + len(st.SupportedVersions) + len(st.SupportedCurves) + len(st.SupportedSignatureAlgorithms)
	for _, now := range []time.Time{preCutover, postBadCutover} {
		d := clientInfoFromState(st, now)
		switch d.Rating {
		case okay, improvable, bad:
		default:
			t.Fatalf("unknown rating %q", d.Rating)
		}
		if len(d.GivenCipherSuites) != len(st.ClientCipherSuites) {
			t.Fatalf("given_cipher_suites has %d entries, the hello had %d", len(d.GivenCipherSuites), len(st.ClientCipherSuites))
		}
		if len(d.GivenNamedGroups) != len(st.SupportedCurves) {
			t.Fatalf("given_named_groups has %d entries, the hello had %d", len(d.GivenNamedGroups), len(st.SupportedCurves))
		}
		if len(d.GivenSignatureAlgorithms) != len(st.SupportedSignatureAlgorithms) {
			t.Fatalf("given_signature_algorithms has %d entries, the hello had %d", len(d.GivenSignatureAlgorithms), len(st.SupportedSignatureAlgorithms))
		}
		for s, reasons := range d.InsecureCipherSuites {
			if len(reasons) == 0 {
				t.Fatalf("insecure suite %q listed with no reason", s)
			}
		}

		r := httptest.NewRequest("GET", "/a/check?callback="+url.QueryEscape(callback), nil)
		body, _, contentType, err := allowedRenderJSON(r, d)
		if err != nil {
			t.Fatalf("allowedRenderJSON: %s", err)
		}
		// The report is the hello's lists spelled out, so it's expected to
		// grow with the hello, but only by a fixed amount per entry.
		if max := 4096 + 256*inputLen + 2*len(callback); len(body) > max {
			t.Fatalf("JSON body is %d bytes for %d hello entries, more than %d", len(body), inputLen, max)
		}
		if contentType == "application/javascript" {
			open := strings.IndexByte(string(body), '(')
			if open < 1 || !isAlnum(string(body[:open])) || !strings.HasSuffix(string(body), ");") {
				t.Fatalf("JSONP body has a callback that isn't letters and digits: %.80q", body)
			}
			body = body[open+1 : len(body)-2]
		}
		var back clientInfo
		if err := json.Unmarshal(body, &back); err != nil {
			t.Fatalf("report JSON doesn't parse: %s", err)
		}
		if back.Rating != d.Rating || len(back.GivenCipherSuites) != len(d.GivenCipherSuites) {
			t.Fatalf("report JSON doesn't round-trip")
		}

		html, _, _, err := renderHTML(r, d)
		if err != nil {
			t.Fatalf("renderHTML: %s", err)
		}
		if max := 65536 + 512*inputLen; len(html) > max {
			t.Fatalf("HTML body is %d bytes for %d hello entries, more than %d", len(html), inputLen, max)
		}
	}
}

func isAlnum(s string) bool {
	return !nonAlphaNumeric.MatchString(s)
}

// encodeState and decodeState are FuzzClientInfoFromState's input format: a
// version, a flags byte, then five lists, each a 2-byte count and that many
// entries (2 bytes, or 1 for compression methods). Short input ends the lists
// early.
func encodeState(st tls.ConnectionState) []byte {
	b := binary.BigEndian.AppendUint16(nil, st.Version)
	var flags byte
	if st.SessionTicketsSupported {
		flags |= 1
	}
	if st.NMinusOneRecordSplittingDetected {
		flags |= 2
	}
	if st.AbleToDetectNMinusOneSplitting {
		flags |= 4
	}
	b = append(b, flags)
	b = appendUint16s(b, st.ClientCipherSuites)
	b = binary.BigEndian.AppendUint16(b, uint16(len(st.CompressionMethods)))
	b = append(b, st.CompressionMethods...)
	b = appendUint16s(b, st.SupportedVersions)
	curves := make([]uint16, len(st.SupportedCurves))
	for i, c := range st.SupportedCurves {
		curves[i] = uint16(c)
	}
	b = appendUint16s(b, curves)
	sigs := make([]uint16, len(st.SupportedSignatureAlgorithms))
	for i, s := range st.SupportedSignatureAlgorithms {
		sigs[i] = uint16(s)
	}
	return appendUint16s(b, sigs)
}

func appendUint16s(b []byte, vs []uint16) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(vs)))
	for _, v := range vs {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

func decodeState(data []byte) tls.ConnectionState {
	st := tls.ConnectionState{HandshakeComplete: true}
	d := stateDecoder{b: data}
	st.Version = d.uint16()
	flags := d.byte()
	st.SessionTicketsSupported = flags&1 != 0
	st.NMinusOneRecordSplittingDetected = flags&2 != 0
	st.AbleToDetectNMinusOneSplitting = flags&4 != 0
	st.ClientCipherSuites = d.uint16s()
	n := int(d.uint16())
	for i := 0; i < n && len(d.b) > 0; i++ {
		st.CompressionMethods = append(st.CompressionMethods, d.byte())
	}
	st.SupportedVersions = d.uint16s()
	for _, c := range d.uint16s() {
		st.SupportedCurves = append(st.SupportedCurves, tls.CurveID(c))
	}
	for _, s := range d.uint16s() {
		st.SupportedSignatureAlgorithms = append(st.SupportedSignatureAlgorithms, tls.SignatureScheme(s))
	}
	return st
}

type stateDecoder struct{ b []byte }

func (d *stateDecoder) byte() byte {
	if len(d.b) == 0 {
		return 0
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v
}

func (d *stateDecoder) uint16() uint16 {
	return uint16(d.byte())<<8 | uint16(d.byte())
}

func (d *stateDecoder) uint16s() []uint16 {
	n := int(d.uint16())
	var vs []uint16
	for i := 0; i < n && len(d.b) >= 2; i++ {
		vs = append(vs, d.uint16())
	}
	return vs
}

// replayConn is a net.Conn whose peer sends exactly the bytes in r and then
// hangs up, and that discards whatever is written to it.
type replayConn struct {
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *replayConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *replayConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "192.0.2.1:443" }

var (
	seedHellosOnce sync.Once
	seedHellos     [][]byte
)

// seedClientHellos returns the first flight (the ClientHello records) of
// real clients: Go's crypto/tls, the fork's own client, and zcrypto's, in
// the shapes the other tests here use.
func seedClientHellos(tb testing.TB) [][]byte {
	seedHellosOnce.Do(func() {
		std := []*stdtls.Config{
			{},
			{MaxVersion: stdtls.VersionTLS12},
			{MinVersion: stdtls.VersionTLS10, MaxVersion: stdtls.VersionTLS10, CipherSuites: []uint16{stdtls.TLS_RSA_WITH_AES_128_CBC_SHA}},
			{CurvePreferences: []stdtls.CurveID{stdtls.X25519MLKEM768, stdtls.X25519}},
			{MinVersion: stdtls.VersionTLS13, CurvePreferences: []stdtls.CurveID{stdtls.CurveP256}},
			{NextProtos: []string{"h2", "http/1.1"}, ClientSessionCache: stdtls.NewLRUClientSessionCache(1)},
		}
		for _, c := range std {
			c.ServerName = "localhost"
			seedHellos = append(seedHellos, captureFirstFlight(func(nc net.Conn) error {
				return stdtls.Client(nc, c).Handshake()
			}))
		}
		fork := []*tls.Config{
			{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}},
			{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}},
		}
		for _, c := range fork {
			c.ServerName = "localhost"
			seedHellos = append(seedHellos, captureFirstFlight(func(nc net.Conn) error {
				return tls.Client(nc, c).Handshake()
			}))
		}
		z := []*ztls.Config{
			{CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519}},
			{
				MaxVersion:   ztls.VersionTLS12,
				ForceSuites:  true,
				CipherSuites: []uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 0x0a0a, 0x00ff},
			},
			{MinVersion: ztls.VersionTLS10, MaxVersion: ztls.VersionTLS10, ForceSuites: true, CipherSuites: []uint16{ztls.TLS_RSA_WITH_RC4_128_MD5, 0x0003, 0x0000, 0xfeff}},
		}
		for _, c := range z {
			c.ServerName = "localhost"
			c.InsecureSkipVerify = true
			seedHellos = append(seedHellos, captureFirstFlight(func(nc net.Conn) error {
				return ztls.Client(nc, c).Handshake()
			}))
		}
	})
	for i, h := range seedHellos {
		if len(h) < 5 || h[0] != 22 {
			tb.Fatalf("seed hello %d isn't a handshake record: %x", i, h)
		}
	}
	return seedHellos
}

// captureFirstFlight runs a client handshake against a peer that never
// answers, and returns the whole records the client sent before it waited.
func captureFirstFlight(handshake func(net.Conn) error) []byte {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handshake(client)
	}()
	var out []byte
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(server, hdr); err != nil {
			break
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
		if _, err := io.ReadFull(server, body); err != nil {
			break
		}
		out = append(out, hdr...)
		out = append(out, body...)
		// A ClientHello fits a record unless it's huge; stop once the
		// first handshake message is whole.
		if len(out) >= 9 && len(out)-5 >= 4+(int(out[6])<<16|int(out[7])<<8|int(out[8])) {
			break
		}
		server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	}
	server.Close()
	client.Close()
	<-done
	return out
}
