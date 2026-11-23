package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/cryptobyte"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// The JSON keys that report what else the ClientHello says. None of them may
// change anything in signalsOldJSONKeys.
var signalsJSONKeys = []string{
	"server_name_sent",
	"given_alpn_protocols",
	"secure_renegotiation_supported",
	"given_key_share_groups",
	"encrypted_client_hello_offered",
}

// The JSON keys the API had before signalsJSONKeys were added.
var signalsOldJSONKeys = []string{
	"given_cipher_suites",
	"given_named_groups",
	"given_signature_algorithms",
	"given_psk_key_exchange_modes",
	"post_quantum_key_agreement",
	"ephemeral_keys_supported",
	"session_ticket_supported",
	"psk_without_forward_secrecy_supported",
	"tls_compression_supported",
	"unknown_cipher_suite_supported",
	"beast_vuln",
	"able_to_detect_n_minus_one_splitting",
	"insecure_cipher_suites",
	"tls_version",
	"rating",
}

// serverSideState is serverSideConn for tests that only want the state.
func serverSideState(t testing.TB, conf *tls.Config, client func(net.Conn) error) (st tls.ConnectionState, serverErr, clientErr error) {
	t.Helper()
	s, serverErr, clientErr := serverSideConn(t, conf, client)
	return s.ConnectionState(), serverErr, clientErr
}

// handshakeState is serverSideState for the fork's own client and the
// production TLS config.
func handshakeState(t testing.TB, clientConf *tls.Config) (st tls.ConnectionState, clientErr error) {
	t.Helper()
	return handshakeStateWithServer(t, serverConf, clientConf)
}

func handshakeStateWithServer(t testing.TB, conf, clientConf *tls.Config) (st tls.ConnectionState, clientErr error) {
	t.Helper()
	if clientConf.ServerName == "" {
		clientConf.ServerName = "localhost"
	}
	clientConf.RootCAs = x509.NewCertPool()
	clientConf.RootCAs.AddCert(rootCA)
	st, serverErr, clientErr := serverSideState(t, conf, func(c net.Conn) error {
		return tls.Client(c, clientConf).Handshake()
	})
	if serverErr != nil {
		t.Fatalf("server handshake: %s (client: %v)", serverErr, clientErr)
	}
	return st, clientErr
}

func TestClientHelloSignals(t *testing.T) {
	type want struct {
		serverNameSent bool
		alpn           []string
		secureReneg    bool
		keyShares      []string
		ech            bool
	}
	check := func(t *testing.T, st tls.ConnectionState, w want) {
		t.Helper()
		ci := clientInfoFromState(st, preCutover)
		got := want{ci.ServerNameSent, ci.GivenALPNProtocols, ci.SecureRenegotiationSupported, ci.GivenKeyShareGroups, ci.EncryptedClientHelloOffered}
		if diff := cmp.Diff(w, got, cmp.AllowUnexported(want{})); diff != "" {
			t.Errorf("signals (-want +got):\n%s", diff)
		}
	}

	t.Run("GoDefault", func(t *testing.T) {
		st, err := handshakeState(t, &tls.Config{})
		if err != nil {
			t.Fatalf("client handshake: %s", err)
		}
		// Go sends a key share for the hybrid and one for its classical
		// half, and lists more groups than that as supported.
		check(t, st, want{true, []string{}, true, []string{"X25519MLKEM768", "x25519"}, false})
		ci := clientInfoFromState(st, preCutover)
		if len(ci.GivenNamedGroups) <= len(ci.GivenKeyShareGroups) {
			t.Errorf("want more supported groups than key shares, got %v and %v", ci.GivenNamedGroups, ci.GivenKeyShareGroups)
		}
	})

	t.Run("ALPN", func(t *testing.T) {
		st, err := handshakeState(t, &tls.Config{NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			t.Fatalf("client handshake: %s", err)
		}
		check(t, st, want{true, []string{"h2", "http/1.1"}, true, []string{"X25519MLKEM768", "x25519"}, false})
	})

	// Protocol names are the client's bytes. Repeats are shown as sent.
	t.Run("ALPNHostile", func(t *testing.T) {
		st, err := handshakeState(t, &tls.Config{NextProtos: []string{
			"http/1.1",
			"http/1.1",
			"<script>alert(1)</script>",
			"\");alert('x');//",
			"\xff\x00\\x41 \n",
			strings.Repeat("a", 255),
		}})
		if err != nil {
			t.Fatalf("client handshake: %s", err)
		}
		check(t, st, want{true, []string{
			"http/1.1",
			"http/1.1",
			`\x3cscript\x3ealert\x281\x29\x3c/script\x3e`,
			`\x22\x29\x3balert\x28\x27x\x27\x29\x3b//`,
			`\xff\x00\x5cx41\x20\x0a`,
			strings.Repeat("a", 32) + " (truncated)",
		}, true, []string{"X25519MLKEM768", "x25519"}, false})
	})

	t.Run("TLS12", func(t *testing.T) {
		st, err := handshakeState(t, &tls.Config{MaxVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatalf("client handshake: %s", err)
		}
		check(t, st, want{true, []string{}, true, []string{}, false})
	})

	// The key shares reported are those of the first ClientHello. The
	// production config takes any group Go's client sends a share for, so
	// this server is one that only takes P-384: the client's first shares
	// are no use to it, it asks for P-384 with a HelloRetryRequest, and the
	// second ClientHello carries that share instead.
	t.Run("HelloRetryRequest", func(t *testing.T) {
		conf := serverConf.Clone()
		conf.CurvePreferences = []tls.CurveID{tls.CurveP384}
		st, err := handshakeStateWithServer(t, conf, &tls.Config{})
		if err != nil {
			t.Fatalf("client handshake: %s", err)
		}
		if !st.HelloRetryRequest {
			t.Fatalf("want a HelloRetryRequest, got none")
		}
		if st.CurveID != tls.CurveP384 {
			t.Errorf("negotiated group: want P-384, got %s", st.CurveID)
		}
		check(t, st, want{true, []string{}, true, []string{"X25519MLKEM768", "x25519"}, false})
	})

	// A real Encrypted Client Hello offer, for a key this server doesn't
	// have. The server carries on with the outer ClientHello, and the client
	// finishes the handshake to authenticate the rejection, then gives up.
	// Go's client leaves secure renegotiation out when it offers ECH.
	t.Run("ECH", func(t *testing.T) {
		st, err := handshakeState(t, &tls.Config{
			MinVersion:                     tls.VersionTLS13,
			ServerName:                     "secret.example",
			EncryptedClientHelloConfigList: testECHConfigList(t, "public.example"),
			// The server's certificate isn't for the public name. That
			// isn't what is being tested.
			EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
		})
		var rej *tls.ECHRejectionError
		if !errors.As(err, &rej) {
			t.Fatalf("client handshake: want an ECHRejectionError, got %v", err)
		}
		if st.ECHAccepted {
			t.Errorf("ECHAccepted: want false, this server has no ECH keys")
		}
		if st.ServerName != "public.example" {
			t.Errorf("ServerName: want the outer name %q, got %q", "public.example", st.ServerName)
		}
		check(t, st, want{true, []string{}, false, []string{"X25519MLKEM768", "x25519"}, true})
	})

	// What none of our clients send, on a real ClientHello.
	t.Run("Changed", func(t *testing.T) {
		st, err := handshakeState(t, &tls.Config{})
		if err != nil {
			t.Fatalf("client handshake: %s", err)
		}
		st.ServerName = ""
		st.SecureRenegotiationSupported = false
		st.EncryptedClientHelloOffered = true
		st.KeyShareGroups = []tls.CurveID{0x1a1a, tls.X25519MLKEM768, tls.X25519, tls.X25519, 0x6399}
		st.ALPNProtocols = nil
		check(t, st, want{false, []string{}, false, []string{"GREASE_1A", "X25519MLKEM768", "x25519", "x25519", namedGroupName(0x6399)}, true})

		st.KeyShareGroups = nil
		check(t, st, want{false, []string{}, false, []string{}, true})

		// Both lists stop at 16.
		st.KeyShareGroups = slices.Repeat([]tls.CurveID{tls.X25519}, 5000)
		st.ALPNProtocols = slices.Repeat([]string{"h2"}, 5000)
		check(t, st, want{false, slices.Repeat([]string{"h2"}, 16), false, slices.Repeat([]string{"x25519"}, 16), true})
	})
}

func TestRenderALPNProtocol(t *testing.T) {
	tests := []struct{ in, want string }{
		{"h2", "h2"},
		{"http/1.1", "http/1.1"},
		{"c-webrtc", "c-webrtc"},
		{"a_b+c.d", "a_b+c.d"},
		{"", ""},
		{" ", `\x20`},
		{`\x41`, `\x5cx41`},
		{"<b>", `\x3cb\x3e`},
		{"&amp;", `\x26amp\x3b`},
		{"'\"`", `\x27\x22\x60`},
		{"h2 (truncated)", `h2\x20\x28truncated\x29`},
		{"caf\xc3\xa9", `caf\xc3\xa9`},
		{"\x00\x7f\x80\xff", `\x00\x7f\x80\xff`},
		{" ", `\xe2\x80\xa8`},
		{strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{strings.Repeat("a", 33), strings.Repeat("a", 32) + " (truncated)"},
		{strings.Repeat("<", 255), strings.Repeat(`\x3c`, 32) + " (truncated)"},
	}
	for _, tt := range tests {
		got := renderALPNProtocol(tt.in)
		if got != tt.want {
			t.Errorf("renderALPNProtocol(%q): want %q, got %q", tt.in, tt.want, got)
		}
	}
	// Whatever the bytes, the result is ASCII with nothing in it that HTML,
	// JavaScript or JSON gives a meaning to.
	const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._/+\\"
	for b := range 256 {
		in := "x" + string([]byte{byte(b)}) + "y"
		got := renderALPNProtocol(in)
		if strings.Trim(got, safe) != "" {
			t.Errorf("renderALPNProtocol(%q): got %q, which has bytes outside of %q", in, got, safe)
		}
	}
}

// TestClientHelloSignalsDoNotRate checks that the signals change nothing the
// API returned before them: not the rating, and not any other key, whatever
// the signals say and on either side of the cutovers.
func TestClientHelloSignalsDoNotRate(t *testing.T) {
	asMap := func(t *testing.T, ci *clientInfo) map[string]any {
		t.Helper()
		b, err := json.Marshal(ci)
		if err != nil {
			t.Fatalf("json.Marshal: %s", err)
		}
		m := make(map[string]any)
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("json.Unmarshal: %s", err)
		}
		return m
	}
	bases := map[string]*tls.Config{
		"TLS13":         {},
		"TLS13Only":     {MinVersion: tls.VersionTLS13},
		"TLS12":         {MaxVersion: tls.VersionTLS12},
		"TLS12NoPQ":     {MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519}},
		"TLS13NoPQ":     {CurvePreferences: []tls.CurveID{tls.X25519}},
		"TLS13WithALPN": {NextProtos: []string{"h2", "http/1.1"}},
	}
	atBad := tls12BadCutover.Add(time.Second)
	atImprovable := tls12ImprovableCutover.Add(time.Second)
	for name, conf := range bases {
		t.Run(name, func(t *testing.T) {
			st, err := handshakeState(t, conf)
			if err != nil {
				t.Fatalf("client handshake: %s", err)
			}
			without := st
			without.ServerName = ""
			without.ALPNProtocols = nil
			without.SecureRenegotiationSupported = false
			without.KeyShareGroups = nil
			without.EncryptedClientHelloOffered = false

			variants := []tls.ConnectionState{st, without}
			for i := range 1 << 5 {
				v := without
				if i&1 != 0 {
					v.ServerName = "localhost"
				}
				if i&2 != 0 {
					v.ALPNProtocols = []string{"h2", "\xff<script>", "spdy/3"}
				}
				if i&4 != 0 {
					v.SecureRenegotiationSupported = true
				}
				if i&8 != 0 {
					// Classical shares only, a retired draft hybrid, and
					// a group that isn't registered.
					v.KeyShareGroups = []tls.CurveID{tls.X25519, 0x6399, 0x9999}
				}
				if i&16 != 0 {
					v.EncryptedClientHelloOffered = true
				}
				variants = append(variants, v)
			}
			for _, now := range []time.Time{preCutover, atImprovable, atBad} {
				want := asMap(t, clientInfoFromState(without, now))
				for _, k := range signalsOldJSONKeys {
					if _, ok := want[k]; !ok {
						t.Fatalf("the API no longer returns %q", k)
					}
				}
				if len(want) != len(signalsOldJSONKeys)+len(signalsJSONKeys) {
					t.Errorf("want %d keys from the API, got %d: %v", len(signalsOldJSONKeys)+len(signalsJSONKeys), len(want), want)
				}
				for _, k := range signalsJSONKeys {
					if _, ok := want[k]; !ok {
						t.Errorf("the API doesn't return %q", k)
					}
					delete(want, k)
				}
				for _, v := range variants {
					got := asMap(t, clientInfoFromState(v, now))
					for _, k := range signalsJSONKeys {
						delete(got, k)
					}
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("at %s, the signals changed the rest of the report (-without +with):\n%s", now, diff)
					}
				}
			}
		})
	}
}

// testECHConfigList returns an ECHConfigList (RFC 9849, Section 4) with one
// config for a new X25519 key that nobody keeps.
func testECHConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0xfe0d) // version
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(7)       // config_id
			b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x0001) // HKDF-SHA256
				b.AddUint16(0x0001) // AES-128-GCM
			})
			b.AddUint8(32) // maximum_name_length
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
			b.AddUint16(0) // extensions
		})
	})
	return b.BytesOrPanic()
}

// A ClientHello extension for rawClientHello.
type rawExt struct {
	id   uint16
	data []byte
}

// TLS extension numbers, from the IANA TLS ExtensionType Values registry.
const (
	rawExtServerName        uint16 = 0
	rawExtALPN              uint16 = 16
	rawExtSupportedVersions uint16 = 43
	rawExtKeyShare          uint16 = 51
	rawExtRenegotiationInfo uint16 = 0xff01
	rawExtECH               uint16 = 0xfe0d
)

// rawClientHello returns a TLS record holding a ClientHello with the given
// cipher suites and extensions, and nothing else of note.
func rawClientHello(suites []uint16, exts []rawExt) []byte {
	var b cryptobyte.Builder
	b.AddUint8(22)      // handshake record
	b.AddUint16(0x0301) // record version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1) // ClientHello
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0303)
			b.AddBytes(make([]byte, 32)) // random
			b.AddUint8(0)                // no session id
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, s := range suites {
					b.AddUint16(s)
				}
			})
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) }) // no compression
			if exts == nil {
				return
			}
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, e := range exts {
					b.AddUint16(e.id)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.data) })
				}
			})
		})
	})
	return b.BytesOrPanic()
}

// u16Prefixed and u8Prefixed return data behind its length.
func u16Prefixed(data ...byte) []byte {
	return append([]byte{byte(len(data) >> 8), byte(len(data))}, data...)
}

func u8Prefixed(data ...byte) []byte {
	return append([]byte{byte(len(data))}, data...)
}

func rawKeyShares(groups ...uint16) []byte {
	var shares []byte
	for _, g := range groups {
		shares = append(shares, byte(g>>8), byte(g))
		shares = append(shares, u16Prefixed(1, 2, 3, 4)...)
	}
	return u16Prefixed(shares...)
}

func rawALPN(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, u8Prefixed([]byte(p)...)...)
	}
	return u16Prefixed(list...)
}

// TestClientHelloSignalsOddInput sends the server ClientHellos no library
// would, and checks what it makes of them. None of these handshakes is
// finished: the point is that the server neither panics nor reports what
// wasn't sent.
func TestClientHelloSignalsOddInput(t *testing.T) {
	const (
		suite    uint16 = 0xc02f // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		suite13  uint16 = 0x1301 // TLS_AES_128_GCM_SHA256
		scsv     uint16 = 0x00ff // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		x25519   uint16 = 0x001d
		unknownG uint16 = 0x9999
	)
	tls13 := rawExt{rawExtSupportedVersions, u8Prefixed(0x03, 0x04)}
	// Shaped like the GREASE extension of RFC 9849, Section 6.2: an outer
	// hello, a cipher suite, a config id, a key and a payload.
	var greaseECH []byte
	greaseECH = append(greaseECH, 0, 0, 1, 0, 1, 99)
	greaseECH = append(greaseECH, u16Prefixed(make([]byte, 32)...)...)
	greaseECH = append(greaseECH, u16Prefixed(make([]byte, 144)...)...)

	manyShares := slices.Repeat([]uint16{x25519}, 2000)
	manyProtos := slices.Repeat([]string{"h2"}, 2000)

	type want struct {
		parsed      bool
		alpn        []string
		secureReneg bool
		keyShares   []string
		ech         bool
	}
	none := []string{}
	tests := []struct {
		name   string
		suites []uint16
		exts   []rawExt
		want   want
	}{
		{"NoExtensionsAtAll", []uint16{suite}, nil, want{true, none, false, none, false}},
		{"EmptyExtensions", []uint16{suite}, []rawExt{}, want{true, none, false, none, false}},
		{"SCSVOnly", []uint16{suite, scsv}, nil, want{true, none, true, none, false}},
		{"RenegotiationInfoOnly", []uint16{suite}, []rawExt{{rawExtRenegotiationInfo, u8Prefixed()}}, want{true, none, true, none, false}},
		{"RenegotiationInfoAndSCSV", []uint16{scsv, suite}, []rawExt{{rawExtRenegotiationInfo, u8Prefixed()}}, want{true, none, true, none, false}},
		{"RenegotiationInfoCutShort", []uint16{suite}, []rawExt{{rawExtRenegotiationInfo, nil}}, want{}},
		{"RenegotiationInfoTwice", []uint16{suite}, []rawExt{{rawExtRenegotiationInfo, u8Prefixed()}, {rawExtRenegotiationInfo, u8Prefixed()}}, want{}},

		{"ALPNRepeats", []uint16{suite}, []rawExt{{rawExtALPN, rawALPN("h2", "h2", "\x00", "h2")}}, want{true, []string{"h2", "h2", `\x00`, "h2"}, false, none, false}},
		{"ALPNMany", []uint16{suite}, []rawExt{{rawExtALPN, rawALPN(manyProtos...)}}, want{true, slices.Repeat([]string{"h2"}, 16), false, none, false}},
		{"ALPNEmptyList", []uint16{suite}, []rawExt{{rawExtALPN, u16Prefixed()}}, want{}},
		{"ALPNEmptyName", []uint16{suite}, []rawExt{{rawExtALPN, rawALPN("h2", "")}}, want{}},
		{"ALPNNoData", []uint16{suite}, []rawExt{{rawExtALPN, nil}}, want{}},
		{"ALPNCutShort", []uint16{suite}, []rawExt{{rawExtALPN, []byte{0, 9, 2, 'h', '2'}}}, want{}},
		{"ALPNNameCutShort", []uint16{suite}, []rawExt{{rawExtALPN, u16Prefixed(8, 'h', '2')}}, want{}},
		{"ALPNTwice", []uint16{suite}, []rawExt{{rawExtALPN, rawALPN("h2")}, {rawExtALPN, rawALPN("http/1.1")}}, want{}},

		{"KeyShareEmptyList", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, rawKeyShares()}}, want{true, none, false, none, false}},
		{"KeyShareRepeatsAndUnknown", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, rawKeyShares(x25519, unknownG, x25519, 0x0a0a)}}, want{true, none, false, []string{"x25519", "Unknown named group: 0x9999", "x25519", "GREASE_0A"}, false}},
		{"KeyShareMany", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, rawKeyShares(manyShares...)}}, want{true, none, false, slices.Repeat([]string{"x25519"}, 16), false}},
		{"KeyShareWithoutTLS13", []uint16{suite}, []rawExt{{rawExtKeyShare, rawKeyShares(x25519)}}, want{true, none, false, []string{"x25519"}, false}},
		{"KeyShareNoData", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, nil}}, want{}},
		{"KeyShareCutShort", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, []byte{0, 6, 0, 0x1d, 0, 32, 1, 2}}}, want{}},
		{"KeyShareEmptyKey", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, u16Prefixed(0, 0x1d, 0, 0)}}, want{}},
		{"KeyShareTwice", []uint16{suite13}, []rawExt{tls13, {rawExtKeyShare, rawKeyShares(x25519)}, {rawExtKeyShare, rawKeyShares(x25519)}}, want{}},

		{"ECHGREASE", []uint16{suite13}, []rawExt{tls13, {rawExtECH, greaseECH}}, want{true, none, false, none, true}},
		// As far as upstream's parser is concerned, an empty extension
		// isn't an offer.
		{"ECHNoData", []uint16{suite13}, []rawExt{tls13, {rawExtECH, nil}}, want{true, none, false, none, false}},
		// An inner ClientHello's marker, which should never reach a server
		// in the clear.
		{"ECHInner", []uint16{suite13}, []rawExt{tls13, {rawExtECH, []byte{1}}}, want{true, none, false, none, true}},
		{"ECHUnknownType", []uint16{suite13}, []rawExt{tls13, {rawExtECH, []byte{7}}}, want{}},
		{"ECHCutShort", []uint16{suite13}, []rawExt{tls13, {rawExtECH, greaseECH[:20]}}, want{}},
		{"ECHTwice", []uint16{suite13}, []rawExt{tls13, {rawExtECH, greaseECH}, {rawExtECH, greaseECH}}, want{}},

		{"ServerNameTwice", []uint16{suite}, []rawExt{{rawExtServerName, u16Prefixed(append([]byte{0}, u16Prefixed('a')...)...)}, {rawExtServerName, u16Prefixed(append([]byte{0}, u16Prefixed('b')...)...)}}, want{}},
		{"ServerNameEmpty", []uint16{suite}, []rawExt{{rawExtServerName, u16Prefixed(append([]byte{0}, u16Prefixed()...)...)}}, want{}},
		{"ServerNameCutShort", []uint16{suite}, []rawExt{{rawExtServerName, []byte{0, 9, 0}}}, want{}},

		{"Everything", []uint16{suite13, suite, scsv}, []rawExt{
			tls13,
			{rawExtServerName, u16Prefixed(append([]byte{0}, u16Prefixed([]byte("<b>.example")...)...)...)},
			{rawExtALPN, rawALPN("h2", "<b>")},
			{rawExtRenegotiationInfo, u8Prefixed()},
			{rawExtKeyShare, rawKeyShares(x25519)},
			{rawExtECH, greaseECH},
		}, want{true, []string{"h2", `\x3cb\x3e`}, true, []string{"x25519"}, true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := rawClientHello(tt.suites, tt.exts)
			st, serverErr, clientErr := serverSideState(t, serverConf, func(c net.Conn) error {
				if _, err := c.Write(hello); err != nil {
					return err
				}
				// Say that nothing more is coming, and read whatever the
				// server has to say until it hangs up.
				if err := c.(*net.TCPConn).CloseWrite(); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, c)
				return err
			})
			if clientErr != nil {
				t.Fatalf("client: %s", clientErr)
			}
			if serverErr == nil {
				t.Fatalf("server handshake: want an error from half a handshake, got none")
			}
			// The ClientHello is kept if and only if it parsed.
			if parsed := len(st.ClientCipherSuites) != 0; parsed != tt.want.parsed {
				t.Fatalf("ClientHello parsed: want %t, got %t (server: %s)", tt.want.parsed, parsed, serverErr)
			}
			// The report is only made from finished handshakes. Pretend,
			// to see that it copes with all of the above.
			st.HandshakeComplete = true
			ci := clientInfoFromState(st, preCutover)
			if !tt.want.parsed {
				tt.want.alpn, tt.want.keyShares = none, none
			}
			got := want{tt.want.parsed, ci.GivenALPNProtocols, ci.SecureRenegotiationSupported, ci.GivenKeyShareGroups, ci.EncryptedClientHelloOffered}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(want{})); diff != "" {
				t.Errorf("signals (-want +got):\n%s", diff)
			}
			if _, err := json.Marshal(ci); err != nil {
				t.Errorf("json.Marshal: %s", err)
			}
		})
	}
}

// fragmentRecords splits a single TLS record, as rawClientHello makes, into
// records of at most 2^14 bytes each, the most one may hold (RFC 8446,
// Section 5.1). A ClientHello bigger than that has to go this way.
func fragmentRecords(record []byte) []byte {
	const maxRecord = 1 << 14
	header, body := record[:3], record[5:]
	var out []byte
	for len(body) > 0 {
		n := min(len(body), maxRecord)
		out = append(out, header...)
		out = append(out, byte(n>>8), byte(n))
		out = append(out, body[:n]...)
		body = body[n:]
	}
	return out
}

// TestClientHelloListCopiesCapped checks that the fork keeps only as many ALPN
// names and key share groups as the report shows, however many the client
// sends, and that the report is what it would be had the fork kept them all.
func TestClientHelloListCopiesCapped(t *testing.T) {
	const (
		count          = 3000
		suite13 uint16 = 0x1301 // TLS_AES_128_GCM_SHA256
	)
	protos := make([]string, count)
	groups := make([]uint16, count)
	for i := range count {
		protos[i] = fmt.Sprintf("p%d", i)
		// Every other one is unknown, so the names show the order kept.
		groups[i] = uint16(0x1d)
		if i%2 == 1 {
			groups[i] = uint16(0x9000 + i)
		}
	}
	hello := fragmentRecords(rawClientHello([]uint16{suite13}, []rawExt{
		{rawExtSupportedVersions, u8Prefixed(0x03, 0x04)},
		{rawExtALPN, rawALPN(protos...)},
		{rawExtKeyShare, rawKeyShares(groups...)},
	}))
	if len(hello) < 2<<14 {
		t.Fatalf("want a ClientHello over two records long, got %d bytes", len(hello))
	}
	st, serverErr, clientErr := serverSideState(t, serverConf, func(c net.Conn) error {
		if _, err := c.Write(hello); err != nil {
			return err
		}
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, c)
		return err
	})
	if clientErr != nil {
		t.Fatalf("client: %s", clientErr)
	}
	if len(st.ClientCipherSuites) == 0 {
		t.Fatalf("ClientHello didn't parse (server: %v)", serverErr)
	}

	if diff := cmp.Diff(protos[:maxGivenALPNProtocols], st.ALPNProtocols); diff != "" {
		t.Errorf("ConnectionState.ALPNProtocols (-want +got):\n%s", diff)
	}
	var wantGroups []tls.CurveID
	for _, g := range groups[:maxGivenKeyShareGroups] {
		wantGroups = append(wantGroups, tls.CurveID(g))
	}
	if diff := cmp.Diff(wantGroups, st.KeyShareGroups); diff != "" {
		t.Errorf("ConnectionState.KeyShareGroups (-want +got):\n%s", diff)
	}

	// The report from the capped state is the same as from the whole lists.
	st.HandshakeComplete = true
	whole := st
	whole.ALPNProtocols = protos
	whole.KeyShareGroups = nil
	for _, g := range groups {
		whole.KeyShareGroups = append(whole.KeyShareGroups, tls.CurveID(g))
	}
	got, err := json.Marshal(clientInfoFromState(st, preCutover))
	if err != nil {
		t.Fatalf("json.Marshal: %s", err)
	}
	want, err := json.Marshal(clientInfoFromState(whole, preCutover))
	if err != nil {
		t.Fatalf("json.Marshal: %s", err)
	}
	if string(got) != string(want) {
		t.Errorf("report from the capped lists differs from the whole lists:\ngot:  %s\nwant: %s", got, want)
	}
}
