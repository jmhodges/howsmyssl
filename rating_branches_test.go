package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// These tests cover the branches of pullClientInfo that decide a rating, a
// reason or a field of the report and that no other test reached. Each one
// checks only what its branch decides: none compares a whole report, so a
// change that adds a field or a reason for some other suite leaves them be.

// The reasons a cipher suite is called insecure, one suite per table in
// insecure_suites.go, and the two kinds of suite that allCipherSuites doesn't
// name.
func TestRatingBranchInsecureSuiteReasons(t *testing.T) {
	const strong = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	tests := []struct {
		name        string
		suite       uint16
		suiteName   string
		insecure    map[string][]string
		wantUnknown bool
	}{
		{
			name:      "FewBits",
			suite:     0x0009,
			suiteName: "TLS_RSA_WITH_DES_CBC_SHA",
			insecure:  map[string][]string{"TLS_RSA_WITH_DES_CBC_SHA": {fewBitReason}},
		},
		{
			name:      "NoAuthentication",
			suite:     0x0034,
			suiteName: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
			insecure:  map[string][]string{"TLS_DH_anon_WITH_AES_128_CBC_SHA": {nullAuthReason}},
		},
		{
			name:      "RC4",
			suite:     0x0005,
			suiteName: "TLS_RSA_WITH_RC4_128_SHA",
			insecure:  map[string][]string{"TLS_RSA_WITH_RC4_128_SHA": {rc4Reason}},
		},
		{
			// A suite in three of the tables gets all three reasons, in
			// the order the page then joins them in.
			name:      "ThreeReasons",
			suite:     0x0017,
			suiteName: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
			insecure: map[string][]string{
				"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5": {fewBitReason, nullAuthReason, rc4Reason},
			},
		},
		{
			// Not in allCipherSuites, but named by weirdNSSSuites, so it
			// is insecure and not "unknown".
			name:      "WeirdNSS",
			suite:     0xFEFF,
			suiteName: "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
			insecure:  map[string][]string{"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA": {weirdNSSReason}},
		},
		{
			// 0xFFFD is in the registry's private use range, so no table
			// here will ever name it.
			name:        "Unknown",
			suite:       0xFFFD,
			suiteName:   "Some unknown cipher suite: 0xfffd",
			insecure:    map[string][]string{},
			wantUnknown: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// ForceSuites makes the zcrypto/tls client offer a suite it
			// doesn't implement. The server picks the first one, which
			// also keeps ephemeral keys and a stronger suite in the offer.
			clientConf := &ztls.Config{
				MaxVersion:   ztls.VersionTLS12,
				CipherSuites: []uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tc.suite},
				ForceSuites:  true,
			}
			c := connectZtls(t, clientConf)
			ci := pullClientInfo(c, preCutover)
			t.Logf("%#v", ci)

			want := []string{strong, tc.suiteName}
			if !cmp.Equal(want, ci.GivenCipherSuites) {
				t.Errorf("GivenCipherSuites: want %v, got %v", want, ci.GivenCipherSuites)
			}
			if !cmp.Equal(tc.insecure, ci.InsecureCipherSuites) {
				t.Errorf("InsecureCipherSuites: want %v, got %v", tc.insecure, ci.InsecureCipherSuites)
			}
			if ci.UnknownCipherSuiteSupported != tc.wantUnknown {
				t.Errorf("UnknownCipherSuiteSupported: want %t, got %t", tc.wantUnknown, ci.UnknownCipherSuiteSupported)
			}
			if ci.Rating != bad {
				t.Errorf("Rating: want %s, got %s", bad, ci.Rating)
			}
		})
	}

	// The same client without the second suite is fine, so it's the suite
	// that makes each of the ratings above.
	t.Run("StrongSuiteAlone", func(t *testing.T) {
		clientConf := &ztls.Config{
			MaxVersion:   ztls.VersionTLS12,
			CipherSuites: []uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
			ForceSuites:  true,
		}
		c := connectZtls(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		if ci.Rating != okay {
			t.Errorf("Rating: want %s, got %s", okay, ci.Rating)
		}
	})
}

// A client is Improvable when none of its cipher suites has an ephemeral key
// exchange. The check goes by the suite's name, so static DH ("DH_") must not
// be taken for ephemeral DH ("DHE_").
func TestRatingBranchEphemeralKeys(t *testing.T) {
	const (
		rsaAES128GCM   = 0x009C // TLS_RSA_WITH_AES_128_GCM_SHA256
		dheRSAAES128   = 0x009E // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
		dhRSAAES128    = 0x00A0 // TLS_DH_RSA_WITH_AES_128_GCM_SHA256
		ecdhRSAAES128  = 0xC031 // TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
		ecdheRSAAES128 = 0xC02F // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	)
	tests := []struct {
		name          string
		suites        []uint16
		wantEphemeral bool
		wantRating    rating
	}{
		{"StaticRSAOnly", []uint16{rsaAES128GCM}, false, improvable},
		{"StaticDH", []uint16{rsaAES128GCM, dhRSAAES128}, false, improvable},
		{"StaticECDH", []uint16{rsaAES128GCM, ecdhRSAAES128}, false, improvable},
		{"FiniteFieldDHE", []uint16{rsaAES128GCM, dheRSAAES128}, true, okay},
		{"ECDHE", []uint16{rsaAES128GCM, ecdheRSAAES128}, true, okay},
		// One ephemeral suite anywhere in the list is enough.
		{"ECDHELast", []uint16{rsaAES128GCM, dhRSAAES128, ecdhRSAAES128, ecdheRSAAES128}, true, okay},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The server takes the static RSA suite when it's the only one
			// both sides have. ForceSuites sends the ones zcrypto/tls
			// doesn't implement.
			clientConf := &ztls.Config{
				MaxVersion:   ztls.VersionTLS12,
				CipherSuites: tc.suites,
				ForceSuites:  true,
			}
			c := connectZtls(t, clientConf)
			ci := pullClientInfo(c, preCutover)
			t.Logf("%#v", ci)

			if len(ci.GivenCipherSuites) != len(tc.suites) {
				t.Fatalf("GivenCipherSuites: want %d of them, got %v", len(tc.suites), ci.GivenCipherSuites)
			}
			if ci.EphemeralKeysSupported != tc.wantEphemeral {
				t.Errorf("EphemeralKeysSupported: want %t, got %t", tc.wantEphemeral, ci.EphemeralKeysSupported)
			}
			if len(ci.InsecureCipherSuites) != 0 {
				t.Errorf("InsecureCipherSuites: want none, got %v", ci.InsecureCipherSuites)
			}
			if ci.Rating != tc.wantRating {
				t.Errorf("Rating: want %s, got %s", tc.wantRating, ci.Rating)
			}
		})
	}
}

// TLS 1.0 is Bad for its version alone. The BEAST finding has two outcomes
// there that TestBEASTVuln doesn't reach: a client that doesn't split its
// records, and a client whose CBC suites are none of the ones the server can
// pick to watch for the splitting.
func TestRatingBranchTLS10(t *testing.T) {
	t.Run("MitigatedIsStillBad", func(t *testing.T) {
		// Go's client splits its records, has no insecure suite here and
		// compresses nothing: only the version is left to make it Bad.
		clientConf := &tls.Config{
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		if ci.TLSVersion != "TLS 1.0" {
			t.Errorf("TLSVersion: want TLS 1.0, got %s", ci.TLSVersion)
		}
		if ci.BEASTVuln {
			t.Errorf("BEASTVuln: want false, got true")
		}
		if len(ci.InsecureCipherSuites) != 0 {
			t.Errorf("InsecureCipherSuites: want none, got %v", ci.InsecureCipherSuites)
		}
		if ci.TLSCompressionSupported || ci.UnknownCipherSuiteSupported {
			t.Errorf("TLSCompressionSupported, UnknownCipherSuiteSupported: want false and false, got %t and %t", ci.TLSCompressionSupported, ci.UnknownCipherSuiteSupported)
		}
		if ci.Rating != bad {
			t.Errorf("Rating: want %s, got %s", bad, ci.Rating)
		}
	})

	t.Run("NoRecordSplitting", func(t *testing.T) {
		clientConf := &ztls.Config{
			MinVersion:                  ztls.VersionTLS10,
			MaxVersion:                  ztls.VersionTLS10,
			CipherSuites:                []uint16{ztls.TLS_RSA_WITH_AES_128_CBC_SHA},
			DisableTLS10BEASTMitigation: true,
		}
		c := connectZtls(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		if !ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("AbleToDetectNMinusOneSplitting: want true, got false")
		}
		if !ci.BEASTVuln {
			t.Errorf("BEASTVuln: want true, got false")
		}
		if ci.Rating != bad {
			t.Errorf("Rating: want %s, got %s", bad, ci.Rating)
		}
	})

	t.Run("RecordSplitting", func(t *testing.T) {
		// The same client with the mitigation left on, to show that it is
		// the splitting that the case above turns on.
		clientConf := &ztls.Config{
			MinVersion:   ztls.VersionTLS10,
			MaxVersion:   ztls.VersionTLS10,
			CipherSuites: []uint16{ztls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}
		c := connectZtls(t, clientConf)
		ci := pullClientInfo(c, preCutover)

		if !ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("AbleToDetectNMinusOneSplitting: want true, got false")
		}
		if ci.BEASTVuln {
			t.Errorf("BEASTVuln: want false, got true")
		}
	})

	t.Run("CBCSuiteTheServerCannotWatch", func(t *testing.T) {
		// The server only watches for record splitting on three static
		// RSA CBC suites. With any other CBC suite it can't tell, and
		// assumes the worst, even of a client that does split.
		clientConf := &tls.Config{
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		if ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("AbleToDetectNMinusOneSplitting: want false, got true")
		}
		if !ci.BEASTVuln {
			t.Errorf("BEASTVuln: want true, got false")
		}
		if ci.Rating != bad {
			t.Errorf("Rating: want %s, got %s", bad, ci.Rating)
		}
	})
}

// A named group that allNamedGroups doesn't have is shown by its number, and
// doesn't count as post-quantum.
func TestRatingBranchUnknownNamedGroup(t *testing.T) {
	// 0xFE42 is in the registry's private use range for ECDHE groups.
	clientConf := &ztls.Config{
		CurvePreferences: []ztls.CurveID{ztls.X25519, 0xFE42},
	}
	c := connectZtls(t, clientConf)
	ci := pullClientInfo(c, preCutover)

	want := []string{"x25519", "Unknown named group: 0xfe42"}
	if !cmp.Equal(want, ci.GivenNamedGroups) {
		t.Errorf("GivenNamedGroups: want %v, got %v", want, ci.GivenNamedGroups)
	}
	if ci.PostQuantumKeyAgreement {
		t.Errorf("PostQuantumKeyAgreement: want false, got true")
	}
}

// branchHello is what the tests below choose of a TLS 1.2 ClientHello. The
// rest is fixed: enough for the server to finish an ECDHE handshake with the
// zcrypto/tls client.
type branchHello struct {
	suites            []uint16
	compression       []uint8
	supportedVersions []uint16 // no supported_versions extension if empty
	groups            []uint16 // x25519 and secp256r1 if empty
}

// marshal returns the ClientHello as a handshake message, which is what
// zcrypto/tls takes as its Config.ExternalClientHello. Neither TLS client
// here has a setting for compression methods other than "none", or for a
// supported_versions list of its own, so those two are written by hand.
func (h branchHello) marshal(t *testing.T) []byte {
	t.Helper()
	u16s := func(vals ...uint16) []byte {
		var b []byte
		for _, v := range vals {
			b = binary.BigEndian.AppendUint16(b, v)
		}
		return b
	}
	u8Len := func(data []byte) []byte { return append([]byte{uint8(len(data))}, data...) }
	u16Len := func(data []byte) []byte { return append(u16s(uint16(len(data))), data...) }
	ext := func(typ uint16, data []byte) []byte { return append(u16s(typ), u16Len(data)...) }

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand.Read: %s", err)
	}

	groups := h.groups
	if len(groups) == 0 {
		groups = []uint16{uint16(ztls.X25519), uint16(ztls.CurveP256)}
	}

	var exts []byte
	exts = append(exts, ext(10, u16Len(u16s(groups...)))...)      // supported_groups
	exts = append(exts, ext(11, u8Len([]byte{0}))...)             // ec_point_formats: uncompressed
	exts = append(exts, ext(13, u16Len(u16s(0x0804, 0x0401)))...) // signature_algorithms: rsa_pss_rsae_sha256, rsa_pkcs1_sha256
	if len(h.supportedVersions) != 0 {
		exts = append(exts, ext(43, u8Len(u16s(h.supportedVersions...)))...)
	}

	var body []byte
	body = append(body, u16s(ztls.VersionTLS12)...)
	body = append(body, random...)
	body = append(body, 0) // no session id
	body = append(body, u16Len(u16s(h.suites...))...)
	body = append(body, u8Len(h.compression)...)
	body = append(body, u16Len(exts)...)

	// A handshake message: type 1, client_hello, and a 3 byte length.
	msg := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// connectBranchHello finishes a handshake that starts with h and returns the
// server's side of it.
func connectBranchHello(t *testing.T, h branchHello) *tls.Conn {
	t.Helper()
	return connectZtls(t, &ztls.Config{
		ExternalClientHello: h.marshal(t),
		// connectZtls gives every client a session cache, and zcrypto/tls
		// reads the first of the supported versions when it has one. A
		// ClientHello without that extension makes it panic.
		SessionTicketsDisabled: true,
	})
}

// A client that lists any compression method but "none" is Bad, whatever
// else it does well.
func TestRatingBranchTLSCompression(t *testing.T) {
	suites := []uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}
	tests := []struct {
		name            string
		compression     []uint8
		wantCompression bool
		wantRating      rating
	}{
		{"NoneOnly", []uint8{0}, false, okay},
		{"DeflateThenNone", []uint8{1, 0}, true, bad},
		{"NoneThenDeflate", []uint8{0, 1}, true, bad},
		// 64 is LZS, the only other method ever registered.
		{"NoneThenLZS", []uint8{0, 64}, true, bad},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := connectBranchHello(t, branchHello{suites: suites, compression: tc.compression})
			ci := pullClientInfo(c, preCutover)
			t.Logf("%#v", ci)

			if ci.TLSCompressionSupported != tc.wantCompression {
				t.Errorf("TLSCompressionSupported: want %t, got %t", tc.wantCompression, ci.TLSCompressionSupported)
			}
			if ci.UnknownCipherSuiteSupported || ci.BEASTVuln || len(ci.InsecureCipherSuites) != 0 {
				t.Errorf("want nothing else that rates Bad, got %#v", ci)
			}
			if ci.Rating != tc.wantRating {
				t.Errorf("Rating: want %s, got %s", tc.wantRating, ci.Rating)
			}
		})
	}
}

// The supported_versions extension is read for a version above the one that
// was negotiated. Values that are no version howsmyssl knows, like RFC 8701's
// GREASE ones, must be passed over however large they are.
func TestRatingBranchSupportedVersions(t *testing.T) {
	const (
		greaseVersion  = 0x8A8A
		x25519MLKEM768 = 0x11ec
	)
	suites := []uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}
	tests := []struct {
		name        string
		versions    []uint16
		wantVersion string
	}{
		{"NoExtension", nil, "TLS 1.2"},
		{"TLS12", []uint16{tls.VersionTLS12}, "TLS 1.2"},
		{"TLS12AndOlder", []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}, "TLS 1.2"},
		{"GREASEFirst", []uint16{greaseVersion, tls.VersionTLS12}, "TLS 1.2"},
		{"GREASELast", []uint16{tls.VersionTLS12, greaseVersion}, "TLS 1.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := connectBranchHello(t, branchHello{
				suites:            suites,
				compression:       []uint8{0},
				supportedVersions: tc.versions,
				groups:            []uint16{x25519MLKEM768, uint16(ztls.X25519)},
			})
			if got := c.ConnectionState().Version; got != tls.VersionTLS12 {
				t.Fatalf("negotiated version: want %#04x, got %#04x", tls.VersionTLS12, got)
			}
			ci := pullClientInfo(c, preCutover)

			if ci.TLSVersion != tc.wantVersion {
				t.Errorf("TLSVersion: want %s, got %s", tc.wantVersion, ci.TLSVersion)
			}
			if !ci.PostQuantumKeyAgreement {
				t.Fatalf("PostQuantumKeyAgreement: want true, got false")
			}
			// The TLS 1.2 cutover goes by the same version. The client
			// lists a post-quantum group, so nothing else makes it Bad.
			if ci.Rating != okay {
				t.Errorf("Rating before the cutovers: want %s, got %s", okay, ci.Rating)
			}
			if ci := pullClientInfo(c, tls12BadCutover); ci.Rating != bad {
				t.Errorf("Rating after the cutovers: want %s, got %s", bad, ci.Rating)
			}
		})
	}
}

// pullClientInfo must not rate a connection whose handshake hasn't finished:
// its state has none of the client's offers, and would rate as a client that
// offered nothing.
func TestRatingBranchUnfinishedHandshakePanics(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := tls.Server(server, serverConf)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("pullClientInfo on a conn with no handshake: want a panic, got none")
		}
	}()
	ci := pullClientInfo(c, preCutover)
	t.Errorf("pullClientInfo returned %#v", ci)
}
