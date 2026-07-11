package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"expvar"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jmhodges/howsmyssl/howhttp"
	tls "github.com/jmhodges/howsmyssl/tls1265"
	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
)

// preCutover is well before any rating cutover, so tests that don't
// care about the date-based downgrades see the same behavior they did
// before the cutovers existed.
var preCutover = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestBEASTVuln(t *testing.T) {
	t.Run("TLS10OnlyCBC", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}

		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		if ci.BEASTVuln {
			t.Errorf("TLS 1.0, CBC suite, ClientInfo: BEASTVuln should be false because Go mitigates the BEAST attack even on TLS 1.0")
		}
		if !ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.0, CBC suite, ClientInfo: AbleToDetectNMinusOneSplitting was false")
		}
	})

	// AbleToDetectNMinusOneSplitting shouldn't be set unless there are BEAST vuln cipher suites included
	// and we're talking over TLS 1.0.
	t.Run("TLS10NoCBC", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		if ci.BEASTVuln {
			t.Errorf("TLS 1.0, no CBC suites, ClientInfo: BEASTVuln should be false because Go mitigates the BEAST attack even on TLS 1.0")
		}
		if ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.0, no CBC suites, ClientInfo: AbleToDetectNMinusOneSplitting was true but should be false because no CBC suites were included even though we used TLS 1.0")
		}
	})

	t.Run("TLS12NoCBC", func(t *testing.T) {
		clientConf := &tls.Config{
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		}

		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		if ci.BEASTVuln {
			t.Errorf("TLS 1.2+, no CBC suites, ClientInfo: BEASTVuln should be false because Go mitigates the BEAST attack even on TLS 1.0")
		}
		if ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.2+, no CBC suites, ClientInfo: AbleToDetectNMinusOneSplitting was true but shouldn't be set since we're not on TLS 1.0 or older")
		}
	})
}

// This is not to make sure that howsmyssl thinks the Go tls library is good,
// but, instead, we assume the client is "Probably Okay" and look to see that we
// can handle that golden path.
func TestGoDefaultIsOkay(t *testing.T) {
	clientConf := &tls.Config{}
	c := connect(t, clientConf)
	ci := pullClientInfo(c, preCutover)
	t.Logf("%#v", ci)

	if ci.Rating != okay {
		t.Errorf("Go client rating: want %s, got %s", okay, ci.Rating)
	}
	if len(ci.GivenCipherSuites) == 0 {
		t.Errorf("no cipher suites given")
	}
	if ci.TLSCompressionSupported {
		t.Errorf("TLSCompressionSupported was somehow true even though Go's TLS client doesn't support it")
	}
	if !ci.SessionTicketsSupported {
		t.Errorf("SessionTicketsSupported was false but we set that in connect explicitly")
	}
}

func TestSweet32(t *testing.T) {
	type sweetTest struct {
		rating   rating
		suites   []uint16
		expected map[string][]string
	}

	// Since the Sweet32 vulnerable ciphersuites are still used by many servers,
	// Sweet32 mitigation involves moving those ciphersuites to the end of the
	// ciphersuite list the client announces it can support. However, meta
	// ciphersuites like the GREASE or renegotiation ciphersuites and the TLS
	// 1.3 ciphersuites are also attached to the end. So, howsmyssl says a
	// client is vulnerable to Sweet32 if the Sweet32 vulnerable ciphersuites
	// are last or would be last except for some known meta ciphersuites like
	// GREASE, etc. In order to support testing this behavior, we use the
	// zcrypto/tls client with ForceSuites: true so that the client sends the
	// meta ciphersuites we ask for without dropping them like the client
	// usually would.
	greaseCS := uint16(0x0A0A)
	renegCS := uint16(0x00FF)
	tests := []sweetTest{
		{
			bad,
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			map[string][]string{
				"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": {sweet32Reason},
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       {sweet32Reason},
			},
		},
		{
			bad,
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			map[string][]string{
				"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": {sweet32Reason},
			},
		},
		{
			okay,
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
			map[string][]string{},
		},
		{
			okay,
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, greaseCS},
			map[string][]string{},
		},
		{
			okay,
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, greaseCS, renegCS},
			map[string][]string{},
		},
	}
	for i, st := range tests {
		t.Run(strconv.Itoa(i),
			func(t *testing.T) {
				clientConf := &ztls.Config{
					MaxVersion:   ztls.VersionTLS12,
					CipherSuites: st.suites,
					ForceSuites:  true,
				}
				c := connectZtls(t, clientConf)
				ci := pullClientInfo(c, preCutover)
				t.Logf("#%d, %#v", i, ci)

				if ci.Rating != st.rating {
					t.Errorf("#%d, Go client rating: want %s, got %s", i, st.rating, ci.Rating)
				}
				if len(ci.GivenCipherSuites) != len(st.suites) {
					suites := []string{}
					for _, cs := range st.suites {
						suites = append(suites, allCipherSuites[cs])
					}
					t.Errorf("#%d, num cipher suites given: want %d, got %d (%v, %v)", i, len(st.suites), len(ci.GivenCipherSuites), suites, ci.GivenCipherSuites)
				}
				if !cmp.Equal(st.expected, ci.InsecureCipherSuites) {
					t.Errorf("#%d, insecure cipher suites found: want %s, got %s", i, st.expected, ci.InsecureCipherSuites)
				}
			},
		)
	}
}

func TestPostQuantumDetection(t *testing.T) {
	t.Run("WithMLKEM", func(t *testing.T) {
		// We've had to reorder the CurvePreferences because crypto/tls (which
		// our tls library is a fork of) reorders them or drops them if it
		// doesn't recognize them.
		clientConf := &ztls.Config{
			// X25519MLKEM768 is 0x11ec, and not in the stdlib, yet.
			CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519},
		}
		c := connectZtls(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		if !ci.PostQuantumKeyAgreement {
			t.Errorf("PostQuantumKeyAgreement: want true, got false")
		}
		if len(ci.GivenNamedGroups) != 2 {
			t.Errorf("GivenNamedGroups length: want 2, got %d (%v)", len(ci.GivenNamedGroups), ci.GivenNamedGroups)
		}
		if ci.GivenNamedGroups[0] != "X25519MLKEM768" {
			t.Errorf("GivenNamedGroups[0]: want X25519MLKEM768, got %s", ci.GivenNamedGroups[0])
		}
		if ci.GivenNamedGroups[1] != "x25519" {
			t.Errorf("GivenNamedGroups[1]: want x25519, got %s", ci.GivenNamedGroups[1])
		}
	})

	t.Run("WithoutMLKEM", func(t *testing.T) {
		clientConf := &tls.Config{
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		if ci.PostQuantumKeyAgreement {
			t.Errorf("PostQuantumKeyAgreement: want false, got true")
		}
		if len(ci.GivenNamedGroups) != 2 {
			t.Errorf("GivenNamedGroups length: want 2, got %d (%v)", len(ci.GivenNamedGroups), ci.GivenNamedGroups)
		}
		if ci.GivenNamedGroups[0] != "x25519" {
			t.Errorf("GivenNamedGroups[0]: want x25519, got %s", ci.GivenNamedGroups[0])
		}
		if ci.GivenNamedGroups[1] != "secp256r1" {
			t.Errorf("GivenNamedGroups[1]: want secp256r1, got %s", ci.GivenNamedGroups[1])
		}
	})
}

func TestGivenSignatureAlgorithms(t *testing.T) {
	t.Run("TLS13Default", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		if len(ci.GivenSignatureAlgorithms) == 0 {
			t.Fatalf("GivenSignatureAlgorithms: want non-empty, got empty")
		}
		// Go's default TLS 1.2+ ClientHello includes these.
		wantAny := map[string]bool{
			"ecdsa_secp256r1_sha256": true,
			"rsa_pss_rsae_sha256":    true,
			"rsa_pkcs1_sha256":       true,
		}
		seen := false
		for _, name := range ci.GivenSignatureAlgorithms {
			if wantAny[name] {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("GivenSignatureAlgorithms: none of %v present, got %v", wantAny, ci.GivenSignatureAlgorithms)
		}
		for _, name := range ci.GivenSignatureAlgorithms {
			if name == "" {
				t.Errorf("GivenSignatureAlgorithms contains empty name: %v", ci.GivenSignatureAlgorithms)
			}
		}
	})

	t.Run("TLS10EmptyButNonNil", func(t *testing.T) {
		// signature_algorithms was added in TLS 1.2, so a TLS 1.0-only client
		// doesn't send the extension. The slice must still be non-nil so the
		// JSON renders [] rather than null.
		clientConf := &tls.Config{
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		if ci.GivenSignatureAlgorithms == nil {
			t.Errorf("GivenSignatureAlgorithms: want non-nil slice, got nil")
		}
		if len(ci.GivenSignatureAlgorithms) != 0 {
			t.Errorf("GivenSignatureAlgorithms: want empty, got %v", ci.GivenSignatureAlgorithms)
		}
	})

	// The development cert is RSA-2048 with a SHA-256 issuer signature. Each
	// override below pins a TLS version explicitly so the cipher suite path is
	// predictable, and includes at least one signature scheme the dev cert can
	// be signed under so the handshake completes.
	t.Run("CustomListEchoed", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.PKCS1WithSHA256,
				tls.PSSWithSHA384,
			},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		want := []string{"rsa_pkcs1_sha256", "rsa_pss_rsae_sha384"}
		if !cmp.Equal(want, ci.GivenSignatureAlgorithms) {
			t.Errorf("GivenSignatureAlgorithms: want %v, got %v", want, ci.GivenSignatureAlgorithms)
		}
	})

	t.Run("GREASERenders", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.SignatureScheme(0x0a0a),
				tls.PKCS1WithSHA256,
				tls.SignatureScheme(0x1a1a),
			},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		want := []string{"GREASE_0A", "rsa_pkcs1_sha256", "GREASE_1A"}
		if !cmp.Equal(want, ci.GivenSignatureAlgorithms) {
			t.Errorf("GivenSignatureAlgorithms: want %v, got %v", want, ci.GivenSignatureAlgorithms)
		}
	})

	t.Run("MLDSARenders", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.SignatureScheme(0x0904),
				tls.SignatureScheme(0x0905),
				tls.SignatureScheme(0x0906),
				tls.PKCS1WithSHA256,
			},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		want := []string{"mldsa44", "mldsa65", "mldsa87", "rsa_pkcs1_sha256"}
		if !cmp.Equal(want, ci.GivenSignatureAlgorithms) {
			t.Errorf("GivenSignatureAlgorithms: want %v, got %v", want, ci.GivenSignatureAlgorithms)
		}
	})

	t.Run("UnknownFallback", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.SignatureScheme(0x0710),
				tls.PKCS1WithSHA256,
			},
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)

		want := []string{"Unknown signature scheme: 0x0710", "rsa_pkcs1_sha256"}
		if !cmp.Equal(want, ci.GivenSignatureAlgorithms) {
			t.Errorf("GivenSignatureAlgorithms: want %v, got %v", want, ci.GivenSignatureAlgorithms)
		}
	})
}

// greaseECHExtension returns a well-formed outer ECHClientHello (RFC-draft
// encrypted_client_hello extension body) with garbage cryptographic contents,
// like the GREASE ECH extension browsers send when they support ECH but have
// no ECHConfig for the server. The server can't decrypt it, but it must parse.
func greaseECHExtension() []byte {
	var b bytes.Buffer
	b.WriteByte(0)              // ECHClientHelloType: outer
	b.Write([]byte{0x00, 0x01}) // KDF: HKDF-SHA256
	b.Write([]byte{0x00, 0x01}) // AEAD: AES-128-GCM
	b.WriteByte(0x42)           // config_id
	b.Write([]byte{0x00, 0x20}) // enc length: 32, an X25519 public key
	b.Write(bytes.Repeat([]byte{0xa5}, 32))
	b.Write([]byte{0x00, 0x64}) // payload length: 100
	b.Write(bytes.Repeat([]byte{0x5a}, 100))
	return b.Bytes()
}

func TestEncryptedClientHelloDetection(t *testing.T) {
	t.Run("NotOffered", func(t *testing.T) {
		clientConf := &tls.Config{}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)
		if ci.EncryptedClientHelloOffered {
			t.Errorf("EncryptedClientHelloOffered: want false, got true")
		}
	})

	t.Run("OfferedGREASE", func(t *testing.T) {
		clientConf := &tls.Config{
			EncryptedClientHelloOverride: greaseECHExtension(),
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)
		if !ci.EncryptedClientHelloOffered {
			t.Errorf("EncryptedClientHelloOffered: want true, got false")
		}
		if ci.Rating != okay {
			t.Errorf("Rating: want %s, got %s", okay, ci.Rating)
		}
	})

	// A GREASE ECH extension is legal even when the connection ends up
	// negotiating TLS 1.2; only *accepted* ECH requires TLS 1.3.
	t.Run("OfferedGREASETLS12", func(t *testing.T) {
		clientConf := &tls.Config{
			MinVersion:                   tls.VersionTLS12,
			MaxVersion:                   tls.VersionTLS12,
			EncryptedClientHelloOverride: greaseECHExtension(),
		}
		c := connect(t, clientConf)
		ci := pullClientInfo(c, preCutover)
		t.Logf("%#v", ci)
		if !ci.EncryptedClientHelloOffered {
			t.Errorf("EncryptedClientHelloOffered: want true, got false")
		}
		if ci.TLSVersion != "TLS 1.2" {
			t.Errorf("TLSVersion: want TLS 1.2, got %s", ci.TLSVersion)
		}
	})
}

func TestRatingCutovers(t *testing.T) {
	// Reference instants. These match the constants in client_info.go.
	beforeImprovable := time.Date(2026, 6, 13, 23, 59, 0, 0, time.UTC)
	atImprovable := time.Date(2026, 6, 14, 17, 0, 0, 0, time.UTC)
	atBad := time.Date(2026, 12, 14, 18, 0, 0, 0, time.UTC)

	t.Run("TLS12MaxNonPQ", func(t *testing.T) {
		// TLS 1.2 max, no post-quantum named group. Both signals
		// degrade in lockstep, so the overall rating tracks them.
		clientConf := &tls.Config{
			MaxVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}
		c := connect(t, clientConf)

		for _, tc := range []struct {
			name       string
			now        time.Time
			wantRating rating
		}{
			{"BeforeImprovable", beforeImprovable, okay},
			{"AtImprovable", atImprovable, improvable},
			{"AtBad", atBad, bad},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ci := pullClientInfo(c, tc.now)
				if ci.Rating != tc.wantRating {
					t.Errorf("Rating: want %s, got %s", tc.wantRating, ci.Rating)
				}
			})
		}
	})

	t.Run("TLS11Max", func(t *testing.T) {
		// TLS 1.1 max client. Already Improvable today; goes Bad at
		// the December cutover alongside TLS 1.2.
		clientConf := &tls.Config{
			MinVersion:   tls.VersionTLS11,
			MaxVersion:   tls.VersionTLS11,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		}
		c := connect(t, clientConf)

		for _, tc := range []struct {
			name       string
			now        time.Time
			wantRating rating
		}{
			{"BeforeImprovable", beforeImprovable, improvable},
			{"AtImprovable", atImprovable, improvable},
			{"AtBad", atBad, bad},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ci := pullClientInfo(c, tc.now)
				if ci.Rating != tc.wantRating {
					t.Errorf("Rating: want %s, got %s", tc.wantRating, ci.Rating)
				}
			})
		}
	})

	t.Run("TLS12MaxWithPQ", func(t *testing.T) {
		// TLS 1.2 max client that also advertises an ML-KEM group. The
		// version cutover still drives the overall rating to bad even
		// though the PQ signal is healthy.
		clientConf := &ztls.Config{
			MaxVersion:       ztls.VersionTLS12,
			CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519},
		}
		c := connectZtls(t, clientConf)

		ci := pullClientInfo(c, atBad)
		if !ci.PostQuantumKeyAgreement {
			t.Fatalf("PostQuantumKeyAgreement: want true, got false")
		}
		if ci.Rating != bad {
			t.Errorf("Rating: want %s, got %s", bad, ci.Rating)
		}
	})

	t.Run("TLS13NonPQ", func(t *testing.T) {
		// TLS 1.3 client without ML-KEM. Only the PQ cutover drives the
		// rating; the version is fine.
		clientConf := &tls.Config{
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}
		c := connect(t, clientConf)

		for _, tc := range []struct {
			name       string
			now        time.Time
			wantRating rating
		}{
			{"BeforeImprovable", beforeImprovable, okay},
			{"AtImprovable", atImprovable, improvable},
			{"AtBad", atBad, bad},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ci := pullClientInfo(c, tc.now)
				if ci.Rating != tc.wantRating {
					t.Errorf("Rating: want %s, got %s", tc.wantRating, ci.Rating)
				}
			})
		}
	})

	t.Run("TLS13WithPQ", func(t *testing.T) {
		// Modern client: TLS 1.3 and ML-KEM. The cutovers must never
		// degrade this client's rating.
		clientConf := &ztls.Config{
			CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519},
		}
		c := connectZtls(t, clientConf)

		ci := pullClientInfo(c, atBad)
		if !ci.PostQuantumKeyAgreement {
			t.Fatalf("PostQuantumKeyAgreement: want true, got false")
		}
		if ci.Rating != okay {
			t.Errorf("Rating: want %s, got %s", okay, ci.Rating)
		}
	})

	t.Run("CutoverFlags", func(t *testing.T) {
		// The template branches its prose on these booleans, so make
		// sure they flip at the configured instants regardless of what
		// the handshake looks like.
		c := connect(t, &tls.Config{})

		for _, tc := range []struct {
			name                 string
			now                  time.Time
			wantImprovablePassed bool
			wantBadPassed        bool
		}{
			{"BeforeImprovable", beforeImprovable, false, false},
			{"AtImprovable", atImprovable, true, false},
			{"AtBad", atBad, true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ci := pullClientInfo(c, tc.now)
				if ci.TLS12ImprovableCutoverPassed != tc.wantImprovablePassed {
					t.Errorf("TLS12ImprovableCutoverPassed: want %t, got %t", tc.wantImprovablePassed, ci.TLS12ImprovableCutoverPassed)
				}
				if ci.TLS12BadCutoverPassed != tc.wantBadPassed {
					t.Errorf("TLS12BadCutoverPassed: want %t, got %t", tc.wantBadPassed, ci.TLS12BadCutoverPassed)
				}
				if ci.NoPQImprovableCutoverPassed != tc.wantImprovablePassed {
					t.Errorf("NoPQImprovableCutoverPassed: want %t, got %t", tc.wantImprovablePassed, ci.NoPQImprovableCutoverPassed)
				}
				if ci.NoPQBadCutoverPassed != tc.wantBadPassed {
					t.Errorf("NoPQBadCutoverPassed: want %t, got %t", tc.wantBadPassed, ci.NoPQBadCutoverPassed)
				}
			})
		}
	})
}

var serverConf *tls.Config
var rootCA *x509.Certificate
var rootCAZtls *zx509.Certificate

func init() {
	serverConf = makeTLSConfig("./config/development_cert.pem", "./config/development_key.pem")
	certBytes, err := os.ReadFile("./config/development_ca_cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	cblock, _ := pem.Decode(certBytes)

	certs, err := x509.ParseCertificates(cblock.Bytes)
	if err != nil {
		log.Fatalf("x509.ParseCertificates: %s", err)
	}
	rootCA = certs[0]

	zcerts, err := zx509.ParseCertificates(cblock.Bytes)
	if err != nil {
		log.Fatalf("zx509.ParseCertificates: %s", err)
	}
	rootCAZtls = zcerts[0]
}

func connect(t *testing.T, clientConf *tls.Config) *tls.Conn {
	clientConf.ServerName = "localhost"

	// Required to flip on session ticket keys
	clientConf.ClientSessionCache = tls.NewLRUClientSessionCache(-1)

	// Required to avoid InsecureSkipVerify (which is probably unnecessary, but
	// nice to be Good™.)
	clientConf.RootCAs = x509.NewCertPool()
	clientConf.RootCAs.AddCert(rootCA)

	tl, err := tls.Listen("tcp", "localhost:0", serverConf)
	if err != nil {
		t.Fatalf("NewListener: %s", err)
	}
	li := howhttp.NewListener(tl, new(expvar.Map).Init())
	// bytesLen is picked to be large enough to trigger the BEAST vuln detection
	// if the client is vulnerable but small enough to not cause too much time
	// spent in the tests.
	bytesLen := 256
	type connRes struct {
		recv []byte
		conn *howhttp.Conn
	}
	ch := make(chan connRes)
	errCh := make(chan error)
	go func() {
		c, err := li.Accept()
		if err != nil {
			errCh <- err
			return
		}
		b := make([]byte, bytesLen)
		io.ReadFull(c, b)
		c.Close()
		li.Close()
		tc := c.(*howhttp.Conn)
		ch <- connRes{recv: b, conn: tc}
	}()
	var c *tls.Conn
	for i := range 10 {
		d := &net.Dialer{
			Timeout: 500 * time.Millisecond,
		}
		c, err = tls.DialWithDialer(d, "tcp", li.Addr().String(), clientConf)
		if err == nil {
			break
		} else {
			t.Logf("unable to connect on attempt %d: %s", i, err)
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err != nil {
		logErrFromServer(t, errCh)
		t.Fatalf("Dial: %s", err)
	}
	defer c.Close()
	sent := bytes.Repeat([]byte("a"), bytesLen)
	_, err = c.Write(sent)
	if err != nil {
		logErrFromServer(t, errCh)
		t.Fatalf("unable to send data to the conn: %s", err)
	}
	var cr connRes
	select {
	case err := <-errCh:
		t.Fatalf("Accept: %s", err)
	case cr = <-ch:
		if !bytes.Equal(cr.recv, sent) {
			t.Fatalf("expected bytes %#v, got %#v", string(sent), string(cr.recv))
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out")
	}
	return cr.conn.Conn
}

func connectZtls(t *testing.T, clientConf *ztls.Config) *tls.Conn {
	clientConf.ServerName = "localhost"

	// Required to flip on session ticket keys
	clientConf.ClientSessionCache = ztls.NewLRUClientSessionCache(-1)

	// Required to avoid InsecureSkipVerify (which is probably unnecessary, but
	// nice to be Good™.)
	clientConf.RootCAs = zx509.NewCertPool()
	clientConf.RootCAs.AddCert(rootCAZtls)

	tl, err := tls.Listen("tcp", "localhost:0", serverConf)
	if err != nil {
		t.Fatalf("NewListener: %s", err)
	}
	li := howhttp.NewListener(tl, new(expvar.Map).Init())
	bytesLen := 256
	type connRes struct {
		recv []byte
		conn *howhttp.Conn
	}
	ch := make(chan connRes)
	errCh := make(chan error)
	go func() {
		c, err := li.Accept()
		if err != nil {
			errCh <- err
			return
		}
		b := make([]byte, bytesLen)
		io.ReadFull(c, b)
		c.Close()
		li.Close()
		tc := c.(*howhttp.Conn)
		ch <- connRes{recv: b, conn: tc}
	}()
	var c *ztls.Conn
	for i := range 10 {
		d := &net.Dialer{
			Timeout: 500 * time.Millisecond,
		}
		c, err = ztls.DialWithDialer(d, "tcp", li.Addr().String(), clientConf)
		if err == nil {
			break
		} else {
			t.Logf("unable to connect on attempt %d: %s", i, err)
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err != nil {
		logErrFromServer(t, errCh)
		t.Fatalf("Dial: %s", err)
	}
	defer c.Close()
	sent := bytes.Repeat([]byte("a"), bytesLen)
	_, err = c.Write(sent)
	if err != nil {
		logErrFromServer(t, errCh)
		t.Fatalf("unable to send data to the conn: %s", err)
	}
	var cr connRes
	select {
	case err := <-errCh:
		t.Fatalf("Accept: %s", err)
	case cr = <-ch:
		if !bytes.Equal(cr.recv, sent) {
			t.Fatalf("expected bytes %#v, got %#v", string(sent), string(cr.recv))
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out")
	}
	return cr.conn.Conn
}

func logErrFromServer(t *testing.T, errCh chan error) {
	defer func() {
		select {
		case err := <-errCh:
			if err != nil {
				t.Logf("error from server side: %s", err)
			}
		case <-time.After(100 * time.Millisecond):
			// do nothing
		}
	}()
}
