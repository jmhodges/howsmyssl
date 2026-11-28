package main

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// OpenSSL's legacy GOST cipher suites live at code points that IANA's registry
// lists as unassigned, so allCipherSuites names them by hand. Two of the three added for
// #417 have no encryption, and so have to be in nullCipherSuites as well:
// with only the name, a client offering one would stop being told about it.
func TestOpenSSLGOSTSuites(t *testing.T) {
	tests := []struct {
		suite    uint16
		name     string
		rating   rating
		insecure map[string][]string
	}{
		{0x0080, "TLS_GOST94-GOST89-GOST89", okay, map[string][]string{}},
		{0x0081, "TLS_GOST2001-GOST89-GOST89", okay, map[string][]string{}},
		{0x0082, "TLS_GOST94-NULL-GOST94", bad, map[string][]string{
			"TLS_GOST94-NULL-GOST94": {nullReason},
		}},
		{0x0083, "TLS_GOST2001-NULL-GOST94", bad, map[string][]string{
			"TLS_GOST2001-NULL-GOST94": {nullReason},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// ForceSuites makes the zcrypto/tls client offer a suite it
			// doesn't implement. The server picks the first one.
			clientConf := &ztls.Config{
				MaxVersion:   ztls.VersionTLS12,
				CipherSuites: []uint16{ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tc.suite},
				ForceSuites:  true,
			}
			c := connectZtls(t, clientConf)
			ci := pullClientInfo(c, preCutover)

			if !slices.Contains(ci.GivenCipherSuites, tc.name) {
				t.Errorf("given cipher suites: want %s among them, got %v", tc.name, ci.GivenCipherSuites)
			}
			if ci.UnknownCipherSuiteSupported {
				t.Errorf("unknown cipher suite supported: want false, got true (%v)", ci.GivenCipherSuites)
			}
			if !cmp.Equal(tc.insecure, ci.InsecureCipherSuites) {
				t.Errorf("insecure cipher suites: want %v, got %v", tc.insecure, ci.InsecureCipherSuites)
			}
			if ci.Rating != tc.rating {
				t.Errorf("rating: want %s, got %s", tc.rating, ci.Rating)
			}
		})
	}
}

func TestSweet32Suites(t *testing.T) {
	const (
		aes128GCM13     = 0x1301 // TLS_AES_128_GCM_SHA256
		rsa3DES         = 0x000A // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		ecdheRSA3DES    = 0xC012 // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
		anon3DES        = 0x001B // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
		rsaAES128       = 0x002F // TLS_RSA_WITH_AES_128_CBC_SHA
		rsaRC4          = 0x0005 // TLS_RSA_WITH_RC4_128_SHA
		rsaDES          = 0x0009 // TLS_RSA_WITH_DES_CBC_SHA
		rsaNULL         = 0x0002 // TLS_RSA_WITH_NULL_SHA
		anonAES128      = 0x0034 // TLS_DH_anon_WITH_AES_128_CBC_SHA
		integrityOnly13 = 0xC0B4 // TLS_SHA256_SHA256
		nssFIPS3DES     = 0xFEFF // SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
		unknownSuite    = 0xFFFE
		greaseSuite     = 0x0A0A
		emptyRenegoSCSV = 0x00FF
	)
	const (
		rsa3DESName      = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
		ecdheRSA3DESName = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
		anon3DESName     = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
	)
	tests := []struct {
		name         string
		suites       []uint16
		tls13Offered bool
		notFallback  []string
		noStronger   []string
	}{
		{name: "No3DES", suites: []uint16{rsaAES128, rsaRC4}},
		{name: "Nothing"},

		// The exemption: 3DES last, behind something stronger.
		{name: "LastBehindAES", suites: []uint16{rsaAES128, rsa3DES}},
		{name: "LastBehindAESThenMeta", suites: []uint16{rsaAES128, ecdheRSA3DES, rsa3DES, greaseSuite, emptyRenegoSCSV}},
		{name: "LastBehindAESThenTLS13", suites: []uint16{rsaAES128, rsa3DES, aes128GCM13}, tls13Offered: true},
		// Before and after this change, a TLS 1.3 suite after 3DES doesn't
		// make the 3DES "not last", whether TLS 1.3 is offered or not.
		{name: "LastBehindAESThenUnofferedTLS13", suites: []uint16{rsaAES128, rsa3DES, aes128GCM13}},

		// 3DES ahead of another real suite, as before this change.
		{name: "AheadOfAES", suites: []uint16{rsa3DES, rsaAES128}, notFallback: []string{rsa3DESName}},
		{name: "AheadOfRC4", suites: []uint16{rsa3DES, rsaRC4}, notFallback: []string{rsa3DESName}},
		{
			name:        "AheadAndLast",
			suites:      []uint16{ecdheRSA3DES, rsaAES128, rsa3DES},
			notFallback: []string{ecdheRSA3DESName},
		},
		{
			name:        "AheadOfFallbackSCSV",
			suites:      []uint16{rsaAES128, rsa3DES, tlsFallbackSCSV},
			notFallback: []string{rsa3DESName},
		},

		// 3DES last, with nothing stronger for it to be the fallback to.
		{name: "Only3DES", suites: []uint16{rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "Only3DESSuites", suites: []uint16{ecdheRSA3DES, rsa3DES}, noStronger: []string{ecdheRSA3DESName, rsa3DESName}},
		{name: "OnlyAnon3DES", suites: []uint16{anon3DES}, noStronger: []string{anon3DESName}},
		{name: "BehindMeta", suites: []uint16{greaseSuite, rsa3DES, emptyRenegoSCSV}, noStronger: []string{rsa3DESName}},
		{name: "BehindFallbackSCSV", suites: []uint16{tlsFallbackSCSV, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindRC4", suites: []uint16{rsaRC4, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindDES", suites: []uint16{rsaDES, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindNULL", suites: []uint16{rsaNULL, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindAnon", suites: []uint16{anonAES128, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindUnknown", suites: []uint16{unknownSuite, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindWeirdNSS", suites: []uint16{nssFIPS3DES, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "BehindIntegrityOnlyTLS13", suites: []uint16{integrityOnly13, rsa3DES}, tls13Offered: true, noStronger: []string{rsa3DESName}},
		{
			name:        "AheadOfRC4AndLast",
			suites:      []uint16{ecdheRSA3DES, rsaRC4, rsa3DES},
			notFallback: []string{ecdheRSA3DESName},
			noStronger:  []string{rsa3DESName},
		},

		// A TLS 1.3 suite is something stronger only for a client that
		// will negotiate TLS 1.3, and then on either side of the 3DES: the
		// two lists are for different protocol versions.
		{name: "TLS13SuiteNotOffered", suites: []uint16{aes128GCM13, rsa3DES}, noStronger: []string{rsa3DESName}},
		{name: "TLS13OfferedAhead", suites: []uint16{aes128GCM13, rsa3DES}, tls13Offered: true},
		{name: "TLS13OfferedBehind", suites: []uint16{rsa3DES, aes128GCM13}, tls13Offered: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			notFallback, noStronger := sweet32Suites(tc.suites, tc.tls13Offered)
			if !slices.Equal(notFallback, tc.notFallback) {
				t.Errorf("notFallback: want %v, got %v", tc.notFallback, notFallback)
			}
			if !slices.Equal(noStronger, tc.noStronger) {
				t.Errorf("noStronger: want %v, got %v", tc.noStronger, noStronger)
			}
		})
	}
}

// A client whose best cipher suite is 3DES uses 3DES with every server, so
// listing it last is no mitigation.
func TestSweet32NothingStronger(t *testing.T) {
	const (
		rsaRC4          = 0x0005 // TLS_RSA_WITH_RC4_128_SHA
		emptyRenegoSCSV = 0x00FF
	)
	tests := []struct {
		name     string
		suites   []uint16
		rating   rating
		insecure map[string][]string
	}{
		{
			"Only3DES",
			[]uint16{ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			bad,
			map[string][]string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA": {sweet32NoStrongerReason}},
		},
		{
			"Only3DESAndMeta",
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, emptyRenegoSCSV},
			bad,
			map[string][]string{
				"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": {sweet32NoStrongerReason},
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       {sweet32NoStrongerReason},
			},
		},
		{
			"RC4Then3DES",
			[]uint16{rsaRC4, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			bad,
			map[string][]string{
				"TLS_RSA_WITH_RC4_128_SHA":      {rc4Reason},
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA": {sweet32NoStrongerReason},
			},
		},
		{
			"AESThen3DES",
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			okay,
			map[string][]string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientConf := &ztls.Config{
				MaxVersion:   ztls.VersionTLS12,
				CipherSuites: tc.suites,
				ForceSuites:  true,
			}
			c := connectZtls(t, clientConf)
			ci := pullClientInfo(c, preCutover)

			if len(ci.GivenCipherSuites) != len(tc.suites) {
				t.Errorf("given cipher suites: want %d of them, got %v", len(tc.suites), ci.GivenCipherSuites)
			}
			if !cmp.Equal(tc.insecure, ci.InsecureCipherSuites) {
				t.Errorf("insecure cipher suites: want %v, got %v", tc.insecure, ci.InsecureCipherSuites)
			}
			if ci.Rating != tc.rating {
				t.Errorf("rating: want %s, got %s", tc.rating, ci.Rating)
			}
		})
	}
}

// 3DES as the only TLS 1.2 cipher suite of a client that also offers TLS 1.3
// is still a fallback: any TLS 1.3 server gives it something stronger.
func TestSweet32FallbackToTLS13(t *testing.T) {
	clientConf := &tls.Config{
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	}
	c := connect(t, clientConf)
	ci := pullClientInfo(c, preCutover)

	if !slices.Contains(ci.GivenCipherSuites, "TLS_RSA_WITH_3DES_EDE_CBC_SHA") {
		t.Fatalf("test client didn't offer 3DES, so it isn't exercising the fallback: %v", ci.GivenCipherSuites)
	}
	if ci.TLSVersion != "TLS 1.3" {
		t.Fatalf("TLSVersion: want TLS 1.3, got %s", ci.TLSVersion)
	}
	if len(ci.InsecureCipherSuites) != 0 {
		t.Errorf("insecure cipher suites: want none, got %v", ci.InsecureCipherSuites)
	}
	if ci.Rating != okay {
		t.Errorf("rating: want %s, got %s", okay, ci.Rating)
	}
}
