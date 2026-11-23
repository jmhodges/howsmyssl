package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	ztls "github.com/zmap/zcrypto/tls"
)

// IDEA and the export-grade RC2 suites count against a client wherever they
// are in its list. Here each one is offered last, where a 3DES suite would be
// let off as a last resort.
func TestIDEAAndExportRC2Suites(t *testing.T) {
	tests := []struct {
		suite  uint16
		name   string
		reason string
	}{
		{0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", ideaReason},
		{0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA", ideaReason},
		{0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5", ideaReason},
		{0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", fewBitReason},
		{0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", fewBitReason},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
			want := map[string][]string{tc.name: {tc.reason}}
			if !cmp.Equal(want, ci.InsecureCipherSuites) {
				t.Errorf("insecure cipher suites: want %v, got %v", want, ci.InsecureCipherSuites)
			}
			if ci.Rating != bad {
				t.Errorf("rating: want %s, got %s", bad, ci.Rating)
			}
		})
	}
}

// The insecure lists are keyed by name and filled in by hand, so a suite that
// allCipherSuites gains can be left out of them without anything failing. This
// catches the ones whose name alone says which list they belong in.
func TestInsecureListsHaveEverySuiteNamedForThem(t *testing.T) {
	for id, name := range allCipherSuites {
		if strings.Contains(name, "_IDEA_") && !ideaCipherSuites[name] {
			t.Errorf("%#04x %s: uses IDEA, but is not in ideaCipherSuites", id, name)
		}
		if strings.Contains(name, "_EXPORT") && !fewBitCipherSuites[name] {
			t.Errorf("%#04x %s: export grade, but is not in fewBitCipherSuites", id, name)
		}
	}
}

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
