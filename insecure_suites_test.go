package main

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

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
