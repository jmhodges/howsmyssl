package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// checkSuiteDetailsAgree fails the test if the per-suite marks say anything
// the fields the rating is made from don't.
func checkSuiteDetailsAgree(t *testing.T, ci *clientInfo) {
	t.Helper()
	names := []string{}
	anyForwardSecret := false
	for _, d := range ci.GivenCipherSuiteDetails {
		names = append(names, d.Name)
		anyForwardSecret = anyForwardSecret || d.ForwardSecret
		reasons, insecure := ci.InsecureCipherSuites[d.Name]
		if d.Weak != insecure {
			t.Errorf("%s: weak is %t, but in InsecureCipherSuites is %t", d.Name, d.Weak, insecure)
		}
		if d.WeakReasons == nil {
			t.Errorf("%s: weak reasons are nil, and would be null in the JSON", d.Name)
		}
		if !cmp.Equal(append([]string{}, reasons...), d.WeakReasons) {
			t.Errorf("%s: weak reasons: want %v, got %v", d.Name, reasons, d.WeakReasons)
		}
	}
	if !cmp.Equal(append([]string{}, ci.GivenCipherSuites...), names) {
		t.Errorf("detail names: want %v, got %v", ci.GivenCipherSuites, names)
	}
	if anyForwardSecret != ci.EphemeralKeysSupported {
		t.Errorf("a suite is marked forward secret: %t, but EphemeralKeysSupported is %t", anyForwardSecret, ci.EphemeralKeysSupported)
	}
}

func TestCipherSuiteDetails(t *testing.T) {
	const (
		greaseCS  = uint16(0x0A0A)
		unknownCS = uint16(0xBEEF)
		nssCS     = uint16(0xFEFF)
		tls13CS   = uint16(0x1301)
	)
	fs := func(name string) cipherSuiteDetail {
		return cipherSuiteDetail{Name: name, ForwardSecret: true, WeakReasons: []string{}}
	}
	plain := func(name string) cipherSuiteDetail {
		return cipherSuiteDetail{Name: name, WeakReasons: []string{}}
	}
	weak := func(name string, forwardSecret bool, reasons ...string) cipherSuiteDetail {
		return cipherSuiteDetail{Name: name, ForwardSecret: forwardSecret, Weak: true, WeakReasons: reasons}
	}
	tests := []struct {
		name   string
		suites []uint16
		want   []cipherSuiteDetail
		rating rating
	}{
		{
			name: "ForwardSecretAndNot",
			suites: []uint16{
				ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
				ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				ztls.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
				greaseCS,
			},
			want: []cipherSuiteDetail{
				fs("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
				fs("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
				plain("TLS_RSA_WITH_AES_128_GCM_SHA256"),
				plain("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
				plain("TLS_GREASE_IS_THE_WORD_0A"),
			},
			rating: okay,
		},
		{
			name: "Weak",
			suites: []uint16{
				ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				ztls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				ztls.TLS_RSA_WITH_RC4_128_SHA,
				0x0017, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
				0x002D, // TLS_DHE_PSK_WITH_NULL_SHA
				nssCS,
				unknownCS,
			},
			want: []cipherSuiteDetail{
				fs("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
				weak("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", true, sweet32Reason),
				weak("TLS_ECDHE_RSA_WITH_RC4_128_SHA", true, rc4Reason),
				weak("TLS_RSA_WITH_RC4_128_SHA", false, rc4Reason),
				weak("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", false, fewBitReason, nullAuthReason, rc4Reason),
				weak("TLS_DHE_PSK_WITH_NULL_SHA", true, nullReason),
				weak("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", false, weirdNSSReason),
				plain("Some unknown cipher suite: 0xbeef"),
			},
			rating: bad,
		},
		{
			// 3DES in the fallback position isn't weak, so it has no mark.
			name: "Sweet32AsFallback",
			suites: []uint16{
				ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				greaseCS,
			},
			want: []cipherSuiteDetail{
				fs("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
				plain("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
				plain("TLS_GREASE_IS_THE_WORD_0A"),
			},
			rating: okay,
		},
		{
			// A TLS 1.3 suite from a client that won't negotiate TLS 1.3 is
			// never used, so it doesn't count for EphemeralKeysSupported and
			// gets no mark either.
			name: "TLS13SuiteWithoutTLS13",
			suites: []uint16{
				ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls13CS,
			},
			want: []cipherSuiteDetail{
				plain("TLS_RSA_WITH_AES_128_GCM_SHA256"),
				plain("TLS_AES_128_GCM_SHA256"),
			},
			rating: improvable,
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
			if diff := cmp.Diff(tc.want, ci.GivenCipherSuiteDetails); diff != "" {
				t.Errorf("GivenCipherSuiteDetails (-want +got):\n%s", diff)
			}
			if ci.Rating != tc.rating {
				t.Errorf("rating: want %s, got %s", tc.rating, ci.Rating)
			}
			checkSuiteDetailsAgree(t, ci)
		})
	}
}

// The TLS 1.3 suites have no key exchange in their names, but are forward
// secret when the client can finish a TLS 1.3 handshake.
func TestCipherSuiteDetailsTLS13(t *testing.T) {
	tests := []struct {
		name string
		conf *tls.Config
	}{
		{"GoDefault", &tls.Config{}},
		{"TLS13Only", &tls.Config{MinVersion: tls.VersionTLS13}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := connect(t, tc.conf)
			ci := pullClientInfo(c, preCutover)
			if len(ci.GivenCipherSuiteDetails) == 0 {
				t.Fatalf("no cipher suite details given")
			}
			for _, d := range ci.GivenCipherSuiteDetails {
				if !d.ForwardSecret || d.Weak {
					t.Errorf("%s: want forward secret and not weak, got %+v", d.Name, d)
				}
			}
			checkSuiteDetailsAgree(t, ci)
		})
	}
}

// The field names are the API: a suite with no weak reasons gets [], not null.
func TestCipherSuiteDetailsJSONShape(t *testing.T) {
	c := connectZtls(t, &ztls.Config{
		MaxVersion:   ztls.VersionTLS12,
		CipherSuites: []uint16{ztls.TLS_RSA_WITH_RC4_128_SHA, ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		ForceSuites:  true,
	})
	b, err := json.Marshal(pullClientInfo(c, preCutover))
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	want := `"given_cipher_suite_details":[` +
		`{"name":"TLS_RSA_WITH_RC4_128_SHA","forward_secret":false,"weak":true,"weak_reasons":["` + rc4Reason + `"]},` +
		`{"name":"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","forward_secret":true,"weak":false,"weak_reasons":[]}]`
	if !strings.Contains(string(b), want) {
		t.Errorf("JSON: want it to contain %s, got %s", want, b)
	}
}

func TestIndexShowsCipherSuiteMarks(t *testing.T) {
	ci := &clientInfo{
		GivenCipherSuiteDetails: []cipherSuiteDetail{
			{Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", ForwardSecret: true, Weak: true, WeakReasons: []string{rc4Reason}},
			{Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", WeakReasons: []string{}},
		},
		InsecureCipherSuites: map[string][]string{"TLS_ECDHE_RSA_WITH_RC4_128_SHA": {rc4Reason}},
		Rating:               bad,
	}
	b := new(bytes.Buffer)
	if err := loadIndex().Execute(b, ci); err != nil {
		t.Fatalf("Execute: %s", err)
	}
	for _, want := range []string{
		`<li>TLS_ECDHE_RSA_WITH_RC4_128_SHA <span class="suite-mark okay">Forward Secrecy</span> <span class="suite-mark bad" title="This cipher suite ` + rc4Reason + `.">Weak</span></li>`,
		`<li>TLS_RSA_WITH_AES_128_GCM_SHA256</li>`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("index page: want it to contain %s", want)
		}
	}
}
