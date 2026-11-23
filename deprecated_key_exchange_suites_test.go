package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	ztls "github.com/zmap/zcrypto/tls"
)

// registryDeprecatedKeyExchangeSuites reads IANA's TLS Cipher Suites registry
// from testdata and returns every suite it marks "D" with RFC 10015 among its
// references.
func registryDeprecatedKeyExchangeSuites(t *testing.T) map[uint16]string {
	t.Helper()
	f, err := os.Open("testdata/iana-tls-cipher-suites.csv")
	if err != nil {
		t.Fatalf("opening registry copy: %s", err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("reading registry copy: %s", err)
	}
	if len(records) == 0 || !slices.Equal(records[0][:5], []string{"Value", "Description", "DTLS-OK", "Recommended", "Reference"}) {
		t.Fatalf("registry copy has an unexpected header: %v", records[0])
	}
	out := make(map[uint16]string)
	for _, rec := range records[1:] {
		if rec[3] != "D" || !strings.Contains(rec[4], "RFC 10015") {
			continue
		}
		hi, lo, ok := strings.Cut(rec[0], ",")
		if !ok {
			t.Fatalf("registry value %q is not a single code point", rec[0])
		}
		h, err := strconv.ParseUint(strings.TrimPrefix(hi, "0x"), 16, 8)
		if err != nil {
			t.Fatalf("registry value %q: %s", rec[0], err)
		}
		l, err := strconv.ParseUint(strings.TrimPrefix(lo, "0x"), 16, 8)
		if err != nil {
			t.Fatalf("registry value %q: %s", rec[0], err)
		}
		out[uint16(h)<<8|uint16(l)] = rec[1]
	}
	return out
}

func TestDeprecatedKeyExchangeSuitesMatchRegistry(t *testing.T) {
	want := registryDeprecatedKeyExchangeSuites(t)
	if len(want) == 0 {
		t.Fatalf("registry copy has no suites marked D for RFC 10015")
	}
	for id, name := range want {
		got, found := deprecatedKeyExchangeSuites[id]
		if !found {
			t.Errorf("missing from deprecatedKeyExchangeSuites, add:\t%#04x: %q,", id, name)
		} else if got != name {
			t.Errorf("%#04x: want name %q, got %q", id, name, got)
		}
	}
	for id, name := range deprecatedKeyExchangeSuites {
		if _, found := want[id]; !found {
			t.Errorf("not marked D for RFC 10015 in the registry, remove:\t%#04x: %q,", id, name)
		}
	}
}

// The table's names have to be the ones given_cipher_suites shows, so the two
// lists can be matched by name.
func TestDeprecatedKeyExchangeSuitesNamedAsInAllCipherSuites(t *testing.T) {
	for id, name := range deprecatedKeyExchangeSuites {
		if got := allCipherSuites[id]; got != name {
			t.Errorf("%#04x: deprecatedKeyExchangeSuites says %q, allCipherSuites says %q", id, name, got)
		}
	}
}

// Every listed suite has one of the deprecated key exchanges in its name, and
// none of them is a TLS 1.3 suite or an ECDHE one. This catches a mislabelled
// entry even if the registry copy were wrong too.
func TestDeprecatedKeyExchangeSuitesFamilies(t *testing.T) {
	families := []string{
		"RSA", "RSA_EXPORT", "RSA_PSK",
		"DHE_DSS", "DHE_DSS_EXPORT", "DHE_RSA", "DHE_RSA_EXPORT", "DHE_PSK", "PSK_DHE",
		"DH_DSS", "DH_DSS_EXPORT", "DH_RSA", "DH_RSA_EXPORT", "DH_anon", "DH_anon_EXPORT",
		"ECDH_ECDSA", "ECDH_RSA", "ECDH_anon",
	}
	for id, name := range deprecatedKeyExchangeSuites {
		if tls13Suites[id] {
			t.Errorf("%#04x %s is a TLS 1.3 suite", id, name)
		}
		kx, _, ok := strings.Cut(strings.TrimPrefix(name, "TLS_"), "_WITH_")
		if !ok || !slices.Contains(families, kx) {
			t.Errorf("%#04x %s: key exchange %q is not one of the deprecated families", id, name, kx)
		}
	}
}

func TestDeprecatedKeyExchangeSuitesReported(t *testing.T) {
	tests := []struct {
		name   string
		suites []uint16
		want   []string
	}{
		{
			"only ECDHE",
			[]uint16{ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
			[]string{},
		},
		{
			"RSA and DHE fallbacks, in the order offered",
			[]uint16{
				ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
				ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			},
			[]string{
				"TLS_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_RSA_WITH_AES_128_GCM_SHA256",
			},
		},
	}
	var ratings []rating
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientConf := &ztls.Config{
				MaxVersion:   ztls.VersionTLS12,
				CipherSuites: tc.suites,
				ForceSuites:  true,
			}
			c := connectZtls(t, clientConf)
			ci := pullClientInfo(c, preCutover)
			if !cmp.Equal(tc.want, ci.DeprecatedKeyExchangeSuites) {
				t.Errorf("deprecated key exchange suites: want %v, got %v", tc.want, ci.DeprecatedKeyExchangeSuites)
			}
			if len(ci.InsecureCipherSuites) != 0 {
				t.Errorf("insecure cipher suites: want none, got %v", ci.InsecureCipherSuites)
			}
			ratings = append(ratings, ci.Rating)
		})
	}
	// Report-only: offering the deprecated suites changes nothing in the rating.
	if len(ratings) == 2 && ratings[0] != ratings[1] {
		t.Errorf("rating changed with deprecated suites offered: %s without, %s with", ratings[0], ratings[1])
	}
}

func TestIndexDeprecatedKeyExchange(t *testing.T) {
	tmpl := loadIndex()
	tests := []struct {
		name     string
		suites   []string
		wantLine string
	}{
		{"none", []string{}, ""},
		{"two", []string{"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
			"TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			ci := &clientInfo{InsecureCipherSuites: map[string][]string{}, DeprecatedKeyExchangeSuites: tc.suites}
			if err := tmpl.Execute(buf, ci); err != nil {
				t.Fatalf("index execution: %s", err)
			}
			body := buf.String()
			shown := strings.Contains(body, `id="deprecated-key-exchange"`)
			if shown != (tc.wantLine != "") {
				t.Fatalf("deprecated key exchange line shown: want %t, got %t", tc.wantLine != "", shown)
			}
			if tc.wantLine != "" && !strings.Contains(body, tc.wantLine) {
				t.Errorf("deprecated key exchange line: want it to contain %q", tc.wantLine)
			}
			if tc.wantLine != "" && !strings.Contains(body, "change your rating") {
				t.Errorf("deprecated key exchange line: want it to say the rating doesn't change")
			}
		})
	}
}
