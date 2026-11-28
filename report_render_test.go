package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// These tests cover how a report that is not all good is written out as
// HTML, JSON and JSONP. The other tests of the handlers only render the
// report of Go's own client, where every finding is good. None of these
// compares a whole page or a whole JSON body.

func TestReportSentence(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		want  string
	}{
		{"One", []string{"is old"}, "is old."},
		{"Two", []string{"is old", "is slow"}, "is old, and is slow."},
		{"Three", []string{"is old", "is slow", "is weak"}, "is old, is slow, and is weak."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sentence(tc.parts); got != tc.want {
				t.Errorf("sentence(%q): want %q, got %q", tc.parts, tc.want, got)
			}
		})
	}
}

func TestReportRatingSpan(t *testing.T) {
	tests := []struct {
		rating rating
		want   string
	}{
		{okay, "okay"},
		{improvable, "improvable"},
		{bad, "bad"},
		// A rating the page has no colour for gets no class, not another
		// rating's.
		{rating("Something New"), ""},
	}
	for _, tc := range tests {
		t.Run(string(tc.rating), func(t *testing.T) {
			if got := string(ratingSpan(tc.rating)); got != tc.want {
				t.Errorf("ratingSpan(%q): want %q, got %q", tc.rating, tc.want, got)
			}
		})
	}
}

// The page has a branch for every finding. A template only fails when a
// branch runs, so a mistake in one that Go's own client never takes would be
// a 500 for just the clients that most need the page.
func TestReportHTMLForFlaggedClients(t *testing.T) {
	index = loadIndex()

	const (
		unknownHeading = "Unknown Cipher Suites Supported"
		insecureItem   = ": This cipher suite "
	)
	tests := []struct {
		name        string
		ci          *clientInfo
		wantHero    string
		wantUnknown bool
		wantItems   []string
	}{
		{
			name: "Okay",
			ci: &clientInfo{
				GivenCipherSuites:       []string{"TLS_AES_128_GCM_SHA256"},
				GivenNamedGroups:        []string{"X25519MLKEM768"},
				PostQuantumKeyAgreement: true,
				EphemeralKeysSupported:  true,
				SessionTicketsSupported: true,
				InsecureCipherSuites:    map[string][]string{},
				TLSVersion:              "TLS 1.3",
				Rating:                  okay,
			},
			wantHero: `<span class="hero-unit-okay">Probably Okay</span>`,
		},
		{
			name: "Improvable",
			ci: &clientInfo{
				GivenCipherSuites:    []string{"TLS_RSA_WITH_AES_128_GCM_SHA256"},
				InsecureCipherSuites: map[string][]string{},
				TLSVersion:           "TLS 1.1",
				Rating:               improvable,
			},
			wantHero: `<span class="hero-unit-improvable">Improvable</span>`,
		},
		{
			// The Version section has a branch for each of TLS 1.2 and
			// TLS 1.1 on each side of the cutovers.
			name: "TLS12AfterImprovableCutover",
			ci: &clientInfo{
				InsecureCipherSuites:         map[string][]string{},
				TLSVersion:                   "TLS 1.2",
				Rating:                       improvable,
				TLS12ImprovableCutoverPassed: true,
				NoPQImprovableCutoverPassed:  true,
			},
			wantHero: `<span class="hero-unit-improvable">Improvable</span>`,
		},
		{
			name: "TLS12AfterBadCutover",
			ci: &clientInfo{
				InsecureCipherSuites:         map[string][]string{},
				TLSVersion:                   "TLS 1.2",
				Rating:                       bad,
				TLS12ImprovableCutoverPassed: true,
				TLS12BadCutoverPassed:        true,
				NoPQImprovableCutoverPassed:  true,
				NoPQBadCutoverPassed:         true,
			},
			wantHero: `<span class="hero-unit-bad">Bad</span>`,
		},
		{
			name: "TLS11AfterBadCutover",
			ci: &clientInfo{
				InsecureCipherSuites:         map[string][]string{},
				TLSVersion:                   "TLS 1.1",
				Rating:                       bad,
				TLS12ImprovableCutoverPassed: true,
				TLS12BadCutoverPassed:        true,
				NoPQImprovableCutoverPassed:  true,
				NoPQBadCutoverPassed:         true,
			},
			wantHero: `<span class="hero-unit-bad">Bad</span>`,
		},
		{
			name: "InsecureSuites",
			ci: &clientInfo{
				GivenCipherSuites: []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
				InsecureCipherSuites: map[string][]string{
					"TLS_RSA_WITH_RC4_128_SHA":           {rc4Reason},
					"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5": {fewBitReason, nullAuthReason, rc4Reason},
				},
				TLSVersion: "TLS 1.2",
				Rating:     bad,
			},
			wantHero: `<span class="hero-unit-bad">Bad</span>`,
			wantItems: []string{
				"<li>TLS_RSA_WITH_RC4_128_SHA: This cipher suite " + rc4Reason + ".</li>",
				"<li>TLS_DH_anon_EXPORT_WITH_RC4_40_MD5: This cipher suite " + fewBitReason + ", " + nullAuthReason + ", and " + rc4Reason + ".</li>",
			},
		},
		{
			name: "UnknownSuite",
			ci: &clientInfo{
				GivenCipherSuites:           []string{"Some unknown cipher suite: 0xfffd"},
				UnknownCipherSuiteSupported: true,
				InsecureCipherSuites:        map[string][]string{},
				TLSVersion:                  "TLS 1.2",
				Rating:                      bad,
			},
			wantHero:    `<span class="hero-unit-bad">Bad</span>`,
			wantUnknown: true,
		},
		{
			// Every finding at its worst, and after both cutovers, so
			// that each bad branch of the page runs once.
			name: "EverythingBad",
			ci: &clientInfo{
				GivenCipherSuites:              []string{"TLS_RSA_WITH_AES_128_CBC_SHA", "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", "Some unknown cipher suite: 0xfffd"},
				GivenNamedGroups:               []string{"Unknown named group: 0xfe42"},
				GivenSignatureAlgorithms:       []string{"Unknown signature scheme: 0xfe42"},
				TLSCompressionSupported:        true,
				UnknownCipherSuiteSupported:    true,
				BEASTVuln:                      true,
				AbleToDetectNMinusOneSplitting: true,
				InsecureCipherSuites: map[string][]string{
					"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA": {weirdNSSReason},
				},
				TLSVersion:                   "TLS 1.0",
				Rating:                       bad,
				TLS12ImprovableCutoverPassed: true,
				TLS12BadCutoverPassed:        true,
				NoPQImprovableCutoverPassed:  true,
				NoPQBadCutoverPassed:         true,
			},
			wantHero:    `<span class="hero-unit-bad">Bad</span>`,
			wantUnknown: true,
			wantItems: []string{
				"<li>SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA: This cipher suite " + weirdNSSReason + ".</li>",
			},
		},
		{
			// BEAST assumed, because the server couldn't watch for the
			// mitigation: the other bad branch of that section.
			name: "BEASTUndetectable",
			ci: &clientInfo{
				GivenCipherSuites:    []string{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
				BEASTVuln:            true,
				InsecureCipherSuites: map[string][]string{},
				TLSVersion:           "an unknown version of SSL/TLS",
				Rating:               bad,
			},
			wantHero: `<span class="hero-unit-bad">Bad</span>`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			b, status, contentType, err := renderHTML(r, tc.ci)
			if err != nil {
				t.Fatalf("renderHTML: %s", err)
			}
			if status != http.StatusOK {
				t.Errorf("status: want %d, got %d", http.StatusOK, status)
			}
			if contentType != htmlContentType {
				t.Errorf("content type: want %s, got %s", htmlContentType, contentType)
			}
			page := string(b)
			if !strings.Contains(page, tc.wantHero) {
				t.Errorf("page: want %s in it, and it is not", tc.wantHero)
			}
			if got := strings.Contains(page, unknownHeading); got != tc.wantUnknown {
				t.Errorf("page has %q: want %t, got %t", unknownHeading, tc.wantUnknown, got)
			}
			for _, item := range tc.wantItems {
				if !strings.Contains(page, item) {
					t.Errorf("page: want %s in it, and it is not", item)
				}
			}
			if got := strings.Count(page, insecureItem); got != len(tc.wantItems) {
				t.Errorf("insecure cipher suites listed on the page: want %d, got %d", len(tc.wantItems), got)
			}
			if !strings.HasSuffix(strings.TrimSpace(page), "</html>") {
				t.Errorf("page: want it to end with </html>, got ...%q", page[max(0, len(page)-40):])
			}
		})
	}
}

// Each finding of the report has its own key in the JSON. This sets them one
// at a time, so a key that got another finding's value, or lost its own,
// shows.
func TestReportJSONFlags(t *testing.T) {
	boolKeys := []string{
		"post_quantum_key_agreement",
		"ephemeral_keys_supported",
		"session_ticket_supported",
		"tls_compression_supported",
		"unknown_cipher_suite_supported",
		"beast_vuln",
		"able_to_detect_n_minus_one_splitting",
	}
	tests := []struct {
		key string
		set func(*clientInfo)
	}{
		{"post_quantum_key_agreement", func(ci *clientInfo) { ci.PostQuantumKeyAgreement = true }},
		{"ephemeral_keys_supported", func(ci *clientInfo) { ci.EphemeralKeysSupported = true }},
		{"session_ticket_supported", func(ci *clientInfo) { ci.SessionTicketsSupported = true }},
		{"tls_compression_supported", func(ci *clientInfo) { ci.TLSCompressionSupported = true }},
		{"unknown_cipher_suite_supported", func(ci *clientInfo) { ci.UnknownCipherSuiteSupported = true }},
		{"beast_vuln", func(ci *clientInfo) { ci.BEASTVuln = true }},
		{"able_to_detect_n_minus_one_splitting", func(ci *clientInfo) { ci.AbleToDetectNMinusOneSplitting = true }},
	}
	r := httptest.NewRequest("GET", "/a/check", nil)
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			ci := &clientInfo{InsecureCipherSuites: map[string][]string{}}
			tc.set(ci)
			b, status, contentType, err := allowedRenderJSON(r, ci)
			if err != nil {
				t.Fatalf("allowedRenderJSON: %s", err)
			}
			if status != http.StatusOK || contentType != "application/json" {
				t.Errorf("status and content type: want %d and application/json, got %d and %s", http.StatusOK, status, contentType)
			}
			got := make(map[string]any)
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("json.Unmarshal: %s (%s)", err, b)
			}
			for _, k := range boolKeys {
				v, ok := got[k].(bool)
				if !ok {
					t.Errorf("%s: want a boolean, got %#v", k, got[k])
					continue
				}
				if want := k == tc.key; v != want {
					t.Errorf("%s: want %t, got %t", k, want, v)
				}
			}
		})
	}

	t.Run("RatingReasonsAndVersion", func(t *testing.T) {
		ci := &clientInfo{
			GivenCipherSuites: []string{"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "Some unknown cipher suite: 0xfffd"},
			InsecureCipherSuites: map[string][]string{
				"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5": {fewBitReason, nullAuthReason, rc4Reason},
			},
			TLSVersion: "TLS 1.0",
			Rating:     bad,
			// The page reads these four. They are not part of the API.
			TLS12ImprovableCutoverPassed: true,
			TLS12BadCutoverPassed:        true,
			NoPQImprovableCutoverPassed:  true,
			NoPQBadCutoverPassed:         true,
		}
		b, _, _, err := allowedRenderJSON(r, ci)
		if err != nil {
			t.Fatalf("allowedRenderJSON: %s", err)
		}
		got := make(map[string]json.RawMessage)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("json.Unmarshal: %s (%s)", err, b)
		}
		want := map[string]string{
			"rating":                 `"Bad"`,
			"tls_version":            `"TLS 1.0"`,
			"given_cipher_suites":    `["TLS_DH_anon_EXPORT_WITH_RC4_40_MD5","Some unknown cipher suite: 0xfffd"]`,
			"insecure_cipher_suites": `{"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":["` + fewBitReason + `","` + nullAuthReason + `","` + rc4Reason + `"]}`,
		}
		for k, w := range want {
			if string(got[k]) != w {
				t.Errorf("%s: want %s, got %s", k, w, got[k])
			}
		}
		for k := range got {
			if strings.Contains(strings.ToLower(k), "cutover") {
				t.Errorf("%s: the cutover flags are for the page, and should not be in the API", k)
			}
		}
	})
}

// The callback of a JSONP request is the caller's text, written into a
// script. Only its ASCII letters and digits may get there.
func TestReportJSONPCallback(t *testing.T) {
	ci := &clientInfo{
		GivenCipherSuites:    []string{"TLS_AES_128_GCM_SHA256"},
		InsecureCipherSuites: map[string][]string{},
		TLSVersion:           "TLS 1.3",
		Rating:               okay,
	}
	report, err := json.Marshal(ci)
	if err != nil {
		t.Fatalf("json.Marshal: %s", err)
	}
	renderers := []struct {
		name        string
		render      func(*http.Request, *clientInfo) ([]byte, int, string, error)
		body        string
		plainStatus int
	}{
		{"Allowed", allowedRenderJSON, string(report), http.StatusOK},
		{"Disallowed", disallowedRenderJSON, string(disallowedOriginBody), http.StatusBadRequest},
	}
	tests := []struct {
		name     string
		callback string
		// The function name written out, or "" for plain JSON.
		wantCallback string
	}{
		{"None", "", ""},
		{"Plain", "parseTLS", "parseTLS"},
		{"Digits", "cb2", "cb2"},
		{"Call", "alert(1);//", "alert1"},
		{"Tag", "</script><script>alert(1)", "scriptscriptalert1"},
		{"DotsAndBrackets", "window.cb[0]", "windowcb0"},
		{"Underscore", "my_cb", "mycb"},
		{"Spaces", " c b\n", "cb"},
		{"Quotes", `"cb"+'x'`, "cbx"},
		// Letters, but not ASCII ones.
		{"NonASCIILetters", "cébｃ", "cb"},
		{"OnlyPunctuation", "();", ""},
		{"OnlyNonASCII", "éｃ", ""},
	}
	for _, rd := range renderers {
		for _, tc := range tests {
			t.Run(rd.name+"/"+tc.name, func(t *testing.T) {
				r := httptest.NewRequest("GET", "/a/check?"+url.Values{"callback": {tc.callback}}.Encode(), nil)
				b, status, contentType, err := rd.render(r, ci)
				if err != nil {
					t.Fatalf("render: %s", err)
				}
				wantBody, wantStatus, wantContentType := rd.body, rd.plainStatus, "application/json"
				if tc.wantCallback != "" {
					// Browsers won't run a script unless the status is OK.
					wantBody, wantStatus, wantContentType = tc.wantCallback+"("+rd.body+");", http.StatusOK, "application/javascript"
				}
				if string(b) != wantBody {
					t.Errorf("body: want %s, got %s", wantBody, b)
				}
				if status != wantStatus {
					t.Errorf("status: want %d, got %d", wantStatus, status)
				}
				if contentType != wantContentType {
					t.Errorf("content type: want %s, got %s", wantContentType, contentType)
				}
			})
		}
	}
}
