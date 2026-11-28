package main

import (
	"bytes"
	"html"
	"regexp"
	"strings"
	"testing"
)

// These tests pin the page texts that page_sections_test.go leaves out: the
// opening lines of the "Given Cipher Suites" and "Given Named Groups"
// sections, and the day the TLS 1.1 text says TLS 1.1 turns Bad. Each text is
// checked whole and inside its own section, so swapping two of them or
// dropping one fails.

var (
	pinnedSectionRE = regexp.MustCompile(`(?s)<section[^>]*>(.*?)</section>`)
	pinnedHeadingRE = regexp.MustCompile(`(?s)<h2[^>]*>(.*?)</h2>`)
	pinnedParaRE    = regexp.MustCompile(`(?s)<p[^>]*>(.*?)</p>`)
	pinnedTagRE     = regexp.MustCompile(`(?s)<[^>]*>`)
)

// pinnedText takes the tags out of raw, decodes its entities and makes each
// run of white space one space.
func pinnedText(raw string) string {
	return strings.Join(strings.Fields(html.UnescapeString(pinnedTagRE.ReplaceAllString(raw, ""))), " ")
}

// pinnedSection renders the page for ci and returns the raw HTML of the one
// section whose heading is heading. It fails the test if there isn't exactly
// one.
func pinnedSection(t *testing.T, ci *clientInfo, heading string) string {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := loadIndex().Execute(buf, ci); err != nil {
		t.Fatalf("rendering the page: %s", err)
	}
	var found []string
	for _, m := range pinnedSectionRE.FindAllStringSubmatch(buf.String(), -1) {
		hm := pinnedHeadingRE.FindStringSubmatch(m[1])
		if hm != nil && pinnedText(hm[1]) == heading {
			found = append(found, m[1])
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one section with the heading %q, got %d", heading, len(found))
	}
	return found[0]
}

func TestPinnedGivenListOpeningLines(t *testing.T) {
	ci := &clientInfo{
		TLSVersion:        "TLS 1.3",
		GivenCipherSuites: []string{"TLS_AES_128_GCM_SHA256"},
		GivenNamedGroups:  []string{"X25519MLKEM768"},
	}
	tests := []struct {
		heading string
		want    string
	}{
		{
			heading: "Given Cipher Suites",
			want:    "The cipher suites your client said it supports, in the order it sent them, are:",
		},
		{
			heading: "Given Named Groups",
			want:    "The named groups your client said it supports, in the order it sent them, are:",
		},
	}
	for _, tc := range tests {
		t.Run(tc.heading, func(t *testing.T) {
			raw := pinnedSection(t, ci, tc.heading)
			pm := pinnedParaRE.FindStringSubmatch(raw)
			if pm == nil {
				t.Fatalf("section %q has no paragraph", tc.heading)
			}
			if got := pinnedText(pm[1]); got != tc.want {
				t.Errorf("section %q opens with %q, want %q", tc.heading, got, tc.want)
			}
		})
	}
}

func TestPinnedTLS11BadDate(t *testing.T) {
	const want = "On December 14th, 2026 at 10 AM PT, TLS 1.1 will be marked as Bad alongside TLS 1.2."
	// Before the cutover, a TLS 1.1 client is Improvable and is told the day
	// it turns Bad.
	before := pinnedText(pinnedSection(t, &clientInfo{TLSVersion: "TLS 1.1"}, "Version"))
	if !strings.Contains(before, want) {
		t.Errorf("TLS 1.1 before the cutover: version section %q doesn't hold %q", before, want)
	}
	// After it, the client is Bad and the date is gone.
	after := pinnedText(pinnedSection(t, &clientInfo{
		TLSVersion:                   "TLS 1.1",
		TLS12ImprovableCutoverPassed: true,
		TLS12BadCutoverPassed:        true,
	}, "Version"))
	if strings.Contains(after, "will be marked as Bad") {
		t.Errorf("TLS 1.1 after the cutover: version section %q still says it will be marked as Bad", after)
	}
}
