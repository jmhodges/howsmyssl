package main

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	ztls "github.com/zmap/zcrypto/tls"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// These tests render templates/index.html and look at it one section at a
// time. A section is tied to its heading, so a text that turns up under the
// wrong heading, or under the right heading for the wrong client, fails.
//
// They pin short phrases, not paragraphs: one phrase for each thing a section
// can say, picked so that no other branch of that section holds it. A
// reworded sentence around a phrase, a new paragraph or a new section doesn't
// fail them.

// The headings of the sections these tests know, in the order the page shows
// them. Other sections may sit between them.
const (
	pageSectionVersion     = "Version"
	pageSectionPostQuantum = "Post-Quantum Key Agreement"
	pageSectionEphemeral   = "Ephemeral Key Support"
	pageSectionTickets     = "Session Ticket Support"
	pageSectionCompression = "TLS Compression"
	pageSectionInsecure    = "Insecure Cipher Suites"
	pageSectionBEAST       = "BEAST Vulnerability"
	pageSectionUnknown     = "Unknown Cipher Suites Supported"
	pageSectionSuites      = "Given Cipher Suites"
	pageSectionGroups      = "Given Named Groups"
	pageSectionSigAlgs     = "Given Signature Algorithms"
)

// pageSectionOrder lists the known headings in page order.
// pageSectionUnknown is only on the page for a client that offers an unknown
// cipher suite.
var pageSectionOrder = []string{
	pageSectionVersion,
	pageSectionPostQuantum,
	pageSectionEphemeral,
	pageSectionTickets,
	pageSectionCompression,
	pageSectionInsecure,
	pageSectionBEAST,
	pageSectionUnknown,
	pageSectionSuites,
	pageSectionGroups,
	pageSectionSigAlgs,
}

// pageSectionPhrases holds, for each section, every phrase these tests know
// from it. For a given client some are wanted and all the others must be
// missing from that section.
var pageSectionPhrases = map[string][]string{
	pageSectionVersion: {
		pageVersionTLS13,
		pageVersionTLS12Okay,
		pageVersionTLS12Late,
		pageVersionTLS12BadSoon,
		pageVersionTLS11Improvable,
		pageVersionTLS11Bad,
		pageVersionOld,
	},
	pageSectionPostQuantum: {
		pagePostQuantumYes,
		pagePostQuantumNo,
		pagePostQuantumImprovableSoon,
		pagePostQuantumImprovableNow,
	},
	pageSectionEphemeral:   {pageEphemeralYes, pageEphemeralNo},
	pageSectionTickets:     {pageTicketsYes, pageTicketsNo},
	pageSectionCompression: {pageCompressionYes, pageCompressionNo},
	pageSectionInsecure:    {pageInsecureYes, pageInsecureNo},
	pageSectionBEAST: {
		pageBEASTOpen,
		pageBEASTProbablyOpen,
		pageBEASTMitigated,
		pageBEASTNewerTLS,
	},
	pageSectionUnknown: {pageUnknownYes},
	pageSectionSigAlgs: {pageSigAlgsNone},
}

const (
	pageVersionTLS13           = "fastest, most secure"
	pageVersionTLS12Okay       = "being phased out"
	pageVersionTLS12Late       = "no longer to be used"
	pageVersionTLS12BadSoon    = "TLS 1.2 clients will be marked as Bad"
	pageVersionTLS11Improvable = "not susceptible to the BEAST attack"
	pageVersionTLS11Bad        = "forward secrecy baked-in"
	pageVersionOld             = "very old"

	pagePostQuantumYes            = "Your client supports post-quantum key agreement"
	pagePostQuantumNo             = "Your client does not support post-quantum key agreement"
	pagePostQuantumImprovableSoon = "will be marked as Improvable"
	pagePostQuantumImprovableNow  = "are marked as Improvable"

	pageEphemeralYes = "Ephemeral keys are used in some"
	pageEphemeralNo  = "Ephemeral keys are not used in any"

	pageTicketsYes = "Session tickets are supported"
	pageTicketsNo  = "Session tickets are not supported"

	pageCompressionYes = "supports compressing the settings"
	pageCompressionNo  = "does not attempt to compress the settings"

	pageInsecureYes = "supports cipher suites that are known to be insecure"
	pageInsecureNo  = "doesn't use any cipher suites that are known to be insecure"

	pageBEASTOpen         = "Your client is open to the BEAST attack"
	pageBEASTProbablyOpen = "Your client is probably open to the BEAST attack"
	pageBEASTMitigated    = "it has implemented the 1/n-1 record splitting mitigation"
	pageBEASTNewerTLS     = "it's using a TLS protocol newer than TLS 1.0"

	pageUnknownYes = "cipher suite this app doesn't recognize"

	pageSigAlgsNone = "didn't send any signature algorithms"
)

// pageSectionWant is what one section must show for one client.
type pageSectionWant struct {
	// label is the rating in the section's label, or "" for a section
	// that must have no label.
	label rating
	// phrases must each be in the section's text.
	phrases []string
	// unchecked are phrases of pageSectionPhrases that may or may not be
	// there. Every phrase in neither list must be missing.
	unchecked []string
}

// pageSectionWants says what each section must show for ci. It is the page's
// rules written out a second time, from the fields of clientInfo alone. A
// section that is missing from the result must be missing from the page.
func pageSectionWants(ci *clientInfo) map[string]pageSectionWant {
	wants := map[string]pageSectionWant{}

	using := "is using " + ci.TLSVersion
	switch ci.TLSVersion {
	case "TLS 1.3":
		wants[pageSectionVersion] = pageSectionWant{label: okay, phrases: []string{using, pageVersionTLS13}}
	case "TLS 1.2":
		switch {
		case ci.TLS12BadCutoverPassed:
			wants[pageSectionVersion] = pageSectionWant{label: bad, phrases: []string{using, pageVersionTLS12Late}}
		case ci.TLS12ImprovableCutoverPassed:
			wants[pageSectionVersion] = pageSectionWant{label: improvable, phrases: []string{using, pageVersionTLS12Late, pageVersionTLS12BadSoon}}
		default:
			wants[pageSectionVersion] = pageSectionWant{label: okay, phrases: []string{using, pageVersionTLS12Okay}}
		}
	case "TLS 1.1":
		if ci.TLS12BadCutoverPassed {
			wants[pageSectionVersion] = pageSectionWant{label: bad, phrases: []string{using, pageVersionTLS11Bad}}
		} else {
			wants[pageSectionVersion] = pageSectionWant{label: improvable, phrases: []string{using, pageVersionTLS11Improvable}}
		}
	default:
		wants[pageSectionVersion] = pageSectionWant{label: bad, phrases: []string{using, pageVersionOld}}
	}

	switch {
	case ci.PostQuantumKeyAgreement:
		wants[pageSectionPostQuantum] = pageSectionWant{label: okay, phrases: []string{pagePostQuantumYes}}
	case ci.NoPQBadCutoverPassed:
		// Which dates this branch gives is left unchecked: after the
		// December cutover the page still gives the dates as they were
		// before June, and a fix for that is waiting.
		wants[pageSectionPostQuantum] = pageSectionWant{
			label:     bad,
			phrases:   []string{pagePostQuantumNo},
			unchecked: []string{pagePostQuantumImprovableSoon, pagePostQuantumImprovableNow},
		}
	case ci.NoPQImprovableCutoverPassed:
		wants[pageSectionPostQuantum] = pageSectionWant{label: improvable, phrases: []string{pagePostQuantumNo, pagePostQuantumImprovableNow}}
	default:
		wants[pageSectionPostQuantum] = pageSectionWant{label: okay, phrases: []string{pagePostQuantumNo, pagePostQuantumImprovableSoon}}
	}

	if ci.EphemeralKeysSupported {
		wants[pageSectionEphemeral] = pageSectionWant{label: okay, phrases: []string{pageEphemeralYes}}
	} else {
		wants[pageSectionEphemeral] = pageSectionWant{label: improvable, phrases: []string{pageEphemeralNo}}
	}

	if ci.SessionTicketsSupported {
		wants[pageSectionTickets] = pageSectionWant{label: okay, phrases: []string{pageTicketsYes}}
	} else {
		wants[pageSectionTickets] = pageSectionWant{label: improvable, phrases: []string{pageTicketsNo}}
	}

	if ci.TLSCompressionSupported {
		wants[pageSectionCompression] = pageSectionWant{label: bad, phrases: []string{pageCompressionYes}}
	} else {
		wants[pageSectionCompression] = pageSectionWant{label: okay, phrases: []string{pageCompressionNo}}
	}

	if len(ci.InsecureCipherSuites) != 0 {
		w := pageSectionWant{label: bad, phrases: []string{pageInsecureYes}}
		for suite, reasons := range ci.InsecureCipherSuites {
			w.phrases = append(w.phrases, suite+": This cipher suite "+sentence(reasons))
		}
		wants[pageSectionInsecure] = w
	} else {
		wants[pageSectionInsecure] = pageSectionWant{label: okay, phrases: []string{pageInsecureNo}}
	}

	switch {
	case ci.BEASTVuln && ci.AbleToDetectNMinusOneSplitting:
		wants[pageSectionBEAST] = pageSectionWant{label: bad, phrases: []string{pageBEASTOpen}}
	case ci.BEASTVuln:
		wants[pageSectionBEAST] = pageSectionWant{label: bad, phrases: []string{pageBEASTProbablyOpen}}
	case ci.AbleToDetectNMinusOneSplitting:
		wants[pageSectionBEAST] = pageSectionWant{label: okay, phrases: []string{pageBEASTMitigated}}
	default:
		wants[pageSectionBEAST] = pageSectionWant{label: okay, phrases: []string{pageBEASTNewerTLS}}
	}

	if ci.UnknownCipherSuiteSupported {
		wants[pageSectionUnknown] = pageSectionWant{label: bad, phrases: []string{pageUnknownYes}}
	}

	wants[pageSectionSuites] = pageSectionWant{}
	wants[pageSectionGroups] = pageSectionWant{}
	if len(ci.GivenSignatureAlgorithms) != 0 {
		wants[pageSectionSigAlgs] = pageSectionWant{}
	} else {
		wants[pageSectionSigAlgs] = pageSectionWant{phrases: []string{pageSigAlgsNone}}
	}
	return wants
}

// pageSection is one <section> of the rendered page.
type pageSection struct {
	heading string
	raw     string
	// text is raw with its tags taken out, its entities decoded and each
	// run of white space made one space.
	text string
	// labels are the ratings of the section's labels, as their class
	// gives them.
	labels []string
	// items are the texts of the section's list items, in order.
	items []string
}

var (
	pageSectionRE = regexp.MustCompile(`(?s)<section[^>]*>(.*?)</section>`)
	pageHeadingRE = regexp.MustCompile(`(?s)<h2[^>]*>(.*?)</h2>`)
	pageLabelRE   = regexp.MustCompile(`(?s)<span class="label ([^"]*)">(.*?)</span>`)
	pageItemRE    = regexp.MustCompile(`(?s)<li[^>]*>(.*?)</li>`)
	pageTagRE     = regexp.MustCompile(`(?s)<[^>]*>`)
	pageHeroRE    = regexp.MustCompile(`(?s)<span class="hero-unit-([^"]*)">(.*?)</span>`)
)

func pageText(raw string) string {
	return strings.Join(strings.Fields(html.UnescapeString(pageTagRE.ReplaceAllString(raw, ""))), " ")
}

// pageLabelText is what a label of each class must read.
var pageLabelText = map[string]string{
	string(ratingSpan(okay)):       "Good",
	string(ratingSpan(improvable)): string(improvable),
	string(ratingSpan(bad)):        string(bad),
}

// pageSections renders the page for ci and cuts it into its sections. It
// fails the test if two sections share a heading, or a label's text doesn't
// fit its class.
func pageSections(t *testing.T, tmpl *template.Template, ci *clientInfo) (page string, sections []pageSection) {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := tmpl.Execute(buf, ci); err != nil {
		t.Fatalf("rendering the page: %s", err)
	}
	page = buf.String()
	seen := map[string]bool{}
	for _, m := range pageSectionRE.FindAllStringSubmatch(page, -1) {
		raw := m[1]
		hm := pageHeadingRE.FindAllStringSubmatch(raw, -1)
		if len(hm) != 1 {
			t.Fatalf("want one h2 in each section, got %d in %q", len(hm), raw)
		}
		s := pageSection{heading: pageText(hm[0][1]), raw: raw, text: pageText(raw)}
		if seen[s.heading] {
			t.Errorf("two sections have the heading %q", s.heading)
		}
		seen[s.heading] = true
		for _, lm := range pageLabelRE.FindAllStringSubmatch(raw, -1) {
			class, text := lm[1], pageText(lm[2])
			if want, ok := pageLabelText[class]; !ok || text != want {
				t.Errorf("section %q: a label of class %q reads %q", s.heading, class, text)
			}
			s.labels = append(s.labels, class)
		}
		for _, im := range pageItemRE.FindAllStringSubmatch(raw, -1) {
			s.items = append(s.items, pageText(im[1]))
		}
		sections = append(sections, s)
	}
	return page, sections
}

// checkPageSections compares the rendered sections with pageSectionWants(ci).
// It returns what is wrong, one line each.
func checkPageSections(ci *clientInfo, page string, sections []pageSection) []string {
	var errs []string
	errf := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	hero := pageHeroRE.FindAllStringSubmatch(page, -1)
	if len(hero) != 1 {
		errf("want one rating at the top, got %d", len(hero))
	} else if class, text := hero[0][1], pageText(hero[0][2]); class != string(ratingSpan(ci.Rating)) || text != string(ci.Rating) {
		errf("rating at the top: want %q with class %q, got %q with class %q", ci.Rating, ratingSpan(ci.Rating), text, class)
	}

	wants := pageSectionWants(ci)
	byHeading := map[string]pageSection{}
	var knownInOrder []string
	for _, s := range sections {
		byHeading[s.heading] = s
		if slices.Contains(pageSectionOrder, s.heading) {
			knownInOrder = append(knownInOrder, s.heading)
		}
	}
	var wantInOrder []string
	for _, h := range pageSectionOrder {
		if _, ok := wants[h]; ok {
			wantInOrder = append(wantInOrder, h)
		}
	}
	if !slices.Equal(knownInOrder, wantInOrder) {
		errf("sections: want %q in that order, got %q", wantInOrder, knownInOrder)
	}

	for _, h := range wantInOrder {
		s, ok := byHeading[h]
		if !ok {
			continue
		}
		w := wants[h]
		var wantLabels []string
		if w.label != "" {
			wantLabels = []string{string(ratingSpan(w.label))}
		}
		if !slices.Equal(s.labels, wantLabels) {
			errf("section %q: want labels %q, got %q", h, wantLabels, s.labels)
		}
		for _, p := range w.phrases {
			if !strings.Contains(s.text, p) {
				errf("section %q: want %q in it, got %q", h, p, s.text)
			}
		}
		for _, p := range pageSectionPhrases[h] {
			if slices.Contains(w.phrases, p) || slices.Contains(w.unchecked, p) {
				continue
			}
			if strings.Contains(s.text, p) {
				errf("section %q: %q belongs to another client's page, got %q", h, p, s.text)
			}
		}
		// The page links each section to the part of the About page
		// named after its heading.
		link := `href="/s/about.html/#` + strings.ReplaceAll(strings.ToLower(h), " ", "-") + `"`
		if !strings.Contains(s.raw, link) {
			errf("section %q: want a link with %s", h, link)
		}
	}

	// A phrase of one section must not show up under any other heading,
	// known or not.
	for h, phrases := range pageSectionPhrases {
		for _, p := range phrases {
			for _, s := range sections {
				if s.heading == h || !strings.Contains(s.text, p) {
					continue
				}
				// The dates of the two cutovers are given in both
				// the Version and the Post-Quantum sections.
				if p == pagePostQuantumImprovableSoon && s.heading == pageSectionVersion {
					continue
				}
				errf("section %q holds %q, which belongs to section %q", s.heading, p, h)
			}
		}
	}

	if s, ok := byHeading[pageSectionGroups]; ok && !slices.Equal(s.items, ci.GivenNamedGroups) && len(s.items)+len(ci.GivenNamedGroups) != 0 {
		errf("section %q: want the list %q, got %q", pageSectionGroups, ci.GivenNamedGroups, s.items)
	}
	if s, ok := byHeading[pageSectionSigAlgs]; ok && !slices.Equal(s.items, ci.GivenSignatureAlgorithms) && len(s.items)+len(ci.GivenSignatureAlgorithms) != 0 {
		errf("section %q: want the list %q, got %q", pageSectionSigAlgs, ci.GivenSignatureAlgorithms, s.items)
	}
	return errs
}

// TestPageSectionTexts renders the page for clients in each state that the
// sections tell apart, and checks that each section shows its own heading's
// label and text for that state and none of the others.
func TestPageSectionTexts(t *testing.T) {
	tmpl := loadIndex()

	type cutovers struct {
		name            string
		improvable, bad bool
	}
	type beast struct{ vuln, ableToDetect bool }
	var (
		versions     = []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "an unknown version of SSL/TLS"}
		cutoverSteps = []cutovers{{"before June", false, false}, {"after June", true, false}, {"after December", true, true}}
		beasts       = []beast{{false, false}, {false, true}, {true, false}, {true, true}}
		insecures    = []map[string][]string{
			{},
			{"TLS_RSA_WITH_RC4_128_SHA": {rc4Reason}},
			{
				"TLS_DH_anon_WITH_RC4_128_MD5":  {nullAuthReason, rc4Reason},
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA": {sweet32Reason},
				"TLS_RSA_EXPORT_WITH_RC4_40_MD5": {
					fewBitReason, rc4Reason, nullAuthReason,
				},
			},
		}
		ratings = []rating{okay, improvable, bad}
		bools   = []bool{false, true}
	)

	// Every version on each side of the cutovers, with and without
	// post-quantum key agreement. The other sections each depend on fields
	// of their own, so they are drawn at random beside those, from a fixed
	// seed: the same pages on every run.
	rnd := rand.New(rand.NewPCG(1219, 2026))
	pick := func() bool { return rnd.IntN(2) == 1 }
	n, failed := 0, 0
	for _, version := range versions {
		for _, cut := range cutoverSteps {
			for _, pq := range bools {
				for range 8 {
					b := beasts[rnd.IntN(len(beasts))]
					ci := &clientInfo{
						TLSVersion:                     version,
						TLS12ImprovableCutoverPassed:   cut.improvable,
						TLS12BadCutoverPassed:          cut.bad,
						NoPQImprovableCutoverPassed:    cut.improvable,
						NoPQBadCutoverPassed:           cut.bad,
						PostQuantumKeyAgreement:        pq,
						EphemeralKeysSupported:         pick(),
						BEASTVuln:                      b.vuln,
						AbleToDetectNMinusOneSplitting: b.ableToDetect,
						InsecureCipherSuites:           insecures[rnd.IntN(len(insecures))],
						SessionTicketsSupported:        pick(),
						TLSCompressionSupported:        pick(),
						UnknownCipherSuiteSupported:    pick(),
						// The page shows the rating it is given, so
						// any will do.
						Rating: ratings[rnd.IntN(len(ratings))],
					}
					if pick() {
						ci.GivenNamedGroups = []string{"X25519MLKEM768", "x25519", "Unknown named group: 0xfe33"}
					}
					if pick() {
						ci.GivenSignatureAlgorithms = []string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"}
					}
					n++
					page, sections := pageSections(t, tmpl, ci)
					errs := checkPageSections(ci, page, sections)
					if len(errs) == 0 {
						continue
					}
					failed++
					if failed > 5 {
						continue
					}
					t.Errorf("%s, %s, client %+v:\n%s", version, cut.name, *ci, strings.Join(errs, "\n"))
				}
			}
		}
	}
	if failed > 5 {
		t.Errorf("%d of %d pages were wrong; the first 5 are shown", failed, n)
	}
}

// TestPageSectionLabelsMatchRating takes the report of real handshakes on
// each side of the two cutovers, and checks the page against the report: each
// section shows what the report's fields call for, and the rating at the top
// is the worst label below it. The session ticket label is left out of
// "worst", since the rating doesn't count it.
func TestPageSectionLabelsMatchRating(t *testing.T) {
	tmpl := loadIndex()

	times := []struct {
		name string
		now  time.Time
	}{
		{"BeforeJune", tls12ImprovableCutover.Add(-time.Minute)},
		{"AfterJune", tls12ImprovableCutover},
		{"BeforeDecember", tls12BadCutover.Add(-time.Minute)},
		{"AfterDecember", tls12BadCutover},
	}
	clients := []struct {
		name    string
		connect func(t *testing.T) *tls.Conn
	}{
		{"GoDefault", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{})
		}},
		{"TLS13NoPostQuantum", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
		}},
		{"TLS12NoPostQuantum", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
		}},
		{"TLS12PostQuantum", func(t *testing.T) *tls.Conn {
			return connectZtls(t, &ztls.Config{MaxVersion: ztls.VersionTLS12, CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519}})
		}},
		{"TLS12NoEphemeralKeys", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}})
		}},
		{"TLS12RC4", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}})
		}},
		{"TLS11", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}})
		}},
		{"TLS10", func(t *testing.T) *tls.Conn {
			return connect(t, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}})
		}},
	}

	worse := map[string]int{
		string(ratingSpan(okay)):       0,
		string(ratingSpan(improvable)): 1,
		string(ratingSpan(bad)):        2,
	}
	for _, client := range clients {
		t.Run(client.name, func(t *testing.T) {
			c := client.connect(t)
			for _, tc := range times {
				t.Run(tc.name, func(t *testing.T) {
					ci := pullClientInfo(c, tc.now)
					page, sections := pageSections(t, tmpl, ci)
					for _, e := range checkPageSections(ci, page, sections) {
						t.Error(e)
					}

					worst := string(ratingSpan(okay))
					for _, s := range sections {
						if s.heading == pageSectionTickets {
							continue
						}
						for _, l := range s.labels {
							if worse[l] > worse[worst] {
								worst = l
							}
						}
					}
					if worst != string(ratingSpan(ci.Rating)) {
						t.Errorf("the rating is %q, but the worst label in the sections is %q", ci.Rating, worst)
					}

					// The list of cipher suites, in the order sent.
					// An item may say more after the suite's name.
					for _, s := range sections {
						if s.heading != pageSectionSuites {
							continue
						}
						if len(s.items) != len(ci.GivenCipherSuites) {
							t.Fatalf("section %q: want %d suites, got %q", s.heading, len(ci.GivenCipherSuites), s.items)
						}
						for i, name := range ci.GivenCipherSuites {
							if s.items[i] != name && !strings.HasPrefix(s.items[i], name+" ") {
								t.Errorf("section %q: item %d: want %q, got %q", s.heading, i, name, s.items[i])
							}
						}
					}
				})
			}
		})
	}
}
