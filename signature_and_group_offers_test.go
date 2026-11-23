package main

import (
	"encoding/csv"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// readRegistryCSV reads a copy of one of IANA's TLS registries from testdata
// and checks that its header starts with wantHeader.
func readRegistryCSV(t *testing.T, path string, wantHeader []string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening registry copy: %s", err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("reading registry copy %s: %s", path, err)
	}
	if len(records) == 0 || len(records[0]) < len(wantHeader) || !slices.Equal(records[0][:len(wantHeader)], wantHeader) {
		t.Fatalf("registry copy %s has an unexpected header: %v", path, records[0])
	}
	return records[1:]
}

func parseRegistryValue(t *testing.T, v string) (uint16, bool) {
	t.Helper()
	if strings.Contains(v, "-") {
		return 0, false // a range, like the reserved ones
	}
	n, err := strconv.ParseUint(v, 0, 16)
	if err != nil {
		t.Fatalf("registry value %q: %s", v, err)
	}
	return uint16(n), true
}

func TestPostQuantumSignatureSchemesMatchRegistry(t *testing.T) {
	want := make(map[uint16]string)
	for _, rec := range readRegistryCSV(t, "testdata/iana-tls-signaturescheme.csv", []string{"Value", "Description", "Recommended"}) {
		id, ok := parseRegistryValue(t, rec[0])
		if !ok {
			continue
		}
		if strings.HasPrefix(rec[1], "mldsa") || strings.HasPrefix(rec[1], "slhdsa") {
			want[id] = rec[1]
		}
	}
	if len(want) == 0 {
		t.Fatalf("registry copy has no ML-DSA or SLH-DSA schemes")
	}
	if diff := cmp.Diff(want, postQuantumSignatureSchemes); diff != "" {
		t.Errorf("postQuantumSignatureSchemes differs from the registry (-registry +ours):\n%s", diff)
	}
}

func TestSHA1OrMD5SignatureSchemesMatchRegistry(t *testing.T) {
	named := make(map[uint16]string)
	for _, rec := range readRegistryCSV(t, "testdata/iana-tls-signaturescheme.csv", []string{"Value", "Description", "Recommended"}) {
		id, ok := parseRegistryValue(t, rec[0])
		if !ok {
			continue
		}
		if !strings.HasPrefix(rec[1], "Reserved") {
			named[id] = rec[1]
		}
	}
	for id, name := range sha1OrMD5SignatureSchemes {
		// The hash is the high byte in TLS 1.2's pairs: md5 is 1, sha1 is 2.
		if hash := id >> 8; hash != 1 && hash != 2 {
			t.Errorf("%#04x (%s) doesn't hash with MD5 or SHA-1", id, name)
		}
		if regName, found := named[id]; found && regName != name {
			t.Errorf("%#04x: registry names it %q, we name it %q", id, regName, name)
		}
	}
	// Every scheme the registry names with a sha1 or md5 hash must be here.
	for id, name := range named {
		if strings.HasSuffix(name, "_sha1") || strings.HasSuffix(name, "_md5") {
			if _, found := sha1OrMD5SignatureSchemes[id]; !found {
				t.Errorf("missing from sha1OrMD5SignatureSchemes, add:\t%#04x: %q,", id, name)
			}
		}
	}
	// And the names have to match the ones given_signature_algorithms shows.
	for id, name := range sha1OrMD5SignatureSchemes {
		if allName, found := allSignatureSchemes[id]; found && allName != name {
			t.Errorf("%#04x: allSignatureSchemes names it %q, we name it %q", id, allName, name)
		}
	}
	for id, name := range postQuantumSignatureSchemes {
		if allName, found := allSignatureSchemes[id]; found && allName != name {
			t.Errorf("%#04x: allSignatureSchemes names it %q, we name it %q", id, allName, name)
		}
	}
}

func TestRetiredKyberDraftGroupsMatchRegistry(t *testing.T) {
	want := make(map[uint16]string)
	for _, rec := range readRegistryCSV(t, "testdata/iana-tls-parameters-8.csv", []string{"Value", "Description", "DTLS-OK", "Recommended"}) {
		name, obsolete := strings.CutSuffix(rec[1], " (OBSOLETE)")
		if !obsolete || !strings.Contains(name, "Kyber") {
			continue
		}
		id, ok := parseRegistryValue(t, rec[0])
		if !ok {
			t.Fatalf("obsolete Kyber group %q is a range", rec[1])
		}
		want[id] = name
	}
	if len(want) == 0 {
		t.Fatalf("registry copy has no obsolete Kyber groups")
	}
	if diff := cmp.Diff(want, retiredKyberDraftGroups); diff != "" {
		t.Errorf("retiredKyberDraftGroups differs from the registry (-registry +ours):\n%s", diff)
	}
	for id, name := range retiredKyberDraftGroups {
		if postQuantumGroups[id] {
			t.Errorf("%s (%#04x) is a retired Kyber draft and must not count as post-quantum", name, id)
		}
		if allName, found := allNamedGroups[id]; found && allName != name {
			t.Errorf("%#04x: allNamedGroups names it %q, we name it %q", id, allName, name)
		}
	}
}

func TestTrustAnchorsExtensionMatchesRegistry(t *testing.T) {
	var found []string
	for _, rec := range readRegistryCSV(t, "testdata/iana-tls-extensiontype-values-1.csv", []string{"Value", "Extension Name"}) {
		if strings.HasPrefix(rec[1], "trust_anchors") {
			found = append(found, rec[0])
		}
	}
	want := []string{strconv.Itoa(int(extensionTrustAnchors))}
	if !slices.Equal(found, want) {
		t.Errorf("trust_anchors in the registry: want %v, got %v", want, found)
	}
}

func TestSignatureSchemesOffered(t *testing.T) {
	testCases := []struct {
		name        string
		table       map[uint16]string
		sigAlgs     []tls.SignatureScheme
		sigAlgsCert []tls.SignatureScheme
		want        []string
	}{
		{"none", sha1OrMD5SignatureSchemes, nil, nil, []string{}},
		{"only modern", sha1OrMD5SignatureSchemes, []tls.SignatureScheme{0x0804, 0x0403}, []tls.SignatureScheme{0x0401}, []string{}},
		{"sha1 and md5", sha1OrMD5SignatureSchemes, []tls.SignatureScheme{0x0804, 0x0201, 0x0101, 0x0203}, nil, []string{"rsa_pkcs1_sha1", "rsa_pkcs1_md5", "ecdsa_sha1"}},
		{"cert only", sha1OrMD5SignatureSchemes, []tls.SignatureScheme{0x0804}, []tls.SignatureScheme{0x0202, 0x0103}, []string{"dsa_sha1", "ecdsa_md5"}},
		{"both, once each", sha1OrMD5SignatureSchemes, []tls.SignatureScheme{0x0201}, []tls.SignatureScheme{0x0203, 0x0201}, []string{"rsa_pkcs1_sha1", "ecdsa_sha1"}},
		{"sha224 isn't flagged", sha1OrMD5SignatureSchemes, []tls.SignatureScheme{0x0301, 0x0303}, nil, []string{}},
		{"pq", postQuantumSignatureSchemes, []tls.SignatureScheme{0x0905, 0x0804}, []tls.SignatureScheme{0x0911, 0x0905}, []string{"mldsa65", "slhdsa_sha2_128s"}},
		{"pq none", postQuantumSignatureSchemes, []tls.SignatureScheme{0x0804, 0x0201}, nil, []string{}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := signatureSchemesOffered(tc.table, tc.sigAlgs, tc.sigAlgsCert)
			if got == nil {
				t.Fatalf("want non-nil slice, got nil")
			}
			if !cmp.Equal(tc.want, got) {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestRetiredKyberDraftGroupsOffered(t *testing.T) {
	testCases := []struct {
		groups []tls.CurveID
		want   []string
	}{
		{nil, []string{}},
		{[]tls.CurveID{0x11ec, tls.X25519}, []string{}},
		{[]tls.CurveID{0x6399, tls.X25519, 0x639a}, []string{"X25519Kyber768Draft00", "SecP256r1Kyber768Draft00"}},
		{[]tls.CurveID{tls.X25519, 0x639a}, []string{"SecP256r1Kyber768Draft00"}},
	}
	for _, tc := range testCases {
		got := retiredKyberDraftGroupsOffered(tc.groups)
		if got == nil {
			t.Fatalf("%v: want non-nil slice, got nil", tc.groups)
		}
		if !cmp.Equal(tc.want, got) {
			t.Errorf("%v: want %v, got %v", tc.groups, tc.want, got)
		}
	}
}

func TestTrustAnchorIDsOffered(t *testing.T) {
	if trustAnchorIDsOffered(nil) {
		t.Errorf("nil extensions: want false")
	}
	if trustAnchorIDsOffered([]uint16{0, 10, 13, 43, 51}) {
		t.Errorf("no trust_anchors: want false")
	}
	if !trustAnchorIDsOffered([]uint16{0, 10, 0xca34, 13}) {
		t.Errorf("with trust_anchors: want true")
	}
}

// rawExtension is a ClientHello extension written byte for byte, so a test
// can send extensions and code points that zcrypto doesn't know.
type rawExtension struct {
	typ  uint16
	data []byte
}

func (e *rawExtension) Marshal() []byte {
	out := []byte{byte(e.typ >> 8), byte(e.typ), byte(len(e.data) >> 8), byte(len(e.data))}
	return append(out, e.data...)
}

func (e *rawExtension) CheckImplemented() error          { return nil }
func (e *rawExtension) WriteToConfig(*ztls.Config) error { return nil }

// uint16ListExtension is an extension whose body is a 2-byte-length-prefixed
// list of 2-byte values, like supported_groups, signature_algorithms and
// signature_algorithms_cert.
func uint16ListExtension(typ uint16, vals ...uint16) *rawExtension {
	data := []byte{byte((2 * len(vals)) >> 8), byte(2 * len(vals))}
	for _, v := range vals {
		data = append(data, byte(v>>8), byte(v))
	}
	return &rawExtension{typ: typ, data: data}
}

// TestSignatureAndGroupOffersFromClientHello sends a hand-written TLS 1.2
// ClientHello and checks that each field reads the ClientHello extension it
// should.
func TestSignatureAndGroupOffersFromClientHello(t *testing.T) {
	const (
		extServerName       = 0
		extSupportedGroups  = 10
		extPointFormats     = 11
		extSigAlgs          = 13
		extSigAlgsCert      = 50
		extRenegotiation    = 0xff01
		extExtendedMSecret  = 23
		ecdheRSAAES128GCM   = 0xc02f
		ecdheRSAAES128GCM_2 = 0xc030
	)
	sni := &ztls.SNIExtension{Domains: []string{"localhost"}}
	clientConf := &ztls.Config{
		MinVersion: ztls.VersionTLS12,
		MaxVersion: ztls.VersionTLS12,
		// The hand-written hello has no supported_versions to pick a
		// resumption path by.
		SessionTicketsDisabled: true,
		CurvePreferences:       []ztls.CurveID{ztls.X25519, ztls.CurveP256},
		ClientFingerprintConfiguration: &ztls.ClientFingerprintConfiguration{
			HandshakeVersion:   ztls.VersionTLS12,
			CipherSuites:       []uint16{ecdheRSAAES128GCM, ecdheRSAAES128GCM_2},
			CompressionMethods: []uint8{0},
			Extensions: []ztls.ClientExtension{
				sni,
				uint16ListExtension(extSupportedGroups, 0x6399, uint16(ztls.X25519), uint16(ztls.CurveP256)),
				&rawExtension{typ: extPointFormats, data: []byte{1, 0}},
				uint16ListExtension(extSigAlgs, 0x0905, 0x0401, 0x0201, 0x0101),
				uint16ListExtension(extSigAlgsCert, 0x0401, 0x0203, 0x0911),
				&rawExtension{typ: extensionTrustAnchors, data: []byte{0, 0}},
				&rawExtension{typ: extRenegotiation, data: []byte{0}},
			},
		},
	}
	c := connectZtls(t, clientConf)
	ci := pullClientInfo(c, preCutover)
	t.Logf("%#v", ci)

	if want := []string{"rsa_pkcs1_sha1", "rsa_pkcs1_md5", "ecdsa_sha1"}; !cmp.Equal(want, ci.SHA1OrMD5SignatureAlgorithms) {
		t.Errorf("SHA1OrMD5SignatureAlgorithms: want %v, got %v", want, ci.SHA1OrMD5SignatureAlgorithms)
	}
	if want := []string{"X25519Kyber768Draft00"}; !cmp.Equal(want, ci.RetiredKyberDraftGroups) {
		t.Errorf("RetiredKyberDraftGroups: want %v, got %v", want, ci.RetiredKyberDraftGroups)
	}
	if want := []string{"mldsa65", "slhdsa_sha2_128s"}; !cmp.Equal(want, ci.PostQuantumSignatureAlgorithms) {
		t.Errorf("PostQuantumSignatureAlgorithms: want %v, got %v", want, ci.PostQuantumSignatureAlgorithms)
	}
	if !ci.TrustAnchorIDsOffered {
		t.Errorf("TrustAnchorIDsOffered: want true, got false")
	}
	if ci.PostQuantumKeyAgreement {
		t.Errorf("PostQuantumKeyAgreement: a retired Kyber draft must not count, got true")
	}
}

// TestSignatureAndGroupOffersChangeNoRating checks that offering every one of
// these leaves the rating what it would be without them.
func TestSignatureAndGroupOffersChangeNoRating(t *testing.T) {
	withAll := connect(t, &tls.Config{
		MinVersion:          tls.VersionTLS13,
		SignatureAlgorithms: []tls.SignatureScheme{tls.PSSWithSHA256, tls.PKCS1WithSHA1, tls.ECDSAWithSHA1, 0x0101, tls.MLDSA65},
	})
	without := connect(t, &tls.Config{
		MinVersion:          tls.VersionTLS13,
		SignatureAlgorithms: []tls.SignatureScheme{tls.PSSWithSHA256},
	})
	for _, now := range []time.Time{preCutover, tls12BadCutover} {
		a := pullClientInfo(withAll, now)
		b := pullClientInfo(without, now)
		if len(a.SHA1OrMD5SignatureAlgorithms) != 3 || len(a.PostQuantumSignatureAlgorithms) != 1 {
			t.Fatalf("%s: offers not seen: %v %v", now, a.SHA1OrMD5SignatureAlgorithms, a.PostQuantumSignatureAlgorithms)
		}
		if a.Rating != b.Rating {
			t.Errorf("%s: rating with the offers %q, without %q", now, a.Rating, b.Rating)
		}
	}
}

func TestSignatureAndGroupOffersPageLines(t *testing.T) {
	render := func(ci *clientInfo) string {
		t.Helper()
		var b strings.Builder
		if err := loadIndex().Execute(&b, ci); err != nil {
			t.Fatalf("rendering index: %s", err)
		}
		return b.String()
	}
	base := clientInfo{
		GivenSignatureAlgorithms: []string{"rsa_pss_rsae_sha256"},
		InsecureCipherSuites:     map[string][]string{},
		Rating:                   okay,
	}

	none := render(&base)
	for _, id := range []string{"retired-kyber-draft-groups", "sha1-or-md5-signature-algorithms", "post-quantum-signatures"} {
		if strings.Contains(none, `id="`+id+`"`) {
			t.Errorf("with nothing offered, the page shows %s", id)
		}
	}

	all := base
	all.RetiredKyberDraftGroups = []string{"X25519Kyber768Draft00"}
	all.SHA1OrMD5SignatureAlgorithms = []string{"rsa_pkcs1_sha1", "ecdsa_sha1"}
	all.PostQuantumSignatureAlgorithms = []string{"mldsa65", "slhdsa_sha2_128s"}
	all.TrustAnchorIDsOffered = true
	page := render(&all)
	for _, want := range []string{
		"marks obsolete: X25519Kyber768Draft00.",
		"SHA-1 or MD5, in its\n                signature_algorithms or signature_algorithms_cert lists: rsa_pkcs1_sha1, ecdsa_sha1.",
		"it accepts the post-quantum signatures mldsa65, slhdsa_sha2_128s, and it sent the trust anchor IDs extension.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}

	onlyTA := base
	onlyTA.TrustAnchorIDsOffered = true
	if want := "post-quantum certificates: it sent the trust anchor IDs extension."; !strings.Contains(render(&onlyTA), want) {
		t.Errorf("page is missing %q", want)
	}
}
