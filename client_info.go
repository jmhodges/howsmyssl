package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

type rating string

const (
	okay       rating = "Probably Okay"
	improvable rating = "Improvable"
	bad        rating = "Bad"
)

// Rating cutovers. 10:00 America/Los_Angeles on the given dates, encoded
// as UTC instants so we don't depend on time/tzdata. June 14 falls in
// PDT (UTC-7); December 14 falls in PST (UTC-8).
var (
	tls12ImprovableCutover = time.Date(2026, 6, 14, 17, 0, 0, 0, time.UTC)
	tls12BadCutover        = time.Date(2026, 12, 14, 18, 0, 0, 0, time.UTC)
	noPQImprovableCutover  = time.Date(2026, 6, 14, 17, 0, 0, 0, time.UTC)
	noPQBadCutover         = time.Date(2026, 12, 14, 18, 0, 0, 0, time.UTC)
)

type clientInfo struct {
	GivenCipherSuites                 []string            `json:"given_cipher_suites"`
	GivenNamedGroups                  []string            `json:"given_named_groups"`
	GivenSignatureAlgorithms          []string            `json:"given_signature_algorithms"`
	GivenPSKKeyExchangeModes          []string            `json:"given_psk_key_exchange_modes"`
	GivenALPNProtocols                []string            `json:"given_alpn_protocols"`
	GivenKeyShareGroups               []string            `json:"given_key_share_groups"`
	PostQuantumKeyAgreement           bool                `json:"post_quantum_key_agreement"`
	EphemeralKeysSupported            bool                `json:"ephemeral_keys_supported"`              // good if true
	SessionTicketsSupported           bool                `json:"session_ticket_supported"`              // good if true
	PSKWithoutForwardSecrecySupported bool                `json:"psk_without_forward_secrecy_supported"` // neutral, for now
	ServerNameSent                    bool                `json:"server_name_sent"`                      // neutral
	SecureRenegotiationSupported      bool                `json:"secure_renegotiation_supported"`        // neutral
	EncryptedClientHelloOffered       bool                `json:"encrypted_client_hello_offered"`        // neutral
	TLSCompressionSupported           bool                `json:"tls_compression_supported"`             // bad if true
	UnknownCipherSuiteSupported       bool                `json:"unknown_cipher_suite_supported"`        // bad if true
	BEASTVuln                         bool                `json:"beast_vuln"`                            // bad if true
	AbleToDetectNMinusOneSplitting    bool                `json:"able_to_detect_n_minus_one_splitting"`  // neutral
	InsecureCipherSuites              map[string][]string `json:"insecure_cipher_suites"`
	TLSVersion                        string              `json:"tls_version"`
	Rating                            rating              `json:"rating"`
	TLS12ImprovableCutoverPassed      bool                `json:"-"`
	TLS12BadCutoverPassed             bool                `json:"-"`
	NoPQImprovableCutoverPassed       bool                `json:"-"`
	NoPQBadCutoverPassed              bool                `json:"-"`
}

const (
	versionTLS13Draft18 = 0x7f00 | 18
	versionTLS13Draft21 = 0x7f00 | 21
	versionTLS13Draft22 = 0x7f00 | 22
	versionTLS13Draft23 = 0x7f00 | 23
	versionTLS13Draft24 = 0x7f00 | 24
	versionTLS13Draft25 = 0x7f00 | 25
	versionTLS13Draft26 = 0x7f00 | 26
	versionTLS13Draft27 = 0x7f00 | 27
	versionTLS13Draft28 = 0x7f00 | 28
	versionTLS13Draft29 = 0x7f00 | 29
	versionTLS13Draft30 = 0x7f00 | 30
	versionTLS13Draft31 = 0x7f00 | 31
	versionTLS13Draft32 = 0x7f00 | 32
	versionTLS13Draft33 = 0x7f00 | 33
)

var actualSupportedVersions = map[uint16]string{
	tls.VersionSSL30:    "SSL 3.0",
	tls.VersionTLS10:    "TLS 1.0",
	tls.VersionTLS11:    "TLS 1.1",
	tls.VersionTLS12:    "TLS 1.2",
	tls.VersionTLS13:    "TLS 1.3",
	versionTLS13Draft18: "TLS 1.3",
	versionTLS13Draft21: "TLS 1.3",
	versionTLS13Draft22: "TLS 1.3",
	versionTLS13Draft23: "TLS 1.3",
	versionTLS13Draft24: "TLS 1.3",
	versionTLS13Draft25: "TLS 1.3",
	versionTLS13Draft26: "TLS 1.3",
	versionTLS13Draft27: "TLS 1.3",
	versionTLS13Draft28: "TLS 1.3",
	versionTLS13Draft29: "TLS 1.3",
	versionTLS13Draft30: "TLS 1.3",
	versionTLS13Draft31: "TLS 1.3",
	versionTLS13Draft32: "TLS 1.3",
	versionTLS13Draft33: "TLS 1.3",
}

func pullClientInfo(c *tls.Conn, now time.Time) *clientInfo {
	return clientInfoFromState(c.ConnectionState(), now)
}

// clientInfoFromState is pullClientInfo without the connection, so that tests
// can describe ClientHellos that none of our test clients will send.
func clientInfoFromState(st tls.ConnectionState, now time.Time) *clientInfo {
	d := &clientInfo{InsecureCipherSuites: make(map[string][]string)}

	if !st.HandshakeComplete {
		panic("given a TLS conn that has not completed its handshake")
	}
	var sweet32Seen []string
	for _, ci := range st.ClientCipherSuites {
		s, found := allCipherSuites[ci]
		if found {
			if strings.Contains(s, "DHE_") {
				d.EphemeralKeysSupported = true
			}
			if cbcSuites[ci] && st.Version <= tls.VersionTLS10 {
				d.BEASTVuln = !st.NMinusOneRecordSplittingDetected
				d.AbleToDetectNMinusOneSplitting = st.AbleToDetectNMinusOneSplitting
			}
			if fewBitCipherSuites[s] {
				d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], fewBitReason)
			}
			if nullCipherSuites[s] {
				d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], nullReason)
			}
			if nullAuthCipherSuites[s] {
				d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], nullAuthReason)
			}
			if rc4CipherSuites[s] {
				d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], rc4Reason)
			}
			if sweet32CipherSuites[s] {
				sweet32Seen = append(sweet32Seen, s)
			} else if len(sweet32Seen) != 0 && !metaCipherSuites[ci] && !tls13Suites[ci] {
				for _, seen := range sweet32Seen {
					d.InsecureCipherSuites[seen] = append(d.InsecureCipherSuites[seen], sweet32Reason)
				}
				sweet32Seen = []string{}
			}
		} else {
			w, found := weirdNSSSuites[ci]
			if !found {
				d.UnknownCipherSuiteSupported = true
				s = fmt.Sprintf("Some unknown cipher suite: %#04x", ci)
			} else {
				s = w
				d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], weirdNSSReason)
			}
		}
		d.GivenCipherSuites = append(d.GivenCipherSuites, s)
	}
	// TLS 1.3 cipher suite names carry no key exchange, so the "DHE_" check
	// above never matches them. Every TLS 1.3 handshake a client can get
	// from a server it has no pre-shared key with is (EC)DHE.
	offersTLS13 := offersTLS13Handshake(st.ClientCipherSuites, st.SupportedVersions)
	if offersTLS13 {
		d.EphemeralKeysSupported = true
	}
	d.PostQuantumKeyAgreement = false
	d.GivenNamedGroups = []string{}
	for _, gid := range st.SupportedCurves {
		id := uint16(gid)
		if postQuantumGroups[id] {
			d.PostQuantumKeyAgreement = true
		}
		d.GivenNamedGroups = append(d.GivenNamedGroups, namedGroupName(id))
	}

	d.GivenSignatureAlgorithms = renderSignatureSchemes(st.SupportedSignatureAlgorithms)

	d.SessionTicketsSupported = st.SessionTicketsSupported

	// TLS 1.3 replaced the session_ticket extension with
	// psk_key_exchange_modes (RFC 8446, Section 4.2.9): a server may only send
	// a TLS 1.3 client a ticket if the client listed a mode the ticket can be
	// used with. A client that offers only TLS 1.3 has no reason to send
	// session_ticket at all. The modes mean nothing to a client that can't
	// get a TLS 1.3 handshake, so they're only judged when it can.
	d.GivenPSKKeyExchangeModes = renderPSKKeyExchangeModes(st.PSKModes)
	if offersTLS13 {
		if slices.Contains(st.PSKModes, pskModeKE) || slices.Contains(st.PSKModes, pskModeDHEKE) {
			d.SessionTicketsSupported = true
		}
		// A session resumed with psk_ke gets no new (EC)DHE exchange: its
		// keys come from the ticket alone, so it has no forward secrecy.
		d.PSKWithoutForwardSecrecySupported = slices.Contains(st.PSKModes, pskModeKE)
	}

	// The rest of what the ClientHello says is reported and nothing more:
	// none of it is looked at by the rating below.
	//
	// The server name itself is not shown. It is the name the client used to
	// get here, so it tells the client nothing, and leaving it out means one
	// fewer string of the client's choosing in the page and the API.
	d.ServerNameSent = st.ServerName != ""
	d.GivenALPNProtocols = renderALPNProtocols(st.ALPNProtocols)
	d.SecureRenegotiationSupported = st.SecureRenegotiationSupported
	d.GivenKeyShareGroups = renderKeyShareGroups(st.KeyShareGroups)
	d.EncryptedClientHelloOffered = st.EncryptedClientHelloOffered

	for _, cm := range st.CompressionMethods {
		if cm != 0x0 {
			d.TLSCompressionSupported = true
			break
		}
	}
	vers := st.Version
	d.TLSVersion = actualSupportedVersions[vers]

	// Check TLS 1.3's supported_versions extension for the actual TLS version
	// if it was passed in.
	for _, v := range st.SupportedVersions {
		maybeStr, found := actualSupportedVersions[v]
		if found && v > vers {
			vers = v
			d.TLSVersion = maybeStr
		}
	}
	if d.TLSVersion == "" {
		d.TLSVersion = "an unknown version of SSL/TLS"
	}

	d.TLS12ImprovableCutoverPassed = !now.Before(tls12ImprovableCutover)
	d.TLS12BadCutoverPassed = !now.Before(tls12BadCutover)
	d.NoPQImprovableCutoverPassed = !now.Before(noPQImprovableCutover)
	d.NoPQBadCutoverPassed = !now.Before(noPQBadCutover)

	d.Rating = okay

	if !d.EphemeralKeysSupported ||
		vers == tls.VersionTLS11 ||
		(vers <= tls.VersionTLS12 && d.TLS12ImprovableCutoverPassed) ||
		(!d.PostQuantumKeyAgreement && d.NoPQImprovableCutoverPassed) {
		d.Rating = improvable
	}

	if d.TLSCompressionSupported ||
		d.UnknownCipherSuiteSupported ||
		d.BEASTVuln ||
		len(d.InsecureCipherSuites) != 0 ||
		vers <= tls.VersionTLS10 ||
		(vers <= tls.VersionTLS12 && d.TLS12BadCutoverPassed) ||
		(!d.PostQuantumKeyAgreement && d.NoPQBadCutoverPassed) {
		d.Rating = bad
	}

	return d
}

// offersTLS13Handshake reports whether a ClientHello with the given cipher
// suites and supported_versions extension can be answered with a TLS 1.3
// handshake. It needs both a TLS 1.3 cipher suite and the final TLS 1.3
// version: a TLS 1.3 suite listed by a client that won't negotiate TLS 1.3 is
// never used, and the draft versions are not finished by any server now.
func offersTLS13Handshake(suites, versions []uint16) bool {
	if !slices.Contains(versions, uint16(tls.VersionTLS13)) {
		return false
	}
	return slices.ContainsFunc(suites, func(ci uint16) bool { return tls13Suites[ci] })
}

// The PskKeyExchangeMode values of RFC 8446, Section 4.2.9.
const (
	pskModeKE    uint8 = 0 // psk_ke
	pskModeDHEKE uint8 = 1 // psk_dhe_ke
)

var allPSKKeyExchangeModes = map[uint8]string{
	pskModeKE:    "psk_ke",
	pskModeDHEKE: "psk_dhe_ke",
}

// renderPSKKeyExchangeModes maps the codepoints of a psk_key_exchange_modes
// extension to their IANA registry names, falling back to a hex string for
// unknown values (which include RFC 8701's GREASE values). It always returns
// a non-nil slice so JSON output renders [] rather than null.
func renderPSKKeyExchangeModes(modes []uint8) []string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		name, found := allPSKKeyExchangeModes[m]
		if !found {
			name = fmt.Sprintf("Unknown PSK key exchange mode: %#02x", m)
		}
		out = append(out, name)
	}
	return out
}

// namedGroupName maps a TLS Supported Groups codepoint to its IANA registry
// name, falling back to a hex string for unknown values.
func namedGroupName(id uint16) string {
	name, found := allNamedGroups[id]
	if !found {
		name = fmt.Sprintf("Unknown named group: %#04x", id)
	}
	return name
}

// Limits on the lists below. Each is a list the client chooses the length
// of, up to the 64KB a ClientHello extension can hold, and real clients send
// two or three entries.
const (
	maxGivenALPNProtocols  = 16
	maxGivenALPNProtoBytes = 32
	maxGivenKeyShareGroups = 16
)

// renderKeyShareGroups maps the groups of a key_share extension (RFC 8446,
// Section 4.2.8) to their names, in the order sent and repeats included. Only
// the first maxGivenKeyShareGroups are returned. It always returns a non-nil
// slice so JSON output renders [] rather than null.
func renderKeyShareGroups(groups []tls.CurveID) []string {
	groups = groups[:min(len(groups), maxGivenKeyShareGroups)]
	out := make([]string, 0, len(groups))
	for _, gid := range groups {
		out = append(out, namedGroupName(uint16(gid)))
	}
	return out
}

// renderALPNProtocols makes the protocol names of an
// application_layer_protocol_negotiation extension (RFC 7301) safe to show,
// in the order sent and repeats included. Only the first
// maxGivenALPNProtocols are returned. It always returns a non-nil slice so
// JSON output renders [] rather than null.
func renderALPNProtocols(protos []string) []string {
	protos = protos[:min(len(protos), maxGivenALPNProtocols)]
	out := make([]string, 0, len(protos))
	for _, p := range protos {
		out = append(out, renderALPNProtocol(p))
	}
	return out
}

// alpnTruncated ends a protocol name that was cut short. A space and
// parentheses are never in a rendered name otherwise, so it can't be mistaken
// for part of one.
const alpnTruncated = " (truncated)"

// renderALPNProtocol returns an ALPN protocol name with every byte that is
// not an ASCII letter, a digit or one of "-._/+" written as \xNN. A protocol
// name is 1 to 255 bytes of the client's choosing and need not be text, so
// the result is ASCII that means nothing to HTML, JavaScript or JSON,
// whatever was sent. A backslash is itself escaped, so the bytes sent can be
// read back out. Names longer than maxGivenALPNProtoBytes are cut to that
// many bytes and marked.
func renderALPNProtocol(p string) string {
	truncated := len(p) > maxGivenALPNProtoBytes
	if truncated {
		p = p[:maxGivenALPNProtoBytes]
	}
	plain := true
	for i := 0; i < len(p); i++ {
		if !isPlainALPNByte(p[i]) {
			plain = false
			break
		}
	}
	if plain && !truncated {
		// What every registered protocol name looks like, without an
		// allocation.
		return p
	}
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 0, 4*len(p)+len(alpnTruncated))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if isPlainALPNByte(c) {
			b = append(b, c)
			continue
		}
		b = append(b, '\\', 'x', hexDigits[c>>4], hexDigits[c&0xf])
	}
	if truncated {
		b = append(b, alpnTruncated...)
	}
	return string(b)
}

func isPlainALPNByte(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '/', '+':
		return true
	}
	return false
}

// renderSignatureSchemes maps TLS SignatureScheme codepoints to their IANA
// registry names, falling back to a hex string for unknown values. It always
// returns a non-nil slice so JSON output renders [] rather than null.
func renderSignatureSchemes(schemes []tls.SignatureScheme) []string {
	out := make([]string, 0, len(schemes))
	for _, s := range schemes {
		id := uint16(s)
		name, found := allSignatureSchemes[id]
		if !found {
			name = fmt.Sprintf("Unknown signature scheme: %#04x", id)
		}
		out = append(out, name)
	}
	return out
}
