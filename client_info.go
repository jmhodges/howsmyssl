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
	GivenCipherSuites              []string            `json:"given_cipher_suites"`
	GivenNamedGroups               []string            `json:"given_named_groups"`
	GivenSignatureAlgorithms       []string            `json:"given_signature_algorithms"`
	PostQuantumKeyAgreement        bool                `json:"post_quantum_key_agreement"`
	EphemeralKeysSupported         bool                `json:"ephemeral_keys_supported"`             // good if true
	SessionTicketsSupported        bool                `json:"session_ticket_supported"`             // good if true
	TLSCompressionSupported        bool                `json:"tls_compression_supported"`            // bad if true
	UnknownCipherSuiteSupported    bool                `json:"unknown_cipher_suite_supported"`       // bad if true
	BEASTVuln                      bool                `json:"beast_vuln"`                           // bad if true
	AbleToDetectNMinusOneSplitting bool                `json:"able_to_detect_n_minus_one_splitting"` // neutral
	InsecureCipherSuites           map[string][]string `json:"insecure_cipher_suites"`
	TLSVersion                     string              `json:"tls_version"`
	Rating                         rating              `json:"rating"`
	TLS12ImprovableCutoverPassed   bool                `json:"-"`
	TLS12BadCutoverPassed          bool                `json:"-"`
	NoPQImprovableCutoverPassed    bool                `json:"-"`
	NoPQBadCutoverPassed           bool                `json:"-"`
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
	d := &clientInfo{InsecureCipherSuites: make(map[string][]string)}

	st := c.ConnectionState()
	if !st.HandshakeComplete {
		panic("given a TLS conn that has not completed its handshake")
	}
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
	tls13Offered := offersTLS13Handshake(st.ClientCipherSuites, st.SupportedVersions)
	notFallback, noStronger := sweet32Suites(st.ClientCipherSuites, tls13Offered)
	for _, s := range notFallback {
		d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], sweet32Reason)
	}
	for _, s := range noStronger {
		d.InsecureCipherSuites[s] = append(d.InsecureCipherSuites[s], sweet32NoStrongerReason)
	}
	// TLS 1.3 cipher suite names carry no key exchange, so the "DHE_" check
	// above never matches them. Every TLS 1.3 handshake a client can get
	// from a server it has no pre-shared key with is (EC)DHE.
	if tls13Offered {
		d.EphemeralKeysSupported = true
	}
	d.PostQuantumKeyAgreement = false
	d.GivenNamedGroups = []string{}
	for _, gid := range st.SupportedCurves {
		id := uint16(gid)
		name, found := allNamedGroups[id]
		if !found {
			name = fmt.Sprintf("Unknown named group: %#04x", id)
		}
		if postQuantumGroups[id] {
			d.PostQuantumKeyAgreement = true
		}
		d.GivenNamedGroups = append(d.GivenNamedGroups, name)
	}

	d.GivenSignatureAlgorithms = renderSignatureSchemes(st.SupportedSignatureAlgorithms)

	d.SessionTicketsSupported = st.SessionTicketsSupported

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

// sweet32Suites returns the names of the 3DES cipher suites in a ClientHello's
// list that count against the client, split by why.
//
// 3DES is tolerated only as a last resort: listed after everything else the
// client would rather use, so that a server picks it only when it has nothing
// better. notFallback holds the 3DES suites that have some other real cipher
// suite listed after them. Meta cipher suites and TLS 1.3 cipher suites don't
// count as "after": clients append them wherever they like.
//
// A last resort needs something to be the last resort of. noStronger holds
// the 3DES suites listed last by a client that offers nothing stronger (see
// strongerThan3DES) at all. Such a client ends up on 3DES, or on something
// worse, with every server.
func sweet32Suites(suites []uint16, tls13Offered bool) (notFallback, noStronger []string) {
	var last []string
	strongerOffered := false
	for _, ci := range suites {
		s := allCipherSuites[ci]
		if sweet32CipherSuites[s] {
			last = append(last, s)
			continue
		}
		if strongerThan3DES(ci, tls13Offered) {
			strongerOffered = true
		}
		if len(last) != 0 && s != "" && !metaCipherSuites[ci] && !tls13Suites[ci] {
			notFallback = append(notFallback, last...)
			last = nil
		}
	}
	if !strongerOffered {
		noStronger = last
	}
	return notFallback, noStronger
}

// strongerThan3DES reports whether a server could pick the cipher suite ci
// and leave the client better off than with a 3DES one. That rules out the
// signalling values that are not cipher suites at all, the suites we don't
// know, the ones insecure_suites.go lists, and the TLS 1.3 suites of a client
// that isn't offering a TLS 1.3 handshake.
func strongerThan3DES(ci uint16, tls13Offered bool) bool {
	s, found := allCipherSuites[ci]
	if !found || metaCipherSuites[ci] || ci == tlsFallbackSCSV {
		return false
	}
	if sweet32CipherSuites[s] || fewBitCipherSuites[s] || nullCipherSuites[s] || nullAuthCipherSuites[s] || rc4CipherSuites[s] {
		return false
	}
	if tls13Suites[ci] {
		return tls13Offered
	}
	return true
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
