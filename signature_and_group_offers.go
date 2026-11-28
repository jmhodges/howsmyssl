package main

import (
	"slices"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// The tables in this file back report-only fields: offering any of these
// doesn't change the rating. Each was read from IANA's TLS registries
// (tls-parameters, updated 2026-11-05, and tls-extensiontype-values, updated
// 2026-11-18).
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

// sha1OrMD5SignatureSchemes are the signature_algorithms and
// signature_algorithms_cert values that hash with SHA-1 or MD5.
//
// rsa_pkcs1_sha1 and ecdsa_sha1 are named in the TLS SignatureScheme registry
// (Recommended: N). The other four are TLS 1.2 hash and signature pairs (RFC
// 5246, Section 7.4.1.4.1) from the TLS HashAlgorithm registry, which marks
// md5 and sha1 "D", and the TLS SignatureAlgorithm registry. The
// SignatureScheme registry only reserves their values "for backward
// compatibility", so it gives them no names: these names are ours, made the
// same way as the two it does name.
var sha1OrMD5SignatureSchemes = map[uint16]string{
	0x0101: "rsa_pkcs1_md5", // md5(1), rsa(1)
	0x0102: "dsa_md5",       // md5(1), dsa(2)
	0x0103: "ecdsa_md5",     // md5(1), ecdsa(3)
	0x0201: "rsa_pkcs1_sha1",
	0x0202: "dsa_sha1", // sha1(2), dsa(2)
	0x0203: "ecdsa_sha1",
}

// retiredKyberDraftGroups are the pre-standard Kyber hybrid groups. The TLS
// Supported Groups registry lists both as "(OBSOLETE)", Recommended "D",
// obsoleted by the ML-KEM hybrids of RFC 10024. They are not post-quantum
// groups for postQuantumGroups.
var retiredKyberDraftGroups = map[uint16]string{
	0x6399: "X25519Kyber768Draft00",
	0x639a: "SecP256r1Kyber768Draft00",
}

// postQuantumSignatureSchemes are the ML-DSA (FIPS 204) and SLH-DSA (FIPS
// 205) values in the TLS SignatureScheme registry.
var postQuantumSignatureSchemes = map[uint16]string{
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
	0x0911: "slhdsa_sha2_128s",
	0x0912: "slhdsa_sha2_128f",
	0x0913: "slhdsa_sha2_192s",
	0x0914: "slhdsa_sha2_192f",
	0x0915: "slhdsa_sha2_256s",
	0x0916: "slhdsa_sha2_256f",
	0x0917: "slhdsa_shake_128s",
	0x0918: "slhdsa_shake_128f",
	0x0919: "slhdsa_shake_192s",
	0x091a: "slhdsa_shake_192f",
	0x091b: "slhdsa_shake_256s",
	0x091c: "slhdsa_shake_256f",
}

// extensionTrustAnchors is the trust_anchors extension of
// draft-ietf-tls-trust-anchor-ids. The TLS ExtensionType Values registry lists
// it as a temporary early allocation, registered 2026-11-18 and expiring
// 2027-11-18. If it lapses or moves, this has to follow.
const extensionTrustAnchors uint16 = 0xca34 // 51764

// signatureSchemesOffered returns the names of the schemes in table that the
// client sent in signature_algorithms or signature_algorithms_cert, each once,
// in the order first seen (signature_algorithms first). It always returns a
// non-nil slice so JSON output renders [] rather than null.
func signatureSchemesOffered(table map[uint16]string, sigAlgs, sigAlgsCert []tls.SignatureScheme) []string {
	out := []string{}
	for _, s := range slices.Concat(sigAlgs, sigAlgsCert) {
		name, found := table[uint16(s)]
		if found && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// retiredKyberDraftGroupsOffered returns the names of the retired Kyber draft
// groups in the client's supported_groups, in the order sent. It always
// returns a non-nil slice so JSON output renders [] rather than null.
func retiredKyberDraftGroupsOffered(groups []tls.CurveID) []string {
	out := []string{}
	for _, g := range groups {
		name, found := retiredKyberDraftGroups[uint16(g)]
		if found && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

func trustAnchorIDsOffered(exts []uint16) bool {
	return slices.Contains(exts, extensionTrustAnchors)
}
