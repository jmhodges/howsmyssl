package main

// All signature schemes in the TLS SignatureScheme registry.
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
//
// Both signature_algorithms (extension 13) and signature_algorithms_cert
// (extension 50) draw values from this same registry, so a single map could
// serve both.
//
// This list was last updated on 2026-11-23, against the registry as IANA last
// updated it on 2026-11-05.
var allSignatureSchemes = map[uint16]string{
	// RSASSA-PKCS1-v1_5 algorithms.
	0x0201: "rsa_pkcs1_sha1",
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",

	// ECDSA algorithms.
	0x0203: "ecdsa_sha1",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",

	// Legacy RSASSA-PKCS1-v1_5 code points for TLS 1.3 (RFC 9963).
	0x0420: "rsa_pkcs1_sha256_legacy",
	0x0520: "rsa_pkcs1_sha384_legacy",
	0x0620: "rsa_pkcs1_sha512_legacy",

	// Identity-based signatures (draft-wang-tls-raw-public-key-with-ibc-02).
	0x0704: "eccsi_sha256",
	0x0705: "iso_ibs1",
	0x0706: "iso_ibs2",
	0x0707: "iso_chinese_ibs",

	// SM2 (RFC 8998).
	0x0708: "sm2sig_sm3",

	// GOST R 34.10-2012 (RFC 9367).
	0x0709: "gostr34102012_256a",
	0x070a: "gostr34102012_256b",
	0x070b: "gostr34102012_256c",
	0x070c: "gostr34102012_256d",
	0x070d: "gostr34102012_512a",
	0x070e: "gostr34102012_512b",
	0x070f: "gostr34102012_512c",

	// bign (draft-kalosha-stb-tls13).
	0x0710: "bign-with-hbelt",
	0x0711: "bign-with-bash384",
	0x0712: "bign-with-bash512",

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",

	// EdDSA algorithms.
	0x0807: "ed25519",
	0x0808: "ed448",

	// RSASSA-PSS algorithms with public key OID RSASSA-PSS.
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",

	// Brainpool ECDSA for TLS 1.3 (RFC 8734).
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512",

	// ML-DSA (FIPS 204), per draft-ietf-tls-mldsa.
	// https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",

	// SLH-DSA (FIPS 205), per draft-reddy-tls-slhdsa-01.
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

	// GREASE values (RFC 8701).
	0x0a0a: "GREASE_0A",
	0x1a1a: "GREASE_1A",
	0x2a2a: "GREASE_2A",
	0x3a3a: "GREASE_3A",
	0x4a4a: "GREASE_4A",
	0x5a5a: "GREASE_5A",
	0x6a6a: "GREASE_6A",
	0x7a7a: "GREASE_7A",
	0x8a8a: "GREASE_8A",
	0x9a9a: "GREASE_9A",
	0xaaaa: "GREASE_AA",
	0xbaba: "GREASE_BA",
	0xcaca: "GREASE_CA",
	0xdada: "GREASE_DA",
	0xeaea: "GREASE_EA",
	0xfafa: "GREASE_FA",
}
