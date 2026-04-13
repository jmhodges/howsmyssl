package main

// All named groups (formerly "elliptic curves" or "supported groups") in the
// TLS Supported Groups registry.
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
//
// This list was last updated on 2026-04-09.
var allNamedGroups = map[uint16]string{
	// SEC curves
	0x0001: "sect163k1",
	0x0002: "sect163r1",
	0x0003: "sect163r2",
	0x0004: "sect193r1",
	0x0005: "sect193r2",
	0x0006: "sect233k1",
	0x0007: "sect233r1",
	0x0008: "sect239k1",
	0x0009: "sect283k1",
	0x000a: "sect283r1",
	0x000b: "sect409k1",
	0x000c: "sect409r1",
	0x000d: "sect571k1",
	0x000e: "sect571r1",
	0x000f: "secp160k1",
	0x0010: "secp160r1",
	0x0011: "secp160r2",
	0x0012: "secp192k1",
	0x0013: "secp192r1",
	0x0014: "secp224k1",
	0x0015: "secp224r1",
	0x0016: "secp256k1",

	// NIST curves
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",

	// Brainpool curves (RFC 7027)
	0x001a: "brainpoolP256r1",
	0x001b: "brainpoolP384r1",
	0x001c: "brainpoolP512r1",

	// Modern curves
	0x001d: "x25519",
	0x001e: "x448",

	// Brainpool curves for TLS 1.3 (RFC 8734)
	0x001f: "brainpoolP256r1tls13",
	0x0020: "brainpoolP384r1tls13",
	0x0021: "brainpoolP512r1tls13",

	// GC-256 curves
	0x0022: "GC256A",
	0x0023: "GC256B",
	0x0024: "GC256C",
	0x0025: "GC256D",
	0x0026: "GC512A",
	0x0027: "GC512B",
	0x0028: "GC512C",

	// curveSM2 (RFC 8998)
	0x0029: "curveSM2",

	// FFDHE groups (RFC 7919)
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x0102: "ffdhe4096",
	0x0103: "ffdhe6144",
	0x0104: "ffdhe8192",

	// ML-KEM hybrid key agreement groups
	0x11eb: "SecP256r1MLKEM768",
	0x11ec: "X25519MLKEM768",
	0x11ed: "SecP384r1MLKEM1024",

	// GREASE values
	// See https://www.rfc-editor.org/rfc/rfc8701
	0x0A0A: "GREASE",
	0x1A1A: "GREASE",
	0x2A2A: "GREASE",
	0x3A3A: "GREASE",
	0x4A4A: "GREASE",
	0x5A5A: "GREASE",
	0x6A6A: "GREASE",
	0x7A7A: "GREASE",
	0x8A8A: "GREASE",
	0x9A9A: "GREASE",
	0xAAAA: "GREASE",
	0xBABA: "GREASE",
	0xCACA: "GREASE",
	0xDADA: "GREASE",
	0xEAEA: "GREASE",
	0xFAFA: "GREASE",
}

// postQuantumGroups are the named groups that provide post-quantum key
// agreement via ML-KEM hybrids.
var postQuantumGroups = map[uint16]bool{
	0x11eb: true, // SecP256r1MLKEM768
	0x11ec: true, // X25519MLKEM768
	0x11ed: true, // SecP384r1MLKEM1024
}
