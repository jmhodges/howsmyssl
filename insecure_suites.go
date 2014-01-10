package main

var (
	fewBitReason   = "uses keys smaller than 128 bits in its encryption"
	nullReason     = "specifies no encryption at all for the connection"
	nullAuthReason = "is open to man-in-the-middle attacks because it does not authenticate the server"
	weirdNSSReason = "was meant to die with SSL 3.0 and is of unknown safety"
)

// Cipher suites with less than 128-bit encryption.
// Generated with (on an OpenSSL build newer than 1.0.1e with the enable-ssl-trace option):
//   ./openssl ciphers -v -stdname LOW:EXPORT | awk '{ print "\""$1"\": true," }' | grep -v UNKNOWN | sed 's/SSL/TLS/' | sort
//
// plus the manual addition of:
//   TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5	 40-bit encryption, export grade
//   TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA	 40-bit encryption, export grade
//   TLS_KRB5_EXPORT_WITH_RC4_40_MD5	     40-bit encryption, export grade
//   TLS_KRB5_EXPORT_WITH_RC4_40_SHA	     40-bit encryption, export grade
//   TLS_KRB5_WITH_DES_CBC_MD5	             56-bit encryption
//   TLS_KRB5_WITH_DES_CBC_SHA               56-bit encryption
//   SSL_RSA_FIPS_WITH_DES_CBC_SHA           56-bit encryption
var fewBitCipherSuites = map[string]bool{
	"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA": true,
	"TLS_DHE_DSS_WITH_DES_CBC_SHA":          true,
	"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA": true,
	"TLS_DHE_RSA_WITH_DES_CBC_SHA":          true,
	"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA":  true,
	"TLS_DH_DSS_WITH_DES_CBC_SHA":           true,
	"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA":  true,
	"TLS_DH_RSA_WITH_DES_CBC_SHA":           true,
	"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA": true,
	"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":    true,
	"TLS_DH_anon_WITH_DES_CBC_SHA":          true,
	"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":     true,
	"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5":    true,
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":        true,
	"TLS_RSA_WITH_DES_CBC_SHA":              true,
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5":   true,
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA":   true,
	"TLS_KRB5_EXPORT_WITH_RC4_40_MD5":       true,
	"TLS_KRB5_EXPORT_WITH_RC4_40_SHA":       true,
	"TLS_KRB5_WITH_DES_CBC_MD5":             true,
	"TLS_KRB5_WITH_DES_CBC_SHA":             true,
	"SSL_RSA_FIPS_WITH_DES_CBC_SHA":         true,
}

// Cipher suites that offer no encryption.
// Generated with:
//   grep NULL all_suites.go
//
// A smaller subset can be found with (on an OpenSSL build newer than 1.0.1e
// with the enable-ssl-trace option):
//   ./openssl ciphers -v -stdname NULL | awk '{ print "\""$1"\": true," }' | sed 's/SSL/TLS/' | sort
var nullCipherSuites = map[string]bool{
	"TLS_DHE_PSK_WITH_NULL_SHA":      true,
	"TLS_DHE_PSK_WITH_NULL_SHA256":   true,
	"TLS_DHE_PSK_WITH_NULL_SHA384":   true,
	"TLS_ECDHE_ECDSA_WITH_NULL_SHA":  true,
	"TLS_ECDHE_PSK_WITH_NULL_SHA":    true,
	"TLS_ECDHE_PSK_WITH_NULL_SHA256": true,
	"TLS_ECDHE_PSK_WITH_NULL_SHA384": true,
	"TLS_ECDHE_RSA_WITH_NULL_SHA":    true,
	"TLS_ECDH_ECDSA_WITH_NULL_SHA":   true,
	"TLS_ECDH_RSA_WITH_NULL_SHA":     true,
	"TLS_ECDH_anon_WITH_NULL_SHA":    true,
	"TLS_NULL_WITH_NULL_NULL":        true,
	"TLS_PSK_WITH_NULL_SHA":          true,
	"TLS_PSK_WITH_NULL_SHA256":       true,
	"TLS_PSK_WITH_NULL_SHA384":       true,
	"TLS_RSA_PSK_WITH_NULL_SHA":      true,
	"TLS_RSA_PSK_WITH_NULL_SHA256":   true,
	"TLS_RSA_PSK_WITH_NULL_SHA384":   true,
	"TLS_RSA_WITH_NULL_MD5":          true,
	"TLS_RSA_WITH_NULL_SHA":          true,
	"TLS_RSA_WITH_NULL_SHA256":       true,
}

// Cipher suites that offer encryption, but no authentication, opening them up
// to MITM attacks.
//
// Generated by combining
//   grep anon all_suites.go | awk '{ print $2 }' | sed 's/,/: true,/' | sort
// and on an OpenSSL build newer than 1.0.1e with the enable-ssl-trace option:
//   ./openssl ciphers -v -stdname aNULL | awk '{ print "\""$1"\": true," }' | sed 's/SSL/TLS/' | sort
var nullAuthCipherSuites = map[string]bool{
	"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA":    true,
	"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":       true,
	"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA":        true,
	"TLS_DH_anon_WITH_AES_128_CBC_SHA":         true,
	"TLS_DH_anon_WITH_AES_128_CBC_SHA256":      true,
	"TLS_DH_anon_WITH_AES_128_GCM_SHA256":      true,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA":         true,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA256":      true,
	"TLS_DH_anon_WITH_AES_256_GCM_SHA384":      true,
	"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256":     true,
	"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256":     true,
	"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384":     true,
	"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384":     true,
	"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA":    true,
	"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256": true,
	"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256": true,
	"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA":    true,
	"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256": true,
	"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384": true,
	"TLS_DH_anon_WITH_DES_CBC_SHA":             true,
	"TLS_DH_anon_WITH_RC4_128_MD5":             true,
	"TLS_DH_anon_WITH_SEED_CBC_SHA":            true,
	"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA":      true,
	"TLS_ECDH_anon_WITH_AES_128_CBC_SHA":       true,
	"TLS_ECDH_anon_WITH_AES_256_CBC_SHA":       true,
	"TLS_ECDH_anon_WITH_NULL_SHA":              true,
	"TLS_ECDH_anon_WITH_RC4_128_SHA":           true,
	"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA":        true,
	"TLS_SRP_SHA_WITH_AES_128_CBC_SHA":         true,
	"TLS_SRP_SHA_WITH_AES_256_CBC_SHA":         true,
}
