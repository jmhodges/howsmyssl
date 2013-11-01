package main

import (
	"fmt"
	"github.com/jmhodges/howsmyssl/tls"
	"strings"
)

type clientInfo struct {
	GivenCipherSuites           []string            `json:"given_cipher_suites"`
	EphemeralKeysSupported      bool                `json:"ephemeral_keys_supported"`       // good if true
	SessionTicketsSupported     bool                `json:"session_ticket_supported"`       // good if true
	TLSCompressionSupported     bool                `json:"tls_compression_supported"`      // bad if true
	UnknownCipherSuiteSupported bool                `json:"unknown_cipher_suite_supported"` // bad if true
	BEASTAttackVuln             bool                `json:"beast_attack_vuln"`              // bad if true
	InsecureCipherSuites        map[string][]string `json:"insecure_cipher_suites"`
	TLSVersion                  string              `json:"tls_version"`
}

func ClientInfo(c *conn) *clientInfo {
	d := &clientInfo{InsecureCipherSuites: make(map[string][]string)}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	for _, ci := range c.st.ClientHello.CipherSuites {
		s, found := allCipherSuites[ci]
		if found {
			if strings.Contains(s, "DHE_") {
				d.EphemeralKeysSupported = true
			}
			if c.st.ClientHello.Vers <= tls.VersionTLS10 && strings.Contains(s, "_CBC_") {
				d.BEASTAttackVuln = true
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

		} else {
			d.UnknownCipherSuiteSupported = true
			s = fmt.Sprintf("Some unknown cipher suite: %#x", ci)
		}
		d.GivenCipherSuites = append(d.GivenCipherSuites, s)
	}
	d.SessionTicketsSupported = c.st.ClientHello.TicketSupported

	for _, cm := range c.st.ClientHello.CompressionMethods {
		if cm != 0x0 {
			d.TLSCompressionSupported = true
			break
		}
	}
	switch c.st.ClientHello.Vers {
	case tls.VersionSSL30:
		d.TLSVersion = "SSL 3.0"
	case tls.VersionTLS10:
		d.TLSVersion = "TLS 1.0"
	case tls.VersionTLS11:
		d.TLSVersion = "TLS 1.1"
	case tls.VersionTLS12:
		d.TLSVersion = "TLS 1.2"
	}
	return d
}
