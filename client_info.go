package main

import (
	"fmt"
	"strings"

	"github.com/jmhodges/howsmyssl/tls"
)

type Rating string

const (
	okay       Rating = "Probably Okay"
	improvable Rating = "Improvable"
	bad        Rating = "Bad"
)

type clientInfo struct {
	GivenCipherSuites              []string            `json:"given_cipher_suites"`
	EphemeralKeysSupported         bool                `json:"ephemeral_keys_supported"`             // good if true
	SessionTicketsSupported        bool                `json:"session_ticket_supported"`             // good if true
	TLSCompressionSupported        bool                `json:"tls_compression_supported"`            // bad if true
	UnknownCipherSuiteSupported    bool                `json:"unknown_cipher_suite_supported"`       // bad if true
	BEASTVuln                      bool                `json:"beast_vuln"`                           // bad if true
	AbleToDetectNMinusOneSplitting bool                `json:"able_to_detect_n_minus_one_splitting"` // neutral
	InsecureCipherSuites           map[string][]string `json:"insecure_cipher_suites"`
	TLSVersion                     string              `json:"tls_version"`
	Rating                         Rating              `json:"rating"`
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
			if c.HasBeastVulnSuites {
				d.BEASTVuln = !c.NMinusOneRecordSplittingDetected
				d.AbleToDetectNMinusOneSplitting = c.AbleToDetectNMinusOneSplitting
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
	d.SessionTicketsSupported = c.st.ClientHello.TicketSupported

	for _, cm := range c.st.ClientHello.CompressionMethods {
		if cm != 0x0 {
			d.TLSCompressionSupported = true
			break
		}
	}
	vers := c.st.ClientHello.Vers
	switch vers {
	case tls.VersionSSL30:
		d.TLSVersion = "SSL 3.0"
	case tls.VersionTLS10:
		d.TLSVersion = "TLS 1.0"
	case tls.VersionTLS11:
		d.TLSVersion = "TLS 1.1"
	case tls.VersionTLS12:
		d.TLSVersion = "TLS 1.2"
	default:
		d.TLSVersion = "an unknown version of SSL/TLS"
	}
	d.Rating = okay

	if !d.EphemeralKeysSupported || !d.SessionTicketsSupported || vers == tls.VersionTLS11 {
		d.Rating = improvable
	}

	if d.TLSCompressionSupported ||
		d.UnknownCipherSuiteSupported ||
		d.BEASTVuln ||
		len(d.InsecureCipherSuites) != 0 ||
		vers <= tls.VersionTLS10 {
		d.Rating = bad
	}
	return d
}
