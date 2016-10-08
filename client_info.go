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

type rec struct {
	Link string `json:"link"`
	Desc string `json:"description"`
}

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
	Recommendations                []rec               `json:"recommendations"`
}

func ClientInfo(c *conn) *clientInfo {
	d := &clientInfo{InsecureCipherSuites: make(map[string][]string)}
	var recs []rec
	var unknownSuites []string
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
				suite := fmt.Sprintf("%04x", ci)
				unknownSuites = append(unknownSuites, suite)
				s = fmt.Sprintf("Some unknown cipher suite: %s", suite)
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
	case 0x0304: // TODO(#119): use crypto/tls's constant when it has it
		d.TLSVersion = "TLS 1.3"

	default:
		d.TLSVersion = "an unknown version of SSL/TLS"
	}
	d.Rating = okay

	if !d.EphemeralKeysSupported {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#ephemeral-key-support",
			Desc: `Add cipher suites with ephemeral key (e.g ones containing "ECDHE", and "DHE")  to the client configuration.`,
		})
		d.Rating = improvable
	}
	if !d.SessionTicketsSupported {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#session-ticket-support",
			Desc: "Add session ticket support to your client configuration.",
		})
		d.Rating = improvable
	}
	if vers == tls.VersionTLS11 {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#version",
			Desc: "Set default protocol version to TLS 1.2.",
		})
		d.Rating = improvable
	}

	if d.TLSCompressionSupported {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#tls-compression-supported",
			Desc: "Disable TLS compression.",
		})
		d.Rating = bad
	}
	if d.UnknownCipherSuiteSupported {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#unknown-cipher-suites-supported",
			Desc: "Remove the cipher suites with these ids: " + sentence(unknownSuites),
		})
		d.Rating = bad
	}
	if d.BEASTVuln {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#beast-vulnerability",
			Desc: "Set the default protocol version to TLS 1.1 or 1.2 or remove the CBC cipher suites.",
		})
		d.Rating = bad
	}
	if len(d.InsecureCipherSuites) != 0 {
		var suites []string
		for k, _ := range d.InsecureCipherSuites {
			suites = append(suites, k)
		}
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#insecure-cipher-suites",
			Desc: "Remove these cipher suites: " + sentence(suites),
		})
		d.Rating = bad
	}
	if vers <= tls.VersionTLS10 {
		recs = append(recs, rec{
			Link: "https://www.howsmyssl.com/s/about.html#version",
			Desc: "Set default protocol version to TLS 1.2.",
		})
		d.Rating = bad
	}
	d.Recommendations = recs
	return d
}
