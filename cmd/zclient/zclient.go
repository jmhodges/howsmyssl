// zclient exists because modern TLS clients drop support for old TLS versions
// and ciphersuites but we still want to test our code against it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"

	ztls "github.com/zmap/zcrypto/tls"
)

var (
	hostPort = flag.String("h", "localhost:10443", "host:port to connect to")
	rawTLS   = flag.Bool("raw", false, "connect only over TLS version, no HTTP")
)

func main() {
	flag.Parse()

	if *hostPort == "" {
		log.Fatal("-h host:port is required")
	}
	host, port, err := net.SplitHostPort(*hostPort)
	if err != nil {
		// No port — treat the whole thing as a host
		host = *hostPort
		port = "443"
	}

	conf := &ztls.Config{
		// InsecureSkipVerify is required to connect to the local host version
		// of the server, which we typically are. We could do something
		// intereting with VerifyPeerCertificate and embedding the current dev
		// cert in this file, but as of writing, the layout of the repo means we
		// can't because embed can't go up parent directories and the top-level
		// directory is a binary.
		// #nosec G402
		InsecureSkipVerify: true,

		// TLS 1.0 with CBC suite
		// MinVersion:         ztls.VersionTLS10,
		// MaxVersion:         ztls.VersionTLS10,
		// CipherSuites:       []uint16{ztls.TLS_RSA_WITH_AES_128_CBC_SHA},

		// TLS 1.3 post-quantum
		// MinVersion:         ztls.VersionTLS13,
		// MaxVersion:         ztls.VersionTLS13,
		// CipherSuites:       []uint16{ztls.TLS_CHACHA20_POLY1305_SHA256},
		// CurvePreferences:   []ztls.CurveID{ztls.X25519MLKEM768},

	}
	if *rawTLS {
		conn, err := ztls.Dial("tcp", net.JoinHostPort(host, port), conf)
		if err != nil {
			log.Fatalf("unable to connect as just TLS: %v", err)
		}
		defer conn.Close()
		state := conn.ConnectionState()
		fmt.Printf("version: %04x\n", state.Version)
		fmt.Printf("cipher:  %04x\n", state.CipherSuite)
		fmt.Println("handshake ok")
		return
	}

	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return ztls.Dial(network, addr, conf)
			},
		},
	}
	apiURLRaw := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
		Path:   "/a/check",
	}
	apiURL := apiURLRaw.String()
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Fatalf("unable to perform HTTP GET /a/check: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("unable to read response body from %s: %v", apiURL, err)
	}
	clientInfo := &clientInfo{}
	json.Unmarshal(data, clientInfo)
	out, err := json.MarshalIndent(clientInfo, "", "  ")
	if err != nil {
		log.Fatalf("unable to marshal client info: %v", err)
	}
	fmt.Println(string(out))
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
	Rating                         rating              `json:"rating"`
}

type rating string

const (
	okay       rating = "Probably Okay"
	improvable rating = "Improvable"
	bad        rating = "Bad"
)
