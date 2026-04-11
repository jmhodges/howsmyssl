// zclient exists because modern TLS clients drop support for old TLS versions
// and ciphersuites but we still want to test our code against it.
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
)

var (
	hostPort = flag.String("h", "localhost:10443", "host:port to connect to")
	rawTLS   = flag.Bool("raw", false, "connect only over TLS version, no HTTP")
	// as of this writing, zcrypto doesn't support system CA roots on macOS. See
	// https://github.com/zmap/zcrypto/issues/484
	caCert = flag.String("ca-cert", "", "path to CA cert (in PEM format) to trust. If connecting to localhost, this will default to the development CA cert included in the repo.")
)

func main() {
	ctx, cancel := context.WithTimeoutCause(context.Background(), 5*time.Second, errors.New("total request time exceeded"))
	defer cancel()

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

	if *caCert != "" {
		pool := loadRootCACertPool(*caCert)
		conf.RootCAs = pool
	} else if *caCert == "" && host == "localhost" {
		// If connecting to localhost and no CA cert was provided, default to the development CA cert included in the repo.
		pool := loadRootCACertPool("config/development_cert.pem")
		conf.RootCAs = pool
	}

	zDialer := &ztls.Dialer{
		Config: conf,
	}
	if *rawTLS {
		netConn, err := zDialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			log.Fatalf("unable to connect as just TLS: %v", err)
		}
		defer netConn.Close()
		conn, ok := netConn.(*ztls.Conn)
		if !ok {
			log.Fatalf("unable to convert net.Conn to ztls.Conn")
		}
		state := conn.ConnectionState()
		fmt.Printf("version: %04x\n", state.Version)
		fmt.Printf("cipher:  %04x\n", state.CipherSuite)
		fmt.Println("handshake ok")
		return
	}

	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: zDialer.DialContext,
		},
	}
	apiURLRaw := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
		Path:   "/a/check",
	}
	apiURL := apiURLRaw.String()
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		log.Fatalf("unable to create HTTP request: %v", err)
	}
	resp, err := client.Do(req)
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

func loadRootCACertPool(caCertPath string) *zx509.CertPool {
	certBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatal(err)
	}
	cblock, _ := pem.Decode(certBytes)

	certs, err := zx509.ParseCertificates(cblock.Bytes)
	if err != nil {
		log.Fatalf("zx509.ParseCertificates: %s", err)
	}
	rootCA := certs[0]
	pool := zx509.NewCertPool()
	pool.AddCert(rootCA)
	return pool
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
