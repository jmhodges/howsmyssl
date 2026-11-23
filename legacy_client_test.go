package main

import (
	"bufio"
	"encoding/json"
	"expvar"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jmhodges/howsmyssl/howhttp"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
)

// TestLegacy3DESClientGetsReport checks that a client too old to offer
// anything the server would rather use can still finish a handshake and be
// told how bad it is. It runs the production TLS config (makeTLSConfig) and
// the production mux, and asks for /a/check over HTTP/1.1 as such a client
// would.
//
// This is the regression test for
// https://github.com/jmhodges/howsmyssl/issues/368 (IE8 on Windows XP). Both
// 3DES suites the server lists need an RSA certificate, as the development
// certificate is: with an ECDSA-only certificate none of these handshakes
// could complete.
func TestLegacy3DESClientGetsReport(t *testing.T) {
	// What IE8 on Windows XP SP3 (SChannel 5.1) offers, in its order. No
	// AES, no ECDHE, and nothing newer than TLS 1.0.
	ie8XPSuites := []uint16{
		ztls.TLS_RSA_WITH_RC4_128_MD5,
		ztls.TLS_RSA_WITH_RC4_128_SHA,
		ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		ztls.TLS_RSA_WITH_DES_CBC_SHA,
		ztls.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
		ztls.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
		ztls.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
		ztls.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
		ztls.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
		ztls.TLS_DHE_DSS_WITH_DES_CBC_SHA,
		ztls.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
	}

	tests := []struct {
		name       string
		version    uint16
		suites     []uint16
		wantSuite  uint16
		wantGiven  []string
		wantTLS    string
		wantEphem  bool
		wantRating rating
		// wantInsecure is nil when the test doesn't care which suites
		// were called out.
		wantInsecure map[string][]string
	}{
		{
			name:       "TLS10-RSA-3DES",
			version:    ztls.VersionTLS10,
			suites:     []uint16{ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			wantSuite:  ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			wantGiven:  []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
			wantTLS:    "TLS 1.0",
			wantRating: bad,
			// A client with nothing but 3DES has it "last", which is
			// where Sweet32 mitigation puts it, so the suite itself is
			// not called out. TLS 1.0 alone makes the client Bad.
			wantInsecure: map[string][]string{},
		},
		{
			name:         "TLS10-ECDHE-RSA-3DES",
			version:      ztls.VersionTLS10,
			suites:       []uint16{ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
			wantSuite:    ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			wantGiven:    []string{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
			wantTLS:      "TLS 1.0",
			wantEphem:    true,
			wantRating:   bad,
			wantInsecure: map[string][]string{},
		},
		{
			name:      "TLS12-RSA-3DES",
			version:   ztls.VersionTLS12,
			suites:    []uint16{ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			wantSuite: ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			wantGiven: []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
			wantTLS:   "TLS 1.2",
			// The handler rates with the wall clock, and a TLS 1.2
			// client goes from Improvable to Bad on 2026-12-14, so this
			// accepts either. See the check on okay below.
			wantRating:   "",
			wantInsecure: map[string][]string{},
		},
		{
			name:         "TLS12-ECDHE-RSA-3DES",
			version:      ztls.VersionTLS12,
			suites:       []uint16{ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
			wantSuite:    ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			wantGiven:    []string{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
			wantTLS:      "TLS 1.2",
			wantEphem:    true,
			wantRating:   "",
			wantInsecure: map[string][]string{},
		},
		{
			name:    "TLS10-IE8-on-XP",
			version: ztls.VersionTLS10,
			suites:  ie8XPSuites,
			// The order of makeTLSConfig's CipherSuites puts RC4 ahead
			// of 3DES, but tls1274, like crypto/tls since Go 1.17,
			// ignores that order and uses its own, where RC4 is last.
			// So 3DES is what this client ends up on.
			wantSuite: ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			wantGiven: []string{
				"TLS_RSA_WITH_RC4_128_MD5",
				"TLS_RSA_WITH_RC4_128_SHA",
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
				"TLS_RSA_WITH_DES_CBC_SHA",
				"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
				"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
				"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
				"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
				"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
				"TLS_DHE_DSS_WITH_DES_CBC_SHA",
				"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
			},
			wantTLS:    "TLS 1.0",
			wantEphem:  true,
			wantRating: bad,
		},
	}

	addr := startProductionTLSServer(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := zx509.NewCertPool()
			pool.AddCert(rootCAZtls)
			clientConf := &ztls.Config{
				ServerName:   "localhost",
				RootCAs:      pool,
				MinVersion:   tt.version,
				MaxVersion:   tt.version,
				CipherSuites: tt.suites,
				// Send exactly these suites, including the ones this
				// client library can't itself complete a handshake with.
				ForceSuites: true,
			}
			d := &net.Dialer{Timeout: 5 * time.Second}
			c, err := ztls.DialWithDialer(d, "tcp", addr, clientConf)
			if err != nil {
				t.Fatalf("handshake with only %v offered failed: %s", tt.wantGiven, err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))

			st := c.ConnectionState()
			if st.Version != tt.version {
				t.Errorf("negotiated version: want %#04x, got %#04x", tt.version, st.Version)
			}
			if st.CipherSuite != tt.wantSuite {
				t.Errorf("negotiated cipher suite: want %s (%#04x), got %s (%#04x)", allCipherSuites[tt.wantSuite], tt.wantSuite, allCipherSuites[st.CipherSuite], st.CipherSuite)
			}

			req, err := http.NewRequest("GET", "https://localhost/a/check", nil)
			if err != nil {
				t.Fatalf("NewRequest: %s", err)
			}
			if err := req.Write(c); err != nil {
				t.Fatalf("writing the request: %s", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), req)
			if err != nil {
				t.Fatalf("reading the response: %s", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading the response body: %s", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status code: want %d, got %d, body: %s", http.StatusOK, resp.StatusCode, body)
			}

			ci := &clientInfo{}
			if err := json.Unmarshal(body, ci); err != nil {
				t.Fatalf("unmarshaling the report: %s, body: %s", err, body)
			}
			if diff := cmp.Diff(tt.wantGiven, ci.GivenCipherSuites); diff != "" {
				t.Errorf("given_cipher_suites (-want +got):\n%s", diff)
			}
			if ci.TLSVersion != tt.wantTLS {
				t.Errorf("tls_version: want %#v, got %#v", tt.wantTLS, ci.TLSVersion)
			}
			if ci.EphemeralKeysSupported != tt.wantEphem {
				t.Errorf("ephemeral_keys_supported: want %t, got %t", tt.wantEphem, ci.EphemeralKeysSupported)
			}
			if tt.wantRating != "" && ci.Rating != tt.wantRating {
				t.Errorf("rating: want %#v, got %#v", tt.wantRating, ci.Rating)
			}
			if ci.Rating == okay {
				t.Errorf("rating: a client limited to %s and %v should never be %#v", tt.wantTLS, tt.wantGiven, okay)
			}
			if tt.wantInsecure != nil {
				if diff := cmp.Diff(tt.wantInsecure, ci.InsecureCipherSuites); diff != "" {
					t.Errorf("insecure_cipher_suites (-want +got):\n%s", diff)
				}
			}
		})
	}

	t.Run("TLS10-IE8-on-XP-insecure-suites", func(t *testing.T) {
		// The IE8 list has a non-3DES suite after each of its 3DES
		// suites, so here 3DES is called out, with the rest of that
		// museum.
		clientConf := &ztls.Config{
			MinVersion:   ztls.VersionTLS10,
			MaxVersion:   ztls.VersionTLS10,
			CipherSuites: ie8XPSuites,
			ForceSuites:  true,
		}
		ci := pullClientInfo(connectZtls(t, clientConf), preCutover)
		want := map[string][]string{
			"TLS_RSA_WITH_RC4_128_MD5":                {rc4Reason},
			"TLS_RSA_WITH_RC4_128_SHA":                {rc4Reason},
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           {sweet32Reason},
			"TLS_RSA_WITH_DES_CBC_SHA":                {fewBitReason},
			"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA":      {fewBitReason, rc4Reason},
			"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA":     {fewBitReason},
			"TLS_RSA_EXPORT_WITH_RC4_40_MD5":          {fewBitReason, rc4Reason},
			"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5":      {fewBitReason},
			"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA":       {sweet32Reason},
			"TLS_DHE_DSS_WITH_DES_CBC_SHA":            {fewBitReason},
			"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA": {fewBitReason},
		}
		if diff := cmp.Diff(want, ci.InsecureCipherSuites); diff != "" {
			t.Errorf("insecure cipher suites (-want +got):\n%s", diff)
		}
		if ci.Rating != bad {
			t.Errorf("rating: want %#v, got %#v", bad, ci.Rating)
		}
	})
}

// startProductionTLSServer serves the production mux over the production TLS
// config, wired the way main does it, and returns the address it listens on.
func startProductionTLSServer(t *testing.T) string {
	t.Helper()
	tl, err := tls.Listen("tcp", "localhost:0", serverConf)
	if err != nil {
		t.Fatalf("tls.Listen: %s", err)
	}
	li := howhttp.NewListener(tl, new(expvar.Map).Init())

	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(&allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	})
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	stats := newStatusStats(new(expvar.Map).Init())
	m := tlsMux("", "localhost", "", makeStaticHandler(stats), http.NotFound, oa, newTestLogger(t), newTestLogger(t))

	srv, err := howhttp.NewServer(li, m)
	if err != nil {
		li.Close()
		t.Fatalf("howhttp.NewServer: %s", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("closing the server: %s", err)
		}
		if err := <-serveErr; err != nil && err != http.ErrServerClosed {
			t.Errorf("Serve: %s", err)
		}
	})
	return li.Addr().String()
}
