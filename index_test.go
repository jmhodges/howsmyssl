package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
)

type testWriter struct {
	t *testing.T
}

func (tl testWriter) Write(b []byte) (int, error) {
	tl.t.Log(string(b))
	return len(b), nil
}

func newTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, nil))
}

func TestDumbNilishIndex(t *testing.T) {
	tmpl := loadIndex()
	buf := new(bytes.Buffer)
	err := tmpl.Execute(buf, &clientInfo{})
	if err != nil {
		t.Errorf("index execution blew up with nilish clientInfo: %#v", err)
	}
	if len(buf.Bytes()) == 0 {
		t.Errorf("index execution did not write anything")
	}
}

type acmeTest struct {
	challPath       string
	acmeRedirectURL string
	expected        string
	code            int
}

func TestACMERedirect(t *testing.T) {
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	webHandleFunc := http.NotFound
	tests := []acmeTest{
		// same domain redirect, acmeRedirectURL leads with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/example.com",
			expected:        "/example.com/.well-known/acme-challenge/foobar",
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "http://example.com",
			expected:        "http://example.com/.well-known/acme-challenge/foobar",
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "http://example.com/",
			expected:        "http://example.com/.well-known/acme-challenge/foobar",
		},
		// Busted acmeRedirectURL. Meant to be a domain, but was not.
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "example.com",
			expected:        "/.well-known/acme-challenge/example.com/.well-known/acme-challenge/foobar",
		},
		// same domain redirect, acmeRedirectURL leads and trails with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/okay/",
			expected:        "/okay/.well-known/acme-challenge/foobar",
		},
		// same domain redirect, acmeRedirectURL leads and trails with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/okay/",
			expected:        "/okay/.well-known/acme-challenge/foobar",
		},
		// same domain redirect, acmeRedirectURL leads with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/okay",
			expected:        "/okay/.well-known/acme-challenge/foobar",
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge",
			acmeRedirectURL: "http://example.com",
			expected:        "/.well-known/acme-challenge/",
			// As of Go 1.26, http.ServeMux will redirect requests that are
			// missing a trailing "/" to the same path with a trailing "/" using
			// 307 Temporary Redirect instead of 301 Moved Permanently. See
			// https://github.com/golang/go/issues/50243 and
			// https://go.dev/doc/go1.26#nethttppkgnethttp
			code: http.StatusTemporaryRedirect,
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/",
			acmeRedirectURL: "http://example.com",
			expected:        "",
			code:            http.StatusOK,
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "http://example.com",
			expected:        "http://example.com/.well-known/acme-challenge/foobar",
		},
		// Empty acmeRedirectURL means no redirect target is configured, so
		// the handler returns a 404 instead of redirecting.
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "",
			expected:        "",
			code:            http.StatusNotFound,
		},
	}
	for i, tt := range tests {
		tm := tlsMux("www.howsmyssl.com", "www.howsmyssl.com", tt.acmeRedirectURL, staticHandler, webHandleFunc, nil, newTestLogger(t), newTestLogger(t))
		r, err := http.NewRequest("GET", tt.challPath, nil)
		if err != nil {
			t.Fatalf("borked request for %#v: %s", tt.challPath, err)
		}
		w := httptest.NewRecorder()
		tm.ServeHTTP(w, r)

		location := w.Header().Get("Location")
		if tt.code == 0 {
			tt.code = http.StatusFound
		}
		if w.Code != tt.code {
			t.Errorf("#%d, want %d, got %d", i, tt.code, w.Code)
		}
		if location != tt.expected {
			t.Errorf("#%d, %q, want %#v, got %#v", i, tt.acmeRedirectURL, tt.expected, location)
		}
	}
}

type vhostTest struct {
	rawVHost  string
	httpsAddr string

	expectedRouteHost    string
	expectedRedirectHost string
}

func TestVHostCalculation(t *testing.T) {
	tests := []vhostTest{
		{
			rawVHost:             "www.howsmyssl.com",
			httpsAddr:            "0:10443",
			expectedRouteHost:    "www.howsmyssl.com",
			expectedRedirectHost: "www.howsmyssl.com",
		},
		{
			rawVHost:             "localhost:10443",
			httpsAddr:            "localhost:10443",
			expectedRouteHost:    "localhost",
			expectedRedirectHost: "localhost:10443",
		},
		{
			rawVHost:             "example.com:10443",
			httpsAddr:            "localhost:10443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com:10443",
		},
		{
			rawVHost:             "example.com:443",
			httpsAddr:            "0:443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com",
		},
		{
			// Empty vhost falls back to the host from httpsAddr.
			rawVHost:             "",
			httpsAddr:            "example.com:443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com",
		},
		{
			// Empty vhost and unparseable httpsAddr fall back to localhost.
			rawVHost:             "",
			httpsAddr:            "",
			expectedRouteHost:    "localhost",
			expectedRedirectHost: "localhost",
		},
		{
			// Colon with empty host on port 443: fall back for routeHost, drop
			// the port for redirectHost.
			rawVHost:             ":443",
			httpsAddr:            "example.com:443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com",
		},
		{
			// Colon with empty host on a non-443 port: fall back for routeHost
			// but keep the raw vhost for redirectHost.
			rawVHost:             ":10443",
			httpsAddr:            "example.com:443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: ":10443",
		},
		{
			// Trailing colon with an empty port: drop the empty port from
			// redirectHost rather than redirecting to "example.com:".
			rawVHost:             "example.com:",
			httpsAddr:            "example.com:443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com",
		},
	}
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	webHandleFunc := http.NotFound

	for i, vt := range tests {
		routeHost, redirectHost := calculateDomains(vt.rawVHost, vt.httpsAddr)
		if routeHost != vt.expectedRouteHost {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want routeHost %#v, got %s", i, vt.rawVHost, vt.httpsAddr, vt.expectedRouteHost, routeHost)
		}
		if redirectHost != vt.expectedRedirectHost {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want redirectHost %#v, got %#v", i, vt.rawVHost, vt.httpsAddr, vt.expectedRedirectHost, redirectHost)
		}

		tm := tlsMux(vt.expectedRouteHost, vt.expectedRedirectHost, "http://otherexample.com", staticHandler, webHandleFunc, nil, newTestLogger(t), newTestLogger(t))
		r, err := http.NewRequest("GET", "https://howsmyssl.com/", nil)
		if err != nil {
			t.Fatalf("borked request")
		}
		w := httptest.NewRecorder()
		tm.ServeHTTP(w, r)
		expectedLocation := "https://" + vt.expectedRedirectHost + "/"
		location := w.Header()["Location"][0]
		if w.Code != http.StatusMovedPermanently {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want Code %d, got %d", i, vt.rawVHost, vt.httpsAddr, http.StatusMovedPermanently, w.Code)
		}
		if location != expectedLocation {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want Location %s, got %s", i, vt.rawVHost, vt.httpsAddr, expectedLocation, location)
		}
	}
}

func TestLLMSTxt(t *testing.T) {
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	webHandleFunc := http.NotFound
	tm := tlsMux("www.howsmyssl.com", "www.howsmyssl.com", "", staticHandler, webHandleFunc, nil, newTestLogger(t), newTestLogger(t))

	r, err := http.NewRequest("GET", "https://www.howsmyssl.com/llms.txt", nil)
	if err != nil {
		t.Fatalf("borked request for /llms.txt: %s", err)
	}
	w := httptest.NewRecorder()
	tm.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status code: want %d, got %d", http.StatusOK, w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type: want %#v, got %#v", "text/plain; charset=utf-8", ct)
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, "# How's My SSL?") {
		t.Errorf("body does not start with the llms.txt H1 site name, got prefix %#v", body[:min(len(body), 40)])
	}
	for _, want := range []string{
		"https://www.tlsversion.com/v1/version.json",
		"https://www.howsmyssl.com/a/check",
		"https://www.howsmyssl.com/s/api.html",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %#v", want)
		}
	}
}

func TestJSONRedirectContentType(t *testing.T) {
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	webHandleFunc := http.NotFound

	// Test that redirects from howsmytls.com to howsmyssl.com respect Accept header
	tm := tlsMux("www.howsmyssl.com", "www.howsmyssl.com", "", staticHandler, webHandleFunc, nil, newTestLogger(t), newTestLogger(t))

	tests := []struct {
		name        string
		path        string
		acceptHdrs  []string // Support multiple Accept headers
		wantCT      string
		wantVaryHdr bool
	}{
		{
			name:        "JSON API redirect with Accept: application/json",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"application/json"},
			wantCT:      "application/json",
			wantVaryHdr: true,
		},
		{
			name:        "JSON with case variation Application/JSON",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"Application/JSON"},
			wantCT:      "application/json",
			wantVaryHdr: true,
		},
		{
			name:        "Wildcard Accept: */* falls through to HTML (browsers send this)",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"*/*"},
			wantCT:      "text/html; charset=utf-8",
			wantVaryHdr: true,
		},
		{
			name:        "Multiple Accept headers (JSON in second)",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"text/plain", "application/json"},
			wantCT:      "application/json",
			wantVaryHdr: true,
		},
		{
			name:        "JSON with q-values",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"application/json;q=0.9, text/html;q=0.8"},
			wantCT:      "application/json",
			wantVaryHdr: true,
		},
		{
			name:        "JSON variant should not match (application/json-patch+json)",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"application/json-patch+json"},
			wantCT:      "text/html; charset=utf-8",
			wantVaryHdr: true,
		},
		{
			name:        "JSON with q=0 is not acceptable, falls through to HTML",
			path:        "https://www.howsmytls.com/a/check",
			acceptHdrs:  []string{"application/json;q=0, text/html"},
			wantCT:      "text/html; charset=utf-8",
			wantVaryHdr: true,
		},
		{
			name:        "Non-ASCII query is percent-encoded in JSON Location",
			path:        "https://www.howsmytls.com/a/check?q=caf\xc3\xa9",
			acceptHdrs:  []string{"application/json"},
			wantCT:      "application/json",
			wantVaryHdr: true,
		},
		{
			name:        "HTML redirect with Accept: text/html",
			path:        "https://www.howsmytls.com/",
			acceptHdrs:  []string{"text/html"},
			wantCT:      "text/html; charset=utf-8",
			wantVaryHdr: true,
		},
		{
			name:        "HTML redirect with no Accept header",
			path:        "https://www.howsmytls.com/",
			acceptHdrs:  nil,
			wantCT:      "text/html; charset=utf-8",
			wantVaryHdr: true, // Response varies on Accept regardless of whether it is sent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest("GET", tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %s", err)
			}
			for _, hdr := range tt.acceptHdrs {
				r.Header.Add("Accept", hdr)
			}
			w := httptest.NewRecorder()
			tm.ServeHTTP(w, r)

			if w.Code != http.StatusMovedPermanently {
				t.Errorf("want status %d, got %d", http.StatusMovedPermanently, w.Code)
			}

			ct := w.Header().Get("Content-Type")
			if ct != tt.wantCT {
				t.Errorf("want Content-Type %q, got %q", tt.wantCT, ct)
			}

			// The Location header must be a valid (ASCII) header value;
			// non-ASCII bytes from the request must be percent-encoded.
			loc := w.Header().Get("Location")
			for i := 0; i < len(loc); i++ {
				if loc[i] >= 0x80 {
					t.Errorf("Location has non-ASCII byte at %d: %q", i, loc)
					break
				}
			}

			// Check for Vary: Accept header to prevent cache poisoning
			// Use Vary header values list to avoid substring matches (e.g., "Accept-Encoding")
			varyHdrs := w.Header().Values("Vary")
			hasVaryAccept := false
			for _, v := range varyHdrs {
				for _, part := range strings.Split(v, ",") {
					if strings.TrimSpace(part) == "Accept" {
						hasVaryAccept = true
						break
					}
				}
			}
			if tt.wantVaryHdr && !hasVaryAccept {
				t.Errorf("want Vary: Accept header, got %v", varyHdrs)
			}
			if !tt.wantVaryHdr && hasVaryAccept {
				t.Errorf("want no Vary: Accept header, got %v", varyHdrs)
			}
		})
	}
}

func TestDisallowedBodyParses(t *testing.T) {
	e := &struct {
		Error      string `json:"error"`
		TLSVersion string `json:"tls_version"`
	}{}
	err := json.Unmarshal(disallowedOriginBody, e)
	if err != nil {
		t.Errorf("disallowedOriginBody did not parse: %s", err)
	}
}

func TestJSONAPI(t *testing.T) {
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	webHandleFunc := http.NotFound
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    map[string]bool{"blocked.com": true},
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	tm := tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", staticHandler, webHandleFunc, oa, newTestLogger(t), newTestLogger(t))

	srv := howhttptest.NewServer(tm)
	defer srv.Close()

	type apiTest struct {
		path        string
		origin      string
		status      int
		contentType string
		body        string
	}
	// The one thing in the body that differs between the clients below is
	// the protocols they offer: net/http offers HTTP/1.1 after HTTP/2.
	expectedJSONBodyH2 := strings.Replace(expectedJSONBody, `"given_alpn_protocols":["http/1.1"]`, `"given_alpn_protocols":["h2","http/1.1"]`, 1)
	if expectedJSONBodyH2 == expectedJSONBody {
		t.Fatalf("expectedJSONBody has no given_alpn_protocols to replace")
	}
	tests := []apiTest{
		{
			path:        "/a/check",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        expectedJSONBody,
		},
		{
			path:        "/a/check?callback=parseTLS",
			status:      http.StatusOK,
			contentType: "application/javascript",
			body:        "parseTLS(" + expectedJSONBody + ");",
		},
		{
			path:        "/a/check",
			origin:      "https://blocked.com",
			status:      http.StatusBadRequest,
			contentType: "application/json",
			body:        string(disallowedOriginBody),
		},
		{
			path:        "/a/check?callback=foobarParse",
			origin:      "https://blocked.com",
			status:      http.StatusOK,
			contentType: "application/javascript",
			body:        "foobarParse(" + string(disallowedOriginBody) + ");",
		},
	}
	run := func(t *testing.T, c *http.Client, wantProtoMajor int, wantConnClose bool) {
		for i, at := range tests {
			if wantProtoMajor == 2 {
				at.body = strings.Replace(at.body, expectedJSONBody, expectedJSONBodyH2, 1)
			}
			t.Run(fmt.Sprintf("%d-%s", i, at.path), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()

				r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+at.path, nil)
				if err != nil {
					t.Fatalf("NewRequest: %s", err)
				}

				r.Header.Set("Origin", at.origin)
				resp, err := c.Do(r)
				if err != nil {
					t.Fatalf("Get: %s", err)
				}
				b, err := io.ReadAll(resp.Body)
				defer resp.Body.Close()
				if err != nil {
					t.Fatalf("ReadAll: %s", err)
				}
				if resp.ProtoMajor != wantProtoMajor {
					t.Errorf("ProtoMajor, want: %d, got: %d (%s)", wantProtoMajor, resp.ProtoMajor, resp.Proto)
				}
				if resp.StatusCode != at.status {
					t.Errorf("status code, want: %d, got: %d", at.status, resp.StatusCode)
				}
				if string(b) != at.body {
					t.Errorf("body, diff: %s", cmp.Diff(at.body, string(b)))
					t.Errorf("body, want:\n%#v\ngot:%#v\n", at.body, string(b))
				}
				ct := resp.Header.Get("Content-Type")
				if ct != at.contentType {
					t.Errorf("Content-Type, want %s, got %s", at.contentType, ct)
				}
				if wantConnClose && !resp.Close {
					t.Errorf("want connection to be closed after each request, but was left open")
				}
			})
		}
	}

	noRedirects := func(req *http.Request, via []*http.Request) error {
		return errors.New("no redirects should be seen")
	}

	t.Run("http1.1", func(t *testing.T) {
		// The per-request Connection: close assertion is only meaningful for
		// HTTP/1.1; force the ALPN choice so the transport can't pick h2.
		tlsConf := srv.ClientTLSConfig()
		tlsConf.NextProtos = []string{"http/1.1"}
		c := &http.Client{
			Transport:     &http.Transport{TLSClientConfig: tlsConf},
			CheckRedirect: noRedirects,
		}
		run(t, c, 1, true)
	})

	t.Run("http2", func(t *testing.T) {
		tlsConf := srv.ClientTLSConfig()
		tlsConf.NextProtos = []string{"h2"}
		c := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   tlsConf,
				ForceAttemptHTTP2: true,
			},
			CheckRedirect: noRedirects,
		}
		run(t, c, 2, false)
	})
}

func TestIndexGoldenPath(t *testing.T) {
	index = loadIndex()

	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	tm := tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", staticHandler, handleWeb, oa, newTestLogger(t), newTestLogger(t))

	srv := howhttptest.NewServer(tm)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %s", err)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Get: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code, want: %d, got: %d", http.StatusOK, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type, want prefix %q, got %q", "text/html", ct)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %s", err)
	}
	if len(b) == 0 {
		t.Error("response body was empty")
	}
}

// expectedJSONBody is what the API says of Go's own client when it offers
// HTTP/1.1 alone and connects to an IP address, and so sends no server name.
const (
	expectedJSONBody = `{"given_cipher_suites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],"given_named_groups":["X25519MLKEM768","SecP256r1MLKEM768","SecP384r1MLKEM1024","x25519","secp256r1","secp384r1","secp521r1"],"given_signature_algorithms":["mldsa44","mldsa65","mldsa87","rsa_pss_rsae_sha256","ecdsa_secp256r1_sha256","ed25519","rsa_pss_rsae_sha384","rsa_pss_rsae_sha512","rsa_pkcs1_sha256","rsa_pkcs1_sha384","rsa_pkcs1_sha512","ecdsa_secp384r1_sha384","ecdsa_secp521r1_sha512"],"given_psk_key_exchange_modes":[],"given_alpn_protocols":["http/1.1"],"given_key_share_groups":["X25519MLKEM768","x25519"],"post_quantum_key_agreement":true,"ephemeral_keys_supported":true,"session_ticket_supported":false,"psk_without_forward_secrecy_supported":false,"server_name_sent":false,"secure_renegotiation_supported":true,"encrypted_client_hello_offered":false,"tls_compression_supported":false,"unknown_cipher_suite_supported":false,"beast_vuln":false,"able_to_detect_n_minus_one_splitting":false,"insecure_cipher_suites":{},"tls_version":"TLS 1.3","rating":"Probably Okay"}`
)

// TestClientHelloSignalsRendered sends ALPN protocol names written to break
// out of HTML, JavaScript and JSON, and checks that the page, the API and its
// JSONP form show them without letting any of it through.
func TestClientHelloSignalsRendered(t *testing.T) {
	index = loadIndex()

	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	tm := tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", staticHandler, handleWeb, oa, newTestLogger(t), newTestLogger(t))

	srv := howhttptest.NewServer(tm)
	defer srv.Close()

	sent := []string{
		"http/1.1",
		"<script>alert(1)</script>",
		`");alert('x');//`,
		"</pre>\u2028\xff\x00\\",
		"<!--",
	}
	want := []string{
		"http/1.1",
		`\x3cscript\x3ealert\x281\x29\x3c/script\x3e`,
		`\x22\x29\x3balert\x28\x27x\x27\x29\x3b//`,
		`\x3c/pre\x3e\xe2\x80\xa8\xff\x00\x5c`,
		`\x3c\x21--`,
	}
	tlsConf := srv.ClientTLSConfig()
	tlsConf.NextProtos = sent
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}

	get := func(t *testing.T, path string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %s", err)
		}
		resp, err := c.Do(r)
		if err != nil {
			t.Fatalf("Get: %s", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status code, want: %d, got: %d", http.StatusOK, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %s", err)
		}
		return string(b)
	}
	// Nothing the client sent may come back as it was, other than the
	// protocol name that is only letters, digits and "/.".
	checkNoneRaw := func(t *testing.T, body string) {
		t.Helper()
		for _, s := range sent[1:] {
			if strings.Contains(body, s) {
				t.Errorf("body has the client's %q in it as sent", s)
			}
		}
		for _, s := range []string{"<script>alert", "alert(", "\xff", "\x00", "\u2028", "<!--\n"} {
			if strings.Contains(body, s) {
				t.Errorf("body has %q in it", s)
			}
		}
	}

	t.Run("page", func(t *testing.T) {
		body := get(t, "/")
		checkNoneRaw(t, body)
		// html/template has nothing to escape in the rendered names but
		// "+", which isn't in these.
		for _, w := range want {
			if li := "<li>" + w + "</li>"; !strings.Contains(body, li) {
				t.Errorf("page doesn't have %q in it", li)
			}
		}
		for _, h := range []string{"Server Name Indication", "Secure Renegotiation", "Encrypted Client Hello", "Given Key Shares", "Given ALPN Protocols"} {
			if !strings.Contains(body, "<h2>"+h+"</h2>") {
				t.Errorf("page has no %q section", h)
			}
		}
		if !strings.Contains(body, "<li>X25519MLKEM768</li>\n                \n                <li>x25519</li>\n                \n              </ul>\n              \n              <p><a href=\"/s/about.html/#given-key-shares\">") {
			t.Errorf("page doesn't list the key shares of Go's client, X25519MLKEM768 then x25519")
		}
	})

	checkJSON := func(t *testing.T, body string) {
		t.Helper()
		var got struct {
			ALPN []string `json:"given_alpn_protocols"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("json.Unmarshal: %s", err)
		}
		if diff := cmp.Diff(want, got.ALPN); diff != "" {
			t.Errorf("given_alpn_protocols (-want +got):\n%s", diff)
		}
	}
	t.Run("json", func(t *testing.T) {
		body := get(t, "/a/check")
		checkNoneRaw(t, body)
		checkJSON(t, body)
	})
	t.Run("jsonp", func(t *testing.T) {
		body := get(t, "/a/check?callback=cb")
		checkNoneRaw(t, body)
		inner, ok := strings.CutPrefix(body, "cb(")
		if !ok {
			t.Fatalf("body doesn't start with the callback: %q", body)
		}
		inner, ok = strings.CutSuffix(inner, ");")
		if !ok {
			t.Fatalf("body doesn't end the callback: %q", body)
		}
		checkJSON(t, inner)
		// The only places a quote may be in the JavaScript are around
		// JSON's own strings, so a name can't end one early.
		if strings.Contains(inner, `\"`) {
			t.Errorf("body has an escaped quote in it, which no value should need: %q", body)
		}
	})
}
