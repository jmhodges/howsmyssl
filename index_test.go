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
	staticHandler := makeStaticHandler("/static", stats)
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
	staticHandler := makeStaticHandler("/static", stats)
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

func TestJSONRedirectContentType(t *testing.T) {
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler("/static", stats)
	webHandleFunc := http.NotFound

	// Test that redirects from howsmytls.com to howsmyssl.com respect Accept header
	tm := tlsMux("www.howsmyssl.com", "www.howsmyssl.com", "", staticHandler, webHandleFunc, nil, newTestLogger(t), newTestLogger(t))

	tests := []struct {
		name         string
		path         string
		acceptHdrs   []string // Support multiple Accept headers
		wantCT       string
		wantVaryHdr  bool
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
			wantVaryHdr: false, // No Vary when no Accept header
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
	staticHandler := makeStaticHandler("/static", stats)
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
	staticHandler := makeStaticHandler("/static", stats)
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

const (
	expectedJSONBody = `{"given_cipher_suites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],"given_named_groups":["X25519MLKEM768","SecP256r1MLKEM768","SecP384r1MLKEM1024","x25519","secp256r1","secp384r1","secp521r1"],"given_signature_algorithms":["rsa_pss_rsae_sha256","ecdsa_secp256r1_sha256","ed25519","rsa_pss_rsae_sha384","rsa_pss_rsae_sha512","rsa_pkcs1_sha256","rsa_pkcs1_sha384","rsa_pkcs1_sha512","ecdsa_secp384r1_sha384","ecdsa_secp521r1_sha512"],"post_quantum_key_agreement":true,"ephemeral_keys_supported":true,"session_ticket_supported":false,"tls_compression_supported":false,"unknown_cipher_suite_supported":false,"beast_vuln":false,"able_to_detect_n_minus_one_splitting":false,"insecure_cipher_suites":{},"tls_version":"TLS 1.3","rating":"Probably Okay"}`
)
